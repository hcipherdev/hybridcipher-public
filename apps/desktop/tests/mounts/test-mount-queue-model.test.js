// Tests the background mount queue in the Mount Center: buildMountCenterModel() and mountStepLabel() in src/ui-utils.js (step labels, elapsed time, slow and cancel states, activity banner) and checkMountBatches()/reportMountBatch() in src/app.js (one summary per batch, none repeated).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildMountCenterModel, mountStepLabel } = uiScope.HybridCipherUiUtils;
const autoScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/auto-mount-utils.js', import.meta.url), 'utf8'), autoScope);
const { summarizeBackgroundMounts } = autoScope.HybridCipherAutoMountUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function section(start, end) {
    const begin = source.indexOf(start);
    const finish = source.indexOf(end, begin + start.length);
    assert.ok(begin >= 0 && finish > begin, `Cannot extract ${start}`);
    return source.slice(begin, finish);
}

const folder = (rootId, extra = {}) => ({
    root_id: rootId, name: rootId, path: `/f/${rootId}`, group_id: 'p', group_name: 'Personal',
    workspace: 'personal', can_mount: true, auto_mount: true, mount: null, ...extra,
});
const overview = {
    selected_group_id: 'p',
    folders: [
        folder('done', { mount: { mountpoint: '/m/done', backend: 'macos-file-provider', availability: 'usable' } }),
        folder('running'),
        folder('slow'),
        folder('waiting'),
    ],
};
const job = (rootId, status, extra = {}) => ({
    job_id: 1, batch_id: 7, root_id: rootId, name: rootId, origin: 'auto', status,
    step: null, elapsed_ms: 0, slow: false, cancel_requested: false, steps: [], ...extra,
});

test('step labels name what the mount is doing', () => {
    assert.equal(mountStepLabel('registering'), 'Registering with Finder');
    assert.equal(mountStepLabel('connecting_finder', 'windows'), 'Waiting for File Explorer');
    assert.equal(mountStepLabel('sync_fallback'), 'Starting sync mount');
    assert.equal(mountStepLabel('unknown'), 'Starting');
});

test('queued and running folders show their step, time and a cancel action', () => {
    const now = 1_000_000;
    const model = buildMountCenterModel(overview, {
        now,
        queue: {
            running: job('running', 'running', { step: 'connecting_finder', elapsed_ms: 4000, received_at: now - 2000,
                steps: [{ step: 'checking', ms: 300 }, { step: 'registering', ms: 1200 }] }),
            slow: job('slow', 'running', { step: 'sync_fallback', elapsed_ms: 50_000, slow: true, received_at: now }),
            waiting: job('waiting', 'queued'),
        },
    });
    const rows = Object.fromEntries(model.sections[0].folders.map(row => [row.rootId, row]));

    assert.equal(rows.running.status, 'mounting');
    assert.equal(rows.running.stepLabel, 'Waiting for Finder');
    assert.equal(rows.running.elapsedLabel, '6 s');
    assert.deepEqual(plain(rows.running.steps), [
        { label: 'Checking access', duration: '0 s' },
        { label: 'Registering with Finder', duration: '1 s' },
    ]);
    assert.deepEqual(plain(rows.running.actions), [{ id: 'cancel', label: 'Cancel' }]);
    assert.equal(rows.slow.slow, true);
    assert.equal(rows.slow.elapsedLabel, '50 s');
    assert.equal(rows.waiting.status, 'queued');
    assert.equal(rows.waiting.stepLabel, 'Waiting in queue');
    assert.equal(model.activity.label, 'Mounting 2 folders · 1 waiting · 1 taking longer than usual');
});

test('a mounted folder can be opened while others are still mounting', () => {
    const model = buildMountCenterModel(overview, {
        queue: {
            done: job('done', 'ready', { mount: { mountpoint: '/m/done' } }),
            running: job('running', 'running', { step: 'registering' }),
        },
    });
    const done = model.sections[0].folders.find(row => row.rootId === 'done');

    assert.equal(done.status, 'mounted');
    assert.deepEqual(plain(done.actions.map(action => action.id)), ['open', 'unmount']);
});

test('a running job asked to stop no longer offers Cancel', () => {
    const model = buildMountCenterModel(overview, {
        queue: { running: job('running', 'running', { step: 'registering', cancel_requested: true }) },
    });
    const row = model.sections[0].folders.find(entry => entry.rootId === 'running');

    assert.equal(row.stepLabel, 'Stopping after this step');
    assert.equal(row.actions.length, 0);
});

function batchApp() {
    const methods = [
        section('    checkMountBatches() {', '    reportMountBatch('),
        section('    reportMountBatch(', '    isWelcomeOverlayDismissed() {'),
    ].join('\n');
    const app = new (Function('summarizeBackgroundMountsValue', `return class { ${methods} }`)(summarizeBackgroundMounts))();
    const notifications = [];
    Object.assign(app, {
        mountQueueJobs: {}, reportedMountBatches: new Set(), mountBatchInfo: {}, backgroundMountResults: {},
        backgroundMountAttentionUnseen: 0, activeWorkspaceView: 'home', platformInfo: { os_type: 'macos' },
        updateMountCenterBadge() {}, showMountCenterView() {},
        showNotification: (message, type) => notifications.push({ message, type }),
    });
    return { app, notifications };
}

test('a batch is summarized once, only after all its folders are done', () => {
    const { app, notifications } = batchApp();
    app.mountBatchInfo[7] = { label: 'Auto-mount', attention: [] };
    app.mountQueueJobs = {
        a: job('a', 'ready', { mount: { backend: 'macos-file-provider', availability: 'usable' } }),
        b: job('b', 'running'),
    };
    app.checkMountBatches();
    assert.equal(notifications.length, 0, 'still running');

    app.mountQueueJobs.b = job('b', 'failed', { error: 'Source folder missing' });
    app.checkMountBatches();
    app.checkMountBatches();
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].message, 'Auto-mount: 1 of 2 folders mounted. 1 needs attention.');
    assert.match(app.backgroundMountResults.b.reason, /Source folder missing/);
    assert.equal(app.backgroundMountAttentionUnseen, 1);
});

test('a clean batch stays silent', () => {
    const { app, notifications } = batchApp();
    app.mountQueueJobs = { a: job('a', 'ready', { mount: { backend: 'macos-file-provider', availability: 'usable' } }) };
    app.checkMountBatches();
    assert.equal(notifications.length, 0);
});

test('a single folder the user mounted reports its own error', () => {
    const { app, notifications } = batchApp();
    app.mountBatchInfo[7] = { label: 'Mount', attention: [] };
    app.mountQueueJobs = { a: job('a', 'failed', { name: 'Taxes', error: 'Mount failed: no keys' }) };
    app.checkMountBatches();
    assert.deepEqual(notifications, [{ message: 'Taxes: Mount failed: no keys', type: 'error' }]);
});
