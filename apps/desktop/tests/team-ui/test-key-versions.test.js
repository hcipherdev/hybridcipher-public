// Tests app.js Key version card and panel (refreshAdminKeyVersionsSummary, renderKeyVersionsSummary, describeKeyDevice, renderKeyVersionsModal), the Key rotation panel state (keyStatusReportsRollout, rollingOutKeyVersion, hasNewerKeyVersion, renderKeyRotationPanel, renderLeftoverKeyFiles, refreshLeftoverKeyFiles), reportKeyReceiptsIfDue() (with and without its file move), newGroupKeyAvailable() and the minute health check that forces a key check for a newer group key (performSessionHealthCheck), the Key versions watch that re-checks while devices switch (keyDeviceSeenRecently, keyStatusWatchIntervalMs, keyStatusWatchTick, quiet refreshAdminKeyVersionsSummary), migrateLeftoverKeyFiles(), and describeGroupKey() for the group screens.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function method(name) {
    const start = new RegExp(`^    (?:async )?${name}\\(`, 'm').exec(source);
    assert.ok(start, name);
    const boundary = /\r?\n    }\r?\n/g;
    boundary.lastIndex = start.index;
    const end = boundary.exec(source);
    assert.ok(end, name);
    return source.slice(start.index, end.index + end[0].length);
}

function element(id = '') {
    const classes = new Set(['hidden']);
    return {
        id, className: '', type: '', textContent: '', innerHTML: '', style: {}, children: [], listeners: new Map(),
        classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains: key => classes.has(key) },
        appendChild(child) { this.children.push(child); },
        addEventListener(event, callback) { this.listeners.set(event, callback); },
    };
}

const NAMES = ['captureWorkspaceReadContext', 'setDashboardCardLink', 'formatKeyVersion', 'formatKeyDate',
    'describeKeyVersionOrigin', 'refreshAdminKeyVersionsSummary', 'renderKeyVersionsSummary', 'describeKeyDevice',
    'buildKeyDeviceRow', 'openKeyVersionsModal', 'closeKeyVersionsModal', 'renderKeyVersionsModal', 'reportKeyReceiptsIfDue',
    'newGroupKeyAvailable', 'performSessionHealthCheck', 'keyDeviceSeenRecently', 'keyStatusWatchIntervalMs', 'keyStatusWatchTick',
    'keyStatusReportsRollout', 'rollingOutKeyVersion', 'hasNewerKeyVersion', 'renderKeyRotationPanel', 'renderLeftoverKeyFiles', 'refreshLeftoverKeyFiles',
    'migrateLeftoverKeyFiles', 'describeGroupKey'];

function environment(invoke = async () => ({ success: true, data: null })) {
    const nodes = new Map();
    const node = id => {
        if (!nodes.has(id)) nodes.set(id, element(id));
        return nodes.get(id);
    };
    const doc = { getElementById: node, createElement: () => element(), visibilityState: 'visible' };
    const methods = vm.runInNewContext(`({${NAMES.map(method).join(',\n')}})`, {
        invoke, console: { warn() {} }, Date, Number, Array,
        document: doc,
    });
    const calls = [];
    const app = Object.assign({
        isLoggedIn: true, workspaceSwitchSequence: 1, desktopAccountGeneration: 1, currentUser: 'owner@example.com',
        currentDeviceId: 'mac', formatCount: value => String(value), escapeHtml: value => String(value),
        showDeviceAccessQueue() { calls.push('approval-queue'); }, focusOperationsSection() { calls.push('focus'); },
    }, methods);
    return { app, node, calls, doc };
}

const v1 = { epoch_id: 'e1', version: 1, created_at: '2026-10-02T09:00:00Z', created_by_email: 'owner@example.com', is_current: false };
const v2 = { epoch_id: 'e2', version: 2, created_at: '2026-10-16T09:00:00Z', created_by_email: 'owner@example.com', reason: 'manual', is_current: true };
const status = {
    current: v2, previous: v1, versions: [v2, v1],
    summary: { devices: 4, updated: 2, waiting: 1, not_sent: 1 },
    devices: [
        { device_id: 'xps', email: 'bo@example.com', state: 'not_sent', invitation_key_present: true, pending_approval: false },
        { device_id: 'old-mac', email: 'owner@example.com', state: 'waiting', held_version: 1, last_seen: '2026-10-10T09:00:00Z', invitation_key_present: true },
        { device_id: 'mac', email: 'owner@example.com', state: 'updated', held_version: 2, confirmed_at: '2026-10-16T09:05:00Z', invitation_key_present: true },
        { device_id: 'ipad', email: 'bo@example.com', state: 'updated', held_version: 2, invitation_key_present: true },
    ],
};

test('the card shows the current version, how many devices updated, and who rotated', async () => {
    const { app, node } = environment(async () => ({ success: true, data: status }));
    await app.refreshAdminKeyVersionsSummary();
    assert.equal(node('adminKeyVersionsValue').textContent, 'v2 · 2 of 4 devices updated');
    assert.match(node('adminKeyVersionsMeta').textContent, /^Rotated .*2026 by owner@example\.com · previous v1$/);
    assert.equal(node('adminKeyVersionsAttentionLink').textContent, '1 device not sent the key →');
    assert.equal(node('adminKeyVersionsAttentionLink').classList.contains('hidden'), false);
});

test('the card falls back to waiting devices, the first key, members and plain-string errors', async () => {
    const { app, node } = environment();
    app.renderKeyVersionsSummary({ ...status, previous: null, current: v1, summary: { devices: 1, updated: 0, waiting: 1, not_sent: 0 } });
    assert.equal(node('adminKeyVersionsValue').textContent, 'v1 · 0 of 1 device updated');
    assert.match(node('adminKeyVersionsMeta').textContent, /^Created /);
    assert.equal(node('adminKeyVersionsAttentionLink').textContent, '1 waiting to update →');

    app.renderKeyVersionsSummary(null);
    assert.equal(node('adminKeyVersionsMeta').textContent, 'Only group admins can see key status');
    assert.equal(node('adminKeyVersionsAttentionLink').classList.contains('hidden'), true);

    const failing = environment(async () => { throw 'Please login through the desktop app'; });
    await failing.app.refreshAdminKeyVersionsSummary();
    assert.equal(failing.node('adminKeyVersionsValue').textContent, 'Key status unavailable');
    assert.equal(failing.node('adminKeyVersionsMeta').textContent, 'Please login through the desktop app');
});

test('each device state explains what happens next', () => {
    const { app } = environment();
    const updated = app.describeKeyDevice(status.devices[2], v2);
    assert.equal(updated.label, 'Updated');
    assert.match(updated.hint, /^Has v2 · confirmed /);
    // Not seen for days: it switches when HybridCipher next runs there.
    const waiting = app.describeKeyDevice(status.devices[1], v2);
    assert.equal(waiting.tone, 'warn');
    assert.match(waiting.hint, /^Still on v1\. The key was sent\. Offline since .+; it switches to v2 when HybridCipher next runs there\. Remove it if nobody uses it\.$/);
    // Seen within two hours: the running app picks it up within about a minute.
    const online = app.describeKeyDevice({ ...status.devices[1], last_seen: new Date().toISOString() }, v2);
    assert.equal(online.hint, 'Still on v1. The key was sent. HybridCipher on it switches to v2 within about a minute.');
    const unseen = app.describeKeyDevice({ ...status.devices[1], held_version: null, last_seen: null }, v2);
    assert.match(unseen.hint, /^The key was sent\. It switches to v2 when HybridCipher next runs there\./);
    const cancelled = app.describeKeyDevice({ ...status.devices[1], held_version: 3, held_version_cancelled: true }, v2);
    assert.equal(cancelled.label, 'Waiting');
    assert.match(cancelled.hint, /^Last confirmed v3, which was cancelled\. Offline since .+; it switches to v2 when HybridCipher next runs there\./);
    const skipped = app.describeKeyDevice(status.devices[0], v2);
    assert.equal(skipped.action, 'approve');
    assert.match(skipped.hint, /Skipped when v2 was created/);
    const pending = app.describeKeyDevice({ ...status.devices[0], pending_approval: true }, v2);
    assert.match(pending.hint, /waiting for approval\. Approving it sends v2/);
    const keyless = app.describeKeyDevice({ ...status.devices[0], invitation_key_present: false }, v2);
    assert.equal(keyless.action, null);
    assert.match(keyless.hint, /Sign in again on it/);
});

test('the panel re-checks every 15 seconds while a running device switches, every 2 minutes for offline ones, never when none wait', () => {
    const { app } = environment();
    const now = Date.parse('2026-10-23T12:00:00Z');
    const device = (state, last_seen) => ({ device_id: Math.random().toString(), state, last_seen });
    assert.equal(app.keyStatusWatchIntervalMs({ devices: [device('waiting', '2026-10-23T11:00:00Z'), device('waiting', '2026-10-22T09:00:00Z')] }, now), 15 * 1000);
    assert.equal(app.keyStatusWatchIntervalMs({ devices: [device('waiting', '2026-10-22T09:00:00Z'), device('updated', '2026-10-23T11:59:00Z')] }, now), 2 * 60 * 1000);
    assert.equal(app.keyStatusWatchIntervalMs({ devices: [device('waiting', null)] }, now), 2 * 60 * 1000);
    assert.equal(app.keyStatusWatchIntervalMs({ devices: [device('updated', '2026-10-23T11:59:00Z'), device('not_sent', null)] }, now), null);
    assert.equal(app.keyStatusWatchIntervalMs(null, now), null);
});

test('the watch fetches only while the panel shows devices still switching, quietly, and re-renders the open window on a change', async () => {
    const recent = new Date(Date.now() - 60 * 1000).toISOString();
    const waitingStatus = { ...status, devices: [{ device_id: 'xps', state: 'waiting', held_version: 1, last_seen: recent, invitation_key_present: true }] };
    let answer = waitingStatus;
    let fetches = 0;
    const { app, node, doc } = environment(async command => {
        if (command !== 'get_group_key_status') return { success: true, data: null };
        fetches += 1;
        return answer instanceof Error ? Promise.reject(answer) : { success: true, data: answer };
    });
    const rendered = [];
    app.renderKeyVersionsModal = value => rendered.push(value);
    Object.assign(app, { isLoggedIn: true, activeWorkspaceView: 'admin', keyStatusCache: waitingStatus, lastKeyStatusFetchAt: 0 });
    const now = Date.now();

    // A hidden window never fetches.
    doc.visibilityState = 'hidden';
    assert.equal(await app.keyStatusWatchTick(now), false);
    doc.visibilityState = 'visible';

    // Due and visible: one quiet fetch; the card is not blanked to "Loading" first.
    const seen = [];
    const value = node('adminKeyVersionsValue');
    let text = 'v2 · 3 of 4 updated';
    Object.defineProperty(value, 'textContent', { get: () => text, set: next => { seen.push(next); text = next; } });
    assert.equal(await app.keyStatusWatchTick(now), true);
    assert.equal(fetches, 1);
    assert.ok(!seen.includes('Loading key status...'));
    // Not due yet: nothing.
    assert.equal(await app.keyStatusWatchTick(now + 5 * 1000), false);
    assert.equal(fetches, 1);
    // Another view: nothing, unless the Key versions window is open.
    app.activeWorkspaceView = 'home';
    assert.equal(await app.keyStatusWatchTick(now + 60 * 1000), false);
    node('keyVersionsModal').style.display = 'flex';
    // The device switched: the open window is re-rendered.
    answer = { ...waitingStatus, devices: [{ ...waitingStatus.devices[0], state: 'updated', held_version: 2 }] };
    assert.equal(await app.keyStatusWatchTick(Date.now() + 60 * 1000), true);
    assert.equal(rendered.length, 1);
    // Nothing is waiting any more: the watch stops fetching.
    assert.equal(await app.keyStatusWatchTick(Date.now() + 10 * 60 * 1000), false);
    assert.equal(fetches, 2);

    // A failed quiet refresh keeps the previous status.
    app.keyStatusCache = waitingStatus;
    app.lastKeyStatusFetchAt = 0;
    answer = new Error('offline');
    assert.equal(await app.keyStatusWatchTick(Date.now()), false);
    assert.equal(app.keyStatusCache, waitingStatus);
});

test('the panel lists the history, a device summary and rows that open the approval queue', async () => {
    const { app, node, calls } = environment(async () => ({ success: true, data: status }));
    await app.openKeyVersionsModal();
    assert.equal(node('keyVersionsModal').style.display, 'flex');
    assert.match(node('keyVersionsCurrent').textContent, /^v2 · Rotated /);
    const history = node('keyVersionsHistory').children;
    assert.equal(history.length, 2);
    assert.match(history[0].innerHTML, /v2 <span class="key-version-tag">Current<\/span>/);
    assert.match(history[0].innerHTML, / · manual/);
    assert.match(history[1].innerHTML, /Previous/);
    assert.equal(node('keyVersionsDeviceSummary').textContent, '2 updated · 1 waiting · 1 not sent');
    const rows = node('keyVersionsDeviceList').children;
    assert.equal(rows.length, 4);
    assert.match(rows[2].innerHTML, /mac \(this device\)/);
    assert.equal(rows[0].children[0].textContent, 'Give access →');
    rows[0].children[0].listeners.get('click')();
    assert.equal(node('keyVersionsModal').style.display, 'none');
    assert.deepEqual(calls, ['approval-queue', 'focus']);
    assert.equal(rows[1].children.length, 0);
});

test('a staged version from an unfinished rotation is labelled as rolling out', () => {
    const { app, node } = environment();
    const v3 = { epoch_id: 'e3', version: 3, created_at: '2026-10-16T10:00:00Z', is_current: false, rolling_out: true };
    app.renderKeyVersionsModal({ ...status, versions: [v3, { ...v2, rolling_out: false }, { ...v1, rolling_out: false }] });
    assert.match(node('keyVersionsHistory').children[0].innerHTML, /Being rolled out/);
});

test('without the server flag a newer version is not guessed to be rolling out', () => {
    const { app, node } = environment();
    const hidden = id => node(id).classList.contains('hidden');
    // An older server after a cancelled rotation: v3 exists, nothing says whether it is running.
    const v3 = { epoch_id: 'e3', version: 3, created_at: '2026-10-18T10:00:00Z', is_current: false };
    const unflagged = { ...status, versions: [v3, v2, v1] };
    assert.equal(app.rollingOutKeyVersion(unflagged), null);
    app.renderKeyRotationPanel(unflagged);
    assert.equal(node('adminRekeyStatusLine').textContent,
        "Current key: v2 · Can't tell whether a rotation is running; the server needs updating.");
    assert.equal(hidden('adminRekeyIdleActions'), false);
    app.renderKeyVersionsModal(unflagged);
    assert.match(node('keyVersionsHistory').children[0].innerHTML, /Status unknown/);
    // An older server with no newer version is simply idle.
    app.renderKeyRotationPanel({ ...status, versions: [v2, v1] });
    assert.match(node('adminRekeyStatusLine').textContent, /^Current key: v2 · Rotated /);
    assert.equal(hidden('adminRekeyIdleActions'), false);
});

test('key receipts are reported hourly, retried after 15 minutes, and forced after a rotation', async () => {
    const MINUTE = 60 * 1000;
    const results = [{ success: true, data: [] }, { success: false, error: 'offline' }, { success: true, data: [] }, { success: true, data: [] },
        { success: true, data: [] }];
    const commands = [];
    const { app } = environment(async command => {
        commands.push(command);
        return command === 'report_key_receipts' ? results.shift() : { success: true, data: { migrated: 0, failed: 0 } };
    });
    assert.equal(await app.reportKeyReceiptsIfDue(0), true);
    assert.equal(await app.reportKeyReceiptsIfDue(59 * MINUTE), false);
    assert.equal(await app.reportKeyReceiptsIfDue(60 * MINUTE), false);
    assert.equal(await app.reportKeyReceiptsIfDue(70 * MINUTE), false);
    assert.equal(await app.reportKeyReceiptsIfDue(75 * MINUTE), true);
    assert.equal(await app.reportKeyReceiptsIfDue(76 * MINUTE, { force: true }), true);
    // Each successful receipt is followed by moving files left on an older key.
    const MOVE = 'migrate_leftover_key_files';
    assert.deepEqual(commands, ['report_key_receipts', MOVE, 'report_key_receipts', 'report_key_receipts', MOVE, 'report_key_receipts', MOVE]);
    // Right after a rotation the caller moves files itself, with progress, so the check skips it.
    assert.equal(await app.reportKeyReceiptsIfDue(77 * MINUTE, { force: true, moveFiles: false }), true);
    assert.deepEqual(commands.slice(7), ['report_key_receipts']);
    app.isLoggedIn = false;
    assert.equal(await app.reportKeyReceiptsIfDue(500 * MINUTE, { force: true }), false);
});

test('a newer group key forces the key check inside the hourly window; otherwise the window holds', async () => {
    const MINUTE = 60 * 1000;
    let newerKey = false;
    const commands = [];
    const { app } = environment(async command => {
        commands.push(command);
        if (command === 'group_key_update_available') return { success: true, data: newerKey };
        if (command === 'report_key_receipts') return { success: true, data: { reported: [], failed_groups: 0 } };
        return { success: true, data: { migrated: 0, failed: 0 } };
    });
    Object.assign(app, {
        ensureSessionReady: async () => ({ refreshed: false }),
        refreshTeamLicenseStatus: async () => {}, refreshJoinCardIfDue() {}, sharePinVerificationsIfDue() {},
        async repairOwnDevicesIfDue() {},
    });
    const tick = () => new Promise(resolve => setImmediate(resolve));
    const receipts = () => commands.filter(command => command === 'report_key_receipts').length;

    await app.reportKeyReceiptsIfDue(Date.now());
    assert.equal(receipts(), 1);
    // A minute later nothing changed on the server: the hourly window holds.
    await app.performSessionHealthCheck({ silent: true });
    await tick(); await tick();
    assert.equal(receipts(), 1);
    // A rotation finished: the next minute's check runs the key check and the file move at once.
    newerKey = true;
    await app.performSessionHealthCheck({ silent: true });
    await tick(); await tick();
    assert.equal(receipts(), 2);
    assert.equal(commands.at(-1), 'migrate_leftover_key_files');
    // Not knowing (an error or no answer) counts as no newer key.
    const failing = environment(async () => { throw new Error('offline'); });
    assert.equal(await failing.app.newGroupKeyAvailable(), false);
    const empty = environment(async () => ({ success: false }));
    assert.equal(await empty.app.newGroupKeyAvailable(), false);
});

test('a key check that failed for one group is retried after 15 minutes, not an hour', async () => {
    const MINUTE = 60 * 1000;
    const results = [
        { success: true, data: { reported: [{ group_id: 'a', version: 3 }], failed_groups: 1 } },
        { success: true, data: { reported: [], failed_groups: 0 } },
    ];
    const commands = [];
    const { app } = environment(async command => {
        commands.push(command);
        return command === 'report_key_receipts' ? results.shift() : { success: true, data: { migrated: 0, failed: 0 } };
    });
    assert.equal(await app.reportKeyReceiptsIfDue(0), true);
    assert.equal(await app.reportKeyReceiptsIfDue(14 * MINUTE), false);
    assert.equal(await app.reportKeyReceiptsIfDue(15 * MINUTE), true);
    // Fully confirmed now, so the next check waits the usual hour.
    assert.equal(await app.reportKeyReceiptsIfDue(74 * MINUTE), false);
    // The groups that did confirm still get their leftover files moved.
    const MOVE = 'migrate_leftover_key_files';
    assert.deepEqual(commands, ['report_key_receipts', MOVE, 'report_key_receipts', MOVE]);
});

test('files are checked again after 15 minutes while a rotation runs or some could not be moved', async () => {
    const MINUTE = 60 * 1000;
    const moves = [
        { success: true, data: { migrated: 0, failed: 0, rotation_running: true } },
        { success: true, data: { migrated: 3, failed: 1, failures: [] } },
        { success: true, data: { migrated: 1, failed: 0, failures: [] } },
    ];
    const notes = [];
    const { app } = environment(async command => (command === 'report_key_receipts'
        ? { success: true, data: { reported: [{ group_id: 'a', version: 3 }], failed_groups: 0 } }
        : command === 'migrate_leftover_key_files' ? moves.shift() : { success: true, data: null }));
    app.showNotification = (message, tone) => notes.push([tone, message]);
    assert.equal(await app.reportKeyReceiptsIfDue(0), true);
    // The rotation was still running: back in 15 minutes, not an hour.
    assert.equal(await app.reportKeyReceiptsIfDue(15 * MINUTE), true);
    // One file failed: again in 15 minutes.
    assert.equal(await app.reportKeyReceiptsIfDue(30 * MINUTE), true);
    // All moved: the usual hour.
    assert.equal(await app.reportKeyReceiptsIfDue(45 * MINUTE), false);
    assert.equal(await app.reportKeyReceiptsIfDue(90 * MINUTE), true);
    assert.deepEqual(notes.map(note => note[0]), ['warning', 'success']);
    assert.match(notes[0][1], /^1 file on this computer could not be moved/);
    assert.equal(notes[1][1], 'Moved 1 file on this computer to the current key.');
});

test('the Key rotation panel offers Rotate keys, and only a status line while a rotation finishes', () => {
    const { app, node } = environment();
    const hidden = id => node(id).classList.contains('hidden');
    app.renderKeyRotationPanel({ ...status, current: v2, versions: [v2, v1] });
    assert.match(node('adminRekeyStatusLine').textContent, /^Current key: v2 · Rotated /);
    assert.equal(hidden('adminRekeyIdleActions'), false);

    // A rotation an older server left running: no actions until the server finishes it.
    const v3 = { epoch_id: 'e3', version: 3, created_at: '2026-10-16T19:21:00Z', is_current: false, rolling_out: true };
    const rolling = { ...status, versions: [v3, { ...v2, rolling_out: false }, { ...v1, rolling_out: false }],
        devices: [{ device_id: 'mac', held_version: 3 }, { device_id: 'xps', held_version: 2 }] };
    app.renderKeyRotationPanel(rolling);
    assert.equal(node('adminRekeyStatusLine').textContent, 'v3 finishing · 1 of 2 devices have it · current key v2');
    assert.equal(hidden('adminRekeyIdleActions'), true);

    // Members and missing key status.
    app.renderKeyRotationPanel(null);
    assert.equal(node('adminRekeyStatusLine').textContent, 'Only group admins can see key status.');
    assert.equal(hidden('adminRekeyIdleActions'), false);
    app.keyStatusError = 'offline';
    app.renderKeyRotationPanel(undefined);
    assert.equal(node('adminRekeyStatusLine').textContent, 'Key status unavailable: offline');
    assert.equal(hidden('adminRekeyIdleActions'), false);
    assert.equal(hidden('adminRekeyLeftoverActions'), false);
});

test('Move files shows only when this computer has files on an older key; while a rotation finishes the panel says they move then', async () => {
    let leftovers = { target_version: 2, files: 0, oldest_version: null };
    const { app, node } = environment(async () => ({ success: true, data: leftovers }));
    const hidden = id => node(id).classList.contains('hidden');
    await app.refreshLeftoverKeyFiles();
    app.renderKeyRotationPanel(status);
    assert.equal(hidden('adminRekeyLeftoverActions'), true);

    leftovers = { target_version: 2, files: 12, oldest_version: 1 };
    await app.refreshLeftoverKeyFiles();
    assert.equal(hidden('adminRekeyLeftoverActions'), false);
    assert.equal(node('adminRekeyMigrationLabel').textContent, 'Move 12 files to v2');
    assert.equal(node('adminRekeyLeftoverHint').textContent,
        '12 files on this computer are still on v1. HybridCipher moves them to v2 automatically within the hour.');
    assert.equal(hidden('adminRekeyLeftoverHint'), false);

    // Folder records count too, alone or with files.
    leftovers = { target_version: 2, files: 1, oldest_version: 1, folders: 2 };
    await app.refreshLeftoverKeyFiles();
    assert.equal(node('adminRekeyMigrationLabel').textContent, 'Move 1 file and 2 folder records to v2');
    leftovers = { target_version: 2, files: 0, oldest_version: null, folders: 1 };
    await app.refreshLeftoverKeyFiles();
    assert.equal(hidden('adminRekeyLeftoverActions'), false);
    assert.equal(node('adminRekeyLeftoverHint').textContent,
        '1 folder record on this computer is still on an older key. HybridCipher moves it to v2 automatically within the hour.');

    // Until a running rotation finishes nothing moves: no button, just the hint.
    const v3 = { epoch_id: 'e3', version: 3, created_at: '2026-10-16T19:21:00Z', is_current: false, rolling_out: true };
    app.renderKeyRotationPanel({ ...status, versions: [v3, v2, v1] });
    assert.equal(hidden('adminRekeyLeftoverActions'), false);
    assert.equal(hidden('adminRekeyMigrationBtn'), true);
    assert.equal(node('adminRekeyLeftoverHint').textContent,
        'Files on this computer move to v3 automatically when the rotation finishes.');
    assert.equal(hidden('adminRekeyLeftoverHint'), false);

    const failing = environment(async () => { throw 'No active group selected'; });
    assert.equal(await failing.app.refreshLeftoverKeyFiles(), null);
    failing.app.renderKeyRotationPanel(status);
    assert.equal(failing.node('adminRekeyLeftoverActions').classList.contains('hidden'), true);
});

test('moving leftover files refreshes the count only when something moved', async () => {
    const commands = [];
    let outcome = { migrated: 0, failed: 0 };
    const { app } = environment(async command => {
        commands.push(command);
        return command === 'migrate_leftover_key_files' ? { success: true, data: outcome }
            : { success: true, data: { target_version: 2, files: 0, oldest_version: null } };
    });
    assert.deepEqual(await app.migrateLeftoverKeyFiles(), { migrated: 0, failed: 0 });
    assert.deepEqual(commands, ['migrate_leftover_key_files']);
    outcome = { migrated: 3, failed: 1 };
    await app.migrateLeftoverKeyFiles();
    assert.deepEqual(commands, ['migrate_leftover_key_files', 'migrate_leftover_key_files', 'get_leftover_key_files']);
    const failing = environment(async () => ({ success: false, error: 'offline' }));
    assert.equal(await failing.app.migrateLeftoverKeyFiles(), null);
});

test('a newer version whose rotation ended is shown as cancelled, not rolling out', () => {
    const { app, node } = environment();
    const cancelled = { epoch_id: 'e3', version: 3, created_at: '2026-10-16T10:00:00Z', is_current: false, rolling_out: false };
    app.renderKeyVersionsModal({ ...status, versions: [cancelled, { ...v2, rolling_out: false }, { ...v1, rolling_out: false }] });
    assert.match(node('keyVersionsHistory').children[0].innerHTML, /Cancelled/);
    assert.equal(app.rollingOutKeyVersion({ ...status, versions: [cancelled] }), null);
    app.renderKeyRotationPanel({ ...status, versions: [cancelled, v2, v1] });
    assert.equal(node('adminRekeyIdleActions').classList.contains('hidden'), false);
});

test('a cancelled version below the current key is still shown as cancelled', () => {
    const { app, node } = environment();
    // v3 was cancelled, so the next rotation became v4.
    const v4 = { epoch_id: 'e4', version: 4, created_at: '2026-10-19T09:00:00Z', is_current: true, rolling_out: false, cancelled: false };
    const v3 = { epoch_id: 'e3', version: 3, created_at: '2026-10-16T10:00:00Z', is_current: false, rolling_out: false, cancelled: true };
    const older = { ...v2, is_current: false, rolling_out: false, cancelled: false };
    app.renderKeyVersionsModal({ ...status, current: v4, previous: older, versions: [v4, v3, older, { ...v1, rolling_out: false }] });
    const tags = node('keyVersionsHistory').children.map(item => (item.innerHTML.match(/key-version-tag">([^<]+)/) || [])[1] || '');
    assert.deepEqual(tags, ['Current', 'Cancelled', 'Previous', '']);
});

test('group screens show the key version, never the raw key ID', () => {
    const { app } = environment();
    assert.equal(app.describeGroupKey({ current_epoch_id: '3f2a-uuid', current_key_version: 2 }, 'key'), 'key v2');
    assert.equal(app.describeGroupKey({ current_epoch_id: '3f2a-uuid', current_key_version: 3 }, 'Current key:'), 'Current key: v3');
    // A server that doesn't send the version yet: say so instead of printing the ID.
    assert.equal(app.describeGroupKey({ current_epoch_id: '3f2a-uuid', current_key_version: null }, 'key'), 'key version unknown');
    assert.equal(app.describeGroupKey({ current_epoch_id: null }, 'Current key:'), 'Current key: none yet');
});
