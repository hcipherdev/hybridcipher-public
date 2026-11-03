// Tests the Finder Reconnect action: buildMountCenterModel() in src/ui-utils.js for folders whose macOS File Provider extension never connected, and reconnectFinder() in src/app.js.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildMountCenterModel } = uiScope.HybridCipherUiUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const folder = (rootId, mount) => ({
    root_id: rootId, name: rootId, path: `/x/${rootId}`, group_id: 'g', group_name: 'Engineering',
    workspace: 'team', can_mount: true, auto_mount: false, mount,
});
const overview = {
    selected_group_id: 'g',
    folders: [
        folder('unreached', {
            root_id: 'unreached', mountpoint: '/cloud/a', backend: 'macos-file-provider', availability: 'degraded',
            operational_health: { extension_connected: false, waiting_secs: 600 },
        }),
        folder('windows', {
            root_id: 'windows', mountpoint: 'C:\\a', backend: 'windows-cloud-files', availability: 'degraded',
            operational_health: { healthy: false },
        }),
    ],
};
const rowsOf = model => Object.fromEntries(model.sections.flatMap(section => section.folders).map(row => [row.rootId, row]));

test('a folder Finder never reached offers Reconnect first and explains the pause', () => {
    const row = rowsOf(buildMountCenterModel(overview)).unreached;

    assert.equal(row.statusLabel, 'Finder isn’t syncing');
    assert.match(row.attentionDetail, /paused syncing/);
    assert.deepEqual(plain(row.actions.map(action => action.id)), ['reconnect', 'folder-page', 'unmount']);
});

test('Reconnect is disabled while it runs, and other degraded mounts never offer it', () => {
    const rows = rowsOf(buildMountCenterModel(overview, { busy: { unreached: 'reconnecting' } }));

    assert.deepEqual(plain(rows.unreached.actions[0]), { id: 'reconnect', label: 'Reconnecting…', disabled: true });
    assert.equal(rows.windows.statusLabel, 'Needs attention');
    assert.equal(rows.windows.attentionDetail, '');
    assert.ok(!rows.windows.actions.some(action => action.id === 'reconnect'));
});

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('    async reconnectFinder(');
const finish = source.indexOf("    // Opens a Mount Center folder's page", begin);
assert.ok(begin >= 0 && finish > begin, 'Cannot extract reconnectFinder');

function appWith({ response = { success: true }, connectedAfter = 1 } = {}) {
    const calls = { invoke: [], notifications: [], refreshes: 0 };
    const invoke = async (command, args) => { calls.invoke.push([command, args]); return response; };
    const App = Function('invoke', `return class { ${source.slice(begin, finish)} }`)(invoke);
    const app = new App();
    Object.assign(app, {
        reconnectingRootIds: new Set(),
        reconnectCheckAttempts: 3,
        reconnectCheckDelayMs: 0,
        activeWorkspaceView: 'mounts',
        selectedFolder: null,
        captureAccountReadContext: () => () => true,
        renderMountCenter() {},
        renderFolderDetailView() {},
        async refreshActiveMounts() { calls.refreshes += 1; },
        async refreshMountCenter() {},
        getMountDetailsForRootId() {
            return { operationalHealth: { extension_connected: calls.refreshes >= connectedAfter } };
        },
        showNotification(message, type) { calls.notifications.push([message, type]); },
    });
    return { app, calls };
}

test('Reconnect asks the backend, waits for Finder to connect, and confirms', async () => {
    const { app, calls } = appWith({ connectedAfter: 2 });

    const running = app.reconnectFinder('r1', { name: 'pqctest' });
    // A second click while it runs does nothing.
    assert.equal(await app.reconnectFinder('r1'), false);
    assert.equal(await running, true);
    assert.deepEqual(plain(calls.invoke), [['reconnect_mount', { rootId: 'r1' }]]);
    assert.equal(calls.refreshes, 2);
    assert.deepEqual(plain(calls.notifications), [['Finder is syncing pqctest again.', 'success']]);
    assert.equal(app.reconnectingRootIds.size, 0);
});

test('Finder that still does not connect is reported with the next step', async () => {
    const { app, calls } = appWith({ connectedAfter: 99 });

    assert.equal(await app.reconnectFinder('r1', { name: 'pqctest' }), false);
    assert.equal(calls.refreshes, 3);
    assert.match(calls.notifications[0][0], /still hasn’t connected to pqctest\. Unmount it and mount it again/);
    assert.equal(calls.notifications[0][1], 'warning');
});

test('a backend failure is shown and nothing is polled', async () => {
    const { app, calls } = appWith({ response: { success: false, error: 'Mount not found' } });

    assert.equal(await app.reconnectFinder('r1'), false);
    assert.equal(calls.refreshes, 0);
    assert.deepEqual(plain(calls.notifications), [['Mount not found', 'error']]);
    assert.equal(app.reconnectingRootIds.size, 0);
});
