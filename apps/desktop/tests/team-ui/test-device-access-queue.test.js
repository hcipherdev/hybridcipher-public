// Tests the group's single "Devices to set up" list: buildDeviceAccessQueue() in src/ui-utils.js, and renderDeviceAccessQueuePage() and updateTeamAttention() in src/app.js (one row per device; the list's number shows every row, while the alert and the tab badge count only devices that need the admin).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const ui = uiScope.HybridCipherUiUtils;
const plain = value => JSON.parse(JSON.stringify(value));

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

// The same device waits for keys and for verification; others show each kind of row.
const pendingDevices = [
    { device_id: 'vm', email: 'xing@example.com', device_name: 'Virtual Machine' },
    { device_id: 'pixel', email: 'sam@example.com', device_name: 'Pixel', owner_can_self_approve: true },
    { device_id: 'old-mac', email: 'bo@example.com', missing_current_key: true },
];
const unverifiedDevices = [
    { device_id: 'vm', email: 'xing@example.com' },
    { device_id: 'xps', email: 'riley@example.com', reason_code: 'not_verified_here' },
    { device_id: 'tablet', email: 'cy@example.com' },
];

test('each device gets one row: give access while it waits for keys, verify when it only needs checking', () => {
    const rows = ui.buildDeviceAccessQueue({ pendingDevices, unverifiedDevices });
    assert.deepEqual(plain(rows.map(row => [row.device.device_id, row.action, row.needsAdmin, row.note])), [
        ['vm', 'give-access', true, ''],
        ['pixel', 'give-access', false, 'Their own trusted device can do this.'],
        ['old-mac', 'give-access', true, 'Missed the latest key rotation.'],
        ['xps', 'verify', false, 'Not verified on this computer. Key rotations from here need it.'],
        ['tablet', 'verify', true, ''],
    ]);
    assert.deepEqual(plain(ui.buildDeviceAccessQueue()), []);
});

function element(tag) {
    return {
        tag, className: '', type: '', textContent: '', innerHTML: '', children: [], listeners: {},
        appendChild(child) { this.children.push(child); return child; },
        addEventListener(event, handler) { this.listeners[event] = handler; },
    };
}

function environment() {
    const nodes = { adminQueueDetailsBody: element('div'), adminDeviceAccessQueue: element('button'), adminTabDevicesBadge: element('span') };
    nodes.adminTabDevicesBadge.classList = { toggle() {} };
    const methods = vm.runInNewContext(`({${['deviceAccessRows', 'renderDeviceAccessQueuePage', 'updateTeamAttention'].map(method).join(',\n')}})`, {
        uiUtils: ui,
        document: { getElementById: id => nodes[id] || null, createElement: element },
    });
    const actions = [];
    const counts = [];
    const app = Object.assign({
        pendingDevicesCache: pendingDevices, unverifiedDevicesCache: unverifiedDevices, staleDevicesCache: [{ device_id: 'gone' }],
        deviceAccessPage: 1, deviceAccessPageSize: 6,
        escapeHtml: value => String(value),
        setQueueDetailsPagination() {},
        updateQueueCount(queue, count, options) { counts.push([queue, count, options?.alert]); },
        giveDeviceAccess(device) { actions.push(['give-access', device.device_id]); },
        verifyUnverifiedDevice(device) { actions.push(['verify', device.device_id]); },
    }, methods);
    return { app, nodes, actions, counts };
}

test('the list shows one row and one button per device, greying the ones the admin need not do', () => {
    const { app, nodes, actions } = environment();
    app.renderDeviceAccessQueuePage();
    const rows = nodes.adminQueueDetailsBody.children;
    assert.equal(rows.length, 5);
    assert.deepEqual(rows.map(row => row.children[0].textContent), ['Give access', 'Give access', 'Give access', 'Verify', 'Verify']);
    assert.deepEqual(rows.map(row => row.className.includes('queue-device-row-quiet')), [false, true, false, true, false]);
    rows[0].children[0].listeners.click();
    rows[4].children[0].listeners.click();
    assert.deepEqual(actions, [['give-access', 'vm'], ['verify', 'tablet']]);
});

test('the list shows its rows as its number; only devices that need the admin raise the alert and the badge', () => {
    const { app, nodes, counts } = environment();
    app.updateTeamAttention();
    // Five rows; vm (in both lists), old-mac and tablet need the admin, pixel and xps don't.
    assert.deepEqual(counts, [[nodes.adminDeviceAccessQueue, 5, true]]);
    assert.equal(nodes.adminTabDevicesBadge.textContent, '4', 'the tab badge adds the inactive device');

    // Only a device its owner can set up: listed and numbered, but no alert and no badge.
    const quiet = environment();
    Object.assign(quiet.app, { pendingDevicesCache: [pendingDevices[1]], unverifiedDevicesCache: [], staleDevicesCache: [] });
    quiet.app.updateTeamAttention();
    assert.deepEqual(quiet.counts, [[quiet.nodes.adminDeviceAccessQueue, 1, false]]);
    assert.equal(quiet.nodes.adminTabDevicesBadge.textContent, '');
});
