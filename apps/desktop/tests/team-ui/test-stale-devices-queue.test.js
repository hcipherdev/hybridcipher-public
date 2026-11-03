// Tests app.js describeStaleDevice(), buildStaleDeviceRow() and removeStaleDevice() for the admin "Inactive devices" queue.
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

function element(tag) {
    return {
        tag, className: '', type: '', textContent: '', innerHTML: '', children: [], listeners: new Map(),
        appendChild(child) { this.children.push(child); },
        addEventListener(event, callback) { this.listeners.set(event, callback); },
    };
}

function environment(invoke = async () => ({ success: true, data: {} })) {
    const notifications = [];
    const copied = [];
    const names = ['captureWorkspaceReadContext', 'ensureDeviceManagementTrust', 'revokeDeviceRecord',
        'describeStaleDevice', 'buildStaleDeviceRow', 'removeStaleDevice', 'copyStaleDeviceId'];
    const methods = vm.runInNewContext(`({${names.map(method).join(',\n')}})`, {
        invoke, console, Date, Number,
        document: { createElement: element },
        navigator: { clipboard: { writeText: async value => { copied.push(value); } } },
    });
    const app = Object.assign({
        currentUser: 'owner@example.com', currentDeviceId: 'current', isLoggedIn: true,
        workspaceSwitchSequence: 1, desktopAccountGeneration: 1, activeWorkspaceType: 'team',
        staleQueueLoads: 0,
        showNotification(message) { notifications.push(message); },
        escapeHtml: value => String(value),
        async refreshPersonalDevicesOverview() {}, async showConfirmDialog() { return true; },
        async handleStaleSession() {}, async loadStaleDevicesQueue() { this.staleQueueLoads += 1; },
    }, methods);
    return { app, notifications, copied };
}

const ownStale = {
    user_id: 'owner-id', device_id: 'device_0870af1933adc572', device_name: 'Primary Device', email: 'owner@example.com',
    last_seen: '2026-09-14T08:16:13Z', reasons: ['Last seen 31 day(s) ago'], invitation_key_present: true,
    owned_by_current_user: true, is_current_device: false,
};
const memberStale = {
    ...ownStale, user_id: 'member-id', device_id: 'device_member', device_name: null,
    email: 'xingchenphy@gmail.com', owned_by_current_user: false,
};

test('own stale devices show the reason, last-seen date and a Remove action', () => {
    const { app } = environment();
    const row = app.buildStaleDeviceRow(ownStale);
    assert.match(row.innerHTML, /Primary Device/);
    assert.match(row.innerHTML, /device_0870af1933adc572 · owner@example\.com/);
    assert.match(row.innerHTML, /Last seen 31 day\(s\) ago · Last seen .*2026/);
    assert.match(row.innerHTML, /Remove it if you no longer use it/);
    assert.equal(row.children.length, 1);
    assert.equal(row.children[0].textContent, 'Remove');
});

test("other members' stale devices explain who can act and only offer copying the ID", async () => {
    const { app, copied } = environment();
    const row = app.buildStaleDeviceRow(memberStale);
    assert.match(row.innerHTML, /Only xingchenphy@gmail\.com can remove this device/);
    assert.match(row.innerHTML, /remove them from the team/);
    assert.equal(row.children[0].textContent, 'Copy ID');
    await row.children[0].listeners.get('click')();
    assert.deepEqual(copied, ['device_member']);
});

test('missing keys and the current device get sign-in guidance instead of removal', () => {
    const { app } = environment();
    const keyless = app.describeStaleDevice({ ...memberStale, invitation_key_present: false, reasons: ['Invitation public key missing'] });
    assert.match(keyless.hint, /sign in again on this device/);
    const current = app.describeStaleDevice({ ...ownStale, device_id: 'current', is_current_device: true });
    assert.equal(current.action, null);
    assert.match(current.hint, /device you are using now/);
    const unknownOwner = app.buildStaleDeviceRow({ ...memberStale, email: '' });
    assert.match(unknownOwner.innerHTML, /Unknown member/);
    assert.match(unknownOwner.innerHTML, /Only this member can remove/);
});

test('expired join cards explain that key rotation is waiting for the device to check in', () => {
    const { app } = environment();
    const reasons = ['Join card expired on 2026-10-04'];
    const own = app.describeStaleDevice({ ...ownStale, reasons });
    assert.match(own.hint, /Open HybridCipher on it to renew its join card/);
    assert.match(own.hint, /Key rotation skips it/);
    assert.equal(own.action, 'remove');
    const member = app.describeStaleDevice({ ...memberStale, reasons });
    assert.match(member.hint, /Ask them to open HybridCipher on this device to renew its join card/);
    assert.equal(member.action, 'copy');
    const current = app.describeStaleDevice({ ...ownStale, reasons, device_id: 'current', is_current_device: true });
    assert.match(current.hint, /renews automatically/);
    assert.match(app.buildStaleDeviceRow({ ...memberStale, reasons }).innerHTML, /Join card expired on 2026-10-04/);
});

test('removing an own stale device uses the trusted revoke flow and reloads the queue', async () => {
    const calls = [];
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_device_trust_status') return { success: true, data: { can_revoke_other_devices: true } };
        return { success: true, data: { removed_current_device: false } };
    });
    await app.removeStaleDevice(ownStale);
    assert.deepEqual(calls.map(([command]) => command), ['get_device_trust_status', 'revoke_device']);
    assert.equal(calls[1][1].deviceId, 'device_0870af1933adc572');
    assert.equal(app.staleQueueLoads, 1);
});

test('a cancelled removal leaves the queue untouched', async () => {
    const { app } = environment(async command => command === 'get_device_trust_status'
        ? { success: true, data: { can_revoke_other_devices: true } }
        : assert.fail('revoke must not run after cancelling'));
    app.showConfirmDialog = async () => false;
    await app.removeStaleDevice(ownStale);
    assert.equal(app.staleQueueLoads, 0);
});
