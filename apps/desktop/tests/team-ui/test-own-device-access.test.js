// Tests giving a device access in one step: adminDeviceReminders(), parseOwnDeviceAccessSummary(), parseOwnDeviceRepairReport(), buildOwnDeviceAccessNotice() and buildTeamTodoItems() in src/ui-utils.js, and giveDeviceAccess(), repairOwnDevices(), repairOwnDevicesIfDue(), issueWelcomeForDevice() and handleDeviceVerifySubmit() in src/app.js.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const ui = uiScope.HybridCipherUiUtils;
// Values built inside the vm context are compared as plain data.
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

/** `repair` is what `repair-own-devices --json` reports; `pending` is get_pending_devices. */
function environment({ repair = { repaired: [], needs_check: [], skipped: false }, pending = [] } = {}) {
    const commands = [];
    const opened = [];
    const invoked = [];
    const methods = vm.runInNewContext(`({${['captureWorkspaceReadContext', 'isOwnDeviceRecord', 'giveDeviceAccess',
        'repairOwnDevices', 'repairOwnDevicesIfDue', 'issueWelcomeForDevice', 'handleDeviceVerifySubmit'].map(method).join(',\n')}})`, {
        console, uiUtils: ui,
        invoke: async command => {
            invoked.push(command);
            if (command === 'get_pending_devices') return { success: true, data: pending };
            return { success: true, data: { can_approve_devices: true, can_verify_devices: true } };
        },
        document: { getElementById: () => ({ value: 'ABCD 1234 EFFF 5678' }) },
        buildDeviceVerificationModelValue: ui.buildDeviceVerificationModel,
        buildDeviceVerificationCommandValue: ui.buildDeviceVerificationCommand,
    });
    const notifications = [];
    const app = Object.assign({
        currentUser: 'me@example.com', currentDeviceId: 'laptop', isLoggedIn: true,
        workspaceSwitchSequence: 1, desktopAccountGeneration: 1, activeWorkspaceType: 'team',
        workspaceGroupContext: { group_id: 'eng' },
        showNotification(message, tone) { notifications.push([message, tone]); },
        async ensureDeviceManagementTrust() { return true; },
        async runBundledCliArgs(args) {
            commands.push(args.join(' '));
            return { status: 0, stdout: `progress\n${JSON.stringify(repair)}\n` };
        },
        async runCliCommandRaw(command) {
            commands.push(command);
            return { status: 0, stdout: command.includes('issue-welcome')
                ? '\u001b[34mℹ\u001b[0m Gave access in 1 of 2 groups; Design needs a group admin.\n' : '' };
        },
        async runTeamTask(request) { commands.push(`team-task:${request.kind}:${request.device_id}`); return true; },
        openDeviceVerifyModal(device, options) { opened.push([device, options]); },
        refreshOwnDeviceAccessNotice() {},
        quoteCliArg: value => `'${value}'`,
        async reconcileWorkspaceState() {}, async loadPendingDevicesQueue() {}, async loadUnverifiedDevicesQueue() {},
        async offerRecoveryWriterHandoffForDevice() {}, async showActionPrompt() {},
        setDeviceVerifyError() {}, closeDeviceVerifyModal() {}, showActionProgressModal() {}, hideActionProgressModal() {},
    }, methods);
    return { app, commands, opened, notifications, invoked };
}

test('admins are reminded only about devices their owner cannot set up, once per device', () => {
    const items = ui.buildTeamTodoItems({ groupName: 'Engineering',
        pendingDevices: [
            { device_id: 'phone', email: 'sam@example.com', device_name: 'Phone', owner_can_self_approve: true },
            { device_id: 'tablet', email: 'bo@example.com', device_name: 'Tablet' },
        ],
        unverifiedDevices: [
            { device_id: 'tablet', email: 'bo@example.com' },
            { device_id: 'xps', email: 'riley@example.com', owner_can_self_approve: true },
            // Only this computer hasn't verified it: the rotation dialog handles that.
            { device_id: 'ipad', email: 'riley@example.com', reason_code: 'not_verified_here' },
            { device_id: 'mac', email: 'cy@example.com', device_name: 'Mac' },
        ] });
    assert.deepEqual(plain(items.map(item => [item.action, item.deviceId])), [
        ['approve_device', 'tablet'],
        ['verify_device', 'mac'],
    ]);
    assert.equal(items[0].actionLabel, 'Give access');
});

test('the CLI summary is read through terminal colors and says when an admin is still needed', () => {
    assert.deepEqual({ ...ui.parseOwnDeviceAccessSummary('\u001b[1mℹ Gave access in 2 of 2 groups.\u001b[0m') },
        { message: 'Gave access in 2 of 2 groups.', needsAdmin: false });
    assert.equal(ui.parseOwnDeviceAccessSummary('Gave access in 1 of 3 groups; Design, Finance need a group admin.').needsAdmin, true);
    assert.equal(ui.parseOwnDeviceAccessSummary('Welcome stored'), null);
});

test('the repair report is read from the last JSON line', () => {
    const report = ui.parseOwnDeviceRepairReport('working…\n{"repaired":[{"device_id":"phone","groups_given":["Eng"],"groups_needing_admin":[]}],"needs_check":["tablet"],"skipped":false}\n');
    assert.deepEqual(plain(report), {
        repaired: [{ device_id: 'phone', groups_given: ['Eng'], groups_needing_admin: [] }],
        needsCheck: ['tablet'], skipped: false,
    });
    assert.equal(ui.parseOwnDeviceRepairReport('no json here'), null);
});

test('the Home notice shows only on a device that can give access, never for itself', () => {
    const waiting = [{ device_id: 'laptop' }, { device_id: 'phone', device_name: 'Pixel' }];
    assert.equal(ui.buildOwnDeviceAccessNotice({ pendingDevices: waiting, currentDeviceId: 'laptop', canGiveAccess: false }).visible, false);
    const notice = ui.buildOwnDeviceAccessNotice({ pendingDevices: waiting, currentDeviceId: 'laptop', canGiveAccess: true });
    assert.equal(notice.visible, true);
    assert.equal(notice.action, 'give-access');
    assert.equal(notice.deviceId, 'phone');
    assert.match(notice.message, /Your new device Pixel is waiting for access/);
    const many = ui.buildOwnDeviceAccessNotice({ canGiveAccess: true,
        pendingDevices: [{ device_id: 'phone' }, { device_id: 'tablet', missing_current_key: true }] });
    assert.equal(many.action, 'open-devices');
    assert.equal(ui.buildOwnDeviceAccessNotice({ pendingDevices: [{ device_id: 'laptop' }], currentDeviceId: 'laptop', canGiveAccess: true }).visible, false);
});

test('an own device this account verified gets its keys without a fingerprint', async () => {
    const { app, commands, opened, notifications } = environment({
        repair: { repaired: [{ device_id: 'tablet', groups_given: ['Eng'], groups_needing_admin: [] }], needs_check: [], skipped: false },
    });
    await app.giveDeviceAccess({ device_id: 'tablet', missing_current_key: true }, { own: true });
    assert.deepEqual(commands, ['repair-own-devices --device tablet --json --no-color']);
    assert.equal(opened.length, 0);
    assert.match(notifications.at(-1)[0], /Sent the current group key to your device tablet/);
});

test('an own device nobody on this account verified compares its fingerprint first', async () => {
    // Trusted on the server (say, confirmed with password and email only) is not enough.
    const { app, opened, commands } = environment({ repair: { repaired: [], needs_check: ['phone'], skipped: false } });
    await app.giveDeviceAccess({ device_id: 'phone', missing_current_key: true, fingerprint_verified: true }, { own: true });
    assert.equal(commands.length, 1, 'only the repair attempt ran; no keys were sent');
    assert.equal(opened[0][0].email, 'me@example.com');
    assert.deepEqual({ ...opened[0][1].thenGiveAccess }, { own: true });
});

test('someone else’s device always compares its fingerprint, even when verified or only missing a key', async () => {
    for (const device of [
        { device_id: 'mac', email: 'bo@example.com', fingerprint_verified: true },
        { device_id: 'mac', email: 'bo@example.com', missing_current_key: true },
    ]) {
        const { app, opened, commands } = environment();
        await app.giveDeviceAccess(device);
        assert.equal(commands.length, 0);
        assert.deepEqual({ ...opened[0][1].thenGiveAccess }, { own: false });
    }
});

test('verifying with a continuation sends an own device every group it needs, outside the Team task', async () => {
    const { app, commands, notifications } = environment();
    app.deviceVerifyDevice = { device_id: 'phone', email: 'me@example.com' };
    app.deviceVerifyContinuation = { own: true };
    await app.handleDeviceVerifySubmit();
    assert.match(commands[0], /^hybridcipher pin verify /);
    assert.equal(commands[1], "hybridcipher issue-welcome --device 'phone'");
    assert.deepEqual(notifications.at(-1), ['Gave access in 1 of 2 groups; Design needs a group admin.', 'warning']);

    const other = environment();
    other.app.deviceVerifyDevice = { device_id: 'mac', email: 'bo@example.com' };
    other.app.deviceVerifyContinuation = { own: false };
    await other.app.handleDeviceVerifySubmit();
    assert.equal(other.commands[1], 'team-task:approve_device:mac');
});

test('background repair runs only while an own device misses a key, at most every 10 minutes unless forced', async () => {
    const idle = environment({ pending: [{ device_id: 'phone' }, { device_id: 'laptop', missing_current_key: true }] });
    assert.equal(await idle.app.repairOwnDevicesIfDue(0), false);
    assert.deepEqual(idle.commands, [], 'this device and approval-only devices are not repaired in the background');

    const { app, commands, notifications } = environment({
        pending: [{ device_id: 'phone', device_name: 'Pixel', missing_current_key: true }],
        repair: { repaired: [{ device_id: 'phone', groups_given: ['Eng'], groups_needing_admin: [] }], needs_check: [], skipped: false },
    });
    assert.equal(await app.repairOwnDevicesIfDue(0), true);
    assert.match(notifications.at(-1)[0], /your Pixel/);
    assert.equal(await app.repairOwnDevicesIfDue(5 * 60 * 1000), false);
    assert.equal(commands.length, 1);
    assert.equal(await app.repairOwnDevicesIfDue(5 * 60 * 1000, { force: true }), true);
    assert.equal(await app.repairOwnDevicesIfDue(16 * 60 * 1000), true);
    assert.equal(commands.length, 3);
});
