// Tests app.js device-management capability gates, delayed account responses, and explicit legacy trust confirmation.
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
function environment(invoke) {
    const notifications = [];
    const uiScope = {};
    vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
    const methods = vm.runInNewContext(`({${['captureWorkspaceReadContext', 'ensureDeviceManagementTrust', 'revokeDeviceRecord', 'issueWelcomeForDevice', 'handleDeviceVerifySubmit'].map(method).join(',\n')}})`, {
        invoke, console, uiUtils: uiScope.HybridCipherUiUtils,
        document: { getElementById: () => ({ value: 'ABCD 1234 EFFF 5678' }) },
        buildDeviceVerificationModelValue: uiScope.HybridCipherUiUtils.buildDeviceVerificationModel,
        buildDeviceVerificationCommandValue: uiScope.HybridCipherUiUtils.buildDeviceVerificationCommand,
    });
    const app = Object.assign({
        currentUser: 'owner@example.com', currentDeviceId: 'actor', isLoggedIn: true,
        workspaceSwitchSequence: 1, desktopAccountGeneration: 1, activeWorkspaceType: 'personal',
        showNotification(message) { notifications.push(message); },
        async refreshPersonalDevicesOverview() {}, async showConfirmDialog() { return true; },
        async handleStaleSession() {}, quoteCliArg: value => `'${value}'`,
        async reconcileWorkspaceState() {}, async loadPendingDevicesQueue() {},
        async showActionPrompt() {},
        setDeviceVerifyError() {}, closeDeviceVerifyModal() {}, showActionProgressModal() {}, hideActionProgressModal() {},
    }, methods);
    return { app, notifications };
}

test('unknown, pending, and partially trusted devices cannot revoke another device', async () => {
    for (const trust of [null, {}, { approved: true, fingerprint_verified: false }, { approved: false, fingerprint_verified: true }]) {
        const calls = [];
        const { app } = environment(async command => {
            calls.push(command);
            return { success: true, data: trust };
        });
        app.showConfirmDialog = () => { throw new Error('Denied device must not reach the revoke confirmation'); };
        app.promptForText = () => { throw new Error('Pending devices must not silently bootstrap trust'); };
        await app.revokeDeviceRecord({ device_id: 'primary' });
        assert.deepEqual(calls, ['get_device_trust_status']);
    }
});

test('fully trusted devices recheck server capability before cross-device deletion', async () => {
    const calls = [];
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_device_trust_status') return { success: true, data: { approved: true, fingerprint_verified: true, can_revoke_other_devices: true } };
        return { success: true, data: { removed_current_device: false } };
    });
    await app.revokeDeviceRecord({ device_id: 'primary' });
    assert.deepEqual(calls.map(([name]) => name), ['get_device_trust_status', 'revoke_device']);
    assert.equal(calls[1][1].deviceId, 'primary');
});

test('a different management capability cannot override a denied approval capability', async () => {
    const { app } = environment(async () => ({ success: true, data: {
        approved: true, fingerprint_verified: true, can_revoke_other_devices: true,
        can_approve_devices: false, confirmation_required: false,
    } }));
    assert.equal(await app.ensureDeviceManagementTrust('approve'), false);
});

test('switching account during confirmation never revokes from the new account', async () => {
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        return { success: true, data: { can_revoke_other_devices: true } };
    });
    app.showConfirmDialog = async () => { app.desktopAccountGeneration += 1; return true; };
    await app.revokeDeviceRecord({ device_id: 'primary' });
    assert.deepEqual(calls, ['get_device_trust_status']);
});

test('changing the selected group during confirmation invalidates a device action', async () => {
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        return { success: true, data: { can_revoke_other_devices: true } };
    });
    app.workspaceGroupContext = { group_id: 'old-group' };
    app.showConfirmDialog = async () => { app.workspaceGroupContext = { group_id: 'new-group' }; return true; };
    await app.revokeDeviceRecord({ device_id: 'primary' });
    assert.deepEqual(calls, ['get_device_trust_status']);
});

test('changing the device identity during confirmation invalidates a device action', async () => {
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        return { success: true, data: { can_revoke_other_devices: true } };
    });
    app.showConfirmDialog = async () => { app.currentDeviceId = 'another-device'; return true; };
    await app.revokeDeviceRecord({ device_id: 'primary' });
    assert.deepEqual(calls, ['get_device_trust_status']);
});

test('legacy trust confirmation masks inputs, preserves password whitespace, and checks completion', async () => {
    const calls = [];
    const prompts = [];
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_device_trust_status') return { success: true, data: { confirmation_required: true } };
        if (command === 'start_device_trust_confirmation') return { success: true, data: { otp_required: true } };
        return { success: true, data: { can_revoke_other_devices: true } };
    });
    app.promptForText = async (message, options) => {
        prompts.push(options);
        return prompts.length === 1 ? ' password with spaces ' : '123456';
    };
    assert.equal(await app.ensureDeviceManagementTrust(), true);
    assert.equal(prompts[0].inputType, 'password');
    assert.equal(prompts[0].preserveWhitespace, true);
    assert.equal(prompts[1].inputType, 'password');
    assert.equal(calls[1][1].password, ' password with spaces ');
    assert.equal(calls[2][1].otpCode, '123456');
    assert.equal(calls[2][1].mfaCode, null);
});

test('cancelled legacy confirmation never starts a recovery or deletes a device', async () => {
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        return { success: true, data: { confirmation_required: true } };
    });
    app.promptForText = async () => null;
    assert.equal(await app.ensureDeviceManagementTrust(), false);
    assert.deepEqual(calls, ['get_device_trust_status']);
});

test('approval awaits workspace reconciliation after a successful operation', async () => {
    const order = [];
    const { app } = environment(async () => ({ success: true, data: { can_approve_devices: true } }));
    app.runCliCommandRaw = async () => { order.push('approve'); return { status: 0 }; };
    app.reconcileWorkspaceState = async () => { order.push('reconcile'); };
    await app.issueWelcomeForDevice('new-device');
    assert.deepEqual(order, ['approve', 'reconcile']);
});

test('successful verification reconciles trust before an optional backup handoff finishes', async () => {
    const order = [];
    const { app } = environment(async () => ({ success: true, data: { can_verify_devices: true } }));
    app.deviceVerifyDevice = { device_id: 'new-device', email: 'owner@example.com' };
    app.runCliCommandRaw = async () => { order.push('verify'); return { status: 0 }; };
    app.reconcileWorkspaceState = async () => { order.push('reconcile'); };
    let finishHandoff;
    app.offerRecoveryWriterHandoffForDevice = async () => {
        order.push('handoff');
        await new Promise(resolve => { finishHandoff = resolve; });
    };
    const operation = app.handleDeviceVerifySubmit();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(order, ['verify', 'reconcile', 'handoff']);
    finishHandoff();
    await operation;
});
