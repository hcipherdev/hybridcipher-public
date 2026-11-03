// Tests the local vault mixin in apps/desktop/src/app-local-vault-methods.js: entering local mode, opening a vault on its own on a fresh device, the recovery-kit gate, the upgrade flow, replacing a vault from a recovery kit, and moving a vault into an existing account.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app-local-vault-methods.js', import.meta.url), 'utf8');
const markup = fs.readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');

function environment(responses = {}) {
    const nodes = new Map();
    const calls = [];
    const node = id => {
        if (!nodes.has(id)) {
            const classes = new Set(['hidden']);
            const attributes = {};
            const listeners = new Map();
            nodes.set(id, {
                id, value: '', textContent: '', checked: false, disabled: false, style: {},
                classList: {
                    toggle(name, force) { (force ?? !classes.has(name)) ? classes.add(name) : classes.delete(name); },
                    remove(name) { classes.delete(name); }, add(name) { classes.add(name); },
                    contains(name) { return classes.has(name); },
                },
                setAttribute(key, value) { attributes[key] = value; },
                removeAttribute(key) { delete attributes[key]; },
                getAttribute(key) { return attributes[key]; },
                addEventListener(event, handler) { listeners.set(event, handler); },
                fire(event, payload = { preventDefault() {} }) { return listeners.get(event)?.(payload); },
                focus() {}, attributes,
            });
        }
        return nodes.get(id);
    };
    const window = {
        document: { getElementById: node },
        setTimeout: fn => fn(),
        navigator: {},
        __TAURI__: { dialog: { save: async () => '/kits/HybridCipher Recovery Kit.hcrk', open: async () => '/kits/kit.hcrk' } },
        invoke: async (command, args) => {
            calls.push({ command, args });
            const response = responses[command];
            return typeof response === 'function' ? response(args) : response;
        },
    };
    vm.runInNewContext(source, { window, console });
    const original = {
        baseCalls: [],
        async checkSession() { this.baseCalls.push('checkSession'); },
        showWorkspaceHome() { this.baseCalls.push('showWorkspaceHome'); },
        showWelcomeScreen() { this.baseCalls.push('showWelcomeScreen'); },
        async addEnrolledFolder() { this.baseCalls.push('addEnrolledFolder'); return 'enrolled'; },
        async logout() { this.baseCalls.push('logout'); return true; },
        // Like the real check, a missing account session signs out and shows the welcome screen.
        async ensureSessionReady() {
            this.baseCalls.push('ensureSessionReady');
            this.showWelcomeScreen();
            return null;
        },
        startSessionHealthTimer() { this.baseCalls.push('startSessionHealthTimer'); },
        startMountStatusPolling() { this.baseCalls.push('startMountStatusPolling'); },
        stopMountStatusPolling() { this.baseCalls.push('stopMountStatusPolling'); },
        setupEventListeners() {},
        setWorkspaceView(view) { this.view = view; },
        updateWorkspaceHomeSummary() {},
        applyAppMode() {},
        async loadEnrolledFolders() { this.baseCalls.push('loadEnrolledFolders'); },
        showNotification(message, type) { this.notifications.push({ message, type }); },
        showRecoveryCodeModal(code) { this.shownCode = code; },
        scheduleMfaPrompt() { this.baseCalls.push('scheduleMfaPrompt'); },
        // The shared Confirm Your Email dialog from app.js.
        openEmailConfirmModal(email, password) {
            this.baseCalls.push('openEmailConfirmModal');
            Object.assign(this, { pendingRegistrationEmail: email, pendingRegistrationPassword: password, confirmationVerified: false });
        },
        closeEmailConfirmModal() {
            this.baseCalls.push('closeEmailConfirmModal');
            Object.assign(this, { pendingRegistrationEmail: null, pendingRegistrationPassword: null });
        },
        async checkEmailConfirmationOnce() { return Boolean(this.emailConfirmed); },
        async handleEmailConfirmYes() { this.baseCalls.push('handleEmailConfirmYes'); },
        handleEmailConfirmLater() { this.baseCalls.push('handleEmailConfirmLater'); },
        handleEmailConfirmed() { this.baseCalls.push('handleEmailConfirmed'); this.confirmationVerified = true; },
        async handleResendConfirmationEmail() { this.baseCalls.push('handleResendConfirmationEmail'); },
        hideWelcomeOverlay() { this.baseCalls.push('hideWelcomeOverlay'); },
        async runPostLegalStartupFlow() { this.baseCalls.push('runPostLegalStartupFlow'); },
        openLoginModal(email) { this.baseCalls.push('openLoginModal'); this.loginEmail = email; },
        async showConfirmDialog(title) { this.confirmTitles.push(title); return this.confirmAnswer; },
        isValidEmail: email => /@/.test(email),
        evaluatePasswordRules: password => ({ length: password.length >= 12 }),
    };
    const proto = Object.assign({}, original);
    Object.assign(proto, window.HybridCipherLocalVaultMethods.create(proto));
    const app = Object.assign(Object.create(proto), {
        baseCalls: [], notifications: [], isLoggedIn: false, confirmTitles: [], confirmAnswer: true,
    });
    app.setupEventListeners();
    return { app, node, calls, models: window.HybridCipherLocalVaultMethods };
}

const vault = (overrides = {}) => ({
    available: true, active: true, group_id: '7b0c6d1e-2f3a-4b5c-8d9e-0f1a2b3c4d5e',
    created_at: '2026-10-07T00:00:00Z', kit_saved: false, upgrade_email: null, upgrade_phase: null, ...overrides,
});

test('markup provides every element the local vault flow uses', () => {
    for (const id of ['startLocalVaultBtn', 'restoreLocalVaultBtn', 'firstRunStartLocalBtn', 'localVaultHeaderBtn',
        'localVaultPanel', 'localVaultKitStatus', 'localVaultKitBtn', 'localVaultUpgradeBtn', 'localRecoveryKitModal',
        'localRecoveryKitIntro', 'localRecoveryKitConfirm', 'localRecoveryKitCode', 'localRecoveryKitCheckInput',
        'localRecoveryKitError', 'localUpgradeModal', 'localUpgradeForm', 'localUpgradeEmailInput',
        'localUpgradePasswordInput', 'localUpgradePasswordConfirmInput', 'localUpgradeConfirmGroup',
        'localUpgradeCodeGroup', 'localUpgradeCodeInput', 'localUpgradeNoCodeInput', 'localUpgradeStatus',
        'localUpgradeError', 'localUpgradeResendBtn', 'localUpgradeChangeEmailBtn', 'submitLocalUpgradeBtn', 'localRecoveryReminderModal',
        'ackLocalRecoveryReminderBtn', 'closeLocalRecoveryReminderBtn', 'localRestoreModal',
        'localRestoreForm', 'localRestoreLead', 'localVaultRestoreBtn', 'localRestoreFileBtn', 'localRestoreFileName', 'localRestoreCodeInput', 'localRestoreError',
        'localUpgradeSignInBtn', 'localMergePanel', 'localMergePanelText', 'localMergeBtn',
        'localMergeModal', 'localMergeStatus', 'localMergeError', 'submitLocalMergeBtn', 'cancelLocalMergeBtn',
        'closeLocalMergeModalBtn', 'settingsLocalKitSection', 'settingsLocalKitStatus', 'settingsLocalKitBtn',
        'settingsRecoverySection']) {
        assert.match(markup, new RegExp(`id="${id}"`), `missing #${id}`);
    }
    assert.match(markup, /<script src="app-local-vault-methods.js"><\/script>\s*<script src="app.js">/);
});

test('models describe kit and upgrade state', () => {
    const { models } = environment();
    assert.equal(models.vaultPanelModel(vault()).kitButton, 'Save recovery kit');
    assert.equal(models.vaultPanelModel(vault({ kit_saved: true })).kitButton, 'Make a new recovery kit');
    assert.equal(models.vaultPanelModel(vault({ upgrade_email: 'a@b.test' })).upgradeButton, 'Finish creating your account');
    const fresh = models.upgradeFormModel(vault({ kit_saved: true }));
    assert.equal(fresh.resuming, false);
    assert.equal(fresh.showPasswordConfirm, true);
    assert.equal(fresh.showRecoveryCode, true);
    const resumed = models.upgradeFormModel(vault({ upgrade_email: 'a@b.test' }));
    assert.equal(resumed.email, 'a@b.test');
    assert.equal(resumed.submitLabel, 'Continue');
    assert.equal(resumed.showPasswordConfirm, false);
    assert.equal(resumed.showRecoveryCode, false, 'no kit means no code to ask for');
});

test('an account session wins; otherwise an existing vault opens in local mode', async () => {
    const signedIn = environment({ local_vault_status: { success: true, data: vault({ active: false }) } });
    signedIn.app.isLoggedIn = true;
    await signedIn.app.checkSession();
    assert.notEqual(signedIn.app.localVaultMode, true, 'an open account is never replaced by the vault');
    assert.notEqual(signedIn.node('localUpgradeModal').style.display, 'flex');

    const resumed = environment({
        local_vault_status: { success: true, data: vault({ active: false, kit_saved: true, upgrade_email: 'me@example.test' }) },
    });
    resumed.app.isLoggedIn = true;
    await resumed.app.checkSession();
    assert.equal(resumed.node('localUpgradeModal').style.display, 'flex', 'an unfinished upgrade asks to finish');
    assert.equal(resumed.node('localUpgradeEmailInput').value, 'me@example.test');
    assert.equal(resumed.node('localUpgradeEmailInput').disabled, true);
    assert.notEqual(resumed.app.localVaultMode, true);

    const { app, node, calls } = environment({ local_vault_status: { success: true, data: vault() } });
    await app.checkSession();
    assert.deepEqual(app.baseCalls.slice(0, 1), ['checkSession']);
    assert.deepEqual(calls.map(call => call.command), ['local_vault_status', 'get_coverage_center_snapshot']);
    assert.equal(app.localVaultMode, true);
    assert.equal(app.isLoggedIn, true);
    assert.equal(app.workspaceGroupContext.group_id, vault().group_id);
    assert.equal(node('appContainer').getAttribute('data-local-vault'), 'true');
    assert.equal(node('localVaultPanel').classList.contains('hidden'), false);
    assert.equal(app.view, 'home');
    assert.ok(!app.baseCalls.includes('showWorkspaceHome'), 'local Home skips account status reads');
});

test('opening a vault applies the app mode as signed in, so Add Protected Folder stays enabled', async () => {
    const { app } = environment({ local_vault_status: { success: true, data: vault() } });
    const loggedInAtApply = [];
    app.applyAppMode = function () { loggedInAtApply.push(this.isLoggedIn); };
    await app.checkSession();
    assert.deepEqual(loggedInAtApply, [true]);
});

test('vault Home status comes from this device’s scan time, without account checks', async () => {
    let coverage = { success: true, data: { last_scan_at: '2026-10-27T11:00:00Z' } };
    const { app, calls } = environment({
        local_vault_status: { success: true, data: vault() },
        get_coverage_center_snapshot: () => coverage,
    });
    await app.checkSession();
    await new Promise(resolve => setImmediate(resolve));
    // The snapshot is built inside the vm context, so compare it as plain data.
    assert.deepEqual(JSON.parse(JSON.stringify(app.homeStatusSnapshot)), {
        local_vault: true, last_scan_at: '2026-10-27T11:00:00Z', scan_status_available: true, unavailable_sections: [],
    });
    assert.ok(!calls.some(call => call.command === 'get_individual_home_status'));

    coverage = { success: false, error: 'unavailable' };
    await app.refreshWorkspaceHomeStatus();
    assert.deepEqual([...app.homeStatusSnapshot.unavailable_sections], ['scan status']);
    assert.equal(app.homeStatusSnapshot.scan_status_available, false);

    app.leaveLocalVaultUi();
    assert.equal(app.homeStatusSnapshot, null, 'an account opened next does not inherit the vault snapshot');
});

test('the first folder waits for a confirmed recovery kit', async () => {
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault() },
        create_local_recovery_kit: { success: true, data: { recovery_code: 'AAAAAAAA-BBBBBBBB-1F2E' } },
        confirm_local_recovery_kit: args => args.lastCharacters === '1F2E'
            ? { success: true, data: vault({ kit_saved: true }) }
            : { success: false, error: 'mismatch' },
    });
    await app.startLocalVault();
    const pending = app.addEnrolledFolder();
    assert.equal(node('localRecoveryKitModal').style.display, 'flex');
    assert.ok(!app.baseCalls.includes('addEnrolledFolder'));
    await node('saveLocalRecoveryKitBtn').fire('click');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(node('localRecoveryKitCode').textContent, 'AAAAAAAA-BBBBBBBB-1F2E');
    assert.equal(calls.find(call => call.command === 'create_local_recovery_kit').args.savePath,
        '/kits/HybridCipher Recovery Kit.hcrk');
    node('localRecoveryKitCheckInput').value = 'XXXX';
    await node('localRecoveryKitConfirm').fire('submit');
    assert.equal(node('localRecoveryKitError').textContent, 'mismatch');
    node('localRecoveryKitCheckInput').value = '1F2E';
    await node('localRecoveryKitConfirm').fire('submit');
    assert.equal(await pending, 'enrolled');
    assert.equal(node('localRecoveryKitCode').textContent, '', 'the key is cleared from the page');
    assert.equal(app.localVault.kit_saved, true);
    await app.addEnrolledFolder();
    assert.equal(app.baseCalls.filter(name => name === 'addEnrolledFolder').length, 2, 'no second prompt');
});

test('a saved kit moves to Settings, and replacing it reminds that the old kit still works', async () => {
    const unsaved = environment({ local_vault_status: { success: true, data: vault() } });
    await unsaved.app.checkSession();
    assert.equal(unsaved.node('localVaultKitBtn').classList.contains('hidden'), false, 'Home asks for the first kit');
    unsaved.app.showActionPrompt = async () => assert.fail('the first kit needs no reminder');
    unsaved.app.closeSettingsModal = () => {};
    await unsaved.node('settingsLocalKitBtn').fire('click');
    assert.equal(unsaved.node('localRecoveryKitModal').style.display, 'flex');

    const { app, node } = environment({ local_vault_status: { success: true, data: vault({ kit_saved: true }) } });
    await app.checkSession();
    assert.equal(node('localVaultKitBtn').classList.contains('hidden'), true, 'Home stops offering more kits');
    assert.equal(node('settingsLocalKitSection').classList.contains('hidden'), false);
    assert.equal(node('settingsLocalKitStatus').textContent, 'Saved');
    assert.equal(node('settingsLocalKitBtn').textContent, 'Make a new recovery kit');
    assert.equal(node('settingsRecoverySection').classList.contains('hidden'), true, 'account backups need an account');

    const prompts = [];
    app.promptAnswer = false;
    app.showActionPrompt = async (title, message, options) => {
        prompts.push({ title, message, options });
        return app.promptAnswer;
    };
    app.closeSettingsModal = () => { app.settingsClosed = true; };
    await node('settingsLocalKitBtn').fire('click');
    assert.equal(prompts[0].title, 'You already have a recovery kit');
    assert.match(prompts[0].message, /still opens every folder/);
    assert.match(prompts[0].options.detail, /doesn’t cancel the old one/);
    assert.equal(prompts[0].options.focusSecondary, true);
    assert.notEqual(node('localRecoveryKitModal').style.display, 'flex', 'cancel keeps the current kit');
    assert.equal(app.settingsClosed, true);

    app.promptAnswer = true;
    await node('settingsLocalKitBtn').fire('click');
    assert.equal(node('localRecoveryKitModal').style.display, 'flex');

    app.leaveLocalVaultUi();
    assert.equal(node('settingsLocalKitSection').classList.contains('hidden'), true);
    assert.equal(node('settingsRecoverySection').classList.contains('hidden'), false);
});

test('closing the kit dialog cancels the folder', async () => {
    const { app, node } = environment({ create_local_vault: { success: true, data: vault() } });
    await app.startLocalVault();
    const pending = app.addEnrolledFolder();
    node('closeLocalRecoveryKitModalBtn').fire('click');
    assert.equal(await pending, undefined);
    assert.ok(!app.baseCalls.includes('addEnrolledFolder'));
});

test('upgrade validates input, waits for email confirmation, then opens the account', async () => {
    let attempt = 0;
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        local_vault_status: () => ({ success: true, data: vault({ kit_saved: true, upgrade_email: attempt ? 'me@example.test' : null }) }),
        upgrade_local_vault_to_account: () => {
            attempt += 1;
            return attempt === 1
                ? { success: true, data: { status: 'confirm_email', email: 'me@example.test', new_recovery_code: null } }
                : { success: true, data: { status: 'complete', email: 'me@example.test', new_recovery_code: null } };
        },
    });
    await app.startLocalVault();
    app.openLocalUpgradeModal();
    node('localUpgradeEmailInput').value = 'me@example.test';
    node('localUpgradePasswordInput').value = 'correct horse battery';
    node('localUpgradePasswordConfirmInput').value = 'different';
    await node('localUpgradeForm').fire('submit');
    assert.equal(node('localUpgradeError').textContent, 'Passwords do not match.');
    node('localUpgradePasswordConfirmInput').value = 'correct horse battery';
    await node('localUpgradeForm').fire('submit');
    assert.match(node('localUpgradeError').textContent, /recovery key/);
    assert.ok(!calls.some(call => call.command === 'upgrade_local_vault_to_account'));

    node('localUpgradeCodeInput').value = '0011-2233';
    await node('localUpgradeForm').fire('submit');
    const first = calls.find(call => call.command === 'upgrade_local_vault_to_account');
    assert.deepEqual({ ...first.args }, { email: 'me@example.test', password: 'correct horse battery', recoveryCode: '0011-2233' });
    assert.ok(app.baseCalls.includes('openEmailConfirmModal'), 'the normal Confirm Your Email dialog opens');
    assert.equal(app.pendingRegistrationEmail, 'me@example.test');
    assert.notEqual(node('localUpgradeModal').style.display, 'flex', 'the account form steps aside');
    assert.equal(app.localVaultMode, true, 'files stay usable while waiting');

    // "Yes, I confirmed" before confirming: the resend prompt, never another upgrade or the login dialog.
    app.confirmAnswer = false;
    await app.handleEmailConfirmYes();
    assert.deepEqual(app.confirmTitles.at(-1), 'Not confirmed yet');
    assert.equal(calls.filter(call => call.command === 'upgrade_local_vault_to_account').length, 1);
    assert.ok(!app.baseCalls.includes('handleEmailConfirmYes'));

    app.handleEmailConfirmed();
    assert.equal(node('emailConfirmYesBtn').textContent, 'Continue');
    await app.handleEmailConfirmYes();
    const second = calls.filter(call => call.command === 'upgrade_local_vault_to_account')[1];
    assert.deepEqual({ ...second.args }, { ...first.args }, 'finishing reruns the upgrade with the same details');
    assert.equal(app.pendingRegistrationPassword, null, 'the password leaves memory with the dialog');
    assert.equal(app.localVaultMode, false);
    assert.equal(node('localRecoveryReminderModal').style.display, 'flex', 'a kept recovery key is still called out');
    assert.ok(!app.baseCalls.includes('scheduleMfaPrompt'), 'MFA waits for the reminder');
    await node('ackLocalRecoveryReminderBtn').fire('click');
    assert.notEqual(node('localRecoveryReminderModal').style.display, 'flex');
    assert.ok(app.baseCalls.includes('scheduleMfaPrompt'), 'MFA is offered as after a normal registration');
    assert.equal(node('appContainer').getAttribute('data-local-vault'), undefined);
    assert.ok(app.baseCalls.filter(name => name === 'checkSession').length >= 1, 'the account session opens');
    assert.equal(node('localUpgradePasswordInput').value, '', 'the password is cleared');
});

test('a lost recovery key is replaced and shown once after upgrade', async () => {
    const { app, node } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        local_vault_status: { success: true, data: vault({ kit_saved: true }) },
        upgrade_local_vault_to_account: args => args.recoveryCode === null
            ? { success: true, data: { status: 'complete', email: 'me@example.test', new_recovery_code: 'NEW-CODE' } }
            : { success: false, error: 'unexpected code' },
    });
    await app.startLocalVault();
    app.openLocalUpgradeModal();
    node('localUpgradeEmailInput').value = 'me@example.test';
    node('localUpgradePasswordInput').value = 'correct horse battery';
    node('localUpgradePasswordConfirmInput').value = 'correct horse battery';
    node('localUpgradeNoCodeInput').checked = true;
    await node('localUpgradeForm').fire('submit');
    assert.equal(app.shownCode, 'NEW-CODE');
    assert.notEqual(node('localRecoveryReminderModal').style.display, 'flex', 'the new key is shown instead');
});

test('account session checks leave the vault open', async () => {
    const { app } = environment({ create_local_vault: { success: true, data: vault() } });
    await app.startLocalVault();
    // Regaining focus (for example after the kit save dialog) runs these.
    assert.equal(await app.ensureSessionReady({ silent: true }), null);
    app.startSessionHealthTimer({ runImmediately: false });
    assert.equal(app.localVaultMode, true);
    assert.equal(app.isLoggedIn, true);
    assert.ok(!app.baseCalls.includes('ensureSessionReady'));
    assert.ok(!app.baseCalls.includes('startSessionHealthTimer'));
    assert.ok(!app.baseCalls.includes('showWelcomeScreen'));

    app.leaveLocalVaultUi();
    await app.ensureSessionReady({ silent: true });
    assert.ok(app.baseCalls.includes('ensureSessionReady'), 'accounts still get the real check');
});

test('mount status is polled while the vault is open', async () => {
    const { app } = environment({ create_local_vault: { success: true, data: vault() } });
    await app.startLocalVault();
    assert.ok(app.baseCalls.includes('startMountStatusPolling'), 'mounted folders show as mounted');
    app.leaveLocalVaultUi();
    assert.ok(app.baseCalls.includes('stopMountStatusPolling'));
});

test('logout and devices make sense without an account', async () => {
    const { app, node } = environment({ create_local_vault: { success: true, data: vault() } });
    await app.startLocalVault();
    assert.equal(await app.logout(), false);
    assert.ok(!app.baseCalls.includes('logout'));
    await app.showDevicesView();
    assert.equal(node('localUpgradeModal').style.display, 'flex');
    app.showWelcomeScreen();
    assert.equal(app.localVaultMode, false);
    assert.ok(app.baseCalls.includes('showWelcomeScreen'));
});

test('a vault whose files are missing offers restore or a confirmed new start', async () => {
    const { app, calls } = environment({
        local_vault_status: { success: true, data: vault({ active: false, storage_missing: true }) },
        create_local_vault: args => args?.replaceMissing
            ? { success: true, data: vault() }
            : { success: false, error: 'missing', error_code: 'LOCAL_VAULT_STORAGE_MISSING' },
    });
    await app.checkSession();
    assert.notEqual(app.localVaultMode, true, 'a missing vault never opens');
    assert.match(app.notifications.at(-1).message, /recovery kit/);

    app.confirmAnswer = false;
    await app.startLocalVault();
    assert.equal(app.localVaultMode, undefined, 'declining keeps the old record');
    assert.equal(calls.filter(call => call.command === 'create_local_vault').length, 1);

    app.confirmAnswer = true;
    await app.startLocalVault();
    assert.deepEqual({ ...calls.filter(call => call.command === 'create_local_vault').at(-1).args }, { replaceMissing: true });
    assert.equal(app.localVaultMode, true);
});

test('a mistyped email can be changed until the account signs in', async () => {
    const { app, node, calls, models } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        local_vault_status: { success: true, data: vault({ kit_saved: true }) },
        cancel_local_vault_upgrade: { success: true, data: vault({ kit_saved: true }) },
    });
    for (const [phase, allowed] of [['registered', true], ['storage_moved', true], ['signed_in', false], ['adopted', false]]) {
        assert.equal(models.upgradeFormModel(vault({ upgrade_email: 'a@b.test', upgrade_phase: phase })).canChangeEmail, allowed, phase);
    }
    await app.startLocalVault();
    app.localVault = vault({ kit_saved: true, upgrade_email: 'typo@example.test', upgrade_phase: 'storage_moved' });
    app.openLocalUpgradeModal();
    assert.equal(node('localUpgradeChangeEmailBtn').classList.contains('hidden'), false, 'offered when the dialog is reopened');
    assert.equal(node('localUpgradeResendBtn').classList.contains('hidden'), false);
    assert.equal(node('localUpgradeEmailInput').disabled, true);

    app.confirmAnswer = false;
    await node('localUpgradeChangeEmailBtn').fire('click');
    assert.ok(!calls.some(call => call.command === 'cancel_local_vault_upgrade'), 'declining changes nothing');

    app.confirmAnswer = true;
    await node('localUpgradeChangeEmailBtn').fire('click');
    assert.ok(calls.some(call => call.command === 'cancel_local_vault_upgrade'));
    assert.equal(node('localUpgradeEmailInput').disabled, false, 'a new email can be typed');
    assert.equal(node('localUpgradeEmailInput').value, '');
    assert.equal(node('localUpgradeChangeEmailBtn').classList.contains('hidden'), true);
    assert.match(node('localUpgradeStatus').textContent, /typo@example.test won’t be used/);
});

test('Later keeps the vault open; normal registrations keep their own handlers', async () => {
    const { app, calls } = environment({
        create_local_vault: { success: true, data: vault() },
        local_vault_status: { success: true, data: vault({ upgrade_email: 'me@example.test', upgrade_phase: 'storage_moved' }) },
        upgrade_local_vault_to_account: { success: true, data: { status: 'confirm_email', email: 'me@example.test', new_recovery_code: null } },
    });
    await app.startLocalVault();
    await app.runLocalUpgrade('me@example.test', 'correct horse battery', null);
    app.handleEmailConfirmLater();
    assert.ok(!app.baseCalls.includes('handleEmailConfirmLater'), 'no jump to the welcome screen');
    assert.equal(app.localVaultMode, true);
    assert.match(app.notifications.at(-1).message, /Finish creating your account/);
    assert.equal(app.localUpgradeConfirm, null);

    // A normal registration's dialog is untouched by the vault.
    app.openEmailConfirmModal('other@example.test', 'pw');
    await app.handleEmailConfirmYes();
    app.handleEmailConfirmLater();
    assert.ok(app.baseCalls.includes('handleEmailConfirmYes'));
    assert.ok(app.baseCalls.includes('handleEmailConfirmLater'));
    assert.equal(calls.filter(call => call.command === 'upgrade_local_vault_to_account').length, 1);
});

test('“I already have an account” closes the vault and opens sign-in with the email', async () => {
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        close_local_vault: { success: true, data: true },
    });
    await app.startLocalVault();
    app.openLocalUpgradeModal();
    assert.equal(node('localUpgradeSignInBtn').classList.contains('hidden'), false, 'offered for a new upgrade');
    node('localUpgradeEmailInput').value = 'me@example.test';
    await node('localUpgradeSignInBtn').fire('click');
    assert.deepEqual(app.confirmTitles, ['Sign in to your account?']);
    assert.ok(calls.some(call => call.command === 'close_local_vault'), 'the backend closes the vault first');
    assert.notEqual(app.localVaultMode, true);
    assert.equal(app.isLoggedIn, false);
    assert.equal(app.loginEmail, 'me@example.test');
    assert.notEqual(node('localUpgradeModal').style.display, 'flex');

    const resuming = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true, upgrade_email: 'me@example.test', upgrade_phase: 'storage_moved' }) },
    });
    await resuming.app.startLocalVault();
    resuming.app.openLocalUpgradeModal();
    assert.equal(resuming.node('localUpgradeSignInBtn').classList.contains('hidden'), true, 'not while finishing a new account');
});

test('an email that already has an account offers to sign in instead', async () => {
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        upgrade_local_vault_to_account: { success: false, error_code: 'ACCOUNT_EXISTS', error: 'This email already has an account.' },
        close_local_vault: { success: true, data: true },
    });
    await app.startLocalVault();
    app.confirmAnswer = false;
    app.openLocalUpgradeModal();
    node('localUpgradeEmailInput').value = 'me@example.test';
    node('localUpgradePasswordInput').value = 'correct horse battery';
    node('localUpgradePasswordConfirmInput').value = 'correct horse battery';
    node('localUpgradeNoCodeInput').checked = true;
    await node('localUpgradeForm').fire('submit');
    assert.deepEqual(app.confirmTitles, ['Sign in to your account?']);
    assert.equal(node('localUpgradeModal').style.display, 'flex', 'declining returns to the form');
    assert.equal(node('localUpgradeEmailInput').value, 'me@example.test');
    assert.equal(app.localVaultMode, true);
    assert.ok(!calls.some(call => call.command === 'close_local_vault'));

    app.confirmAnswer = true;
    node('localUpgradePasswordInput').value = 'correct horse battery';
    node('localUpgradePasswordConfirmInput').value = 'correct horse battery';
    node('localUpgradeNoCodeInput').checked = true;
    await node('localUpgradeForm').fire('submit');
    assert.ok(calls.some(call => call.command === 'close_local_vault'));
    assert.equal(app.loginEmail, 'me@example.test');
    assert.notEqual(app.localVaultMode, true);
});

test('Home offers to move a vault while signed in, or names the account it is moving into', async () => {
    const { app, node } = environment({
        local_vault_status: { success: true, data: vault({ active: false, can_merge: true }) },
    });
    Object.assign(app, { isLoggedIn: true, currentUser: 'me@example.test', activeWorkspaceType: 'personal' });
    await app.checkSession();
    assert.equal(node('localMergePanel').classList.contains('hidden'), false);
    assert.equal(node('localMergeBtn').textContent, 'Move them into your account');
    assert.equal(node('localMergeBtn').classList.contains('hidden'), false);

    app.renderLocalMergePanel(vault({ active: false, can_merge: true, merge_email: 'ME@example.test' }));
    assert.equal(node('localMergeBtn').textContent, 'Finish moving files', 'the same account, case aside');

    app.renderLocalMergePanel(vault({ active: false, can_merge: true, merge_email: 'other@example.test' }));
    assert.match(node('localMergePanelText').textContent, /Sign in as other@example\.test/);
    assert.equal(node('localMergeBtn').classList.contains('hidden'), true);

    app.activeWorkspaceType = 'team';
    app.renderLocalMergePanel(vault({ active: false, can_merge: true }));
    assert.equal(node('localMergePanel').classList.contains('hidden'), true, 'only in Personal');

    app.activeWorkspaceType = 'personal';
    app.renderLocalMergePanel(vault({ active: false, can_merge: false }));
    assert.equal(node('localMergePanel').classList.contains('hidden'), true);
});

test('a vault that is moving into an account does not open while signed out', async () => {
    const { app } = environment({
        local_vault_status: { success: true, data: vault({ active: false, merge_email: 'me@example.test' }) },
    });
    await app.checkSession();
    assert.notEqual(app.localVaultMode, true);
    assert.match(app.notifications.at(-1).message, /Sign in as me@example\.test to finish/);
});

test('moving files reports failures in the dialog and success on Home', async () => {
    let ready = false;
    const { app, node, calls } = environment({
        merge_local_vault_into_account: () => (ready
            ? { success: true, data: { protected_folders: 2, moved_files: 40 } }
            : { success: false, error_code: 'ACCOUNT_KEYS_NOT_READY', error: 'Finish setting up your account on this device first.' }),
    });
    Object.assign(app, { isLoggedIn: true, currentUser: 'me@example.test', activeWorkspaceType: 'personal' });
    app.renderLocalMergePanel(vault({ active: false, can_merge: true }));
    await node('localMergeBtn').fire('click');
    assert.equal(node('localMergeModal').style.display, 'flex');
    await node('submitLocalMergeBtn').fire('click');
    assert.match(node('localMergeError').textContent, /Finish setting up/);
    assert.equal(node('localMergeModal').style.display, 'flex', 'stays open to retry');
    assert.equal(node('submitLocalMergeBtn').getAttribute('disabled'), undefined);

    ready = true;
    await node('submitLocalMergeBtn').fire('click');
    assert.equal(calls.filter(call => call.command === 'merge_local_vault_into_account').length, 2);
    assert.notEqual(node('localMergeModal').style.display, 'flex');
    assert.equal(node('localMergePanel').classList.contains('hidden'), true);
    assert.ok(app.baseCalls.includes('loadEnrolledFolders'));
    assert.match(app.notifications.at(-1).message, /^2 folders are now part of your Personal workspace/);
});

test('move progress and results read naturally', () => {
    const { models } = environment();
    assert.equal(models.mergeProgressText({ folder: '/Users/me/Documents', folder_index: 0, folder_count: 1, phase: 'moving', total_files: 12, processed_files: 5 }),
        'Moving Documents: 5 of 12 files…');
    assert.equal(models.mergeProgressText({ folder: 'C:\\Users\\me\\Photos', folder_index: 1, folder_count: 3, phase: 'protecting' }),
        'Protecting Photos in your account (folder 2 of 3)…');
    assert.match(models.mergeDoneText({ protected_folders: 1 }), /^1 folder is now part/);
    assert.match(models.mergeDoneText({ protected_folders: 0 }), /^Your vault’s files are now part/);
});

test('an open vault can be replaced from a recovery kit only after confirming', async () => {
    const restored = vault({ group_id: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', kit_saved: true });
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        restore_local_vault_from_kit: { success: true, data: restored },
    });
    await app.startLocalVault();
    assert.equal(node('localVaultRestoreBtn').classList.contains('hidden'), false, 'offered inside the vault');
    await node('localVaultRestoreBtn').fire('click');
    assert.match(node('localRestoreLead').textContent, /Replace the vault on this device/);
    await node('localRestoreFileBtn').fire('click');
    node('localRestoreCodeInput').value = 'ABCD';

    app.confirmAnswer = false;
    await node('localRestoreForm').fire('submit');
    assert.ok(!calls.some(call => call.command === 'restore_local_vault_from_kit'), 'nothing happens without confirming');

    app.confirmAnswer = true;
    await node('localRestoreForm').fire('submit');
    const restore = calls.find(call => call.command === 'restore_local_vault_from_kit');
    assert.equal(restore.args.replaceEmpty, true);
    assert.deepEqual(app.confirmTitles, ['Replace the vault on this device?', 'Replace the vault on this device?']);
    assert.equal(app.localVault.group_id, restored.group_id);
    assert.equal(app.localVaultMode, true);
});

test('a vault that still protects files is not replaced, and stays open', async () => {
    const message = 'The vault on this device still protects files in: /Users/me/Docs. Unprotect these folders and decrypt their files first, then restore.';
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        restore_local_vault_from_kit: { success: false, error: message, error_code: 'LOCAL_VAULT_NOT_EMPTY' },
        local_vault_status: { success: true, data: vault({ kit_saved: true }) },
    });
    await app.startLocalVault();
    app.openLocalRestoreModal();
    await node('localRestoreFileBtn').fire('click');
    node('localRestoreCodeInput').value = 'ABCD';
    await node('localRestoreForm').fire('submit');
    assert.equal(node('localRestoreError').textContent, message);
    assert.ok(calls.some(call => call.command === 'local_vault_status'), 'the current vault is reopened');
    assert.equal(app.localVaultMode, true);
    assert.equal(app.localVault.group_id, vault().group_id);
});

test('restoring from the welcome screen does not ask to replace anything', async () => {
    const { app, node, calls } = environment({
        restore_local_vault_from_kit: { success: true, data: vault({ kit_saved: true }) },
    });
    app.openLocalRestoreModal();
    assert.match(node('localRestoreLead').textContent, /another computer/);
    await node('localRestoreFileBtn').fire('click');
    node('localRestoreCodeInput').value = 'ABCD';
    await node('localRestoreForm').fire('submit');
    assert.deepEqual(app.confirmTitles, []);
    assert.equal(calls.find(call => call.command === 'restore_local_vault_from_kit').args.replaceEmpty, undefined);
    assert.equal(app.localVaultMode, true);
});

test('restore is not offered while an account is being created from the vault', () => {
    const { models } = environment();
    assert.equal(models.vaultPanelModel(vault()).canRestore, true);
    assert.equal(models.vaultPanelModel(vault({ upgrade_email: 'a@b.test' })).canRestore, false);
});

test('markup provides the first-launch welcome, the Home guide and the panel sign-in', () => {
    for (const id of ['localVaultSignInBtn', 'firstRunGetStartedBtn', 'firstRunVaultSignInBtn', 'firstRunVaultRestoreBtn',
        'firstRunWelcomeSubtitle', 'firstRunWelcomeSteps', 'gettingStartedPanel', 'gettingStartedTitle',
        'gettingStartedProgress', 'gettingStartedList', 'gettingStartedDismissBtn', 'gettingStartedOptional',
        'gettingStartedOptionalLabel', 'gettingStartedOptionalDetail', 'gettingStartedOptionalBtn', 'settingsShowGuideBtn']) {
        assert.match(markup, new RegExp(`id="${id}"`), `missing #${id}`);
    }
    assert.match(markup, /<script src="getting-started-utils.js"><\/script>[\s\S]*<script src="app.js">/);
});

test('a fresh device opens straight into a vault once the terms are accepted', async () => {
    const { app, calls } = environment({
        local_vault_status: { success: true, data: { available: false, active: false, fresh_device: true } },
        create_local_vault: { success: true, data: vault() },
    });
    await app.checkSession();
    assert.ok(!calls.some(call => call.command === 'create_local_vault'), 'nothing is created before the terms');
    assert.notEqual(app.localVaultMode, true);

    await app.runPostLegalStartupFlow();
    assert.equal(calls.filter(call => call.command === 'create_local_vault').length, 1);
    assert.equal(app.localVaultMode, true);
    assert.deepEqual(app.notifications, [], 'the welcome and the guide explain the next steps');
    assert.equal(app.baseCalls.at(-1), 'runPostLegalStartupFlow', 'the welcome follows the vault');

    await app.runPostLegalStartupFlow();
    assert.equal(calls.filter(call => call.command === 'create_local_vault').length, 1, 'only once');
});

test('a device an account has used still shows the welcome screen', async () => {
    const used = environment({
        local_vault_status: { success: true, data: { available: false, active: false, fresh_device: false } },
        create_local_vault: { success: true, data: vault() },
    });
    await used.app.checkSession();
    await used.app.runPostLegalStartupFlow();
    assert.ok(!used.calls.some(call => call.command === 'create_local_vault'));
    assert.notEqual(used.app.localVaultMode, true);
    assert.ok(used.app.baseCalls.includes('runPostLegalStartupFlow'));

    const signedIn = environment({
        local_vault_status: { success: true, data: { available: false, active: false, fresh_device: true } },
    });
    signedIn.app.isLoggedIn = true;
    await signedIn.app.checkSession();
    await signedIn.app.runPostLegalStartupFlow();
    assert.ok(!signedIn.calls.some(call => call.command === 'create_local_vault'), 'an open account wins');
});

test('a vault that failed to open on its own leaves the welcome screen with a warning', async () => {
    const { app } = environment({
        local_vault_status: { success: true, data: { available: false, active: false, fresh_device: true } },
        create_local_vault: { success: false, error: 'Keychain unavailable' },
    });
    await app.checkSession();
    await app.runPostLegalStartupFlow();
    assert.notEqual(app.localVaultMode, true);
    assert.deepEqual(app.notifications, [{ message: 'Keychain unavailable', type: 'warning' }]);
});

test('signing in from a vault that never protected anything needs no confirmation', async () => {
    const { app, node, calls } = environment({
        create_local_vault: { success: true, data: vault() },
        close_local_vault: { success: true, data: true },
    });
    await app.startLocalVault();
    assert.equal(node('localVaultSignInBtn').classList.contains('hidden'), false);
    await node('localVaultSignInBtn').fire('click');
    assert.deepEqual(app.confirmTitles, [], 'nothing to move, so nothing to confirm');
    assert.ok(calls.some(call => call.command === 'close_local_vault'));
    assert.ok(app.baseCalls.includes('openLoginModal'));
    assert.notEqual(app.localVaultMode, true);

    const saved = environment({
        create_local_vault: { success: true, data: vault({ kit_saved: true }) },
        close_local_vault: { success: true, data: true },
    });
    await saved.app.startLocalVault();
    saved.app.confirmAnswer = false;
    await saved.node('firstRunVaultSignInBtn').fire('click');
    assert.deepEqual(saved.app.confirmTitles, ['Sign in to your account?'], 'its folders need moving after sign-in');
    assert.ok(saved.app.baseCalls.includes('hideWelcomeOverlay'));
    assert.equal(saved.app.localVaultMode, true);
});

test('the welcome’s restore button opens the recovery kit restore', async () => {
    const { app, node } = environment({ create_local_vault: { success: true, data: vault() } });
    await app.startLocalVault();
    await node('firstRunVaultRestoreBtn').fire('click');
    assert.ok(app.baseCalls.includes('hideWelcomeOverlay'));
    assert.equal(node('localRestoreModal').style.display, 'flex');
});
