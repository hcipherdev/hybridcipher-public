// Tests Windows argument transport, authenticated desktop workflows, and mount session handling.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');

function section(start, end) {
    const begin = source.indexOf(start);
    const finish = source.indexOf(end, begin + start.length);
    assert.ok(begin >= 0 && finish > begin, `Cannot extract ${start}`);
    return source.slice(begin, finish);
}

function workflowApp(invoke) {
    const methods = [
        section('    captureWorkspaceReadContext(', '    async loadEnrolledFolders('),
        section('    async ensureSessionReady(', '    async handleStaleSession('),
        section('    async handleStaleSession(', '    async submitLoginRequest('),
        section('    checkedCommandResult(', '    async handleForgotPassword('),
        section('    async handleQuitRequested(', '    basename('),
        section('    async refreshActiveMounts(', '    async maybeShowRecoveryPrompts('),
        section('    async mountFolderFromContext(', '    async pollMountState('),
        section('    parseGeneratedCliArgs(', '    async runCliStatusCommand('),
    ].join('\n');
    const app = new (Function('invoke', `return class { ${methods} }`)(invoke))();
    const window = { invoke, document: { getElementById() { return null; } } };
    vm.runInNewContext(fs.readFileSync(new URL('../src/app-team-methods.js', import.meta.url), 'utf8'), { window });
    const dialogs = window.HybridCipherTeamMethods.create({});
    Object.assign(app, { runSettingsCliCommand: dialogs.runSettingsCliCommand,
        currentUser: 'owner@example.com', isLoggedIn: true, workspaceGroupContext: { group_id: 'group-id' },
        workspaceUiModel: () => ({ resolved: true }), cliActionTitle: dialogs.cliActionTitle,
        runDesktopOperation: request => invoke('start_desktop_operation', { request }), refreshAdminDashboard() {},
    });
    return app;
}

test('Windows generated arguments preserve literal percent signs, spaces, ampersands, Unicode and trailing backslashes', () => {
    const app = workflowApp(async () => {});
    assert.deepEqual(
        app.parseGeneratedCliArgs('hybridcipher coverage scan --root "C:\\%NAME%\\a & b\\日本語\\"'),
        ['coverage', 'scan', '--root', 'C:\\%NAME%\\a & b\\日本語\\']
    );
    assert.deepEqual(app.parseGeneratedCliArgs('hybridcipher pin verify "a""b"'), ['pin', 'verify', 'a"b']);
    assert.throws(() => app.parseGeneratedCliArgs('hybridcipher coverage "unfinished'), /Unclosed quote/);
});

test('Windows process argument vectors round trip literal selected paths', { skip: process.platform !== 'win32' }, () => {
    const args = ['C:\\%NAME%\\a & b\\日本語\\', 'C:\\', 'a"b'];
    const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', ...args], {
        encoding: 'utf8', windowsHide: true,
    });
    assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), args);
});

test('generated CLI uses an argument array and passes stdin without shell expansion', async () => {
    const calls = [];
    const app = workflowApp(async (name, args) => {
        calls.push({ name, args });
        return { success: true, data: { status: 0, stdout: 'done', stderr: '' } };
    });
    app.sessionPersistent = true;
    const args = ['coverage', 'scan', '--root', 'C:\\%NAME%\\a & b\\日本語\\'];
    assert.equal((await app.runBundledCliArgs(args, { input: 'literal %NAME% & input\n' })).stdout, 'done');
    assert.deepEqual(calls, [{ name: 'run_bundled_cli', args: { args, input: 'literal %NAME% & input\n' } }]);
    app.sessionPersistent = false;
    await assert.rejects(app.runBundledCliArgs(args), /persistent login/);
    assert.equal(calls.length, 1);
});

test('Windows Settings actions use the shared operation without starting a terminal', async () => {
    const calls = [];
    const app = workflowApp(async (name, args) => {
        calls.push({ name, args });
        return { success: true, data: { status: 0, stdout: 'complete', stderr: '' } };
    });
    Object.assign(app, {
        platformInfo: { os_type: 'windows' }, sessionPersistent: true,
        adminPanelVisible: false, createTerminalTab: () => { throw new Error('Terminal created'); },
        showTerminalView() { throw new Error('Terminal opened'); }, updateActiveTabTitle() {}, appendTerminalLine() {},
        closeSettingsModal() {}, showNotification() {},
        executeCommandDirectly: () => { throw new Error('Terminal shell was used'); },
    });
    assert.equal(await app.runSettingsCliCommand('hybridcipher coverage audit --root "C:\\%NAME%\\a & b\\"'), true);
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ name: 'start_desktop_operation', args: { request: {
        kind: 'cli', args: ['coverage', 'audit', '--root', 'C:\\%NAME%\\a & b\\'], group_id: 'group-id', title: 'Protection coverage',
    } } }]);
});

test('temporary login explains why CLI-only Settings actions are unavailable', async () => {
    let invoked = 0;
    const notices = [];
    const app = workflowApp(async () => { invoked += 1; return { success: true }; });
    Object.assign(app, {
        platformInfo: { os_type: 'windows' }, sessionPersistent: false,
        adminPanelVisible: false, showNotification: message => notices.push(message),
    });
    assert.equal(await app.runSettingsCliCommand('hybridcipher coverage audit --verify-proofs'), false);
    assert.equal(invoked, 0);
    assert.match(notices[0], /Remember me/);
});

test('temporary desktop sessions skip CLI health checks', async () => {
    let cliChecks = 0;
    const app = workflowApp(async () => ({ status: 'active', email: 'person@example.com', persistent: false }));
    app.verifyCliSession = async () => { cliChecks += 1; return false; };
    assert.equal((await app.ensureSessionReady()).persistent, false);
    assert.equal(cliChecks, 0);
    assert.equal(app.sessionPersistent, false);
});

test('failed logout retains the session and mounted workspace', async () => {
    let welcomeCount = 0;
    const app = workflowApp(async () => ({ success: false, error: 'Mount still active' }));
    Object.assign(app, {
        currentUser: 'person@example.com', enrolledFolders: [{ root_id: 'root' }],
        showWelcomeScreen: () => { welcomeCount += 1; }, showNotification() {},
    });
    const originalError = console.error;
    console.error = () => {};
    try {
        assert.equal(await app.logout(), false);
    } finally {
        console.error = originalError;
    }
    assert.equal(app.currentUser, 'person@example.com');
    assert.equal(app.enrolledFolders.length, 1);
    assert.equal(welcomeCount, 0);
});

test('cancelled, blocked and failed Quit all allow a later retry', async () => {
    let exits = 0;
    const exitResponses = [{ success: false, error: 'Cleanup blocked' }, { success: true }];
    const decisions = ['cancel', 'normal', 'normal', 'normal'];
    const stops = [false, true, true];
    const app = workflowApp(async name => {
        if (name === 'exit_application') {
            exits += 1;
            return exitResponses.shift();
        }
        throw new Error(`Unexpected command: ${name}`);
    });
    Object.assign(app, {
        activeMountDetailsByRootId: { root: {} }, quitFlowInProgress: false,
        refreshActiveMounts: async () => {},
        promptUnsafeUnmountDecision: async () => decisions.shift(),
        executeUnmountAllCommand: async () => stops.shift(),
        showNotification() {},
    });
    const originalError = console.error;
    console.error = () => {};
    try {
        await app.handleQuitRequested();
        assert.equal(exits, 0);
        assert.equal(app.quitFlowInProgress, false);
        await app.handleQuitRequested();
        assert.equal(exits, 0);
        await app.handleQuitRequested();
        assert.equal(exits, 1);
        assert.equal(app.quitFlowInProgress, false);
        await app.handleQuitRequested();
        assert.equal(exits, 2);
    } finally {
        console.error = originalError;
    }
});

test('degraded and unavailable mounts never open Explorer or start a duplicate mount', async () => {
    for (const response of [
        { success: true, data: { mountpoint: 'C:\\mount', availability: 'degraded', operational_health: { error: 'provider stopped' } } },
        { success: false, error_code: 'MOUNT_SOURCE_UNAVAILABLE', error: 'Source unavailable' },
    ]) {
        let opened = 0;
        const app = workflowApp(async name => {
            assert.equal(name, 'check_mount_status_by_root_id');
            return response;
        });
        Object.assign(app, {
            mountSessions: {}, showNotification() {},
            openMountInExplorer: async () => { opened += 1; },
            createMountProgressJob: () => { throw new Error('Duplicate mount started'); },
        });
        assert.equal(await app.mountFolderFromContext({ root_id: 'root', path: 'C:\\source' }), false);
        assert.equal(opened, 0);
    }
});

test('active mount refresh retains provider diagnostics for the folder detail view', async () => {
    const diagnostics = { operational: { healthy: false, last_start_failure: 'Callback stopped' } };
    const app = workflowApp(async name => {
        if (name === 'list_active_mounts') {
            return { success: true, data: [{ root_id: 'root', mountpoint: 'C:\\mount', backend: 'windows-cloud-files', availability: 'degraded', operational_health: diagnostics }] };
        }
        return { success: false };
    });
    Object.assign(app, {
        isLoggedIn: true, activeWorkspaceView: 'terminal',
        syncSelectedFolderMountUi() {}, updateSidebarMountSummary() {},
    });
    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    assert.equal(app.activeMountDetailsByRootId.root.availability, 'degraded');
    assert.deepEqual(app.activeMountDetailsByRootId.root.operationalHealth, diagnostics);
});

test('active mount refresh clears the reconciliation timer after sync finishes', async () => {
    let reconciling = true;
    const app = workflowApp(async name => {
        if (name === 'list_active_mounts') {
            return { success: true, data: [{
                root_id: 'root', mountpoint: 'C:\\mount', backend: 'windows-cloud-files', availability: 'usable',
                sync_status: reconciling
                    ? { safe_to_unmount: false, unsafe_reasons: [{ kind: 'provider_reconciliation' }] }
                    : { safe_to_unmount: true, unsafe_reasons: [] },
            }] };
        }
        return { success: false };
    });
    Object.assign(app, {
        isLoggedIn: true, activeWorkspaceView: 'terminal',
        syncSelectedFolderMountUi() {}, updateSidebarMountSummary() {},
    });
    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    assert.ok(Number.isFinite(app.reconciliationStartedAtByRootId.root));
    reconciling = false;
    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    assert.equal(app.reconciliationStartedAtByRootId.root, undefined);
});
