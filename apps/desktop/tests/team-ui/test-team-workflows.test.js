// Tests Team workspace isolation, role gates (including the device-trust notice when trust is unverified or cannot be checked), Team overview and sidebar group navigation, operation dialogs (including Continue in background, Activity progress and the background finish notification), and group initialization retries.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const uiUtils = createRequire(import.meta.url)('../../src/ui-utils.js');

const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');
const moduleSource = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function environment(invoke = async () => {}) {
    const nodes = new Map();
    const intervals = new Map();
    const events = new Map();
    function node(id) {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, { id, value: '', innerHTML: '', textContent: '', style: {}, attributes: {}, children: [], listeners: new Map(),
                classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains(key) { return classes.has(key); } },
                setAttribute(key, value) { this.attributes[key] = value; }, removeAttribute(key) { delete this.attributes[key]; },
                toggleAttribute(key, force) { if (force) this.attributes[key] = ''; else delete this.attributes[key]; },
                querySelector() { return node(`${id}-label`); }, querySelectorAll() { return []; },
                appendChild(child) { this.children.push(child); }, addEventListener(event, callback) { this.listeners.set(event, callback); }, focus() {},
            });
        }
        return nodes.get(id);
    }
    const values = new Map();
    const window = { document: { getElementById: node, querySelectorAll() { return []; }, createElement: tag => node(`new-${tag}-${nodes.size}`) },
        localStorage: { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
        setTimeout: callback => setImmediate(callback),
        setInterval(callback, ms) { const id = Symbol('interval'); intervals.set(id, { callback, ms }); return id; },
        clearInterval: id => intervals.delete(id), addEventListener: (event, callback) => events.set(event, callback), invoke };
    window.document.addEventListener = (event, callback) => events.set(event, callback);
    vm.runInNewContext(source, { window });
    const original = { setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {},
        async loadEnrolledFolders() {}, refreshAdminDashboard() {}, async refreshAdminGroupStatus() {},
        async refreshTeamDirectory() {}, async logout() { this.isLoggedIn = false; return true; }, showWelcomeScreen() {},
        openCreateGroupModal() {}, addEnrolledFolder() {
            this.enrollmentStarted = (this.enrollmentStarted || 0) + 1;
            return this.enrollmentPickerPromise;
        },
        async showDevicesView() { this.devicesOpened = true; },
        async refreshPersonalDevicesOverview() { this.devicesRead = true; },
        async refreshWorkspaceHomeStatus() { this.homeRead = true; },
        showCoverageView() { this.coverageOpened = true; },
        async refreshCoverageCenter() { this.coverageRead = true; },
        showWorkspaceHome() { this.setWorkspaceView('home'); }, };
    const app = Object.assign({ currentUser: 'owner@example.com', isLoggedIn: true, activeWorkspaceType: 'team', appMode: 'team',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'team-group', name: 'init-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' },
        workspaceContextReady: true, showNotification() {}, clearFolderSelectionForGroupSwitch() {}, updateSidebarViewButtons() {},
        currentDeviceTrust: { account: 'owner@example.com', device: undefined,
            status: { approved: true, fingerprint_verified: true, can_revoke_other_devices: true } },
        renderFolderList() {}, closeSettingsModal() {}, renderTeamLicenseSettings() {},
        async refreshPendingTeamRequests() {},
        workspacePreferenceKey() { return `workspace_${this.currentUser}`; }, parseGeneratedCliArgs(command) { return command.split(' ').slice(1); },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node, values, window, intervals, events, model: window.HybridCipherTeamMethods.workspaceModel };
}

function personalWorkspace(app, { entitled = false } = {}) {
    app.activeWorkspaceType = 'personal'; app.appMode = 'individual';
    app.workspaceGroupContext = { group_id: 'personal-group', name: 'Personal', organization_id: null, role: 'owner', readiness: 'ready' };
    app.workspaceContextReady = true;
    if (!entitled) app.teamLicenseStatus = { workspace: 'personal', online: true, can_write: false, organization: null };
}

function unresolvedPersonalWorkspace(app) {
    personalWorkspace(app);
    app.currentDeviceId = 'current-device';
    app.workspaceGroupContext = null;
    app.workspaceContextReady = false;
}

function readyPersonalContext(overrides = {}) {
    return { group_id: 'personal-group', name: 'Personal', organization_id: null, role: 'owner',
        readiness: 'ready', groups: [{ id: 'personal-group' }], ...overrides };
}

function deferred() {
    let resolve;
    const promise = new Promise(finish => { resolve = finish; });
    return { promise, resolve };
}

const nextTurn = () => new Promise(resolve => setImmediate(resolve));

test('Settings opens an existing Team directly and retains activation for accounts without Team', async () => {
    for (const { status, expected } of [
        { status: { workspace: 'team', organization: { id: 'existing-team' }, online: true, can_write: true },
            expected: ['close-settings', 'open-team'] },
        { status: { workspace: 'team', organization: { id: 'existing-team' }, online: false, can_write: false, revoked: true },
            expected: ['close-settings', 'open-team'] },
        { status: { workspace: 'personal', organization: null }, expected: ['activate-team'] },
        { status: { workspace: 'team', organization: null }, expected: ['activate-team'] },
    ]) {
        const { app, node } = environment(async () => { throw new Error('Navigation must not redeem a Team code'); });
        personalWorkspace(app, { entitled: true });
        app.teamLicenseStatus = status;
        const actions = [];
        app.closeSettingsModal = () => actions.push('close-settings');
        app.openEntitledTeamWorkspace = async () => actions.push('open-team');
        app.openTeamActivationModal = () => actions.push('activate-team');
        app.setupEventListeners();
        const click = node('settingsOpenTeamBtn').listeners.get('click');
        await click();
        assert.deepEqual(actions, expected);
        actions.length = 0;
        app.isLoggedIn = false;
        await click();
        assert.deepEqual(actions, []);
    }
});

function operationScope(app) {
    return { account: app.currentUser, generation: app.desktopAccountGeneration || 0, sequence: app.workspaceSwitchSequence,
        workspace: app.activeWorkspaceType, groupId: app.workspaceGroupContext?.group_id || null };
}

test('Team controls reject Personal and other-organization contexts', () => {
    const { app } = environment();
    assert.equal(app.workspaceUiModel().resolved, true);
    app.workspaceGroupContext.organization_id = null;
    assert.equal(app.workspaceUiModel().resolved, false);
    assert.equal(app.workspaceUiModel().canWrite, false);
    app.workspaceGroupContext.organization_id = 'another-org';
    assert.equal(app.workspaceUiModel().canAdministerGroup, false);
});

test('organization and group administration are distinct and expiry blocks writes', () => {
    const { app } = environment();
    app.teamLicenseStatus.organization.role = 'member';
    app.workspaceGroupContext.role = 'reader';
    assert.equal(app.workspaceUiModel().canAdminister, false);
    assert.equal(app.workspaceUiModel().canCreate, false);
    app.workspaceGroupContext.role = 'admin';
    assert.equal(app.workspaceUiModel().canAdministerGroup, true);
    assert.equal(app.workspaceUiModel().canCreate, false);
    app.teamLicenseStatus.can_write = false;
    assert.equal(app.workspaceUiModel().resolved, true);
    assert.equal(app.workspaceUiModel().canWrite, false);
    assert.equal(app.workspaceUiModel().canAdministerGroup, false);
});

test('unknown Team context cannot read Personal metadata or run recovery and pins', async () => {
    const calls = [];
    const { app } = environment((...args) => { calls.push(args); });
    app.workspaceGroupContext = null; app.workspaceContextReady = false;
    await app.showDevicesView(); await app.refreshPersonalDevicesOverview();
    await app.refreshWorkspaceHomeStatus(); await app.refreshCoverageCenter();
    app.showCoverageView();
    assert.ok(!app.devicesOpened && !app.devicesRead && !app.homeRead && !app.coverageRead && !app.coverageOpened);
    assert.equal(await app.runDashboardCliCommand('hybridcipher recovery fetch'), false);
    assert.equal(await app.runDashboardCliCommand('hybridcipher pin list'), false);
    assert.equal(calls.length, 0);
});

test('known Team awaiting keys completes device setup and reloads the correct group', async () => {
    const calls = [];
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'start_desktop_operation') return { id: 'welcome', status: 'succeeded', output: [], result: {} };
        if (command === 'get_workspace_group_context') return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' };
        throw new Error(command);
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    await app.showDevicesView(); assert.equal(app.devicesOpened, true);
    assert.equal(await app.runDashboardCliCommand('hybridcipher process-welcome-messages'), true);
    assert.equal(calls[0][1].request.group_id, 'team-group');
    assert.equal(app.workspaceUiModel().resolved, true);
    assert.equal(app.workspaceGroupContext.group_id, 'team-group');
});

test('legacy Settings approval and dashboard verification await the shared device refresh', async () => {
    for (const command of ['hybridcipher issue-welcome --device pending-device', 'hybridcipher pin verify pending-device']) {
        const calls = [];
        let finishReconciliation;
        const { app } = environment(async (name, args) => {
            calls.push([name, args]);
            if (name === 'start_desktop_operation') return { id: 'verified', status: 'succeeded', output: [], result: {} };
            if (name === 'get_workspace_group_context') return new Promise(resolve => { finishReconciliation = resolve; });
            throw new Error(name);
        });
        let completed = false;
        const pending = (command.includes('issue-welcome') ? app.runSettingsCliCommand(command) : app.runDashboardCliCommand(command))
            .then(result => { completed = true; return result; });
        while (!finishReconciliation) await new Promise(resolve => setImmediate(resolve));
        assert.equal(completed, false);
        assert.equal(calls[0][1].request.group_id, 'team-group');
        assert.equal(calls[1][1].readOnly, false);
        finishReconciliation({ group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' });
        assert.equal(await pending, true);
        assert.ok(app.devicesRead && app.homeRead);
    }
});

test('failed and offline workspace selection clears prior files and blocks actions', async () => {
    const { app } = environment(async () => ({ group_id: 'personal-group', name: 'Personal', organization_id: null, role: 'owner', readiness: 'ready' }));
    app.enrolledFolders = [{ path: 'private-personal-folder' }];
    app.personalDevicesOverview = { private: 'prior device' };
    app.coverageCenterSnapshot = { private: 'prior file' };
    assert.equal(await app.selectWorkspaceType('team'), false);
    assert.equal(app.enrolledFolders.length, 0);
    assert.equal(app.personalDevicesOverview, null);
    assert.equal(app.coverageCenterSnapshot, null);
    assert.equal(app.workspaceContextReady, false);
    assert.equal(app.workspaceUiModel().canWrite, false);
    assert.equal(app.activeWorkspaceType, 'team');
});

test('the group page and the Team overview are mutually exclusive and headings name the organization and group', () => {
    const { app, node } = environment();
    app.toggleAdminPanel();
    assert.equal(node('adminDashboard').style.display, 'flex');
    assert.equal(node('workspaceHome').style.display, 'none');
    assert.equal(node('folderDetailView').style.display, 'none');
    assert.equal(node('terminalContainer').style.display, 'none');
    assert.equal(node('teamAdministrationTitle').textContent, 'init-group');
    assert.equal(node('adminGroupBreadcrumb').textContent, 'Research / Groups');
    assert.equal(node('sidebarOverviewBtn').attributes['aria-pressed'], 'false');
    app.setWorkspaceView('home');
    assert.equal(node('adminDashboard').style.display, 'none');
    assert.equal(node('workspaceHomeTitle').textContent, 'Research');
    assert.equal(node('workspaceHomeEyebrow').textContent, 'Team overview');
    assert.equal(node('sidebarOverviewBtn').attributes['aria-pressed'], 'true');
});

test('everyone lands on Home; in a Team the sidebar opens the overview and admins open the selected group page', () => {
    const lands = (app, node) => {
        app.showWorkspaceHome();
        assert.equal(app.activeWorkspaceView, 'home');
        assert.equal(node('workspaceHome').style.display, 'flex');
        assert.equal(node('adminDashboard').style.display, 'none');
    };
    const admin = environment();
    lands(admin.app, admin.node);
    admin.app.applyAppMode();
    assert.ok(!admin.node('sidebarTeamNav').classList.contains('hidden'), 'Team shows its groups in the sidebar');
    assert.ok(admin.node('sidebarHomeSlot').classList.contains('hidden'), 'the overview replaces the Personal Home button');
    assert.equal(admin.node('sidebarOverviewLabel').textContent, 'Team overview');
    assert.equal(admin.node('sidebarOverviewBtn').attributes['aria-pressed'], 'true');
    admin.app.toggleAdminPanel();
    assert.equal(admin.app.activeWorkspaceView, 'admin');
    assert.equal(admin.node('sidebarOverviewBtn').attributes['aria-pressed'], 'false');

    const member = environment();
    member.app.workspaceGroupContext.role = 'member';
    member.app.teamLicenseStatus.organization.role = 'member';
    lands(member.app, member.node);
    member.app.applyAppMode();
    assert.equal(member.node('sidebarOverviewLabel').textContent, 'Team home');
    assert.equal(member.node('workspaceHomeEyebrow').textContent, 'Team home');
    member.app.toggleAdminPanel();
    assert.equal(member.app.activeWorkspaceView, 'home', 'members have no group page');

    const settingUp = environment();
    settingUp.app.workspaceContextReady = false;
    settingUp.app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    lands(settingUp.app, settingUp.node);
    settingUp.app.toggleAdminPanel();
    assert.equal(settingUp.app.activeWorkspaceView, 'admin', 'admins keep a way in during setup');

    const personal = environment();
    personalWorkspace(personal.app);
    lands(personal.app, personal.node);
    personal.app.applyAppMode();
    assert.ok(personal.node('sidebarTeamNav').classList.contains('hidden'), 'Personal has no Team navigation');
    assert.ok(!personal.node('sidebarHomeSlot').classList.contains('hidden'), 'Personal keeps its Home button');
    assert.equal(personal.node('sidebarFoldersTitle').textContent, 'Protected Folders');
});

test('a Team admin switching to a ready Team stays on the overview, which lists every group', async () => {
    const { app, node, window } = environment(async command => {
        if (command === 'get_workspace_group_context') return { group_id: 'team-group', name: 'init-group', organization_id: 'org-1', role: 'owner',
            readiness: 'ready', groups: [{ id: 'team-group', name: 'init-group' }, { id: 'legal', name: 'Legal' }] };
        if (command === 'get_group_summaries') return { success: true, data: [{ id: 'team-group', member_count: 3, current_key_version: 2 }] };
        return null;
    });
    window.HybridCipherUiUtils = uiUtils;
    Object.assign(app, { escapeHtml: String, escapeHtmlAttr: String });
    personalWorkspace(app, { entitled: true });
    app.setWorkspaceView('home');
    assert.equal(await app.selectWorkspaceType('team'), true);
    assert.equal(app.activeWorkspaceView, 'home');
    await nextTurn();
    assert.match(node('teamGroupCards').innerHTML, /init-group<\/span><span class="team-group-card-facts">3 people · Key version 2/);
    assert.match(node('teamGroupCards').innerHTML, /data-group-id="legal">[\s\S]*Legal/);
    assert.match(node('sidebarGroupList').innerHTML, /data-group-id="team-group" aria-current="true"/);
    assert.equal(node('sidebarGroupsTitle').textContent, 'Groups · 2');
    assert.equal(node('sidebarFoldersTitle').textContent, 'init-group folders');
});

test('opening another group from the sidebar switches to it, then shows its page to admins', async () => {
    const calls = [];
    let selected = 'team-group';
    const { app } = environment(async (command, args) => {
        calls.push(command);
        if (command === 'start_desktop_operation') { selected = args.request.group_id; return { id: 'switch', status: 'succeeded', result: {} }; }
        if (command === 'get_workspace_group_context') return { group_id: selected, name: selected, organization_id: 'org-1', role: 'owner', readiness: 'ready' };
        return null;
    });
    const dialogs = [];
    app.openDesktopOperation = () => dialogs.push('dialog');
    assert.equal(await app.openTeamGroup('legal'), true);
    assert.equal(app.workspaceGroupContext.group_id, 'legal');
    assert.equal(app.activeWorkspaceView, 'admin');
    assert.deepEqual(dialogs, [], 'a quick switch runs without the operation dialog');
    calls.length = 0;
    assert.equal(await app.openTeamGroup('legal'), true, 'the selected group opens without switching');
    assert.ok(!calls.includes('start_desktop_operation'));
});

test('normal actions pass explicit argv and group context without starting terminal', async () => {
    const calls = [];
    const { app } = environment(async (name, args) => {
        calls.push([name, args]);
        if (name === 'start_desktop_operation') return { id: 'op-1', status: 'succeeded', phase: 'Complete', output: [], result: {} };
        throw new Error(`Unexpected IPC ${name}`);
    });
    app.showTerminalView = app.createTerminalTab = () => { throw new Error('Terminal opened'); };
    assert.equal(await app.runDashboardCliCommand('hybridcipher rekey status'), true);
    assert.equal(calls.length, 1);
    assert.deepEqual(Array.from(calls[0][1].request.args), ['rekey', 'status']);
    assert.equal(calls[0][1].request.group_id, 'team-group');
});

test('password challenges use masked dialog fields and answers are cleared', async () => {
    let answered = false;
    const calls = [];
    const waiting = { id: 'op-2', status: 'needs_input', phase: 'Recovery password', output: [], input_request: { id: 'input-1', kind: 'password', message: 'Account password' } };
    const { app, node } = environment(async (name, args) => {
        calls.push([name, args]);
        if (name === 'start_desktop_operation') return waiting;
        if (name === 'answer_desktop_operation') { answered = true; return { id: 'op-2', status: 'running', phase: 'Decrypting backup', output: [] }; }
        if (name === 'get_desktop_operation') return answered ? { id: 'op-2', status: 'succeeded', phase: 'Backup restored', output: [], result: {} } : waiting;
        throw new Error(name);
    });
    await app.runDesktopOperation({ kind: 'cli', args: ['recovery', 'fetch'] }, { onUpdate(snapshot) {
        if (snapshot.status === 'needs_input' && !answered) {
            assert.equal(node('desktopOperationInput').type, 'password');
            node('desktopOperationInput').value = 'test-secret';
            app.answerDesktopOperation(false);
        }
    } });
    assert.equal(node('desktopOperationInput').value, '');
    assert.equal(calls.find(([name]) => name === 'answer_desktop_operation')[1].answer.value, 'test-secret');
    assert.ok(!node('desktopOperationOutput').textContent.includes('test-secret'));
});

test('failed initialization retries the created group instead of creating again', async () => {
    const requests = [];
    const { app, node } = environment(async (name, args) => {
        assert.equal(name, 'start_desktop_operation'); requests.push(args.request);
        return { id: `op-${requests.length}`, group_id: 'created-once', status: 'failed', phase: 'Initialization pending', output: [], error: { code: 'network', message: 'Connect to retry initialization' } };
    });
    node('createGroupName').value = 'Research';
    await app.handleCreateGroupSubmit({ preventDefault() {} });
    assert.equal(app.createdGroupPendingId, 'created-once');
    assert.equal(node('submitCreateGroupBtn').textContent, 'Retry initialization');
    await app.handleCreateGroupSubmit({ preventDefault() {} });
    assert.equal(requests[0].kind, 'create_group');
    assert.equal(requests[1].kind, 'initialize_group');
    assert.equal(requests[1].group_id, 'created-once');
});

test('late operation completion cannot restore content after logout', async () => {
    let resolve;
    const { app } = environment(() => new Promise(r => { resolve = r; }));
    const pending = app.runDesktopOperation({ kind: 'team_setup' });
    app.currentUser = 'another@example.com'; app.clearTeamUiState();
    resolve({ id: 'old-op', status: 'succeeded', output: ['old account data'], result: {} });
    await assert.rejects(pending, /Account changed/);
    assert.equal(app.desktopOperation, null);
});

test('only Advanced Settings exposes a terminal entry in rendered markup', () => {
    const html = fs.readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');
    assert.ok(!html.includes('sidebarTerminalBtn'));
    assert.ok(!html.includes('homeOpenTerminalBtn'));
    assert.equal((html.match(/>Open terminal<\/button>/g) || []).length, 1);
    assert.ok(html.indexOf('settingsOpenTerminalBtn') > html.indexOf('settingsAdvancedTools'));
    assert.ok(!moduleSource.includes('data-coverage-action="open-terminal"'));
});

test('generated argv preserves literal punctuation and Unicode on every platform', () => {
    const { app } = environment();
    const start = moduleSource.indexOf('    parseGeneratedCliArgs(rawCommand) {');
    const end = moduleSource.indexOf('    async runBundledCliArgs(', start);
    const parser = vm.runInNewContext(`({${moduleSource.slice(start, end)}})`);
    for (const os of ['windows', 'macos', 'linux']) {
        app.platformInfo = { os_type: os };
        const values = ['', 'Research team', 'a"b', "a'b", 'C:\\files\\', '工具 & %PATH% $(value); `code`'];
        const args = parser.parseGeneratedCliArgs(`hybridcipher test ${values.map(value => app.quoteCliArg(value)).join(' ')}`);
        assert.deepEqual(Array.from(args), ['test', ...values]);
    }
});

test('late group loading cannot switch the next account to the prior preferred group', async () => {
    let complete;
    const calls = [];
    const { app, values } = environment((name, args) => {
        calls.push([name, args]);
        return new Promise(resolve => { complete = resolve; });
    });
    values.set(app.groupPreferenceKey(), 'old-preferred-group');
    const pending = app.selectWorkspaceType('team');
    app.currentUser = 'new-account@example.com'; app.clearTeamUiState();
    complete({ group_id: 'old-group', organization_id: 'org-1', readiness: 'ready' });
    assert.equal(await pending, false);
    assert.equal(calls.length, 1);
    assert.equal(app.workspaceGroupContext, null);
});

test('a confirmation from the prior workspace cannot execute in the next one', async () => {
    let confirm;
    const calls = [];
    const { app } = environment((...args) => { calls.push(args); });
    app.showConfirmDialog = () => new Promise(resolve => { confirm = resolve; });
    const pending = app.runDashboardCliCommand('hybridcipher rekey status', { confirmTitle: 'Confirm' });
    app.workspaceSwitchSequence = 1;
    confirm(true);
    assert.equal(await pending, false);
    assert.equal(calls.length, 0);
});

test('logout and login to the same account still discards an old operation', async () => {
    let complete;
    const { app } = environment(() => new Promise(resolve => { complete = resolve; }));
    const pending = app.runDesktopOperation({ kind: 'team_setup' });
    app.clearTeamUiState();
    complete({ id: 'old', status: 'succeeded', output: ['private'], result: {} });
    await assert.rejects(pending, /Account changed/);
    assert.equal(app.desktopOperation, null);
});

test('created group awaiting device approval never reports Ready', async () => {
    const { app, node } = environment(async name => {
        assert.equal(name, 'start_desktop_operation');
        return { id: 'create', status: 'succeeded', group_id: 'created-group', output: [],
            result: { group_id: 'created-group', readiness: 'waiting_for_device_approval' } };
    });
    node('createGroupName').value = 'Research';
    await app.handleCreateGroupSubmit({ preventDefault() {} });
    assert.equal(app.createdGroupPendingId, 'created-group');
    assert.ok(!app.groupCreationComplete);
    assert.match(node('createGroupError').textContent, /waiting for approval/);
    assert.equal(node('submitCreateGroupBtn').textContent, 'Retry initialization');
});

test('windowless CLI reports retain string output for approval and member workflows', async () => {
    const { app } = environment(async () => ({ id: 'approve', status: 'succeeded', output: ['Welcome issued'],
        result: { exit_status: 0, output: 'Welcome issued\nDevice approved' } }));
    const result = await app.runCliCommandRaw('hybridcipher issue-welcome --device device-id');
    assert.equal(result.status, 0);
    assert.equal(result.stdout, 'Welcome issued\nDevice approved');
});

test('Personal UI hides Team setup, role labels, header controls and Activity after a successful command, keeping only the workspace selector', async () => {
    const { app, node } = environment(async () => ({ id: 'personal-verify', status: 'succeeded', phase: 'Verified', output: [], result: {} }));
    personalWorkspace(app, { entitled: true });
    await app.runDesktopOperation({ kind: 'cli', args: ['pin', 'verify'], title: 'Verify device' });
    app.applyAppMode();
    for (const id of ['teamSetupNotice', 'teamSetupRetryBtn', 'teamSetupDevicesBtn', 'workspaceContextLabel',
        'sidebarTeamNav', 'workspaceLicenseBadge', 'desktopOperationsBtn', 'desktopOperationRetryBtn',
        'teamSetupCompleteBtn', 'teamSetupCheckStatusBtn']) {
        assert.ok(node(id).classList.contains('hidden'), `${id} must be hidden in Personal`);
    }
    assert.ok(!node('workspaceSelector').classList.contains('hidden'), 'an entitled account switches back to Team from the header');
    personalWorkspace(app);
    app.applyAppMode();
    assert.ok(node('workspaceSelector').classList.contains('hidden'), 'accounts without Team have no workspace selector');
    assert.equal(node('workspaceContextLabel').textContent, '');
    assert.equal(node('workspaceHomeTitle').textContent, 'Personal Workspace');
});

test('Personal setup retry cannot invoke Team preparation or change workspace', async () => {
    const calls = [];
    const { app, node } = environment(async (...args) => { calls.push(args); throw new Error('Must not invoke'); });
    personalWorkspace(app);
    app.setupEventListeners();
    node('teamSetupRetryBtn').listeners.get('click')();
    assert.equal(await app.prepareTeamWorkspace(), false);
    assert.deepEqual(calls, []);
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(app.appMode, 'individual');
});

test('setup errors preserve an entitled Personal workspace and its saved selection', async () => {
    const { app, values, node } = environment(async name => {
        if (name === 'start_desktop_operation') return { id: 'setup', status: 'failed', output: [], error: { code: 'network', message: 'Connect to retry' } };
        throw new Error(`Unexpected IPC ${name}`);
    });
    personalWorkspace(app, { entitled: true });
    values.set(app.workspacePreferenceKey(), 'personal');
    assert.equal(await app.prepareTeamWorkspace(), false);
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(app.appMode, 'individual');
    assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
    assert.ok(node('teamSetupNotice').classList.contains('hidden'));
});

test('Team setup retry appears only for recoverable pending owner setup', () => {
    const { app, node } = environment();
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'uninitialized';
    app.updateWorkspaceLabels();
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
    assert.ok(!node('teamSetupCompleteBtn').classList.contains('hidden'));
    app.teamSetupError = { code: 'network', message: 'Connect to retry' };
    app.updateWorkspaceLabels();
    assert.ok(!node('teamSetupRetryBtn').classList.contains('hidden'));
    assert.ok(node('teamSetupCompleteBtn').classList.contains('hidden'));
    app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.updateWorkspaceLabels();
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
    assert.ok(!node('teamSetupDevicesBtn').classList.contains('hidden'));
    app.workspaceGroupContext.readiness = 'deleted';
    app.updateWorkspaceLabels();
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
    app.workspaceGroupContext.readiness = 'uninitialized'; app.teamLicenseStatus.online = false;
    app.updateWorkspaceLabels();
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
});

test('stale Retry clicks cannot repeat a completed command, cancelled task or prior workspace action', async () => {
    const calls = [];
    const { app } = environment(async (...args) => { calls.push(args); });
    app.desktopOperationContext = operationScope(app);
    app.desktopOperationRequest = { kind: 'initialize_group', group_id: 'team-group' };
    for (const status of ['succeeded', 'cancelled', 'running', 'needs_input']) {
        app.desktopOperation = { id: 'done', status, error: { code: 'network', message: 'Connect to retry' } };
        assert.equal(await app.retryDesktopOperation(), false);
    }
    app.desktopOperation.status = 'failed'; app.workspaceSwitchSequence = 1;
    assert.equal(await app.retryDesktopOperation(), false);
    assert.deepEqual(calls, []);
});

test('nonrecoverable operation failures never offer Retry', () => {
    const { app, node } = environment();
    app.desktopOperationContext = operationScope(app);
    app.desktopOperationRequest = { kind: 'initialize_group', group_id: 'team-group' };
    app.desktopOperation = { id: 'denied', status: 'failed', error: { code: 'group_setup_failed', message: 'Permission denied' } };
    app.renderDesktopOperation();
    assert.ok(node('desktopOperationRetryBtn').classList.contains('hidden'));
    assert.equal(app.canRetryDesktopOperation(), false);
});

test('Team Activity acknowledges success while keeping failed operation details accessible', () => {
    const { app, node } = environment();
    app.desktopOperationContext = operationScope(app);
    app.desktopOperation = { id: 'done', status: 'succeeded', output: [] };
    app.renderDesktopOperation();
    assert.ok(!node('desktopOperationsBtn').classList.contains('hidden'));
    app.closeDesktopOperation();
    assert.ok(node('desktopOperationsBtn').classList.contains('hidden'));
    app.desktopOperation = { id: 'failed', status: 'failed', output: [], error: { code: 'network', message: 'Connect to retry' } };
    app.renderDesktopOperation(); app.closeDesktopOperation();
    assert.ok(!node('desktopOperationsBtn').classList.contains('hidden'));
    app.workspaceSwitchSequence = 1; app.openDesktopOperation();
    assert.equal(node('desktopOperationModal').style.display, 'none');
});

test('an active workspace operation remains accessible until completion and its history clears on leaving Team', async () => {
    const calls = [];
    let completeOperation;
    const { app, node, values } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'start_desktop_operation' && args.request.kind === 'cli')
            return { id: 'personal-action', status: 'succeeded', output: [], result: { complete: true } };
        if (command === 'start_desktop_operation') return { id: 'active', status: 'needs_input', output: ['Current Team operation'],
            input_request: { id: 'approval', kind: 'confirm', message: 'Confirm group change' } };
        if (command === 'get_desktop_operation') return new Promise(resolve => { completeOperation = resolve; });
        if (command === 'get_workspace_group_context') return { group_id: 'personal-group', organization_id: null, role: 'owner', readiness: 'ready' };
        throw new Error(command);
    });
    values.set(app.workspacePreferenceKey(), 'team');
    app.enrolledFolders = [{ path: 'current-team-folder' }];
    const pending = app.runDesktopOperation({ kind: 'initialize_group', group_id: 'team-group', title: 'Initialize group' });
    while (!completeOperation) await new Promise(resolve => setImmediate(resolve));
    node('workspaceSelector').value = 'personal';
    assert.equal(await app.selectWorkspaceType('personal'), false);
    assert.equal(app.activeWorkspaceType, 'team');
    assert.equal(app.workspaceSwitchSequence, undefined);
    assert.equal(values.get(app.workspacePreferenceKey()), 'team');
    assert.equal(node('workspaceSelector').value, 'team');
    assert.equal(node('desktopOperationModal').style.display, 'flex');
    assert.ok(!node('desktopOperationsBtn').classList.contains('hidden'));
    assert.equal(app.enrolledFolders[0].path, 'current-team-folder');
    assert.equal(calls.length, 2);

    completeOperation({ id: 'active', status: 'succeeded', output: ['Completed Team operation'], result: {} });
    await pending;
    assert.equal(await app.selectWorkspaceType('personal'), true);
    assert.equal(app.desktopOperation, null);
    assert.equal(app.desktopOperationRequest, null);
    assert.equal(app.desktopOperationContext, null);
    assert.equal(app.desktopInputRequestId, null);
    assert.equal(node('desktopOperationOutput').textContent, '');
    assert.equal(node('desktopOperationModal').style.display, 'none');
    assert.ok(node('desktopOperationsBtn').classList.contains('hidden'));
    assert.ok(node('desktopOperationRetryBtn').classList.contains('hidden'));
    assert.equal(await app.retryDesktopOperation(), false);
    assert.equal(calls.length, 3);
    assert.equal((await app.runDesktopOperation({ kind: 'cli', args: ['pin', 'list'] })).complete, true);
    assert.equal(calls.length, 4);
});

test('reconciliation removes completed setup state and refreshes devices, Home and folders together', async () => {
    const calls = [];
    const { app, node, intervals } = environment(async (command, args) => {
        calls.push([command, args]);
        assert.equal(command, 'get_workspace_group_context');
        return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' };
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.teamSetupErrorCode = 'device_approval_required'; app.teamSetupMessage = 'Waiting';
    app.startWorkspaceReadinessPolling(); assert.equal(intervals.size, 1);
    let folders = 0; app.loadEnrolledFolders = async () => { folders += 1; };
    assert.equal(await app.reconcileWorkspaceState(), true);
    assert.equal(calls[0][1].readOnly, false);
    assert.equal(app.workspaceContextReady, true);
    assert.ok(app.devicesRead && app.homeRead); assert.equal(folders, 1);
    assert.equal(intervals.size, 0);
    assert.ok(node('teamSetupNotice').classList.contains('hidden'));
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
});

test('pending polling reads status without starting setup, overlaps or changing selected group', async () => {
    const calls = [];
    let complete;
    const { app, intervals } = environment((command, args) => {
        calls.push([command, args]); return new Promise(resolve => { complete = resolve; });
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.startWorkspaceReadinessPolling();
    const timer = [...intervals.values()][0]; assert.equal(timer.ms, 10000);
    const pending = timer.callback(); await timer.callback();
    assert.equal(calls.length, 1); assert.equal(calls[0][0], 'get_workspace_group_context');
    assert.equal(calls[0][1].readOnly, true);
    app.workspaceSwitchSequence = 1; app.workspaceGroupContext = { group_id: 'new-group', organization_id: 'org-1', readiness: 'ready' };
    complete({ group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' });
    await pending;
    assert.equal(app.workspaceGroupContext.group_id, 'new-group');
    assert.ok(!app.devicesRead && !app.homeRead);
    app.clearTeamUiState(); assert.equal(intervals.size, 0);
});

test('fresh external approval attempts Welcome acquisition once and leaves failure retry to Check status', async () => {
    const calls = [];
    let completeDevices;
    let allowAcquisition = false;
    const waiting = { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval',
        groups: [{ id: 'team-group', current_epoch_id: 'issued-epoch' }] };
    const { app, node } = environment(async (command, args) => {
        assert.equal(command, 'get_workspace_group_context');
        calls.push(args);
        if (!args.readOnly && !allowAcquisition) throw new Error('Welcome temporarily unavailable');
        return { ...waiting, readiness: args.readOnly ? waiting.readiness : 'ready' };
    });
    app.currentDeviceId = 'this-device'; app.workspaceGroupContext = waiting; app.workspaceContextReady = false;
    app.personalDevicesOverview = { device_trust: { approved: false } };
    const approved = { device_id: 'this-device', approved: true, identity_key_sha256: 'a'.repeat(64) };
    app.refreshPersonalDevicesOverview = () => new Promise(resolve => {
        completeDevices = () => { app.personalDevicesOverview = { device_trust: { ...approved } }; resolve(); };
    });
    const pending = app.reconcileWorkspaceState({ readOnly: true, refreshFolders: false });
    while (!completeDevices) await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(calls.map(args => args.readOnly), [true]);
    completeDevices();
    assert.equal(await pending, false);
    assert.deepEqual(calls.map(args => args.readOnly), [true, false]);
    assert.equal(app.workspaceWelcomeAcquisitionAttempts.keys.size, 1);

    app.refreshPersonalDevicesOverview = async () => { app.personalDevicesOverview = { device_trust: { ...approved } }; };
    assert.equal(await app.reconcileWorkspaceState({ readOnly: true, refreshFolders: false }), true);
    assert.deepEqual(calls.map(args => args.readOnly), [true, false, true]);
    allowAcquisition = true;
    assert.equal(await app.checkWorkspaceReadiness(), true);
    assert.deepEqual(calls.map(args => args.readOnly), [true, false, true, false]);
    assert.equal(app.workspaceContextReady, true);
    assert.ok(node('teamSetupNotice').classList.contains('hidden'));
    app.clearTeamUiState(); assert.equal(app.workspaceWelcomeAcquisitionAttempts, null);
});

test('read-only readiness cannot acquire Welcome from stale Devices state or after leaving its scope', async () => {
    const calls = [];
    let completeDevices;
    const waiting = { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval',
        groups: [{ id: 'team-group', current_epoch_id: 'issued-epoch' }] };
    const { app } = environment(async (command, args) => { calls.push(args); return waiting; });
    app.currentDeviceId = 'this-device'; app.workspaceGroupContext = waiting; app.workspaceContextReady = false;
    const approved = { device_id: 'this-device', approved: true, identity_key_sha256: 'a'.repeat(64) };
    app.personalDevicesOverview = { device_trust: approved };
    assert.equal(await app.reconcileWorkspaceState({ readOnly: true }), true);
    assert.deepEqual(calls.map(args => args.readOnly), [true]);
    app.refreshPersonalDevicesOverview = () => new Promise(resolve => {
        completeDevices = () => { app.personalDevicesOverview = { device_trust: { ...approved } }; resolve(); };
    });
    const pending = app.reconcileWorkspaceState({ readOnly: true });
    while (!completeDevices) await new Promise(resolve => setImmediate(resolve));
    app.workspaceSwitchSequence = (app.workspaceSwitchSequence || 0) + 1;
    completeDevices();
    assert.equal(await pending, false);
    assert.deepEqual(calls.map(args => args.readOnly), [true, true]);
    assert.equal(app.workspaceWelcomeAcquisitionAttempts, undefined);
});

test('external approval polling acquires issued keys and removes the waiting notice without Team setup', async () => {
    const calls = [];
    let keysAcquired = false;
    let folderReads = 0;
    const waiting = { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval',
        groups: [{ id: 'team-group', current_epoch_id: 'issued-epoch' }] };
    const { app, node, intervals } = environment(async (command, args) => {
        assert.equal(command, 'get_workspace_group_context');
        calls.push(args);
        if (!args.readOnly) keysAcquired = true;
        return { ...waiting, readiness: keysAcquired ? 'ready' : waiting.readiness };
    });
    app.currentDeviceId = 'this-device'; app.workspaceGroupContext = waiting; app.workspaceContextReady = false;
    app.refreshPersonalDevicesOverview = async () => {
        app.personalDevicesOverview = { device_trust: { device_id: 'this-device', approved: true, identity_key_sha256: 'b'.repeat(64) } };
    };
    app.loadEnrolledFolders = async () => { folderReads += 1; };
    app.startWorkspaceReadinessPolling();
    await [...intervals.values()][0].callback();
    assert.deepEqual(calls.map(args => args.readOnly), [true, false]);
    assert.equal(app.workspaceContextReady, true);
    assert.equal(folderReads, 1);
    assert.equal(intervals.size, 0);
    assert.ok(node('teamSetupNotice').classList.contains('hidden'));
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
});

test('a failed invitation entitlement refresh preserves Personal and does not claim successful joining', async () => {
    const calls = [];
    const { app, node, values } = environment(async (command, args) => {
        calls.push(command);
        assert.equal(args.expectedAccountEmail, 'owner@example.com');
        assert.equal(args.expectedDeviceId, 'current-device');
        if (command === 'accept_team_invitation') return null;
        if (command === 'get_team_license_status') throw new Error('Network unavailable');
        throw new Error(`Unexpected IPC ${command}`);
    });
    app.currentDeviceId = 'current-device';
    personalWorkspace(app); values.set(app.workspacePreferenceKey(), 'personal'); node('teamInvitationCode').value = 'invite';
    await app.acceptTeamInvitationFromSettings();
    assert.deepEqual(calls, ['accept_team_invitation', 'get_team_license_status']);
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
    assert.match(node('teamActivationError').textContent, /Network unavailable/);
});

test('failed Team selection from activation preserves Personal files and workspace preference', async () => {
    const { app, values } = environment(async (command, args) => {
        assert.equal(command, 'get_workspace_group_context');
        if (args.workspace === 'team') throw new Error('Network unavailable');
        return { group_id: 'personal-group', organization_id: null, role: 'owner', readiness: 'ready' };
    });
    personalWorkspace(app, { entitled: true }); values.set(app.workspacePreferenceKey(), 'personal');
    app.enrolledFolders = [{ path: 'personal-folder' }];
    assert.equal(await app.selectWorkspaceType('team', { preserveOnFailure: true }), false);
    assert.equal(app.activeWorkspaceType, 'personal'); assert.equal(app.workspaceGroupContext.group_id, 'personal-group');
    assert.equal(app.enrolledFolders[0].path, 'personal-folder'); assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
});

test('verified Team awaiting approval remains reachable from explicit activation without offering setup retry', async () => {
    const { app, node } = environment(async (command, args) => {
        if (command === 'start_desktop_operation') return { id: 'setup', status: 'succeeded', output: [], result: {
            group_id: 'team-group', organization_id: 'org-1', readiness: 'waiting_for_device_approval', first_setup: true } };
        if (command === 'get_workspace_group_context') return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval' };
        throw new Error(command);
    });
    personalWorkspace(app, { entitled: true });
    app.refreshTeamDirectory = async () => {};
    assert.equal(await app.finishTeamActivation(app.teamLicenseStatus, app.currentUser, 0), true);
    assert.equal(app.activeWorkspaceType, 'team'); assert.equal(app.workspaceContextReady, false);
    assert.ok(!node('teamSetupDevicesBtn').classList.contains('hidden'));
    assert.ok(node('teamSetupRetryBtn').classList.contains('hidden'));
});

test('activation completion from an earlier login cannot enable Team on the next login', async () => {
    let complete;
    const { app, node } = environment(() => new Promise(resolve => { complete = resolve; }));
    personalWorkspace(app); node('teamOrganizationName').value = 'Research'; node('teamUnlockCode').value = 'code';
    const pending = app.activateTeamFromSettings();
    app.clearTeamUiState();
    complete({ workspace: 'team', online: true, can_write: true, organization: { id: 'old-org', role: 'owner' } });
    await pending;
    assert.equal(app.activeWorkspaceType, 'personal'); assert.equal(app.teamLicenseStatus.workspace, 'personal');
});

test('cancelling activation before redemption finishes cannot switch Personal to Team', async () => {
    let complete;
    const calls = [];
    const { app, node, values } = environment((command, args) => {
        calls.push(command);
        assert.equal(args.expectedAccountEmail, 'owner@example.com');
        assert.equal(args.expectedDeviceId, 'current-device');
        return new Promise(resolve => { complete = resolve; });
    });
    app.currentDeviceId = 'current-device';
    personalWorkspace(app); values.set(app.workspacePreferenceKey(), 'personal');
    node('teamOrganizationName').value = 'Research'; node('teamUnlockCode').value = 'code';
    const pending = app.activateTeamFromSettings(); app.closeTeamActivationModal();
    complete({ workspace: 'team', online: true, can_write: true, organization: { id: 'org-1', role: 'owner' } });
    await pending;
    assert.deepEqual(calls, ['redeem_team_code']); assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
});

test('cancelling activation during group loading restores the Personal selection', async () => {
    let complete;
    const { app, values } = environment(async (command, args) => {
        assert.equal(command, 'get_workspace_group_context');
        if (args.workspace === 'team') return new Promise(resolve => { complete = resolve; });
        return { group_id: 'personal-group', organization_id: null, role: 'owner', readiness: 'ready' };
    });
    personalWorkspace(app, { entitled: true }); app.teamLicenseStatus.organization.role = 'member';
    values.set(app.workspacePreferenceKey(), 'personal');
    const attempt = Symbol('activation'); app.teamActivationAttempt = attempt;
    const pending = app.finishTeamActivation(app.teamLicenseStatus, app.currentUser, 0, attempt);
    app.closeTeamActivationModal();
    complete({ group_id: 'team-group', organization_id: 'org-1', role: 'reader', readiness: 'ready' });
    assert.equal(await pending, false);
    assert.equal(app.activeWorkspaceType, 'personal'); assert.equal(app.workspaceGroupContext.group_id, 'personal-group');
    assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
});

test('license refresh for an already pending device performs read-only reconciliation without retrying setup', async () => {
    const calls = [];
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') return app.teamLicenseStatus;
        if (command === 'get_workspace_group_context') return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval' };
        throw new Error(`Unexpected IPC ${command}`);
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.currentDeviceId = 'current-device';
    app.workspaceChoiceLoaded = true; app.refreshTeamDirectory = async () => {}; app.refreshPendingTeamRequests = async () => {};
    await app.refreshTeamLicenseStatus();
    assert.deepEqual(calls.map(([command]) => command), ['get_team_license_status', 'get_device_trust_status', 'get_workspace_group_context']);
    assert.equal(calls[0][1].expectedAccountEmail, 'owner@example.com');
    assert.equal(calls[0][1].expectedDeviceId, 'current-device');
    assert.equal(calls[2][1].readOnly, true);
});

test('readiness polling stops after thirty checks and pauses while hidden or offline', async () => {
    const calls = [];
    const { app, window, intervals } = environment(async (command, args) => {
        calls.push([command, args]);
        return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval' };
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.startWorkspaceReadinessPolling(); const timer = [...intervals.values()][0];
    window.document.hidden = true; await timer.callback(); assert.equal(calls.length, 0);
    window.document.hidden = false; window.navigator = { onLine: false }; await timer.callback(); assert.equal(calls.length, 0);
    window.navigator.onLine = true;
    for (let i = 0; i < 30; i += 1) await timer.callback();
    assert.equal(calls.length, 30); assert.equal(intervals.size, 0);
    await timer.callback(); assert.equal(calls.length, 30);
    app.teamLicenseStatus.online = false; app.startWorkspaceReadinessPolling(); assert.equal(intervals.size, 0);
});

test('elapsed readiness poll budget stops requests and explicit Check status can acquire already-issued welcome keys', async () => {
    const calls = [];
    const { app, intervals, node } = environment(async (command, args) => {
        calls.push([command, args]);
        return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' };
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.startWorkspaceReadinessPolling(); const timer = [...intervals.values()][0];
    app.workspaceReadinessTimer.startedAt -= 300001;
    await timer.callback(); assert.equal(calls.length, 0); assert.equal(intervals.size, 0);
    assert.equal(await app.checkWorkspaceReadiness(), true);
    // Check status also rechecks this device's trust before reloading the group.
    assert.deepEqual(calls.map(([command]) => command), ['get_device_trust_status', 'get_workspace_group_context']);
    assert.equal(calls[1][1].readOnly, false);
    assert.equal(app.workspaceContextReady, true); assert.ok(node('teamSetupCheckStatusBtn').classList.contains('hidden'));
});

test('focus and reconnection refresh pending status without a Team setup operation', async () => {
    const calls = [];
    const { app, window, events, intervals } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') return app.teamLicenseStatus;
        if (command === 'get_workspace_group_context') return { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'waiting_for_device_approval' };
        throw new Error(`Unexpected IPC ${command}`);
    });
    app.workspaceContextReady = false; app.workspaceGroupContext.readiness = 'waiting_for_device_approval';
    app.workspaceChoiceLoaded = true; app.refreshTeamDirectory = async () => {}; app.refreshPendingTeamRequests = async () => {};
    app.setupEventListeners(); app.startWorkspaceReadinessPolling(); assert.equal(intervals.size, 1);
    window.document.hidden = true; events.get('visibilitychange')(); assert.equal(intervals.size, 0);
    window.document.hidden = false; await events.get('focus')();
    assert.equal(intervals.size, 1); assert.ok(calls.every(([name, args]) => name !== 'start_desktop_operation' && (name !== 'get_workspace_group_context' || args.readOnly)));
    // Switching windows again right away (focus plus visibilitychange) reuses that refresh.
    const callsAfterFirstFocus = calls.length;
    await events.get('focus')(); await events.get('visibilitychange')();
    assert.equal(calls.length, callsAfterFirstFocus);
    app.workspaceResumeRefreshAt -= 30001; await events.get('focus')();
    assert.ok(calls.length > callsAfterFirstFocus);
    events.get('offline')(); assert.equal(intervals.size, 0);
    await events.get('online')(); assert.equal(intervals.size, 1);
});

test('failed Team entitlement refresh still loads Personal and enables folder enrollment', async () => {
    const calls = [];
    const { app, node } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') throw new Error('Team service unavailable');
        if (command === 'get_workspace_group_context') return readyPersonalContext();
        throw new Error(`Unexpected IPC ${command}`);
    });
    unresolvedPersonalWorkspace(app);
    await app.refreshTeamLicenseStatus({ silent: true });
    await nextTurn();
    assert.equal(calls.filter(([command]) => command === 'get_workspace_group_context').length, 1);
    assert.equal(calls.find(([command]) => command === 'get_workspace_group_context')[1].workspace, 'personal');
    assert.equal(app.workspaceContextReady, true);
    assert.equal(app.workspaceGroupContext.group_id, 'personal-group');
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.ok(!Object.hasOwn(node('addFolderBtn').attributes, 'disabled'));
    await app.addEnrolledFolder();
    assert.equal(app.enrollmentStarted, 1);
    assert.ok(calls.every(([command]) => command !== 'start_desktop_operation'));
});

test('an unfinished Team entitlement request does not delay loading Personal or opening its picker', async () => {
    const license = deferred();
    const calls = [];
    let licenseFinished = false;
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') return license.promise;
        if (command === 'get_workspace_group_context') return readyPersonalContext();
        throw new Error(`Unexpected IPC ${command}`);
    });
    unresolvedPersonalWorkspace(app);
    const refresh = app.refreshTeamLicenseStatus({ silent: true }).then(result => { licenseFinished = true; return result; });
    await nextTurn();
    try {
        assert.equal(licenseFinished, false);
        assert.equal(app.workspaceContextReady, true);
        assert.equal(calls.filter(([command]) => command === 'get_workspace_group_context').length, 1);
        await app.addEnrolledFolder();
        assert.equal(app.enrollmentStarted, 1);
    } finally {
        license.resolve({ workspace: 'personal', online: true, can_write: false, organization: null });
        await refresh;
    }
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(calls.filter(([command]) => command === 'get_workspace_group_context').length, 1);
});

test('overlapping login refreshes and Add share one Personal context request', async () => {
    const license = deferred();
    const personal = deferred();
    const calls = [];
    const { app, node } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') return license.promise;
        if (command === 'get_workspace_group_context') return personal.promise;
        throw new Error(`Unexpected IPC ${command}`);
    });
    unresolvedPersonalWorkspace(app);
    app.applyAppMode();
    assert.ok(!Object.hasOwn(node('addFolderBtn').attributes, 'disabled'));
    assert.ok(!Object.hasOwn(node('homeAddFolderBtn').attributes, 'disabled'));
    const first = app.refreshTeamLicenseStatus({ silent: true });
    const second = app.refreshTeamLicenseStatus({ silent: true });
    const add = app.addEnrolledFolder();
    await nextTurn();
    const beforeCompletion = calls.map(([command]) => command);
    assert.equal(app.enrollmentStarted || 0, 0);
    personal.resolve(readyPersonalContext());
    license.resolve({ workspace: 'personal', online: true, can_write: false, organization: null });
    await Promise.all([first, second, add]);
    assert.equal(beforeCompletion.filter(command => command === 'get_workspace_group_context').length, 1);
    assert.equal(calls.filter(([command]) => command === 'get_team_license_status').length, 1);
    assert.equal(calls.filter(([command]) => command === 'get_workspace_group_context').length, 1);
    assert.equal(app.enrollmentStarted, 1);
    assert.equal(app.workspaceContextReady, true);
});

test('Personal Add retries a failed context read before opening the folder picker', async () => {
    let contextReads = 0;
    const notices = [];
    const { app, node } = environment(async command => {
        assert.equal(command, 'get_workspace_group_context');
        contextReads += 1;
        if (contextReads === 1) throw new Error('Connection temporarily unavailable');
        return readyPersonalContext();
    });
    unresolvedPersonalWorkspace(app);
    app.showNotification = message => notices.push(message);
    assert.equal(await app.ensurePersonalWorkspaceReady(), false);
    assert.equal(app.enrollmentStarted || 0, 0);
    assert.equal(app.workspaceContextReady, false);
    app.applyAppMode();
    assert.ok(!Object.hasOwn(node('addFolderBtn').attributes, 'disabled'));
    await app.addEnrolledFolder();
    assert.equal(contextReads, 2);
    assert.equal(app.enrollmentStarted, 1);
    assert.equal(app.workspaceContextReady, true);
    assert.ok(notices.every(message => !/Team/i.test(message)));
});

test('Personal Add joining a failed startup read completes its own readiness retry on the same click', async () => {
    let rejectStartup;
    let contextReads = 0;
    const { app } = environment(async command => {
        assert.equal(command, 'get_workspace_group_context');
        contextReads += 1;
        if (contextReads === 1) return new Promise((resolve, reject) => { rejectStartup = reject; });
        return readyPersonalContext();
    });
    unresolvedPersonalWorkspace(app);
    const startup = app.ensurePersonalWorkspaceReady();
    const startupSequence = app.workspaceSwitchSequence;
    const add = app.addEnrolledFolder();
    await nextTurn();
    assert.equal(contextReads, 1);
    assert.equal(app.enrollmentStarted || 0, 0);
    rejectStartup(new Error('Connection temporarily unavailable'));
    const [startupReady] = await Promise.all([startup, add]);
    assert.equal(startupReady, false);
    assert.equal(contextReads, 2);
    assert.ok(app.workspaceSwitchSequence > startupSequence);
    assert.equal(app.workspaceContextReady, true);
    assert.equal(app.enrollmentStarted, 1);
});

test('Personal enrollment explains missing keys and empty groups without bypassing write permissions', async () => {
    for (const { context, expectedMessage } of [
        { context: readyPersonalContext({ readiness: 'waiting_for_device_approval' }), expectedMessage: /approv|Devices/i },
        { context: readyPersonalContext({ group_id: null, readiness: 'no_groups', groups: [] }), expectedMessage: /group|workspace/i },
        { context: readyPersonalContext({ role: 'reader' }), expectedMessage: /read.only|write|permission/i },
    ]) {
        const notices = [];
        const { app } = environment(async command => {
            assert.equal(command, 'get_workspace_group_context');
            return context;
        });
        unresolvedPersonalWorkspace(app);
        app.showNotification = message => notices.push(message);
        await app.addEnrolledFolder();
        assert.equal(app.enrollmentStarted || 0, 0, context.readiness);
        assert.equal(app.workspaceUiModel().canWrite, false, context.readiness);
        assert.ok(notices.some(message => expectedMessage.test(message)), `${context.readiness}: ${notices.join('; ')}`);
        assert.ok(notices.every(message => !/Team/i.test(message)), context.readiness);
    }
});

test('Personal context responses from an earlier account, device, login or workspace cannot open enrollment', async () => {
    for (const change of ['account', 'device', 'login', 'workspace']) {
        const personal = deferred();
        const { app } = environment(async command => {
            assert.equal(command, 'get_workspace_group_context');
            return personal.promise;
        });
        unresolvedPersonalWorkspace(app);
        const add = app.addEnrolledFolder();
        await nextTurn();
        if (change === 'account') app.currentUser = 'different@example.com';
        if (change === 'device') app.currentDeviceId = 'replacement-device';
        if (change === 'login') app.desktopAccountGeneration = (app.desktopAccountGeneration || 0) + 1;
        if (change === 'workspace') {
            app.activeWorkspaceType = 'team'; app.appMode = 'team';
            app.workspaceSwitchSequence = (app.workspaceSwitchSequence || 0) + 1;
            app.teamLicenseStatus = { workspace: 'team', online: true, can_write: true, organization: { id: 'org-1', role: 'owner' } };
            app.workspaceGroupContext = { group_id: 'team-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' };
            app.workspaceContextReady = true;
        }
        personal.resolve(readyPersonalContext());
        await add;
        assert.equal(app.enrollmentStarted || 0, 0, change);
        assert.notEqual(app.workspaceGroupContext?.group_id, 'personal-group', change);
        if (change === 'workspace') assert.equal(app.workspaceGroupContext.group_id, 'team-group');
    }
});

test('a stale saved Personal group cannot force an invalid switch before enrollment', async () => {
    const calls = [];
    const { app, values } = environment(async (command, args) => {
        calls.push([command, args]);
        assert.equal(command, 'get_workspace_group_context');
        assert.equal(args.workspace, 'personal');
        return readyPersonalContext();
    });
    unresolvedPersonalWorkspace(app);
    values.set(app.groupPreferenceKey('personal'), 'removed-personal-group');
    await app.addEnrolledFolder();
    assert.equal(app.enrollmentStarted, 1);
    assert.equal(app.workspaceGroupContext.group_id, 'personal-group');
    assert.equal(values.get(app.groupPreferenceKey('personal')), 'personal-group');
    assert.deepEqual(calls.map(([command]) => command), ['get_workspace_group_context']);
});

test('an active operation blocks Personal Add even when its encryption group is ready', async () => {
    const notices = [];
    const calls = [];
    const { app } = environment(async command => { calls.push(command); throw new Error(`Unexpected IPC ${command}`); });
    personalWorkspace(app);
    app.desktopOperation = { id: 'active-operation', status: 'running' };
    app.showNotification = message => notices.push(message);
    await app.addEnrolledFolder();
    assert.equal(app.enrollmentStarted || 0, 0);
    assert.deepEqual(calls, []);
    assert.ok(notices.some(message => /complete.*operation|operation.*complete/i.test(message)));
});

test('a late Team entitlement cannot change Personal while its folder picker is open', async () => {
    const license = deferred();
    const picker = deferred();
    const calls = [];
    const { app, values } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_team_license_status') return license.promise;
        if (command === 'get_workspace_group_context') {
            assert.equal(args.workspace, 'personal');
            return readyPersonalContext();
        }
        throw new Error(`Unexpected IPC ${command}`);
    });
    unresolvedPersonalWorkspace(app);
    app.refreshTeamDirectory = async () => {};
    values.set(app.workspacePreferenceKey(), 'team');
    app.enrollmentPickerPromise = picker.promise;
    const refresh = app.refreshTeamLicenseStatus({ silent: true });
    await nextTurn();
    const add = app.addEnrolledFolder();
    await nextTurn();
    assert.equal(app.enrollmentStarted, 1);
    try {
        license.resolve({ workspace: 'team', online: true, can_write: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } });
        await refresh;
        assert.equal(app.activeWorkspaceType, 'personal');
        assert.equal(app.workspaceGroupContext.group_id, 'personal-group');
        assert.equal(values.get(app.workspacePreferenceKey()), 'personal');
        assert.ok(calls.every(([command]) => command !== 'start_desktop_operation'));
    } finally {
        picker.resolve();
        await add;
    }
});

test('changing the Personal group during its pending readiness request cannot open an old picker', async () => {
    const readiness = deferred();
    const { app } = environment(async command => {
        assert.equal(command, 'get_workspace_group_context');
        return readiness.promise;
    });
    unresolvedPersonalWorkspace(app);
    app.workspaceGroupContext = readyPersonalContext({ group_id: 'personal-old', readiness: 'waiting_for_device_approval' });
    const add = app.addEnrolledFolder();
    await nextTurn();
    app.workspaceGroupContext = readyPersonalContext({ group_id: 'personal-new' });
    app.workspaceContextReady = true;
    readiness.resolve(readyPersonalContext({ group_id: 'personal-old' }));
    await add;
    assert.equal(app.enrollmentStarted || 0, 0);
    assert.equal(app.workspaceGroupContext.group_id, 'personal-new');
});

test('automatic Personal readiness preserves a saved Team workspace preference', async () => {
    const calls = [];
    const { app, values } = environment(async (command, args) => {
        calls.push([command, args]);
        assert.equal(command, 'get_workspace_group_context');
        assert.equal(args.workspace, 'personal');
        return readyPersonalContext();
    });
    unresolvedPersonalWorkspace(app);
    values.set(app.workspacePreferenceKey(), 'team');
    assert.equal(await app.ensurePersonalWorkspaceReady(), true);
    assert.equal(app.workspaceContextReady, true);
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(values.get(app.workspacePreferenceKey()), 'team');
    assert.deepEqual(calls.map(([command]) => command), ['get_workspace_group_context']);
});

test('startup restores a saved Team workspace for organization owners and members', async () => {
    for (const role of ['owner', 'member']) {
        const { app, values } = environment(async (command, args) => {
            if (command === 'get_team_license_status') return { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role } };
            if (command === 'get_workspace_group_context') return args.workspace === 'team'
                ? { group_id: 'team-group', name: 'Team', organization_id: 'org-1', role: 'owner', readiness: 'ready' } : readyPersonalContext();
            if (command === 'start_desktop_operation') return { id: 'setup', status: 'succeeded' };
            return null;
        });
        unresolvedPersonalWorkspace(app);
        app.teamLicenseStatus = null;
        values.set(app.workspacePreferenceKey(), 'team');
        assert.equal(await app.ensurePersonalWorkspaceReady(), true);
        await app.refreshTeamLicenseStatus({ silent: true });
        assert.equal(app.activeWorkspaceType, 'team', role);
        assert.equal(app.workspaceGroupContext.group_id, 'team-group', role);
        assert.equal(values.get(app.workspacePreferenceKey()), 'team', role);
    }
});

const untrusted = { approved: true, fingerprint_verified: false, can_revoke_other_devices: false };

test('an unverified owner device works as a member until its trust is confirmed', async () => {
    let trust = untrusted;
    const { app, node } = environment(async command => {
        if (command === 'get_device_trust_status') return { success: true, data: trust };
        throw new Error(`Unexpected IPC ${command}`);
    });
    app.currentDeviceTrust = null;
    await app.refreshCurrentDeviceTrust();
    const model = app.workspaceUiModel();
    assert.equal(model.canAdminister, false);
    assert.equal(model.canAdministerGroup, false);
    assert.equal(model.canCreate, false);
    assert.equal(model.needsDeviceVerification, true);
    assert.equal(model.canWrite, true, 'member-level writes stay available');
    assert.equal(app.canPrepareTeamWorkspace(), false, 'owner setup needs a verified device');
    app.applyAppMode();
    assert.ok(!node('teamDeviceTrustNotice').classList.contains('hidden'));
    assert.equal(node('sidebarOverviewLabel').textContent, 'Team home');

    trust = { approved: true, fingerprint_verified: true, can_revoke_other_devices: true };
    app.setWorkspaceView('home');
    await app.refreshCurrentDeviceTrust();
    assert.equal(app.workspaceUiModel().canAdminister, true);
    assert.equal(app.activeWorkspaceView, 'home');
    assert.equal(node('sidebarOverviewLabel').textContent, 'Team overview', 'a verified admin gets the Team overview');
    assert.ok(node('teamDeviceTrustNotice').classList.contains('hidden'));
});

test('a trust check that fails (expired session or offline) says so instead of calling the device unverified', async () => {
    let failing = true;
    const { app, node } = environment(async command => {
        if (command !== 'get_device_trust_status') throw new Error(`Unexpected IPC ${command}`);
        if (failing) return { success: false, error: 'Authentication token rejected. Please login again.' };
        return { success: true, data: { approved: true, fingerprint_verified: true, can_revoke_other_devices: true } };
    });
    app.currentDeviceTrust = null;
    assert.equal(app.workspaceUiModel().deviceTrustUnavailable, false, 'nothing is reported before a check runs');
    assert.equal(await app.refreshCurrentDeviceTrust(), null);
    const model = app.workspaceUiModel();
    assert.equal(model.canAdminister, false, 'an unknown status never grants admin rights');
    assert.equal(model.needsDeviceVerification, false);
    assert.equal(model.deviceTrustUnavailable, true);
    app.applyAppMode();
    assert.ok(!node('teamDeviceTrustNotice').classList.contains('hidden'));
    assert.match(node('teamDeviceTrustMessage').textContent, /couldn't be checked\. Sign in again/);
    assert.ok(node('teamDeviceTrustConfirmBtn').classList.contains('hidden'), 'password confirmation needs a working session');
    assert.ok(node('teamDeviceTrustFingerprintBtn').classList.contains('hidden'));

    failing = false;
    await app.refreshCurrentDeviceTrust();
    assert.equal(app.workspaceUiModel().canAdminister, true);
    assert.ok(node('teamDeviceTrustNotice').classList.contains('hidden'));
});

test('losing device trust leaves administration and a stale trust cache never grants admin', async () => {
    const { app } = environment(async command => {
        if (command === 'get_device_trust_status') return { success: true, data: untrusted };
        throw new Error(`Unexpected IPC ${command}`);
    });
    app.setWorkspaceView('admin');
    assert.equal(app.activeWorkspaceView, 'admin');
    await app.refreshCurrentDeviceTrust();
    assert.equal(app.activeWorkspaceView, 'home');
    app.currentDeviceTrust = { account: 'someone-else@example.com', device: undefined,
        status: { approved: true, fingerprint_verified: true, can_revoke_other_devices: true } };
    assert.equal(app.currentDeviceTrusted(), false);
});

test('the unverified-device notice buttons show the fingerprint, confirm trust, and recheck', async () => {
    const calls = [];
    const { app, node } = environment(async command => { calls.push(command); return { success: true, data: untrusted }; });
    app.openSecurityPanel = () => calls.push('open-panel');
    app.ensureDeviceManagementTrust = async action => { calls.push(`confirm-${action}`); return true; };
    app.setupEventListeners();
    node('teamDeviceTrustFingerprintBtn').listeners.get('click')({ stopPropagation() {} });
    await node('teamDeviceTrustConfirmBtn').listeners.get('click')();
    await node('teamDeviceTrustCheckBtn').listeners.get('click')();
    assert.deepEqual(calls, ['open-panel', 'confirm-approve', 'get_device_trust_status', 'get_device_trust_status']);
});

test('Team folder enrollment names the reason it is blocked', () => {
    const { app } = environment();
    const reason = () => app.teamEnrollmentBlockingReason();
    app.workspaceGroupContext.name = 'Research';
    app.workspaceGroupContext.readiness = 'waiting_for_device_approval'; app.workspaceContextReady = false;
    assert.match(reason(), /missed the latest key rotation/);
    app.currentDeviceTrust.status = { approved: false };
    assert.match(reason(), /doesn't have the key for Research yet\. On another of your devices, press Give access/);
    app.workspaceGroupContext.readiness = 'uninitialized';
    assert.match(reason(), /Finish Team setup/);
    app.teamLicenseStatus.organization.role = 'member';
    assert.match(reason(), /Research hasn't been set up yet/);
    app.workspaceGroupContext.readiness = 'deleted';
    assert.match(reason(), /Research was deleted/);
    app.workspaceGroupContext.readiness = 'ready'; app.workspaceContextReady = true;
    app.teamLicenseStatus.revoked = true;
    assert.match(reason(), /license was revoked/);
    app.teamLicenseStatus.revoked = false; app.teamLicenseStatus.can_write = false;
    assert.match(reason(), /couldn't be confirmed/);
    app.teamLicenseStatus.can_write = true; app.workspaceGroupContext.role = 'reader';
    assert.match(reason(), /Your role in Research is reader/);
    app.workspaceGroupContext.organization_id = 'another-org';
    assert.match(reason(), /No Team group is selected/);
    app.teamLicenseStatus = { workspace: 'personal' };
    assert.match(reason(), /Team access isn't available/);
});

test('blocked Team enrollment shows the specific reason instead of a generic warning', async () => {
    const { app } = environment();
    const notices = [];
    app.showNotification = (message, level) => notices.push([message, level]);
    app.workspaceGroupContext.readiness = 'waiting_for_device_approval'; app.workspaceContextReady = false;
    await app.addEnrolledFolder();
    assert.equal(notices.length, 1);
    assert.match(notices[0][0], /current key for init-group/);
    assert.equal(notices[0][1], 'warning');
    assert.equal(app.enrollmentStarted, undefined);
});

test('a server refusal from an unverified device explains verification and rechecks trust', async () => {
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        return { success: true, data: { approved: true, fingerprint_verified: false, can_revoke_other_devices: false } };
    });
    assert.match(app.teamErrorText(new Error('Add member failed: 428 Precondition Required')), /needs a verified device/);
    assert.equal(app.teamErrorText(new Error('Upload of file 14281 failed')), 'Upload of file 14281 failed');
    await nextTurn();
    assert.deepEqual(calls, ['get_device_trust_status']);
    assert.equal(app.workspaceUiModel().canAdminister, false);
});

test('an operation sent to the background shows its step and percent in Activity and notifies when it finishes', async () => {
    let resolvePoll;
    const polls = [];
    const notes = [];
    const { app, node, window } = environment(async command => {
        if (command === 'start_desktop_operation') return { id: 'rotate', status: 'running', phase: 'Creating the new key', output: [] };
        if (command === 'get_desktop_operation') return new Promise(resolve => { resolvePoll = resolve; polls.push(resolve); });
        throw new Error(command);
    });
    window.HybridCipherUiUtils = { describeTeamTaskResult: () => ['Group keys rotated.', 'Moved 159 files on this computer to the new key.'] };
    app.showNotification = (message, tone) => notes.push([tone, message]);
    const tick = () => new Promise(resolve => setImmediate(resolve));
    const nextPoll = async () => { const count = polls.length; while (polls.length === count) await tick(); };

    const pending = app.runDesktopOperation({ kind: 'rotate_keys', group_id: 'team-group', title: 'Rotate group keys' });
    await nextPoll();
    // Running: the window offers to continue in the background.
    assert.equal(node('desktopOperationModal').style.display, 'flex');
    assert.equal(node('desktopOperationCloseBtn').textContent, 'Continue in background');
    app.closeDesktopOperation();
    assert.equal(node('desktopOperationModal').style.display, 'none');

    resolvePoll({ id: 'rotate', status: 'running', phase: 'Moving files', progress: 40, output: [] });
    await nextPoll();
    assert.equal(node('desktopOperationsBtn-label').textContent, 'Moving files 40%');

    resolvePoll({ id: 'rotate', status: 'succeeded', phase: 'Complete', output: [], result: { action: 'keys_rotated' } });
    await pending;
    assert.deepEqual(notes, [['success', 'Rotate group keys finished · Moved 159 files on this computer to the new key.']]);
    assert.equal(node('desktopOperationsBtn-label').textContent, 'Activity');
    assert.equal(node('desktopOperationCloseBtn').textContent, 'Close');

    // Watched to the end, it does not notify.
    notes.length = 0;
    polls.length = 0;
    app.clearFinishedDesktopOperation();
    const watched = app.runDesktopOperation({ kind: 'rotate_keys', group_id: 'team-group', title: 'Rotate group keys' });
    await nextPoll();
    resolvePoll({ id: 'rotate', status: 'succeeded', phase: 'Complete', output: [], result: {} });
    await watched;
    assert.deepEqual(notes, []);
});
