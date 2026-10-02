// Tests Team workspace isolation, role gates, operation dialogs, and group initialization retries.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');
const moduleSource = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function environment(invoke = async () => {}) {
    const nodes = new Map();
    function node(id) {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, { id, value: '', innerHTML: '', textContent: '', style: {}, attributes: {}, children: [],
                classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains(key) { return classes.has(key); } },
                setAttribute(key, value) { this.attributes[key] = value; }, removeAttribute(key) { delete this.attributes[key]; },
                toggleAttribute(key, force) { if (force) this.attributes[key] = ''; else delete this.attributes[key]; },
                querySelector() { return node(`${id}-label`); }, querySelectorAll() { return []; },
                appendChild(child) { this.children.push(child); }, addEventListener() {}, focus() {},
            });
        }
        return nodes.get(id);
    }
    const values = new Map();
    const window = { document: { getElementById: node, querySelectorAll() { return []; }, createElement: tag => node(`new-${tag}-${nodes.size}`) },
        localStorage: { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value) },
        setTimeout: callback => setImmediate(callback), invoke };
    vm.runInNewContext(source, { window });
    const original = { setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {},
        async loadEnrolledFolders() {}, refreshAdminDashboard() {}, async refreshAdminGroupStatus() {},
        async refreshTeamDirectory() {}, async logout() { this.isLoggedIn = false; return true; }, showWelcomeScreen() {},
        openCreateGroupModal() {}, addEnrolledFolder() {},
        async showDevicesView() { this.devicesOpened = true; },
        async refreshPersonalDevicesOverview() { this.devicesRead = true; },
        async refreshWorkspaceHomeStatus() { this.homeRead = true; },
        showCoverageView() { this.coverageOpened = true; },
        async refreshCoverageCenter() { this.coverageRead = true; },
        showFileBrowserView() { this.filesOpened = true; }, };
    const app = Object.assign({ currentUser: 'owner@example.com', isLoggedIn: true, activeWorkspaceType: 'team', appMode: 'team',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'team-group', name: 'init-group', organization_id: 'org-1', role: 'owner', readiness: 'ready' },
        workspaceContextReady: true, showNotification() {}, clearFolderSelectionForGroupSwitch() {}, updateSidebarViewButtons() {},
        closeCommandPalette() {}, renderFolderList() {}, closeSettingsModal() {}, renderTeamLicenseSettings() {},
        workspacePreferenceKey() { return `workspace_${this.currentUser}`; }, parseGeneratedCliArgs(command) { return command.split(' ').slice(1); },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node, values, window, model: window.HybridCipherTeamMethods.workspaceModel };
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
    app.showCoverageView(); app.showFileBrowserView();
    assert.ok(!app.devicesOpened && !app.devicesRead && !app.homeRead && !app.coverageRead && !app.coverageOpened && !app.filesOpened);
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

test('administration and Home are mutually exclusive and headings show organization', () => {
    const { app, node } = environment();
    app.toggleAdminPanel();
    assert.equal(node('adminDashboard').style.display, 'flex');
    assert.equal(node('workspaceHome').style.display, 'none');
    assert.equal(node('folderDetailView').style.display, 'none');
    assert.equal(node('terminalContainer').style.display, 'none');
    assert.equal(node('teamAdministrationTitle').textContent, 'Research · Team administration');
    app.setWorkspaceView('home');
    assert.equal(node('adminDashboard').style.display, 'none');
    assert.equal(node('workspaceHomeTitle').textContent, 'Research · Team Workspace');
    assert.equal(node('adminPanelBtn-label').textContent, 'Team administration');
});

test('normal actions pass explicit argv and group context without starting terminal', async () => {
    const calls = [];
    const { app } = environment(async (name, args) => {
        calls.push([name, args]);
        if (name === 'start_desktop_operation') return { id: 'op-1', status: 'succeeded', phase: 'Complete', output: [], result: {} };
        throw new Error(`Unexpected IPC ${name}`);
    });
    app.showTerminalView = app.createTerminalTab = () => { throw new Error('Terminal opened'); };
    assert.equal(await app.runDashboardCliCommand('hybridcipher rekey cutover'), true);
    assert.equal(calls.length, 1);
    assert.deepEqual(Array.from(calls[0][1].request.args), ['rekey', 'cutover']);
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
    const pending = app.runDashboardCliCommand('hybridcipher rekey cutover', { confirmTitle: 'Confirm' });
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
