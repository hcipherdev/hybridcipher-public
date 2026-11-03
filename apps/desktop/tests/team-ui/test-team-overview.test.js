// Tests the Team overview and sidebar group helpers in src/ui-utils.js (buildSidebarGroupItems, buildTeamGroupCards,
// describeGroupFacts, buildTeamTodoItems) and, in src/app-team-methods.js, the overview to-do list, its actions,
// the People filter and search, and that a People read finishing after a group switch is discarded.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const uiUtils = require('../../src/ui-utils.js');
const { buildSidebarGroupItems, buildTeamGroupCards, describeGroupFacts, buildTeamTodoItems } = uiUtils;
const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');

function environment(invoke) {
    const nodes = new Map();
    function node(id) {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, { id, value: '', innerHTML: '', textContent: '', style: {}, attributes: {}, dataset: {}, listeners: new Map(),
                classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains: key => classes.has(key) },
                setAttribute(key, value) { this.attributes[key] = value; }, removeAttribute(key) { delete this.attributes[key]; },
                toggleAttribute(key, force) { if (force) this.attributes[key] = ''; else delete this.attributes[key]; },
                querySelector() { return null; }, querySelectorAll() { return []; },
                appendChild() {}, addEventListener(event, callback) { this.listeners.set(event, callback); }, focus() {} });
        }
        return nodes.get(id);
    }
    const window = { document: { getElementById: node, querySelectorAll: () => [], createElement: tag => node(`new-${tag}-${nodes.size}`),
        addEventListener() {} }, localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
        setTimeout: callback => setImmediate(callback), setInterval: () => 0, clearInterval() {}, addEventListener() {},
        invoke, HybridCipherUiUtils: uiUtils };
    vm.runInNewContext(source, { window });
    const original = { setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {}, async loadEnrolledFolders() {},
        refreshAdminDashboard() {}, async refreshAdminGroupStatus() {}, async refreshTeamDirectory() {}, async logout() { return true; },
        showWelcomeScreen() {}, openCreateGroupModal() {}, addEnrolledFolder() {}, async showDevicesView() {},
        async refreshPersonalDevicesOverview() {}, async refreshWorkspaceHomeStatus() {}, showCoverageView() {},
        async refreshCoverageCenter() {}, showWorkspaceHome() { this.setWorkspaceView('home'); } };
    const app = Object.assign({ currentUser: 'owner@example.com', currentDeviceId: 'device-1', isLoggedIn: true, activeWorkspaceType: 'team',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'eng', name: 'Engineering', organization_id: 'org-1', role: 'owner', readiness: 'ready',
            groups: [{ id: 'eng', name: 'Engineering' }, { id: 'fin', name: 'Finance' }] },
        workspaceContextReady: true, activeWorkspaceView: 'home', showNotification() {}, updateSidebarViewButtons() {},
        renderTeamLicenseSettings() {}, async refreshPendingTeamRequests() {},
        escapeHtml: value => String(value), escapeHtmlAttr: value => String(value),
        currentDeviceTrust: { account: 'owner@example.com', device: 'device-1', status: { approved: true, can_revoke_other_devices: true } },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node };
}

const directory = { online: true, members: [{ user_id: 'u-owner', email: 'owner@example.com', role: 'owner' },
    { user_id: 'u-bo', email: 'bo@example.com', role: 'member' },
    { user_id: 'u-cy', email: 'cy@example.com', role: 'member', pending_groups: [{ id: 'eng', name: 'Engineering' }] }], invitations: [] };
const peopleInvoke = (calls = []) => async (name, args) => {
    calls.push([name, args]);
    if (name === 'get_team_directory') return directory;
    if (name === 'get_group_members') return { success: true, data: [{ user_id: 'u-owner', email: 'owner@example.com', is_owner: true },
        { user_id: 'u-bo', email: 'bo@example.com' }] };
    if (name === 'get_group_member_details') return { success: true, data: [{ user_id: 'u-bo', email: 'bo@example.com',
        devices: [{ device_id: 'old', last_seen: '2026-01-01T00:00:00Z', stale: true }] }] };
    if (name === 'get_group_summaries') return { success: true, data: [{ id: 'eng', member_count: 2, current_key_version: 3 }] };
    if (name === 'start_desktop_operation') return { id: 'op', status: 'succeeded', result: {} };
    throw new Error(`Unexpected IPC ${name}`);
};

test('sidebar groups are sorted by name, filtered by the typed text, and only the selected one carries the count', () => {
    const groups = [{ id: 'l', name: 'legal' }, { id: 'e', name: 'Engineering' }, { id: 'f', name: 'Finance' }, { name: 'no id' }];
    const items = buildSidebarGroupItems({ groups, activeGroupId: 'e', attentionCount: 2 });
    assert.deepEqual(items.map(item => [item.name, item.selected, item.badge]),
        [['Engineering', true, '2'], ['Finance', false, ''], ['legal', false, '']]);
    assert.equal(items[0].initial, 'E');
    assert.equal(buildSidebarGroupItems({ groups, activeGroupId: 'e' })[0].tone, items[0].tone, 'a group keeps its tone');
    assert.deepEqual(buildSidebarGroupItems({ groups, query: ' FIN ' }).map(item => item.name), ['Finance']);
});

test('group cards add people, and for admins the key version, when the server summary has them', () => {
    const cards = buildTeamGroupCards({ groups: [{ id: 'e', name: 'Engineering' }, { id: 'f', name: 'Finance' }],
        summaries: [{ id: 'e', member_count: 1, current_key_version: 3 }, { id: 'f', member_count: 12, current_key_version: null }],
        activeGroupId: 'e', attentionCount: 2 });
    assert.deepEqual(cards.map(card => [card.name, card.facts, card.status]),
        [['Engineering', '1 person · Key version 3', '2 to do'], ['Finance', '12 people', '']]);
    assert.equal(buildTeamGroupCards({ groups: [{ id: 'e', name: 'Engineering' }], activeGroupId: 'e' })[0].status, 'Selected');
    assert.equal(buildTeamGroupCards({ groups: [{ id: 'e', name: 'Engineering' }], showKeyVersion: false,
        summaries: [{ id: 'e', member_count: 4, current_key_version: 3 }] })[0].facts, '4 people', 'members are not shown key versions');
});

test('the group page summary names people, folders, key version and the viewer role', () => {
    assert.equal(describeGroupFacts({ summary: { member_count: 12, current_key_version: 3 }, folderCount: 1, role: 'admin' }),
        '12 people · 1 protected folder · Key version 3 · You are an admin');
    assert.equal(describeGroupFacts({ role: 'owner' }), 'You are the owner');
    assert.equal(describeGroupFacts({ folderCount: 0, role: 'member' }), '0 protected folders · You are a member');
});

test('to-do items put people waiting for access first and fold inactive devices into one entry', () => {
    const items = buildTeamTodoItems({ groupName: 'Engineering',
        people: [{ status: 'ready_to_add', email: 'cy@example.com' }, { status: 'has_access', email: 'bo@example.com' }],
        pendingDevices: [{ device_id: 'mac-1', email: 'sam@example.com', device_name: 'MacBook Pro', missing_current_key: true }],
        unverifiedDevices: [{ device_id: 'device_97209c00', email: 'riley@example.com' }],
        staleDevices: [{ device_id: 'a' }, { device_id: 'b' }] });
    assert.deepEqual(items.map(item => [item.action, item.title]), [
        ['give_access', 'Give cy@example.com access'],
        ['approve_device', "Give sam@example.com's MacBook Pro access"],
        ['verify_device', "Verify riley@example.com's device device_9"],
        ['review_stale', '2 inactive devices'],
    ]);
    assert.equal(items[1].detail, 'Engineering · missed the latest key rotation');
    assert.deepEqual(buildTeamTodoItems(), []);
});

test('the Team overview lists what waits on an admin and counts it in the sidebar', async () => {
    const { app, node } = environment(peopleInvoke());
    app.pendingDevicesCache = [{ device_id: 'mac-1', email: 'bo@example.com', device_name: 'MacBook Pro' }];
    app.unverifiedDevicesCache = []; app.staleDevicesCache = []; app.enrolledFolders = [];
    await app.refreshTeamOverview();
    const todo = node('teamTodoList').innerHTML;
    assert.match(todo, /Give cy@example.com access[\s\S]*data-todo-action="give_access"/);
    assert.match(todo, /Give bo@example.com's MacBook Pro access[\s\S]*data-todo-action="approve_device" data-device-id="mac-1"/);
    assert.equal(node('teamTodoCount').textContent, '2');
    assert.equal(node('sidebarOverviewBadge').textContent, '2');
    assert.match(node('sidebarGroupList').innerHTML, /data-group-id="eng" aria-current="true">[\s\S]*Engineering[\s\S]*>2</);
    assert.match(node('teamGroupCards').innerHTML, /Engineering<\/span><span class="team-group-card-facts">2 people · Key version 3/);
    assert.equal(node('adminGroupMeta').textContent, '2 people · 0 protected folders · Key version 3 · You are the owner');

    const member = environment(peopleInvoke());
    member.app.workspaceGroupContext.role = 'member';
    member.app.teamLicenseStatus.organization.role = 'member';
    member.app.pendingDevicesCache = app.pendingDevicesCache;
    await member.app.refreshTeamOverview();
    assert.ok(member.node('teamTodoPanel').classList.contains('hidden'), 'members have no to-do list');
    assert.equal(member.node('sidebarOverviewBadge').textContent, '');
    assert.equal(member.node('teamGroupsTitle').textContent, 'Your groups');
});

test('to-do actions give access, approve and verify in the selected group, or open the Devices tab', async () => {
    const calls = [];
    const { app } = environment(peopleInvoke(calls));
    const done = [];
    app.issueWelcomeForDevice = async deviceId => done.push(['approve', deviceId]);
    app.unverifiedDevicesCache = [{ device_id: 'xps', email: 'riley@example.com' }];
    app.verifyUnverifiedDevice = device => done.push(['verify', device.email]);
    app.showStaleDevicesQueue = () => done.push(['stale-queue']);
    app.selectAdminTab = name => done.push(['tab', name]);
    const button = dataset => ({ dataset, disabled: false });
    await app.handleTeamTodoAction(button({ todoAction: 'give_access', email: 'cy@example.com' }));
    const request = calls.find(([name]) => name === 'start_desktop_operation')[1].request;
    assert.deepEqual([request.kind, request.email, request.group_id], ['add_member', 'cy@example.com', 'eng']);
    await app.handleTeamTodoAction(button({ todoAction: 'approve_device', deviceId: 'mac-1' }));
    await app.handleTeamTodoAction(button({ todoAction: 'verify_device', deviceId: 'xps' }));
    await app.handleTeamTodoAction(button({ todoAction: 'review_stale' }));
    assert.deepEqual(done, [['approve', 'mac-1'], ['verify', 'riley@example.com'], ['stale-queue'], ['tab', 'devices']]);
    assert.equal(app.activeWorkspaceView, 'admin');
});

test('Needs action and search narrow the People list without reading it again', async () => {
    const calls = [];
    const { app, node } = environment(peopleInvoke(calls));
    await app.refreshPeoplePanel();
    const reads = calls.length;
    assert.match(node('adminPeopleList').innerHTML, /cy@example.com[\s\S]*bo@example.com[\s\S]*owner@example.com/);
    assert.equal(node('adminTabPeopleBadge').textContent, '1');
    app.peopleFilter = 'attention';
    app.renderPeopleList();
    const attention = node('adminPeopleList').innerHTML;
    assert.match(attention, /cy@example.com/);
    assert.match(attention, /bo@example.com/, 'a member with an inactive device needs action');
    assert.doesNotMatch(attention, /owner@example.com/);
    node('adminPeopleSearch').value = 'CY';
    app.renderPeopleList();
    assert.doesNotMatch(node('adminPeopleList').innerHTML, /bo@example.com/);
    node('adminPeopleSearch').value = 'nobody';
    app.renderPeopleList();
    assert.match(node('adminPeopleList').innerHTML, /No one here matches/);
    assert.equal(calls.length, reads);
});

test('a People read that finishes after a group switch is discarded', async () => {
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const { app, node } = environment(async (name, args) => { await gate; return peopleInvoke()(name, args); });
    node('adminPeopleList').innerHTML = 'Finance people';
    const pending = app.loadPeopleRows();
    app.workspaceGroupContext = { ...app.workspaceGroupContext, group_id: 'fin', name: 'Finance' };
    release();
    assert.equal(await pending, null);
    assert.equal(app.peopleRowsCache, undefined);
    app.renderPeopleList();
    assert.equal(node('adminPeopleList').innerHTML, 'Finance people');
});
