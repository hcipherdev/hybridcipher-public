// Tests the People panel (only this group's people, including per-person device summaries), Add person suggestions, Add person, Remove access, invitation discovery and task result sentences (describeTeamTaskResult, including the files a rotation moved), and the People note, which leaves out devices their owner can set up, in src/app-team-methods.js and src/ui-utils.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const uiUtils = require('../../src/ui-utils.js');
const { buildPeopleRows, describeMemberDevices, describeTeamTaskResult } = uiUtils;
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
                querySelector() { return node(`${id}-label`); }, querySelectorAll() { return []; },
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
        async refreshCoverageCenter() {} };
    const app = Object.assign({ currentUser: 'owner@example.com', currentDeviceId: 'device-1', isLoggedIn: true, activeWorkspaceType: 'team',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'team-group', name: 'Research', organization_id: 'org-1', role: 'owner', readiness: 'ready' },
        workspaceContextReady: true, showNotification() {}, updateSidebarViewButtons() {}, renderTeamLicenseSettings() {},
        async refreshPendingTeamRequests() {}, escapeHtml: value => String(value), escapeHtmlAttr: value => String(value),
        currentDeviceTrust: { account: 'owner@example.com', device: 'device-1', status: { approved: true, can_revoke_other_devices: true } },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node };
}

const directory = {
    online: true,
    // The server lists the groups an admin chose for each member or invitation (pending_groups).
    members: [{ user_id: 'u-owner', email: 'Owner@example.com', role: 'owner' },
        { user_id: 'u-bo', email: 'bo@example.com', role: 'member', pending_groups: [{ id: 'other-group', name: 'Other' }] },
        { user_id: 'u-cy', email: 'cy@example.com', role: 'member', pending_groups: [{ id: 'team-group', name: 'Team' }] }],
    invitations: [{ id: 'inv-dee', email: 'dee@example.com', status: 'pending', expires_at: '2999-01-01T00:00:00Z',
        pending_groups: [{ id: 'team-group', name: 'Team' }] },
        { id: 'inv-old', email: 'old@example.com', status: 'pending', expires_at: '2000-01-01T00:00:00Z',
            pending_groups: [{ id: 'team-group', name: 'Team' }] }],
};
const groupMembers = [{ user_id: 'u-owner', email: 'owner@example.com', is_owner: true }, { user_id: 'u-bo', email: 'bo@example.com' }];

test('People rows show access, people waiting for access, and open invitations', () => {
    const rows = buildPeopleRows({ directory, groupMembers, groupId: 'team-group', currentUserEmail: 'OWNER@example.com' });
    assert.deepEqual(rows.map(row => [row.email, row.status, row.action]), [
        ['cy@example.com', 'ready_to_add', 'add'],
        ['bo@example.com', 'has_access', 'remove'],
        ['owner@example.com', 'has_access', null],
        ['dee@example.com', 'invited', 'cancel_invite'],
    ]);
    assert.match(rows[0].label, /finish giving access/);
    assert.match(rows[3].label, /after joining/);
});

test('People rows leave out organization members and invitations that do not involve this group', () => {
    const wider = {
        ...directory,
        members: [...directory.members, { user_id: 'u-eve', email: 'eve@example.com', role: 'member' }],
        invitations: [...directory.invitations, { id: 'inv-fay', email: 'fay@example.com', status: 'pending', expires_at: '2999-01-01T00:00:00Z' }],
    };
    const rows = buildPeopleRows({ directory: wider, groupMembers, groupId: 'team-group', currentUserEmail: 'owner@example.com' });
    assert.deepEqual(rows.map(row => row.email), ['cy@example.com', 'bo@example.com', 'owner@example.com', 'dee@example.com']);
    assert.ok(rows.every(row => !/no access to this group/.test(row.label)));
    // bo was promised to another group, so here bo is only listed as a member of this one.
    assert.equal(rows.find(row => row.email === 'bo@example.com').status, 'has_access');
});

test('Add person suggests organization members who are not in this group yet', async () => {
    const calls = [];
    const { app, node } = environment(recordingInvoke(calls));
    await app.loadPeopleRows();
    const suggested = [];
    node('groupMemberSuggestions').appendChild = option => suggested.push(option.value);
    await app.openAddGroupMemberDialog();
    assert.deepEqual(suggested, ['cy@example.com']);
});

test('task results read as plain sentences', () => {
    assert.deepEqual(describeTeamTaskResult({ action: 'member_added', email: 'bo@example.com', devices_added: 2,
        unverified_devices: [{ device_id: 'd' }] }), ['bo@example.com now has access to this group.',
        '2 devices received the group key.', '1 device not verified yet. Compare fingerprints in Devices.']);
    assert.match(describeTeamTaskResult({ action: 'person_invited', email: 'dee@example.com' })[0], /Invitation sent/);
    assert.match(describeTeamTaskResult({ action: 'person_invited', email: 'dee@example.com', access: 'on_accept' })[1],
        /as soon as they accept/);
    assert.match(describeTeamTaskResult({ action: 'person_invited', email: 'dee@example.com', access: 'after_signup' })[1],
        /after they sign up and accept/);
    assert.match(describeTeamTaskResult({ action: 'already_invited', email: 'dee@example.com', access: 'on_accept' }).join(' '),
        /This group was added to it\. They get access to this group as soon as they accept/);
    assert.match(describeTeamTaskResult({ action: 'access_removed', member: 'bo', keys_rotated: false })[1], /not rotated/);
    assert.deepEqual(describeTeamTaskResult({ action: 'unknown' }), []);
    assert.deepEqual(describeTeamTaskResult(null), []);
});

test('a rotation result says what happened to this computer\'s files', () => {
    const rotated = files => describeTeamTaskResult({ action: 'keys_rotated', rotation: { files } });
    assert.deepEqual(rotated({ moved: 159, failed: 0, failures: [] }).slice(1), ['Moved 159 files on this computer to the new key.']);
    assert.deepEqual(rotated({ moved: 1, failed: 2, failures: [{ path: 'C:\\Docs\\a.pdf', reason: 'open in another app' },
        { path: '/Users/x/b.txt', reason: 'no key' }] }).slice(1),
        ['Moved 1 file on this computer to the new key.', '2 files could not be moved; HybridCipher tries again within the hour.',
            'a.pdf: open in another app', 'b.txt: no key']);
    assert.match(rotated({ error: 'offline' })[1], /were not moved yet \(offline\)/);
    assert.match(rotated({ moved: 0, failed: 0, rotation_running: true })[1], /once the server finishes/);
    // Nothing to move adds no line; removing someone reports the files too.
    assert.equal(rotated({ moved: 0, failed: 0, failures: [] }).length, 1);
    assert.match(describeTeamTaskResult({ action: 'access_removed', member: 'bo', keys_rotated: true,
        rotation: { files: { moved: 3, failed: 0 } } }).at(-1), /^Moved 3 files/);
});

function recordingInvoke(calls, results = {}) {
    return async (name, args) => {
        calls.push([name, args]);
        if (name === 'start_desktop_operation') return { id: 'op', status: 'succeeded', phase: 'Completed', output: [], result: results[args.request.kind] || {} };
        if (name === 'get_team_directory') return directory;
        if (name === 'get_group_members') return { success: true, data: groupMembers };
        throw new Error(`Unexpected IPC ${name}`);
    };
}

test('Add person sends one task with the typed email and selected group', async () => {
    const calls = [];
    const { app, node } = environment(recordingInvoke(calls, { add_person: { action: 'person_invited', email: 'dee@example.com' } }));
    app.setupEventListeners();
    await app.openAddGroupMemberDialog();
    node('groupMemberEmail').value = '  Dee@Example.com ';
    await node('addGroupMemberForm').listeners.get('submit')({ preventDefault() {} });
    const start = calls.find(([name]) => name === 'start_desktop_operation');
    assert.equal(start[1].request.kind, 'add_person');
    assert.equal(start[1].request.email, 'dee@example.com');
    assert.equal(start[1].request.group_id, 'team-group');
    assert.equal(node('addGroupMemberModal').style.display, 'none');
    assert.match(node('adminPeopleList').innerHTML, /Give access/);
    assert.match(node('adminPeopleAttention').textContent, /1 person has joined/);
});

test('Remove access always rotates keys and nothing runs when cancelled', async () => {
    const calls = [];
    const { app } = environment(recordingInvoke(calls));
    app.showActionPrompt = async () => false;
    assert.equal(await app.confirmMemberRemoval({ user_id: 'u-bo', email: 'bo@example.com' }), false);
    assert.equal(calls.length, 0);
    app.showActionPrompt = async () => true;
    await app.confirmMemberRemoval({ user_id: 'u-bo', email: 'bo@example.com' });
    const request = calls.find(([name]) => name === 'start_desktop_operation')[1].request;
    assert.equal(request.kind, 'remove_access');
    assert.equal(request.member, 'u-bo');
    assert.equal(request.rotate_keys, true);
});

test('members can join from an invitation addressed to them, or dismiss it', async () => {
    const calls = [];
    const { app, node } = environment(async (name, args) => {
        calls.push([name, args]);
        if (name === 'list_my_team_invitations') return [{ id: 'inv-1', organization_name: 'Research', invited_by: 'owner@example.com' }];
        if (name === 'accept_my_team_invitation') return null;
        if (name === 'get_team_license_status') return { workspace: 'team', online: true, can_write: true };
        throw new Error(`Unexpected IPC ${name}`);
    });
    app.activeWorkspaceType = 'personal';
    app.teamLicenseStatus = { workspace: 'personal', online: true };
    app.currentUser = 'member@example.com';
    const finished = [];
    app.finishTeamActivation = async status => finished.push(status.workspace);
    await app.refreshTeamInvitations();
    assert.equal(node('teamInvitationNotice').classList.contains('hidden'), false);
    assert.match(node('teamInvitationMessage').textContent, /owner@example.com invited you to join Research/);
    await app.joinInvitedTeam();
    const accept = calls.find(([name]) => name === 'accept_my_team_invitation')[1];
    assert.deepEqual([accept.invitationId, accept.expectedAccountEmail], ['inv-1', 'member@example.com']);
    assert.deepEqual(finished, ['team']);
    assert.equal(node('teamInvitationNotice').classList.contains('hidden'), true);

    app.setupEventListeners();
    await app.refreshTeamInvitations();
    node('teamInvitationDismissBtn').listeners.get('click')();
    await app.refreshTeamInvitations();
    assert.equal(node('teamInvitationNotice').classList.contains('hidden'), true);
});

test('Team members are never offered invitations meant for accounts without a Team', async () => {
    const calls = [];
    const { app, node } = environment(async name => { calls.push(name); return []; });
    await app.refreshTeamInvitations({ workspace: 'team' });
    assert.deepEqual(calls, []);
    assert.equal(node('teamInvitationNotice').classList.contains('hidden'), true);
});

test('device summaries count devices, flag inactive ones, and show recent activity', () => {
    const now = Date.parse('2026-10-15T12:00:00Z');
    assert.equal(describeMemberDevices([], now), 'No devices yet');
    assert.equal(describeMemberDevices([{ last_seen: '2026-10-15T11:30:00Z' }], now), '1 device · active within the hour');
    assert.equal(describeMemberDevices([{ last_seen: '2026-10-15T09:00:00Z' }, { last_seen: '2026-10-10T09:00:00Z' }], now),
        '2 devices · active 3h ago');
    assert.equal(describeMemberDevices([{ last_seen: '2026-10-15T09:00:00Z' }, { last_seen: '2026-09-14T09:00:00Z', stale: true }], now),
        '2 devices · 1 inactive');
});

test('People rows carry device summaries only for members with access', () => {
    const now = Date.parse('2026-10-15T12:00:00Z');
    const memberDevices = new Map([
        ['owner@example.com', { devices: [{ last_seen: '2026-10-15T11:00:00Z' }, { last_seen: '2026-09-14T00:00:00Z', stale: true }] }],
        ['u-bo', { devices: [{ last_seen: '2026-10-14T12:00:00Z' }] }],
    ]);
    const rows = buildPeopleRows({ directory, groupMembers, groupId: 'team-group',
        currentUserEmail: 'owner@example.com', memberDevices, now });
    const byEmail = Object.fromEntries(rows.map(row => [row.email, row]));
    assert.equal(byEmail['owner@example.com'].devicesLabel, '2 devices · 1 inactive');
    assert.equal(byEmail['owner@example.com'].inactiveDevices, 1);
    assert.equal(byEmail['bo@example.com'].devicesLabel, '1 device · active 24h ago');
    assert.equal(byEmail['cy@example.com'].devicesLabel, undefined);
    assert.equal(byEmail['dee@example.com'].devicesLabel, undefined);
    // Without device details the rows keep their access-only shape.
    assert.equal(buildPeopleRows({ directory, groupMembers, groupId: 'team-group' })[1].devicesLabel, undefined);
});

test('the People panel shows device summaries and highlights inactive devices', async () => {
    const calls = [];
    const base = recordingInvoke(calls);
    const { app, node } = environment(async (name, args) => (name === 'get_group_member_details'
        ? { success: true, data: [{ user_id: 'u-bo', email: 'bo@example.com', devices: [{ device_id: 'd1', last_seen: '2026-09-01T00:00:00Z', stale: true }] }] }
        : base(name, args)));
    await app.refreshPeoplePanel();
    const html = node('adminPeopleList').innerHTML;
    assert.match(html, /people-row-devices has-inactive">1 device · 1 inactive</);
});

test('the People note mentions waiting devices only when they need a group admin', async () => {
    const { app, node } = environment(recordingInvoke([]));
    app.pendingDevicesCache = [{ device_id: 'vm', email: 'xing@example.com', owner_can_self_approve: true }];
    await app.refreshPeoplePanel();
    assert.doesNotMatch(node('adminPeopleAttention').textContent, /waiting for approval/);
    app.pendingDevicesCache.push({ device_id: 'solo', email: 'solo@example.com' });
    await app.refreshPeoplePanel();
    assert.match(node('adminPeopleAttention').textContent, /1 device is waiting for approval in Devices/);
});
