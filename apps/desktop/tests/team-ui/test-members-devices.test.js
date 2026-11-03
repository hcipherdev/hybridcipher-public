// Tests the organization Members & devices page: buildMemberDeviceRows() in src/ui-utils.js (including devices their owner sets up, which ask no attention) and showMembersView(), renderMembersCenter(), openGroupApprovals(), revokeMemberDevice(), finishMemberGroupAccess(), autoFinishGroupAccess(), stageInvitationAccess(), removeTeamMember() and the Invite to Team dialog in src/app-team-methods.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const uiUtils = require('../../src/ui-utils.js');
const { buildMemberDeviceRows } = uiUtils;
const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');

const now = Date.parse('2026-10-26T12:00:00Z');
const roster = {
    organization_id: 'org-1', generated_at: '2026-10-26T12:00:00Z', stale_threshold_days: 30,
    members: [
        { user_id: 'u-owner', email: 'owner@example.com', role: 'owner', groups: [{ id: 'g-research', name: 'Research' }],
            devices: [{ device_id: 'device-1', device_name: 'Owner Mac', status: 'trusted', approved: true, fingerprint_verified: true,
                last_seen: '2026-10-26T11:30:00Z' }] },
        { user_id: 'u-mia', email: 'mia@example.com', role: 'member', groups: [{ id: 'g-research', name: 'Research' }],
            devices: [
                { device_id: 'mia-laptop', device_name: 'Mia laptop', status: 'missing_key', approved: true, fingerprint_verified: true,
                    last_seen: '2026-10-25T12:00:00Z', missing_key_groups: [{ id: 'g-research', name: 'Research' }] },
                { device_id: 'mia-phone', device_name: 'Mia phone', status: 'stale', approved: true, fingerprint_verified: true,
                    last_seen: '2026-08-01T12:00:00Z', stale_reasons: ['Last seen 86 day(s) ago'] },
            ] },
        { user_id: 'u-ana', email: 'ana@example.com', role: 'admin', groups: [],
            devices: [{ device_id: 'ana-pc', device_name: 'Ana PC', status: 'unverified', approved: true, fingerprint_verified: false,
                last_seen: '2026-10-26T09:00:00Z' }] },
        { user_id: 'u-boss', email: 'boss@example.com', role: 'owner', groups: [], devices: [] },
    ],
};

test('roster rows put members needing attention first and count each status', () => {
    const { rows, counts } = buildMemberDeviceRows({ roster, currentUserId: 'u-owner', currentDeviceId: 'device-1', actorRole: 'admin', now });
    // A member without devices has nothing to fix, so they sort after trusted members.
    assert.deepEqual(rows.map(row => row.email), ['ana@example.com', 'mia@example.com', 'owner@example.com', 'boss@example.com']);
    assert.deepEqual(counts, { members: 4, devices: 4, attention: 2, needs_access: 0, invited: 0, pending: 0, unverified: 1, missing_key: 1, stale: 1 });
    const mia = rows.find(row => row.userId === 'u-mia');
    assert.deepEqual(mia.devices.map(device => [device.id, device.label]), [['mia-laptop', 'Missed key update'], ['mia-phone', 'Stale']]);
    assert.match(mia.devices[0].reasons.join(), /Missed the current key for Research/);
    assert.equal(mia.devices[0].activity, 'active 24h ago');
    assert.equal(mia.summary, '2 devices · 2 need attention');
    assert.match(rows.find(row => row.userId === 'u-ana').devices[0].reasons.join(), /Fingerprint not checked/);
});

test('a device its owner can set up keeps Needs approval but asks no attention from the admin', () => {
    const member = (email, devices) => ({ user_id: `u-${email}`, email, role: 'member', groups: [{ id: 'g-eng', name: 'Engineering' }], devices });
    const laptop = { device_id: 'laptop', device_name: 'Laptop', status: 'trusted', approved: true, fingerprint_verified: true, last_seen: '2026-10-26T11:00:00Z' };
    const vm = { device_id: 'vm', device_name: 'Virtual Machine', status: 'pending', approved: false, fingerprint_verified: false, last_seen: '2026-10-26T09:00:00Z' };
    const { rows, counts } = buildMemberDeviceRows({ now, roster: { members: [
        member('xing@example.com', [laptop, { ...vm, owner_can_self_approve: true }]),
        member('solo@example.com', [{ ...vm, device_id: 'solo-vm' }]),
    ] } });
    const xing = rows.find(row => row.email === 'xing@example.com');
    const device = xing.devices.find(entry => entry.id === 'vm');
    assert.equal(device.label, 'Needs approval');
    assert.ok(device.ownerCanSetUp);
    assert.deepEqual([...device.reasons], ['They can give it access from another of their devices']);
    assert.equal(xing.attention, false);
    assert.equal(xing.summary, '2 devices');
    // Without another trusted device, a group admin is needed, and that does need attention.
    const solo = rows.find(row => row.email === 'solo@example.com');
    assert.equal(solo.attention, true);
    assert.deepEqual([...solo.devices[0].reasons], ['No other trusted device: a group admin needs to give it access']);
    // The Pending filter still finds both; only the solo member needs attention (the sidebar badge).
    assert.equal(counts.pending, 2);
    assert.equal(counts.attention, 1);
});

test('admins revoke members but never owners or their own devices', () => {
    const asAdmin = buildMemberDeviceRows({ roster, currentUserId: 'u-ana', currentDeviceId: 'ana-pc', actorRole: 'admin', now }).rows;
    assert.equal(asAdmin.find(row => row.userId === 'u-mia').canRevoke, true);
    assert.equal(asAdmin.find(row => row.userId === 'u-owner').canRevoke, false);
    assert.equal(asAdmin.find(row => row.userId === 'u-ana').devices[0].canRevoke, false, 'own devices go through Devices');
    const asOwner = buildMemberDeviceRows({ roster, currentUserId: 'u-owner', actorRole: 'owner', now }).rows;
    assert.equal(asOwner.find(row => row.userId === 'u-boss').canRevoke, true, 'an owner may revoke another owner');
});

test('filters and search narrow rows while counts stay for the whole roster', () => {
    const missing = buildMemberDeviceRows({ roster, filter: 'missing_key', now });
    assert.deepEqual(missing.rows.map(row => row.email), ['mia@example.com']);
    assert.equal(missing.counts.members, 4);
    assert.deepEqual(buildMemberDeviceRows({ roster, filter: 'attention', now }).rows.map(row => row.email), ['ana@example.com', 'mia@example.com']);
    assert.deepEqual(buildMemberDeviceRows({ roster, query: 'phone', now }).rows.map(row => row.email), ['mia@example.com']);
    assert.equal(buildMemberDeviceRows({ roster, filter: 'bogus', now }).filter, 'all');
    const unknown = buildMemberDeviceRows({ roster: { members: [{ user_id: 'x', email: 'x@example.com', role: 'member',
        devices: [{ device_id: 'd', status: 'quarantined' }] }] }, now });
    assert.equal(unknown.rows[0].devices[0].status, 'unverified', 'an unknown status never reads as trusted');
});

test('members waiting for group access need attention, and open invitations follow the members', () => {
    const withGrants = { members: [roster.members[0], { ...roster.members[1], pending_groups: [{ id: 'g-ops', name: 'Ops' }] },
        { user_id: 'u-new', email: 'new@example.com', role: 'member', groups: [], devices: [], pending_groups: [{ id: 'g-ops', name: 'Ops' }] }] };
    const invitations = [
        { id: 'inv-zed', email: 'zed@example.com', status: 'pending', expires_at: '2026-11-01T00:00:00Z', pending_groups: [{ id: 'g-research', name: 'Research' }] },
        { id: 'inv-amy', email: 'amy@example.com', status: 'pending', expires_at: '2026-11-01T00:00:00Z',
            pending_groups: [{ id: 'g-ops', name: 'Ops', staged: true }, { id: 'g-legal', name: 'Legal' }] },
        { id: 'inv-old', email: 'old@example.com', status: 'pending', expires_at: '2026-10-01T00:00:00Z' },
        { id: 'inv-done', email: 'done@example.com', status: 'accepted', expires_at: '2026-11-01T00:00:00Z' },
    ];
    const all = buildMemberDeviceRows({ roster: withGrants, invitations, now });
    assert.deepEqual(all.rows.map(row => [row.kind, row.email]), [['member', 'mia@example.com'], ['member', 'new@example.com'],
        ['member', 'owner@example.com'], ['invitation', 'amy@example.com'], ['invitation', 'zed@example.com']]);
    assert.equal(all.counts.needs_access, 2);
    assert.equal(all.counts.attention, 2);
    assert.equal(all.counts.invited, 2);
    assert.deepEqual(all.rows[1].pendingGroups.map(group => group.name), ['Ops']);
    assert.equal(all.rows[3].summary, 'Invited · gets Ops when they accept · gets Legal after joining');
    assert.equal(all.rows[4].summary, 'Invited · gets Research after joining');
    assert.deepEqual(buildMemberDeviceRows({ roster: withGrants, invitations, filter: 'invited', now }).rows.map(row => row.email),
        ['amy@example.com', 'zed@example.com']);
    assert.deepEqual(buildMemberDeviceRows({ roster: withGrants, invitations, filter: 'needs_access', now }).rows.map(row => row.email),
        ['mia@example.com', 'new@example.com']);
    assert.deepEqual(buildMemberDeviceRows({ roster: withGrants, invitations, filter: 'stale', now }).rows.map(row => row.email), ['mia@example.com']);
});

function environment(invoke) {
    const nodes = new Map();
    function node(id) {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, { id, value: '', innerHTML: '', textContent: '', style: {}, attributes: {}, dataset: {}, listeners: new Map(), childElementCount: 0,
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
        async refreshCoverageCenter() {}, showWorkspaceHome() { this.setWorkspaceView('home'); } };
    const notifications = [];
    const app = Object.assign({ currentUser: 'owner@example.com', currentDeviceId: 'device-1', isLoggedIn: true, activeWorkspaceType: 'team',
        appMode: 'team', activeWorkspaceView: 'home',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'g-research', name: 'Research', organization_id: 'org-1', role: 'owner', readiness: 'ready',
            groups: [{ id: 'g-research', name: 'Research' }] },
        workspaceContextReady: true, showNotification: (message, kind) => notifications.push([kind, message]),
        updateSidebarViewButtons() {}, renderTeamLicenseSettings() {}, async refreshPendingTeamRequests() {},
        escapeHtml: value => String(value), escapeHtmlAttr: value => String(value),
        currentDeviceTrust: { account: 'owner@example.com', device: 'device-1', status: { approved: true, can_revoke_other_devices: true } },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node, notifications };
}

test('owners and admins on a verified device see the page; members and unverified devices do not', async () => {
    const calls = [];
    const { app, node } = environment(async command => { calls.push(command); return { success: true, data: roster }; });
    await app.showMembersView();
    assert.equal(app.activeWorkspaceView, 'members');
    assert.equal(node('membersCenterView').style.display, 'flex');
    assert.deepEqual(calls, ['get_team_member_devices', 'get_team_directory']);
    assert.match(node('membersList').innerHTML, /mia@example.com/);
    assert.match(node('membersSummary').textContent, /4 members · 4 devices · 2 need attention/);
    assert.equal(node('sidebarMembersBadge').textContent, '2');

    app.currentDeviceTrust.status = { approved: true, fingerprint_verified: false, can_revoke_other_devices: false };
    app.applyAppMode();
    assert.equal(app.activeWorkspaceView, 'home', 'losing trust leaves the page');
    assert.ok(node('sidebarMembersBtn').classList.contains('hidden'));

    const member = environment(async () => { throw new Error('members never load the roster'); });
    member.app.teamLicenseStatus.organization.role = 'member';
    await member.app.showMembersView();
    assert.notEqual(member.app.activeWorkspaceView, 'members');
});

test('an older server hides the page instead of showing an error', async () => {
    const { app, node } = environment(async () => ({ success: false, error_code: 'TEAM_DEVICES_UNSUPPORTED', error: 'not supported' }));
    await app.showMembersView();
    assert.equal(app.activeWorkspaceView, 'home');
    assert.equal(app.canOpenMembersView(), false);
    assert.ok(node('sidebarMembersBtn').classList.contains('hidden'));
});

test('revoking a device confirms, signs out the device, and offers a rotation for each of its groups', async () => {
    const calls = [];
    let current = roster;
    const { app, notifications } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'admin_revoke_member_device') {
            current = { ...roster, members: roster.members.map(member => member.user_id === 'u-mia'
                ? { ...member, devices: member.devices.filter(device => device.device_id !== 'mia-phone') } : member) };
            return { success: true, data: { removed_device_id: 'mia-phone', revoked_sessions: 1, group_ids: ['g-research'] } };
        }
        return { success: true, data: current };
    });
    const prompts = [];
    app.showActionPrompt = async (title, _message, options) => { prompts.push([title, options.primaryLabel]); return true; };
    const rotations = [];
    app.beginRekeyFlow = async options => rotations.push([app.workspaceGroupContext.group_id, options.title]);
    await app.showMembersView();

    assert.equal(await app.revokeMemberDevice('u-mia', 'mia-phone'), true);
    assert.deepEqual(prompts, [['Revoke Mia phone?', 'Revoke device']]);
    // Arguments come from the vm realm, so compare them as JSON.
    assert.equal(JSON.stringify(calls.filter(([command]) => command === 'admin_revoke_member_device').map(([, args]) => args)),
        JSON.stringify([{ userId: 'u-mia', deviceId: 'mia-phone' }]));
    assert.deepEqual(rotations, [['g-research', 'Rotate keys for Research?']]);
    assert.ok(notifications.some(([kind, message]) => kind === 'success' && /Mia phone was revoked/.test(message)));
    assert.equal(app.activeWorkspaceView, 'members', 'the admin returns to the roster');
    assert.doesNotMatch(app.membersRoster.roster.members[1].devices.map(device => device.device_id).join(), /mia-phone/);
});

test('a declined revoke changes nothing and a refused revoke explains why', async () => {
    const calls = [];
    const { app, notifications } = environment(async command => {
        calls.push(command);
        if (command === 'admin_revoke_member_device') return { success: false, error: 'Only organization owners and admins can revoke another member\'s device.' };
        return { success: true, data: roster };
    });
    await app.showMembersView();
    app.showActionPrompt = async () => false;
    assert.equal(await app.revokeMemberDevice('u-mia', 'mia-phone'), false);
    assert.ok(!calls.includes('admin_revoke_member_device'));

    app.showActionPrompt = async () => true;
    app.beginRekeyFlow = async () => assert.fail('no rotation after a refused revoke');
    assert.equal(await app.revokeMemberDevice('u-mia', 'mia-phone'), false);
    assert.ok(notifications.some(([kind, message]) => kind === 'error' && /owners and admins/.test(message)));
    assert.equal(app.membersRevokeInFlight, null);
});

function withDevices(changes) {
    return { ...roster, members: roster.members.map(member => (changes[member.user_id] ? { ...member, devices: changes[member.user_id] } : member)) };
}
const click = (userId, groupId = '') => ({ target: { closest: () => ({ disabled: false,
    dataset: { membersAction: 'open-group', userId, groupId } }) } });

test('a missed key or waiting device, your own included, opens its group approval list', async () => {
    const data = withDevices({
        'u-owner': [
            { device_id: 'device-1', device_name: 'Owner Mac', status: 'trusted', approved: true, fingerprint_verified: true, last_seen: '2026-10-26T11:30:00Z' },
            { device_id: 'owner-pc', device_name: 'Owner PC', status: 'missing_key', approved: true, fingerprint_verified: true,
                last_seen: '2026-10-20T11:30:00Z', missing_key_groups: [{ id: 'g-research', name: 'Research' }] },
        ],
        'u-mia': [{ device_id: 'mia-tablet', device_name: 'Mia tablet', status: 'pending', last_seen: '2026-10-26T10:00:00Z' }],
    });
    const { app, node } = environment(async () => ({ success: true, data }));
    const opened = [];
    app.selectAdminTab = name => opened.push(`tab:${name}`);
    app.showDeviceAccessQueue = async () => opened.push('approve-queue');
    await app.showMembersView();
    const html = node('membersList').innerHTML;
    assert.match(html, /data-group-id="g-research" data-user-id="u-owner">Open group to approve/);
    assert.doesNotMatch(html, /Open Devices/, 'the Devices view cannot send a missed key');

    await app.handleMembersListClick(click('u-owner', 'g-research'));
    assert.equal(app.activeWorkspaceView, 'admin');
    assert.deepEqual(opened, ['tab:devices', 'approve-queue']);

    // A waiting device names no group, so its member's first group is opened.
    opened.length = 0;
    await app.showMembersView();
    await app.handleMembersListClick(click('u-mia'));
    assert.deepEqual(opened, ['tab:devices', 'approve-queue']);
});

test('a group you are not in explains who can approve, and only this unverified device opens Devices', async () => {
    const data = withDevices({
        'u-owner': [{ device_id: 'device-1', device_name: 'Owner Mac', status: 'unverified', approved: true, fingerprint_verified: false,
            last_seen: '2026-10-26T11:30:00Z' }],
        'u-mia': [{ device_id: 'mia-laptop', device_name: 'Mia laptop', status: 'missing_key', approved: true, fingerprint_verified: true,
            last_seen: '2026-10-25T12:00:00Z', missing_key_groups: [{ id: 'g-finance', name: 'Finance' }] }],
    });
    data.members = data.members.map(member => member.user_id === 'u-mia' ? { ...member, groups: [{ id: 'g-finance', name: 'Finance' }] } : member);
    const { app, node, notifications } = environment(async () => ({ success: true, data }));
    app.showDeviceAccessQueue = async () => assert.fail('no approval list for a group this account is not in');
    await app.showMembersView();
    assert.match(node('membersList').innerHTML, /data-members-action="own-devices">Open Devices/);
    assert.equal(await app.openGroupApprovals('g-finance', 'u-mia'), false);
    assert.equal(app.activeWorkspaceView, 'members');
    assert.ok(notifications.some(([kind, message]) => kind === 'warning' && /not in Finance/.test(message)));
});

const granted = { ...roster, members: roster.members.map(member => (member.user_id === 'u-mia'
    ? { ...member, pending_groups: [{ id: 'g-research', name: 'Research' }, { id: 'g-legal', name: 'Legal' }] } : member)) };
const openInvitations = { online: true, role: 'owner', members: [], invitations: [
    { id: 'inv-zed', email: 'zed@example.com', status: 'pending', expires_at: '2999-01-01T00:00:00Z', pending_groups: [{ id: 'g-research', name: 'Research' }] }] };

function membersInvoke(calls, extra = {}) {
    return async (command, args) => {
        calls.push([command, args]);
        if (extra[command]) return extra[command](args);
        if (command === 'get_team_member_devices') return { success: true, data: granted };
        if (command === 'get_team_directory') return openInvitations;
        if (command === 'start_desktop_operation') return { id: 'op', status: 'succeeded', phase: 'Completed', output: [], result: {} };
        return { success: true, data: [] };
    };
}

test('a group admin\'s app finishes waiting adds by itself, only in groups it administers', async () => {
    const calls = [];
    const { app, node, notifications } = environment(membersInvoke(calls));
    app.teamGroupSummaries = { account: 'owner@example.com', loadedAt: Date.now(),
        groups: [{ id: 'g-research', name: 'Research', organization_id: 'org-1', user_role: 'admin' }] };
    await app.showMembersView();
    const started = calls.filter(([command]) => command === 'start_desktop_operation').map(([, args]) => args.request);
    assert.deepEqual(started.map(request => [request.kind, request.email, request.group_id]), [['add_member', 'mia@example.com', 'g-research']]);
    assert.ok(notifications.some(([kind, message]) => kind === 'success' && message === 'mia@example.com now has access to Research.'));
    const html = node('membersList').innerHTML;
    assert.doesNotMatch(html, /data-members-action="finish-group"/, 'Finish only after a failed attempt');
    assert.match(html, /Waiting for an admin of Legal; their app finishes this automatically/);
    assert.match(html, /data-members-action="remove-member" data-user-id="u-mia"/);
    assert.doesNotMatch(html, /data-members-action="remove-member" data-user-id="u-boss"/, 'owners stay');
    assert.doesNotMatch(html, /data-members-action="member-groups" data-user-id="u-owner"/, 'not for yourself');
    assert.match(html, /zed@example.com[\s\S]*Invited · gets Research after joining[\s\S]*data-members-action="cancel-invite"/);
    assert.match(node('membersSummary').textContent, /1 invited/);

    // Each add is tried once per visit, and never while another operation runs.
    calls.length = 0;
    assert.equal(await app.autoFinishGroupAccess(), 0);
    app.groupAccessAutoFailures = null;
    app.desktopOperation = { status: 'running' };
    assert.equal(await app.autoFinishGroupAccess(), 0);
    assert.ok(!calls.some(([command]) => command === 'start_desktop_operation'));
});

test('a failed automatic add shows Finish with the reason, and Finish tries again', async () => {
    const calls = [];
    let fail = true;
    const { app, node } = environment(membersInvoke(calls, {
        start_desktop_operation: () => (fail
            ? { id: 'op', status: 'failed', phase: 'Failed', output: [], error: { message: 'No devices to give the key to' } }
            : { id: 'op', status: 'succeeded', phase: 'Completed', output: [], result: {} }),
    }));
    app.teamGroupSummaries = { account: 'owner@example.com', loadedAt: Date.now(),
        groups: [{ id: 'g-research', name: 'Research', organization_id: 'org-1', user_role: 'admin' }] };
    await app.showMembersView();
    assert.match(node('membersList').innerHTML,
        /Couldn't finish adding to Research: No devices to give the key to<\/span><button[^>]*data-members-action="finish-group" data-group-id="g-research" data-user-id="u-mia" data-email="mia@example.com"/);
    fail = false;
    calls.length = 0;
    app.desktopOperation = null;
    await app.finishMemberGroupAccess({ disabled: false, dataset: { groupId: 'g-research', userId: 'u-mia', email: 'mia@example.com' } });
    const request = calls.find(([command]) => command === 'start_desktop_operation')[1].request;
    assert.deepEqual([request.kind, request.email, request.group_id], ['add_member', 'mia@example.com', 'g-research']);
    assert.ok(!app.groupAccessAutoFailures.get('u-mia:g-research'));
});

test('removing someone from the Team sends the request, then offers rotation for their groups this admin is in', async () => {
    const calls = [];
    const { app, notifications } = environment(membersInvoke(calls, {
        queue_team_admin_request: args => ({ request: { id: 'req-1', kind: args.kind, target_id: args.targetId }, status: 'pending' }),
        sync_team_admin_requests: () => [{ request: { id: 'req-1', kind: 'remove_member' }, status: 'accepted' }],
    }));
    app.teamGroupSummaries = { account: 'owner@example.com', groups: [{ id: 'g-research', name: 'Research', organization_id: 'org-1' }], loadedAt: Date.now() };
    const prompts = [];
    app.showActionPrompt = async (title, message) => { prompts.push([title, message]); return true; };
    const rotations = [];
    app.beginRekeyFlow = async options => rotations.push(options.title);
    app.refreshTeamLicenseStatus = async () => app.teamLicenseStatus;
    await app.showMembersView();
    assert.equal(await app.removeTeamMember('u-mia', 'mia@example.com'), true);
    assert.equal(prompts[0][0], 'Remove from Team?');
    assert.match(prompts[0][1], /taken out of Research/);
    const queued = calls.find(([command]) => command === 'queue_team_admin_request')[1];
    assert.deepEqual([queued.kind, queued.targetId], ['remove_member', 'u-mia']);
    assert.ok(calls.some(([command, args]) => command === 'dismiss_team_admin_request' && args.requestId === 'req-1'));
    assert.deepEqual(rotations, ['Rotate keys for Research?']);
    assert.ok(notifications.some(([kind, message]) => kind === 'success' && /removed from the Team/.test(message)));

    // Offline, the request waits in the queue and nothing is rotated yet.
    rotations.length = 0;
    app.teamLicenseStatus.online = false;
    assert.equal(await app.removeTeamMember('u-mia', 'mia@example.com'), false);
    assert.deepEqual(rotations, []);
});

test('Invite to Team sends the email with the chosen groups, prepares their access and shows the code once', async () => {
    const calls = [];
    const { app, node, notifications } = environment(membersInvoke(calls, {
        get_group_summaries: () => ({ success: true, data: [{ id: 'g-research', name: 'Research', organization_id: 'org-1' },
            { id: 'personal', name: 'Personal', organization_id: null }].map(group => ({ ...group, user_role: 'admin' })) }),
        invite_team_member: () => ({ invitation_id: 'inv-new', invitation_code: 'HC-INVITE-CODE' }),
        start_desktop_operation: () => ({ id: 'op', status: 'succeeded', phase: 'Completed', output: [], result: { access: 'on_accept' } }),
    }));
    app.teamLicenseStatus.organization = { ...app.teamLicenseStatus.organization, seats_used: 3, seat_limit: 5 };
    app.isValidEmail = email => /@/.test(email);
    await app.openTeamInviteDialog();
    assert.equal(node('teamInviteSeats').textContent, 'Uses 1 seat · 2 of 5 left');
    assert.match(node('teamInviteGroups').innerHTML, /value="g-research"> Research/);
    assert.doesNotMatch(node('teamInviteGroups').innerHTML, /Personal/);
    node('teamInviteEmail').value = ' New@Example.com ';
    node('teamInviteGroups').querySelectorAll = () => [{ value: 'g-research' }];
    await app.submitTeamInviteDialog();
    const invite = calls.find(([command]) => command === 'invite_team_member')[1];
    assert.equal(JSON.stringify(invite), JSON.stringify({ email: 'new@example.com', groupIds: ['g-research'] }));
    assert.equal(node('teamInviteCode').value, 'HC-INVITE-CODE');
    assert.equal(node('teamInviteSubmitBtn').textContent, 'Done');
    // Their existing devices get the group key now, kept with the invitation until they accept.
    const staged = calls.find(([command]) => command === 'start_desktop_operation')[1].request;
    assert.deepEqual([staged.kind, staged.invitation_id, staged.email, staged.group_id],
        ['stage_invitation_access', 'inv-new', 'new@example.com', 'g-research']);
    assert.ok(notifications.some(([kind, message]) => kind === 'success' && /get their groups as soon as they accept/.test(message)));

    // Offline, an invitation with groups cannot be queued.
    calls.length = 0;
    app.teamLicenseStatus.online = false;
    await app.openTeamInviteDialog();
    node('teamInviteEmail').value = 'later@example.com';
    await app.submitTeamInviteDialog();
    assert.ok(!calls.some(([command]) => command === 'queue_team_admin_request' || command === 'invite_team_member'));
});
