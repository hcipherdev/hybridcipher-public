// Tests app.js Team license, directory, and durable request review workflows.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function section(start, end) {
    const begin = source.indexOf(start);
    const finish = source.indexOf(end, begin + start.length);
    assert.ok(begin >= 0 && finish > begin);
    return source.slice(begin, finish);
}
function setup(invoke) {
    const elements = new Map();
    const document = { getElementById(id) {
        if (!elements.has(id)) elements.set(id, {
            textContent: '', innerHTML: '', hidden: false,
            classList: { toggle(name, hidden) { this[name] = hidden; } },
            querySelectorAll() { return []; },
        });
        return elements.get(id);
    } };
    const methods = section('    renderTeamLicenseSettings()', '    async activateTeamFromSettings()');
    const App = Function('invoke', 'document', `return class { ${methods} }`)(invoke, document);
    const app = new App();
    app.escapeHtml = app.escapeHtmlAttr = value => String(value ?? '').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
    return { app, document };
}

test('Personal displays activation and Team expiry retains read-only workspace controls', () => {
    const { app, document } = setup(async () => {});
    app.teamLicenseStatus = { workspace: 'personal' };
    app.renderTeamLicenseSettings();
    assert.equal(document.getElementById('teamActivationForm').classList.hidden, false);
    assert.equal(document.getElementById('teamDirectoryPanel').classList.hidden, true);
    app.teamLicenseStatus = { workspace: 'team', can_write: false, online: false };
    app.renderTeamLicenseSettings();
    assert.equal(document.getElementById('teamLicenseState').textContent, 'Read-only');
    assert.equal(document.getElementById('teamExportExistingBtn').classList.hidden, false);
    assert.equal(document.getElementById('teamInviteForm').classList.hidden, true);
    assert.match(document.getElementById('teamLicenseNote').textContent, /pending edits are preserved/);
});

test('directory excludes owners and expired invitations from removable seats and hides actions on revocation', async () => {
    const directory = { role: 'owner', online: true,
        members: [{ user_id: 'owner', email: 'owner@example.com', role: 'owner' }, { user_id: 'member', email: '<member>@example.com', role: 'member' }],
        invitations: [{ id: 'fresh', email: 'fresh@example.com', status: 'pending', expires_at: new Date(Date.now() + 60_000).toISOString() },
            { id: 'old', email: 'old@example.com', status: 'pending', expires_at: '2000-01-01T00:00:00Z' }],
    };
    const { app, document } = setup(async name => { assert.equal(name, 'get_team_directory'); return directory; });
    app.teamLicenseStatus = { workspace: 'team', can_write: true };
    await app.refreshTeamDirectory();
    let html = document.getElementById('teamDirectoryList').innerHTML;
    assert.ok(html.includes('data-team-directory-id="member"'));
    assert.ok(!html.includes('data-team-directory-id="owner"'));
    assert.ok(!html.includes('old@example.com'));
    assert.ok(html.includes('&lt;member>'));
    app.teamLicenseStatus.can_write = false;
    await app.refreshTeamDirectory();
    html = document.getElementById('teamDirectoryList').innerHTML;
    assert.ok(!html.includes('<button'));
    assert.ok(html.includes('owner@example.com'));
});

test('group setup remains reviewable and cannot be cleared before encryption succeeds', async () => {
    const requests = [
        { request: { id: 'pending-keys', kind: 'create_group', group_name: 'Research' }, status: 'initializing', result_id: 'group-1', last_error: 'encryption setup pending' },
        { request: { id: 'ready', kind: 'create_group', group_name: 'Ready' }, status: 'accepted', result_id: 'group-2' },
        { request: { id: 'rejected', kind: 'invite_member', email: 'full@example.com' }, status: 'rejected', last_error: 'Server rejected request: 409' },
    ];
    const { app, document } = setup(async name => { assert.equal(name, 'sync_team_admin_requests'); return requests; });
    app.teamLicenseStatus = { workspace: 'team' };
    await app.refreshPendingTeamRequests(true);
    const html = document.getElementById('teamPendingRequestsList').innerHTML;
    assert.ok(!html.includes('data-dismiss-team-request="pending-keys"'));
    assert.ok(html.includes('data-dismiss-team-request="ready"'));
    assert.ok(html.includes('Group ready: group-2'));
    assert.ok(html.includes('Server rejected request: 409'));
});
