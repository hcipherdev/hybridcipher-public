// Tests app.js Team license settings and the offline request review shown on Members & devices.
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
    assert.equal(document.getElementById('settingsOpenTeamBtn').textContent, 'Activate Team');
    assert.equal(document.getElementById('settingsOpenTeamBtn').classList.hidden, false);
    assert.equal(document.getElementById('teamActivationForm').classList.hidden, false);
    app.teamLicenseStatus = { workspace: 'team', organization: { id: 'existing-team' }, can_write: false, online: false };
    app.renderTeamLicenseSettings();
    // Entitled accounts switch from the header selector, so Settings drops its Team entry.
    assert.equal(document.getElementById('settingsOpenTeamBtn').classList.hidden, true);
    assert.equal(document.getElementById('teamLicenseState').textContent, 'Read-only');
    assert.equal(document.getElementById('teamExportExistingBtn').classList.hidden, false);
    assert.match(document.getElementById('teamLicenseNote').textContent, /pending edits are preserved/);
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
    const html = document.getElementById('membersPendingRequestsList').innerHTML;
    assert.equal(document.getElementById('membersPendingRequests').classList.hidden, false);
    assert.ok(!html.includes('data-dismiss-team-request="pending-keys"'));
    assert.ok(html.includes('data-dismiss-team-request="ready"'));
    assert.ok(html.includes('Create group: Ready'));
    assert.ok(html.includes('Server rejected request: 409'));
});
