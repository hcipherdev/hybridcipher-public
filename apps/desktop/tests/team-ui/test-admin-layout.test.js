// Tests the Team sidebar and tabbed group page layout in src/index.html and summarizeOperationOutput() in src/ui-utils.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { summarizeOperationOutput } = require('../../src/ui-utils.js');
const html = fs.readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');

function adminPanel(key) {
    const match = html.match(new RegExp(`<div class="admin-tab-panel" id="[^"]+" role="tabpanel"[^>]*data-admin-panel="${key}"([^>]*)>([\\s\\S]*?)(?=<div class="admin-tab-panel"|</section>)`));
    assert.ok(match, `panel ${key} exists`);
    return { hidden: /\bhidden\b/.test(match[1]), body: match[2] };
}

test('the group page is organised as tabs, with expert tools under Advanced', () => {
    const header = html.match(/<section class="admin-dashboard"[\s\S]*?<div class="admin-tabs"/)?.[0] || '';
    for (const id of ['teamAdministrationTitle', 'adminGroupMeta', 'adminAddMemberBtn', 'adminGroupSettingsBtn',
        'adminRenameGroupBtn', 'adminDeleteGroupBtn', 'adminRefreshStatusBtn']) assert.match(header, new RegExp(`id="${id}"`), `${id} sits in the group header`);
    const expected = {
        people: ['adminPeopleList', 'adminPeopleSearch', 'adminTeamMembersValue'],
        devices: ['adminDeviceAccessQueue', 'adminStaleDevicesQueue', 'adminQueueRefreshBtn', 'adminTrustVerifyBtn'],
        keys: ['adminKeyVersionsValue', 'adminRekeyStartBtn', 'adminRekeyMigrationBtn', 'adminRekeyStatusLine', 'adminVerifyMembershipBtn'],
        advanced: ['adminServerStatusValue', 'adminCoverageStatus', 'adminCoverageSampleAuditBtn', 'adminCoverageFullAuditBtn',
            'adminCoverageVerifyBtn', 'adminCoverageEnrolledListBtn', 'adminTrustCheckpointBtn', 'adminPinListBtn'],
    };
    for (const [key, ids] of Object.entries(expected)) {
        const { body } = adminPanel(key);
        for (const id of ids) assert.match(body, new RegExp(`id="${id}"`), `${id} belongs to ${key}`);
    }
    assert.equal(adminPanel('people').hidden, false, 'People opens first');
    for (const key of ['devices', 'keys', 'advanced']) assert.equal(adminPanel(key).hidden, true, `${key} starts hidden`);
    assert.doesNotMatch(adminPanel('people').body + adminPanel('keys').body, />\s*(Cutover|Fallback|Start rekey)\s*</);
    // Rotation follow-up actions sit with Rotate group keys, not under Advanced.
    assert.doesNotMatch(adminPanel('advanced').body, /adminRekey|Manual key rotation/);
    // Each modal-only list is gone: people act from their row, groups from the sidebar.
    assert.doesNotMatch(html, /id="(switchGroupModal|listGroupsModal|removeMemberModal|listMembersModal|adminRemoveMemberBtn|adminListMembersBtn|adminSwitchGroupBtn|adminListGroupsBtn|sidebarSwitchGroupBtn)"/);
    assert.doesNotMatch(html, /accordion-section|dashboard-status-grid/);
});

test('the unused Files view is gone; folders open in folder detail and the system file manager', () => {
    assert.doesNotMatch(html, /id="sidebarFilesBtn"|id="fileBrowser"|id="fileList"|id="breadcrumb"/);
    assert.match(html, /id="sidebarHomeBtn"/);
});

test('Team groups open from the sidebar, above the selected group\'s folders, and the header keeps no search or palette', () => {
    const sidebar = html.match(/<aside class="sidebar"[\s\S]*?<\/aside>/)?.[0] || '';
    assert.match(sidebar, /id="sidebarTeamNav"[\s\S]*id="sidebarOverviewBtn"[\s\S]*id="sidebarGroupList"[\s\S]*id="sidebarFoldersTitle"[\s\S]*id="folderList"/);
    assert.match(sidebar, /<div class="sidebar-view-actions">[\s\S]*id="sidebarHomeBtn"/);
    assert.doesNotMatch(html, /id="sidebarAdminBtn"|id="adminPanelBtn"|id="commandPalette"|cli-commands\.js/);
    const header = html.match(/<header class="app-header">([\s\S]*?)<\/header>/)?.[1] || '';
    assert.doesNotMatch(header, /id="globalSearch"/);
    assert.match(header.split('<div class="header-right">')[1] || '', /id="settingsBtn"/, 'Settings sits on the right of the header');
    assert.match(html, /<aside class="sidebar"[\s\S]*id="sidebarSearch"[\s\S]*id="folderList"/);
});

test('Settings no longer offers buttons that print CLI help', () => {
    assert.doesNotMatch(html, /settingsPinHelpBtn|settingsServerTrustHelpBtn|Pin help|Server trust help/);
});

test('operation results summarise success lines and keep the transcript collapsed', () => {
    assert.match(html, /<details id="desktopOperationDetails" class="hidden">\s*<summary>Technical details<\/summary>/);
    assert.deepEqual(summarizeOperationOutput([
        'Initializing secure session management...',
        'ℹ Using current active group: 6db87b78',
        "✓ Member 'a@example.test' added successfully!",
        '✓ ✅ Successfully logged in as a@example.test',
        "✓ Member 'a@example.test' added successfully!",
        '\u001b[32m✓ Recovery backup uploaded\u001b[0m',
    ]), [
        "Member 'a@example.test' added successfully!",
        'Successfully logged in as a@example.test',
        'Recovery backup uploaded',
    ]);
    assert.deepEqual(summarizeOperationOutput(['✓ one', '✓ two', '✓ three'], 2), ['two', 'three']);
    assert.deepEqual(summarizeOperationOutput(null), []);
});
