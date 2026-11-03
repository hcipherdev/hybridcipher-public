// Tests planFolderPageRoute() in src/ui-utils.js and openMountCenterFolderPage() in src/app.js: reaching a Mount Center folder's page in the app, switching workspace or Team group first when needed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { planFolderPageRoute } = uiScope.HybridCipherUiUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const personalFolder = { root_id: 'r-taxes', name: 'Taxes', workspace: 'personal', group_id: 'personal-1', group_name: 'Personal' };
const engFolder = { root_id: 'r-specs', name: 'Specs', workspace: 'team', group_id: 'team-eng', group_name: 'Engineering' };

test('a folder of the selected group is opened in place', () => {
    assert.deepEqual(plain(planFolderPageRoute(personalFolder, { activeWorkspaceType: 'personal', activeGroupId: 'personal-1' })), { kind: 'here' });
    assert.deepEqual(plain(planFolderPageRoute(engFolder, { activeWorkspaceType: 'team', activeGroupId: 'team-eng' })), { kind: 'here' });
});

test('a folder of another Team group switches group', () => {
    assert.deepEqual(plain(planFolderPageRoute(engFolder, { activeWorkspaceType: 'team', activeGroupId: 'team-legal' })),
        { kind: 'group', groupId: 'team-eng' });
});

test('a folder of the other workspace switches workspace, with its group', () => {
    assert.deepEqual(plain(planFolderPageRoute(engFolder, { activeWorkspaceType: 'personal', activeGroupId: 'personal-1' })),
        { kind: 'workspace', workspace: 'team', groupId: 'team-eng' });
    assert.deepEqual(plain(planFolderPageRoute(personalFolder, { activeWorkspaceType: 'team', activeGroupId: 'team-eng' })),
        { kind: 'workspace', workspace: 'personal', groupId: 'personal-1' });
});

test('vault folders open in the vault; folders outside every workspace have no page', () => {
    const vaultFolder = { root_id: 'r1', workspace: 'vault', group_id: 'vault' };
    assert.deepEqual(plain(planFolderPageRoute(vaultFolder, { localVaultMode: true })), { kind: 'here' });
    assert.deepEqual(plain(planFolderPageRoute({ root_id: 'r2', workspace: 'other', group_id: null })), { kind: 'unavailable' });
    assert.deepEqual(plain(planFolderPageRoute({ root_id: 'r3', workspace: 'team', group_id: '' })), { kind: 'unavailable' });
});

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('    async openMountCenterFolderPage(');
const finish = source.indexOf('    async handleMountCenterAction(', begin);
assert.ok(begin >= 0 && finish > begin, 'Cannot extract openMountCenterFolderPage');

function appWith({ activeWorkspaceType = 'personal', activeGroupId = 'personal-1', switchResult = true, foldersAfterSwitch = [] } = {}) {
    const App = Function('planFolderPageRouteValue', `return class { ${source.slice(begin, finish)} }`)(planFolderPageRoute);
    const app = new App();
    const calls = { selectWorkspaceType: [], switchTeamGroup: [], selected: [], notifications: [] };
    let releaseSwitch = () => {};
    Object.assign(app, {
        activeWorkspaceType,
        workspaceGroupContext: { group_id: activeGroupId },
        localVaultMode: false,
        enrolledFolders: [{ root_id: 'r-taxes', path: '/Users/me/Taxes' }],
        mountCenterOverview: { folders: [personalFolder, engFolder, { root_id: 'r-stray', name: 'Old', workspace: 'other' }] },
        findMountCenterFolder(rootId) { return this.mountCenterOverview.folders.find(folder => folder.root_id === rootId) || null; },
        captureAccountReadContext: () => () => true,
        async selectWorkspaceType(type, options) {
            calls.selectWorkspaceType.push([type, options]);
            await new Promise(resolve => { releaseSwitch = resolve; });
            if (switchResult) { this.activeWorkspaceType = type; this.enrolledFolders = foldersAfterSwitch; }
            return switchResult;
        },
        async switchTeamGroup(groupId) {
            calls.switchTeamGroup.push(groupId);
            if (switchResult) this.enrolledFolders = foldersAfterSwitch;
            return switchResult;
        },
        selectFolder(folder, options) { calls.selected.push([folder, options]); },
        showNotification(message, type) { calls.notifications.push([message, type]); },
    });
    return { app, calls, releaseSwitch: () => releaseSwitch() };
}

test('a folder of the selected group opens its page without switching', async () => {
    const { app, calls } = appWith();

    assert.equal(await app.openMountCenterFolderPage('r-taxes'), true);
    assert.equal(calls.selectWorkspaceType.length + calls.switchTeamGroup.length, 0);
    assert.deepEqual(plain(calls.selected), [[{ root_id: 'r-taxes', path: '/Users/me/Taxes' }, { showDetail: true }]]);
});

test('a Team folder seen from Personal switches to Team and its group, then opens the page', async () => {
    const specs = { root_id: 'r-specs', path: '/work/Specs' };
    const { app, calls, releaseSwitch } = appWith({ foldersAfterSwitch: [specs] });

    const opening = app.openMountCenterFolderPage('r-specs');
    // A second click while the switch runs is ignored.
    assert.equal(await app.openMountCenterFolderPage('r-specs'), false);
    releaseSwitch();
    assert.equal(await opening, true);
    assert.deepEqual(plain(calls.selectWorkspaceType), [['team', { forceGroupId: 'team-eng', preserveOnFailure: true }]]);
    assert.deepEqual(plain(calls.selected), [[specs, { showDetail: true }]]);
    assert.equal(app.folderPageNavigationInFlight, false);
});

test('a folder of another Team group switches group first', async () => {
    const specs = { root_id: 'r-specs', path: '/work/Specs' };
    const { app, calls } = appWith({ activeWorkspaceType: 'team', activeGroupId: 'team-legal', foldersAfterSwitch: [specs] });

    assert.equal(await app.openMountCenterFolderPage('r-specs'), true);
    assert.deepEqual(plain(calls.switchTeamGroup), ['team-eng']);
    assert.deepEqual(plain(calls.selected), [[specs, { showDetail: true }]]);
});

test('a failed switch selects nothing and leaves its own warning', async () => {
    const { app, calls } = appWith({ activeWorkspaceType: 'team', activeGroupId: 'team-legal', switchResult: false });

    assert.equal(await app.openMountCenterFolderPage('r-specs'), false);
    assert.equal(calls.selected.length, 0);
    // switchTeamGroup reports its own failure; no second message is added.
    assert.equal(calls.notifications.length, 0);
});

test('a folder missing after the switch, or outside every workspace, is reported', async () => {
    const { app, calls } = appWith({ activeWorkspaceType: 'team', activeGroupId: 'team-legal', foldersAfterSwitch: [] });

    assert.equal(await app.openMountCenterFolderPage('r-specs'), false);
    assert.match(calls.notifications[0][0], /Specs could not be found in Engineering/);
    assert.equal(await app.openMountCenterFolderPage('r-stray'), false);
    assert.match(calls.notifications[1][0], /no folder page/);
    assert.equal(calls.selected.length, 0);
});
