// Tests actual app.js folder, mount, member, and enrollment methods against delayed account/workspace responses.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');

function actualMethod(name) {
    const match = new RegExp(`^    (?:async )?${name}\\(`, 'm').exec(source);
    assert.ok(match, `Actual app method ${name} must exist`);
    const boundary = /\r?\n    }\r?\n/g;
    boundary.lastIndex = match.index;
    const end = boundary.exec(source);
    assert.ok(end && end.index > match.index);
    return source.slice(match.index, end.index + end[0].length);
}

function deferred() {
    let resolve, reject;
    const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
    return { promise, resolve, reject };
}

function appFor(names, invoke, globals = {}) {
    const renders = [];
    const nodes = new Map();
    const document = { getElementById(id) {
        if (!nodes.has(id)) nodes.set(id, { innerHTML: 'current content', style: {} });
        return nodes.get(id);
    } };
    const methods = vm.runInNewContext(`({${['captureWorkspaceReadContext', ...names].map(actualMethod).join(',\n')}})`,
        { invoke, document, console, ...globals });
    const app = Object.assign({
        currentUser: 'account-a@example.com', isLoggedIn: true, workspaceSwitchSequence: 1, desktopAccountGeneration: 0,
        enrolledFolders: [], selectedFolder: null, userFolderPreferences: {}, activeWorkspaceView: 'home',
        activeMountsByRootId: {}, activeMountDetailsByRootId: {}, reconciliationStartedAtByRootId: {},
        renderFolderList() { renders.push(this.enrolledFolders.map(folder => folder.path)); },
        renderSettingsEnrollmentList() {}, maybeShowMarkersReminder() {}, hideMarkersReminder() {},
        syncSelectedFolderMountUi() {}, updateSidebarMountSummary() {}, showNotification() {},
        async refreshActiveMounts() {},
    }, methods);
    return { app, renders, nodes };
}

test('a late Personal folder response cannot render or replace the newer Team folder list', async () => {
    const old = deferred();
    let reads = 0;
    const { app, renders } = appFor(['loadEnrolledFolders'], () => ++reads === 1 ? old.promise
        : Promise.resolve({ success: true, data: [{ path: 'team-folder' }] }));
    const pending = app.loadEnrolledFolders();
    app.workspaceSwitchSequence += 1;
    assert.equal(await app.loadEnrolledFolders(), true);
    old.resolve({ success: true, data: [{ path: 'personal-secret-folder' }] });
    assert.equal(await pending, false);
    assert.deepEqual(Array.from(app.enrolledFolders, folder => folder.path), ['team-folder']);
    assert.deepEqual(renders, [['team-folder']]);
});

test('same-account logout and login rejects the earlier folder response by account generation', async () => {
    const old = deferred();
    const { app, renders } = appFor(['loadEnrolledFolders'], () => old.promise);
    const pending = app.loadEnrolledFolders();
    app.desktopAccountGeneration += 1;
    app.enrolledFolders = [{ path: 'new-login-folder' }];
    old.resolve({ success: true, data: [{ path: 'old-login-folder' }] });
    assert.equal(await pending, false);
    assert.deepEqual(app.enrolledFolders, [{ path: 'new-login-folder' }]);
    assert.deepEqual(renders, []);
});

test('a delayed mount refresh cannot restore mount paths from the previous account', async () => {
    const old = deferred();
    const { app } = appFor(['refreshActiveMounts'], () => old.promise);
    const pending = app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    app.currentUser = 'account-b@example.com';
    app.activeMountsByRootId = { current: 'current-account-mount' };
    old.resolve({ success: true, data: [{ root_id: 'private', mountpoint: 'previous-account-mount' }] });
    await pending;
    assert.deepEqual(app.activeMountsByRootId, { current: 'current-account-mount' });
});

test('workspace changes while awaiting secondary mount status do not render folders or select old files', async () => {
    const mounts = deferred();
    const { app, renders } = appFor(['loadEnrolledFolders'], async () => ({ success: true, data: [{ path: 'old-folder' }] }));
    app.refreshActiveMounts = () => mounts.promise;
    const pending = app.loadEnrolledFolders();
    await Promise.resolve();
    app.workspaceSwitchSequence += 1;
    app.enrolledFolders = [{ path: 'new-folder' }];
    mounts.resolve();
    assert.equal(await pending, false);
    assert.deepEqual(app.enrolledFolders, [{ path: 'new-folder' }]);
    assert.deepEqual(renders, []);
});

test('late member-list failures cannot clear content displayed for the newer group', async () => {
    const old = deferred();
    const { app, nodes } = appFor(['loadListMembers'], () => old.promise);
    const pending = app.loadListMembers();
    app.workspaceSwitchSequence += 1;
    old.reject(new Error('Old group failed'));
    await pending;
    assert.equal(nodes.get('listMembersList').innerHTML, 'current content');
});

test('a native folder picker completing after a workspace switch cannot enroll into the next group', async () => {
    const picker = deferred();
    const calls = [];
    const { app } = appFor(['addEnrolledFolder'], async (...args) => { calls.push(args); },
        { window: { __TAURI__: { dialog: { open: () => picker.promise } } } });
    app.showConfirmDialog = () => { throw new Error('Stale picker must not show confirmation'); };
    const pending = app.addEnrolledFolder();
    app.workspaceSwitchSequence += 1;
    picker.resolve('previous-account-folder');
    await pending;
    assert.deepEqual(calls, []);
});
