// Tests buildMountCenterModel() in src/ui-utils.js: grouping by workspace and group, row actions and status, folder-page links, filters, and the auto-mount fields (row and tri-state section toggles, last results).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildMountCenterModel } = uiScope.HybridCipherUiUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const overview = {
    local_vault: false,
    selected_group_id: 'team-eng',
    auto_mount_configured: true,
    folders: [
        {
            root_id: 'r-taxes', name: 'Taxes', path: '/Users/me/Taxes', group_id: 'personal-1',
            group_name: 'Personal', workspace: 'personal', can_mount: true, auto_mount: true,
            mount: { root_id: 'r-taxes', mountpoint: '/cloud/Personal · Taxes', backend: 'macos-file-provider', availability: 'usable', display_name: 'Personal · Taxes' },
        },
        {
            root_id: 'r-photos', name: 'Photos', path: '/Users/me/Photos', group_id: 'personal-1',
            group_name: 'Personal', workspace: 'personal', can_mount: true, auto_mount: true, mount: null,
        },
        {
            root_id: 'r-specs', name: 'Specs', path: '/work/Specs', group_id: 'team-eng',
            group_name: 'Engineering', workspace: 'team', can_mount: true, auto_mount: true,
            mount: { root_id: 'r-specs', mountpoint: '/cloud/Engineering · Specs', backend: 'windows-cloud-files', availability: 'degraded' },
        },
        {
            root_id: 'r-legal', name: 'Contracts', path: '/work/Contracts', group_id: 'team-legal',
            group_name: 'Legal', workspace: 'team', can_mount: false, auto_mount: false,
            blocked_reason: "This device doesn't have this group's keys yet.", mount: null,
        },
        {
            root_id: 'r-stray', name: 'Old', path: '/old', group_id: null, group_name: null,
            workspace: 'other', can_mount: false, auto_mount: false, blocked_reason: 'outside', mount: null,
        },
    ],
};

const rowsById = model => Object.fromEntries(
    model.sections.flatMap(section => section.folders).map(row => [row.rootId, row])
);

test('folders are grouped by workspace and Team group, Personal first', () => {
    const model = buildMountCenterModel(overview);

    assert.deepEqual(plain(model.sections.map(section => section.title)), ['Personal', 'Engineering', 'Legal', 'Other folders']);
    assert.equal(model.summary.total, 5);
    assert.equal(model.summary.mounted, 2);
    assert.equal(model.summary.degraded, 1);
    assert.equal(model.summary.blocked, 2);
    assert.equal(model.summary.mountable, 1, 'only Photos can be mounted now');
    const personal = model.sections[0];
    assert.equal(personal.countLabel, '1 of 2 mounted');
    assert.deepEqual(plain(personal.folders.map(row => row.name)), ['Photos', 'Taxes']);
    assert.equal(personal.selected, false);
    assert.equal(model.sections[1].selected, true);
    assert.equal(model.sections[1].eyebrow, 'Team');
});

test('each folder offers the actions its state allows', () => {
    const rows = rowsById(buildMountCenterModel(overview));

    assert.deepEqual(plain(rows['r-taxes'].actions.map(action => action.id)), ['open', 'unmount']);
    assert.equal(rows['r-taxes'].displayName, 'Personal · Taxes');
    assert.equal(rows['r-taxes'].backendLabel, 'macOS File Provider');
    assert.deepEqual(plain(rows['r-photos'].actions.map(action => action.id)), ['mount']);
    assert.equal(rows['r-specs'].status, 'degraded');
    assert.deepEqual(plain(rows['r-specs'].actions.map(action => action.id)), ['folder-page', 'unmount']);
    assert.equal(rows['r-legal'].status, 'blocked');
    assert.deepEqual(plain(rows['r-legal'].actions.map(action => action.id)), ['folder-page']);
    assert.match(rows['r-legal'].blockedReason, /keys/);
});

test('every folder in a workspace links to its page; those needing attention also get a button', () => {
    const rows = rowsById(buildMountCenterModel(overview, { results: { 'r-photos': { reason: 'Mount failed' } } }));

    assert.equal(rows['r-taxes'].canOpenFolderPage, true);
    assert.equal(rows['r-taxes'].needsAttention, false);
    assert.deepEqual(plain(rows['r-taxes'].actions.map(action => action.id)), ['open', 'unmount']);
    assert.equal(rows['r-photos'].needsAttention, true);
    assert.deepEqual(plain(rows['r-photos'].actions.map(action => action.id)), ['folder-page', 'mount']);
    // A folder outside every workspace has no page in the app.
    assert.equal(rows['r-stray'].canOpenFolderPage, false);
    assert.equal(rows['r-stray'].actions.length, 0);
});

test('work in progress replaces the actions', () => {
    const model = buildMountCenterModel(overview, { busy: { 'r-photos': 'mounting', 'r-taxes': 'unmounting' } });

    assert.deepEqual(plain(model.sections[0].folders.map(row => [row.rootId, row.status, row.actions.length])), [
        ['r-photos', 'mounting', 0],
        ['r-taxes', 'unmounting', 0],
    ]);
});

test('filters narrow by mount state and search text', () => {
    const mounted = buildMountCenterModel(overview, { filter: 'mounted' });
    assert.deepEqual(plain(mounted.sections.flatMap(section => section.folders).map(row => row.rootId)), ['r-taxes', 'r-specs']);

    const unmounted = buildMountCenterModel(overview, { filter: 'unmounted', query: 'legal' });
    assert.deepEqual(plain(unmounted.sections.map(section => section.title)), ['Legal']);

    const none = buildMountCenterModel(overview, { query: 'nothing matches' });
    assert.equal(none.emptyFiltered, true);
    assert.equal(none.empty, false);
    assert.equal(none.sections.length, 0);
});

test('an empty or missing overview is reported as empty', () => {
    const model = buildMountCenterModel(null);

    assert.equal(model.empty, true);
    assert.equal(model.summary.total, 0);
    assert.equal(model.summary.autoMountState, 'none');
    assert.equal(model.activity, null);
});

test('the accountless vault is labelled as this device', () => {
    const model = buildMountCenterModel({
        local_vault: true,
        selected_group_id: 'vault',
        folders: [{ root_id: 'r1', name: 'Notes', path: '/n', group_id: 'vault', workspace: 'vault', can_mount: true }],
    });

    assert.equal(model.sections[0].title, 'On this device');
    assert.equal(model.sections[0].selected, true);
    assert.equal(model.sections[0].folders[0].canToggleAutoMount, true);
});

test('auto-mount is shown per folder, and as all, some or none per section and overall', () => {
    const model = buildMountCenterModel(overview);
    const rows = rowsById(model);
    const states = Object.fromEntries(model.sections.map(section => [section.title, section.autoMountState]));

    assert.equal(rows['r-photos'].autoMount, true);
    assert.equal(rows['r-legal'].autoMount, false);
    assert.deepEqual(states, { Personal: 'all', Engineering: 'all', Legal: 'none', 'Other folders': 'none' });
    assert.equal(model.summary.autoMount, 3);
    assert.equal(model.summary.autoMountState, 'some');
});

test('folders outside the workspaces cannot be set to auto-mount', () => {
    const model = buildMountCenterModel(overview);
    const other = model.sections.find(section => section.workspace === 'other');

    assert.equal(rowsById(model)['r-stray'].canToggleAutoMount, false);
    assert.equal(other.canToggleAutoMount, false);
    // Blocked folders inside a workspace can still be chosen; they report why when auto-mount runs.
    assert.equal(rowsById(model)['r-legal'].canToggleAutoMount, true);
    assert.equal(model.summary.canToggleAutoMount, 4);
});

test('results that need attention show on their rows', () => {
    const model = buildMountCenterModel(overview, {
        results: {
            'r-photos': { reason: 'Mount failed: source missing' },
            'r-legal': { reason: "This device doesn't have this group's keys yet." },
        },
    });
    const rows = rowsById(model);

    assert.match(rows['r-photos'].lastResult, /source missing/);
    assert.match(rows['r-legal'].lastResult, /keys/);
    // A folder being mounted again hides its old result.
    const remounting = rowsById(buildMountCenterModel(overview, {
        results: { 'r-photos': { reason: 'old' } },
        busy: { 'r-photos': 'mounting' },
    }));
    assert.equal(remounting['r-photos'].lastResult, '');
});
