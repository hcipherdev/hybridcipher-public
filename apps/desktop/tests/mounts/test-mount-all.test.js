// Tests mountAllFromMountCenter() in src/app.js: the Mount Center's Mount all queues every mountable folder of every workspace and group, whatever the filter shows, and nothing when all are mounted.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildMountCenterModel } = uiScope.HybridCipherUiUtils;

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('    async mountAllFromMountCenter(');
const finish = source.indexOf('    async handleMountCenterAction(', begin);
assert.ok(begin >= 0 && finish > begin, 'Cannot extract mountAllFromMountCenter');

const folder = (rootId, workspace, groupId, extra = {}) => ({
    root_id: rootId, name: rootId, path: `/x/${rootId}`, group_id: groupId, group_name: groupId,
    workspace, can_mount: true, auto_mount: false, mount: null, ...extra,
});

function appWith(folders, { queue = {} } = {}) {
    const App = Function('buildMountCenterModelValue', `return class { ${source.slice(begin, finish)} }`)(buildMountCenterModel);
    const app = new App();
    const queued = [];
    Object.assign(app, {
        mountCenterOverview: { selected_group_id: 'personal', folders },
        mountCenterState: { filter: 'mounted', query: 'nothing matches' },
        mountQueueJobs: queue,
        backgroundMountResults: { photos: { reason: 'old failure' } },
        getMountCenterBusyState: () => ({}),
        async enqueueMounts(rootIds, options) { queued.push([rootIds, options]); return true; },
    });
    return { app, queued };
}

test('every mountable folder in every workspace is queued, whatever the filter shows', async () => {
    const { app, queued } = appWith([
        folder('photos', 'personal', 'personal'),
        folder('specs', 'team', 'eng'),
        folder('taxes', 'personal', 'personal', { mount: { root_id: 'taxes', mountpoint: '/m', backend: 'macos-file-provider' } }),
        folder('legal', 'team', 'legal', { can_mount: false, blocked_reason: 'no keys' }),
        folder('queued', 'team', 'eng'),
    ], { queue: { queued: { root_id: 'queued', status: 'queued' } } });

    assert.equal(await app.mountAllFromMountCenter(), true);
    assert.equal(queued.length, 1);
    assert.deepEqual([...queued[0][0]].sort(), ['photos', 'specs']);
    assert.equal(queued[0][1].label, 'Mount all');
    assert.equal(app.backgroundMountResults.photos, undefined, 'an old failure is cleared');
});

test('nothing is queued when every folder is already mounted', async () => {
    const { app, queued } = appWith([
        folder('taxes', 'personal', 'personal', { mount: { root_id: 'taxes', mountpoint: '/m', backend: 'macos-file-provider' } }),
    ]);

    assert.equal(await app.mountAllFromMountCenter(), false);
    assert.equal(queued.length, 0);
});
