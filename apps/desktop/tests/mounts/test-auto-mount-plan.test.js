// Tests planAutoMount(), summarizeBackgroundMounts(), readLegacyAutoMountSeed() and clearLegacyAutoMount() in src/auto-mount-utils.js (which folders auto-mount, when one summary notification is needed, and carrying over the old "auto-mount last folder" setting).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const scope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/auto-mount-utils.js', import.meta.url), 'utf8'), scope);
const {
    AUTO_MOUNT_PREFERENCE_KEY,
    LAST_MOUNTED_ROOT_KEY,
    planAutoMount,
    summarizeBackgroundMounts,
    readLegacyAutoMountSeed,
    clearLegacyAutoMount,
} = scope.HybridCipherAutoMountUtils;
const plain = value => JSON.parse(JSON.stringify(value));

function createStorage(initialValues = {}) {
    const values = new Map(Object.entries(initialValues));
    return {
        getItem: key => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => values.set(key, String(value)),
        removeItem: key => values.delete(key),
        has: key => values.has(key),
    };
}

const folder = (rootId, extra = {}) => ({
    root_id: rootId, name: rootId, path: `/f/${rootId}`, can_mount: true, auto_mount: true, mount: null, ...extra,
});

test('planAutoMount queues chosen folders that are not mounted yet', () => {
    const plan = planAutoMount({
        folders: [
            folder('a'),
            folder('b', { auto_mount: false }),
            folder('c', { mount: { mountpoint: '/m/c' } }),
            folder('d'),
            folder('e', { can_mount: false, blocked_reason: 'No keys on this device.' }),
            folder('f', { can_mount: false, auto_mount: false }),
        ],
    }, { busyRootIds: ['d'] });

    assert.deepEqual(plain(plan.queue.map(entry => entry.root_id)), ['a']);
    assert.deepEqual(plain(plan.attention), [{ rootId: 'e', name: 'e', reason: 'No keys on this device.' }]);
});

test('planAutoMount handles a missing overview', () => {
    assert.deepEqual(plain(planAutoMount(null)), { queue: [], attention: [] });
});

test('a clean background run produces no notification', () => {
    const summary = summarizeBackgroundMounts([
        { rootId: 'a', name: 'A', status: 'mounted' },
        { rootId: 'b', name: 'B', status: 'already' },
        { rootId: 'c', name: 'C', status: 'busy' },
    ]);

    assert.equal(summary.mounted, 2);
    assert.equal(summary.attempted, 2);
    assert.equal(summary.needsAttention.length, 0);
    assert.equal(summary.message, null);
});

test('failures, unmountable folders, unhealthy mounts and sync fallback make one message', () => {
    const summary = summarizeBackgroundMounts([
        { rootId: 'a', name: 'A', status: 'mounted' },
        { rootId: 'b', name: 'B', status: 'failed', error: 'Source folder missing' },
        { rootId: 'c', name: 'C', status: 'mounted', fallbackReason: 'File Provider unavailable' },
        { rootId: 'd', name: 'D', status: 'failed', degraded: true, error: 'Cloud Files cannot serve it safely' },
    ], [{ rootId: 'e', name: 'E', reason: 'No keys on this device.' }]);

    assert.equal(summary.mounted, 2);
    assert.equal(summary.attempted, 5);
    assert.deepEqual(plain(summary.needsAttention.map(item => item.rootId)).sort(), ['b', 'c', 'd', 'e']);
    assert.match(summary.needsAttention.find(item => item.rootId === 'c').reason, /sync fallback/);
    assert.equal(summary.message, 'Auto-mount: 2 of 5 folders mounted. 4 need attention.');
});

test('stopping a run says so', () => {
    const summary = summarizeBackgroundMounts([{ rootId: 'a', name: 'A', status: 'mounted' }], [], { stopped: true });

    assert.equal(summary.message, 'Auto-mount stopped after 1 folder.');
});

test('the old setting carries over its last folder unless it was switched off', () => {
    assert.equal(readLegacyAutoMountSeed(createStorage({ [LAST_MOUNTED_ROOT_KEY]: ' root-1 ' })), 'root-1');
    assert.equal(readLegacyAutoMountSeed(createStorage({
        [AUTO_MOUNT_PREFERENCE_KEY]: 'false',
        [LAST_MOUNTED_ROOT_KEY]: 'root-1',
    })), null);
    assert.equal(readLegacyAutoMountSeed(createStorage()), null);
    assert.equal(readLegacyAutoMountSeed(null), null);
});

test('clearLegacyAutoMount removes both old keys', () => {
    const storage = createStorage({ [AUTO_MOUNT_PREFERENCE_KEY]: 'true', [LAST_MOUNTED_ROOT_KEY]: 'root-1' });

    clearLegacyAutoMount(storage);

    assert.equal(storage.has(AUTO_MOUNT_PREFERENCE_KEY), false);
    assert.equal(storage.has(LAST_MOUNTED_ROOT_KEY), false);
});
