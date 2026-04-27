const test = require('node:test');
const assert = require('node:assert/strict');

const {
    AUTO_MOUNT_PREFERENCE_KEY,
    LAST_MOUNTED_ROOT_KEY,
    loadAutoMountPreference,
    saveAutoMountPreference,
    loadLastMountedRootId,
    saveLastMountedRootId,
    resolveAutoMountFolder,
} = require('./auto-mount-utils');

function createStorage(initialValues = {}) {
    const values = new Map(Object.entries(initialValues));
    return {
        getItem(key) {
            return values.has(key) ? values.get(key) : null;
        },
        setItem(key, value) {
            values.set(key, String(value));
        },
        removeItem(key) {
            values.delete(key);
        },
    };
}

test('loadAutoMountPreference defaults to enabled when nothing is stored', () => {
    const storage = createStorage();

    assert.equal(loadAutoMountPreference(storage), true);
});

test('loadAutoMountPreference honors a stored opt-out', () => {
    const storage = createStorage({
        [AUTO_MOUNT_PREFERENCE_KEY]: 'false',
    });

    assert.equal(loadAutoMountPreference(storage), false);
});

test('saveAutoMountPreference persists boolean values as strings', () => {
    const storage = createStorage();

    saveAutoMountPreference(storage, false);

    assert.equal(storage.getItem(AUTO_MOUNT_PREFERENCE_KEY), 'false');
});

test('saveLastMountedRootId persists the most recent mounted root id', () => {
    const storage = createStorage();

    saveLastMountedRootId(storage, 'root-123');

    assert.equal(loadLastMountedRootId(storage), 'root-123');
});

test('saveLastMountedRootId clears the stored value when given an empty id', () => {
    const storage = createStorage({
        [LAST_MOUNTED_ROOT_KEY]: 'root-123',
    });

    saveLastMountedRootId(storage, '');

    assert.equal(loadLastMountedRootId(storage), null);
});

test('resolveAutoMountFolder returns the enrolled folder matching the stored root id', () => {
    const storage = createStorage({
        [LAST_MOUNTED_ROOT_KEY]: 'root-2',
    });
    const folders = [
        { root_id: 'root-1', path: '/tmp/a' },
        { root_id: 'root-2', path: '/tmp/b' },
    ];

    const folder = resolveAutoMountFolder({
        storage,
        enrolledFolders: folders,
        activeMountsByRootId: {},
    });

    assert.deepEqual(folder, folders[1]);
});

test('resolveAutoMountFolder skips restore when auto-mount is disabled', () => {
    const storage = createStorage({
        [AUTO_MOUNT_PREFERENCE_KEY]: 'false',
        [LAST_MOUNTED_ROOT_KEY]: 'root-2',
    });

    const folder = resolveAutoMountFolder({
        storage,
        enrolledFolders: [{ root_id: 'root-2', path: '/tmp/b' }],
        activeMountsByRootId: {},
    });

    assert.equal(folder, null);
});

test('resolveAutoMountFolder skips restore when the folder is already mounted', () => {
    const storage = createStorage({
        [LAST_MOUNTED_ROOT_KEY]: 'root-2',
    });

    const folder = resolveAutoMountFolder({
        storage,
        enrolledFolders: [{ root_id: 'root-2', path: '/tmp/b' }],
        activeMountsByRootId: { 'root-2': '/Volumes/HybridCipher/b' },
    });

    assert.equal(folder, null);
});

test('resolveAutoMountFolder skips restore when the stored folder is no longer enrolled', () => {
    const storage = createStorage({
        [LAST_MOUNTED_ROOT_KEY]: 'root-2',
    });

    const folder = resolveAutoMountFolder({
        storage,
        enrolledFolders: [{ root_id: 'root-1', path: '/tmp/a' }],
        activeMountsByRootId: {},
    });

    assert.equal(folder, null);
});
