(function (global) {
    const AUTO_MOUNT_PREFERENCE_KEY = 'hybridcipher_auto_mount_last_folder';
    const LAST_MOUNTED_ROOT_KEY = 'hybridcipher_last_mounted_root_id';

    function safeGetItem(storage, key) {
        if (!storage || typeof storage.getItem !== 'function') {
            return null;
        }

        try {
            return storage.getItem(key);
        } catch (_error) {
            return null;
        }
    }

    function safeSetItem(storage, key, value) {
        if (!storage || typeof storage.setItem !== 'function') {
            return;
        }

        try {
            storage.setItem(key, value);
        } catch (_error) {
            // Ignore storage failures and fall back to in-memory behavior.
        }
    }

    function safeRemoveItem(storage, key) {
        if (!storage || typeof storage.removeItem !== 'function') {
            return;
        }

        try {
            storage.removeItem(key);
        } catch (_error) {
            // Ignore storage failures and fall back to in-memory behavior.
        }
    }

    function loadAutoMountPreference(storage) {
        const stored = safeGetItem(storage, AUTO_MOUNT_PREFERENCE_KEY);
        if (stored === null) {
            return true;
        }
        return stored === 'true';
    }

    function saveAutoMountPreference(storage, enabled) {
        safeSetItem(storage, AUTO_MOUNT_PREFERENCE_KEY, enabled ? 'true' : 'false');
    }

    function loadLastMountedRootId(storage) {
        const stored = String(safeGetItem(storage, LAST_MOUNTED_ROOT_KEY) || '').trim();
        return stored || null;
    }

    function saveLastMountedRootId(storage, rootId) {
        const normalized = String(rootId || '').trim();
        if (!normalized) {
            safeRemoveItem(storage, LAST_MOUNTED_ROOT_KEY);
            return;
        }
        safeSetItem(storage, LAST_MOUNTED_ROOT_KEY, normalized);
    }

    function resolveAutoMountFolder({
        storage,
        enrolledFolders = [],
        activeMountsByRootId = {},
    } = {}) {
        if (!loadAutoMountPreference(storage)) {
            return null;
        }

        const rootId = loadLastMountedRootId(storage);
        if (!rootId) {
            return null;
        }

        if (activeMountsByRootId && activeMountsByRootId[rootId]) {
            return null;
        }

        if (!Array.isArray(enrolledFolders)) {
            return null;
        }

        return enrolledFolders.find(folder => String(folder?.root_id || '').trim() === rootId) || null;
    }

    const api = {
        AUTO_MOUNT_PREFERENCE_KEY,
        LAST_MOUNTED_ROOT_KEY,
        loadAutoMountPreference,
        saveAutoMountPreference,
        loadLastMountedRootId,
        saveLastMountedRootId,
        resolveAutoMountFolder,
    };

    global.HybridCipherAutoMountUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
