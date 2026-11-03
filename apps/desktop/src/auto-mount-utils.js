(function (global) {
    // Settings of the older "auto-mount last folder" option, read once to carry it over.
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

    function safeRemoveItem(storage, key) {
        if (!storage || typeof storage.removeItem !== 'function') {
            return;
        }

        try {
            storage.removeItem(key);
        } catch (_error) {
            // Ignore storage failures; the old keys are only read once.
        }
    }

    // The folder the older option would have mounted, or null. That option was on unless
    // switched off, and remembered only the last folder mounted.
    function readLegacyAutoMountSeed(storage) {
        if (safeGetItem(storage, AUTO_MOUNT_PREFERENCE_KEY) === 'false') {
            return null;
        }
        const rootId = String(safeGetItem(storage, LAST_MOUNTED_ROOT_KEY) || '').trim();
        return rootId || null;
    }

    function clearLegacyAutoMount(storage) {
        safeRemoveItem(storage, AUTO_MOUNT_PREFERENCE_KEY);
        safeRemoveItem(storage, LAST_MOUNTED_ROOT_KEY);
    }

    function folderLabel(folder) {
        return String(folder?.name || folder?.path || folder?.root_id || 'Folder');
    }

    // Splits the folders chosen for auto-mount into those to mount now and those that
    // cannot be mounted on this device. Mounted folders and those already being worked on
    // are left out.
    function planAutoMount(overview, { busyRootIds = [] } = {}) {
        const busy = new Set(Array.from(busyRootIds || [], String));
        const folders = Array.isArray(overview?.folders) ? overview.folders : [];
        const queue = [];
        const attention = [];
        for (const folder of folders) {
            const rootId = String(folder?.root_id || '');
            if (!rootId || !folder?.auto_mount || folder?.mount || busy.has(rootId)) continue;
            if (folder.can_mount) {
                queue.push(folder);
            } else {
                attention.push({
                    rootId,
                    name: folderLabel(folder),
                    reason: String(folder.blocked_reason || 'This folder cannot be mounted on this device.'),
                });
            }
        }
        return { queue, attention };
    }

    // One result per attempted folder: { rootId, name, status, error, fallbackReason, degraded }.
    // A clean run produces no message; anything that failed, was skipped as unmountable, is
    // unhealthy, or fell back to sync mounting is listed and counted once.
    function summarizeBackgroundMounts(results = [], attention = [], { stopped = false } = {}) {
        const list = Array.isArray(results) ? results : [];
        const needsAttention = Array.isArray(attention) ? attention.slice() : [];
        let mounted = 0;
        for (const result of list) {
            const name = String(result?.name || result?.rootId || 'Folder');
            const rootId = String(result?.rootId || '');
            if (result?.status === 'mounted' || result?.status === 'already') {
                mounted += 1;
                if (result.degraded) {
                    needsAttention.push({ rootId, name, reason: 'Mounted, but its file provider is unhealthy.' });
                } else if (result.fallbackReason) {
                    needsAttention.push({ rootId, name, reason: `Mounted with sync fallback. ${result.fallbackReason}` });
                }
            } else if (result?.status === 'failed') {
                needsAttention.push({ rootId, name, reason: String(result.error || 'Mount failed.') });
            }
        }
        // Folders the user was mounting by hand are not counted; unmountable ones are.
        const attempted = list.filter(result => result?.status !== 'busy').length
            + (Array.isArray(attention) ? attention.length : 0);
        let message = null;
        if (needsAttention.length > 0) {
            message = `Auto-mount: ${mounted} of ${attempted} folder${attempted === 1 ? '' : 's'} mounted. `
                + `${needsAttention.length} need${needsAttention.length === 1 ? 's' : ''} attention.`;
        }
        if (stopped) {
            message = `Auto-mount stopped after ${mounted} folder${mounted === 1 ? '' : 's'}.`
                + (needsAttention.length > 0 ? ` ${needsAttention.length} need${needsAttention.length === 1 ? 's' : ''} attention.` : '');
        }
        return { mounted, attempted, needsAttention, message };
    }

    // The `mounts_reconnected` event as mount jobs, so it is summarized like a background
    // mount batch: reconnected folders count as mounted, the others as failed.
    function reconnectedMountJobs(payload) {
        const reconnected = Array.isArray(payload?.reconnected) ? payload.reconnected : [];
        const failed = Array.isArray(payload?.failed) ? payload.failed : [];
        return reconnected
            .map(rootId => ({ root_id: String(rootId), name: String(rootId), status: 'ready' }))
            .concat(failed.map(failure => ({
                root_id: String(failure?.root_id || ''),
                name: folderLabel(failure),
                status: 'failed',
                error: String(failure?.error || 'This folder could not be reconnected.'),
            })));
    }

    const api = {
        AUTO_MOUNT_PREFERENCE_KEY,
        LAST_MOUNTED_ROOT_KEY,
        readLegacyAutoMountSeed,
        clearLegacyAutoMount,
        planAutoMount,
        summarizeBackgroundMounts,
        reconnectedMountJobs,
    };

    global.HybridCipherAutoMountUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
