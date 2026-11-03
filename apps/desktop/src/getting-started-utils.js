// Getting Started guide on Home and the first-run welcome copy, for the vault ("On this device only") and accounts.
(function (global) {
    const GUIDE_STORAGE_PREFIX = 'hybridcipher_getting_started_v1:';

    function fileManager(platform) {
        if (platform === 'macos') {
            return { name: 'Finder', where: 'It appears in Finder under Locations' };
        }
        if (platform === 'windows') {
            return { name: 'File Explorer', where: 'It appears in File Explorer’s navigation pane' };
        }
        return { name: 'your file manager', where: 'It opens in your file manager' };
    }

    function step(id, label, done, detail, doneDetail, action, actionLabel) {
        return { id, label, done: Boolean(done), detail: done ? doneDetail : detail, action, actionLabel };
    }

    /**
     * The Home checklist. Each step is ticked off from real state, never from a click.
     * Unknown MFA or device status (null) hides that step, so it never shows a false tick or cross.
     */
    function buildGettingStartedModel({
        mode = 'account',
        platform = '',
        kitSaved = false,
        folderCount = 0,
        mounted = false,
        mfaEnabled = null,
        deviceVerified = null,
        dismissed = false,
    } = {}) {
        // Team has its own To-do panel.
        if (mode === 'team') return { visible: false, steps: [], optional: null, allDone: false };
        const files = fileManager(platform);
        const steps = [];
        if (mode === 'vault') {
            steps.push(step('kit', 'Save your recovery kit', kitSaved,
                'It’s the only way back into your files if this computer is lost. Keep it somewhere other than this computer.',
                'Saved. Keep the kit file and its key somewhere other than this computer.',
                'open-local-kit', 'Save recovery kit'));
        }
        steps.push(step('folder', 'Protect your first folder', folderCount > 0,
            'Choose a folder. Its files are encrypted in place with post-quantum protection.',
            folderCount === 1 ? '1 folder is protected.' : `${folderCount} folders are protected.`,
            'add-protected-folder', 'Choose a folder'));
        steps.push(step('mount', `Open it in ${files.name}`, mounted,
            `Mount your folder to work with it. ${files.where}.`,
            'Files you save in the mounted folder are encrypted automatically.',
            'mount-first-folder', 'Mount folder'));
        if (mode === 'account') {
            if (mfaEnabled !== null) {
                steps.push(step('mfa', 'Turn on two-step sign-in', mfaEnabled,
                    'A code from your authenticator app keeps your account safe even if your password leaks.',
                    'Two-step sign-in is on.',
                    'open-settings-mfa', 'Turn on'));
            }
            if (deviceVerified !== null) {
                steps.push(step('device', 'Verify this device', deviceVerified,
                    'Confirm its fingerprint so your other devices and your team can trust it.',
                    'This device is verified.',
                    'open-devices', 'Open Devices'));
            }
        }
        // Only the next step to do gets a button; the rest show their status.
        const next = steps.find(entry => !entry.done);
        for (const entry of steps) entry.primary = entry === next;
        const doneCount = steps.filter(entry => entry.done).length;
        const allDone = doneCount === steps.length;
        return {
            visible: !dismissed,
            title: allDone ? 'You’re all set' : 'Get started',
            progress: `${doneCount} of ${steps.length} done`,
            steps,
            optional: mode === 'vault' ? {
                label: 'Use your files on other devices',
                detail: 'Create an account when you need it. Your protected folders become part of it.',
                action: 'open-local-upgrade',
                actionLabel: 'Create account',
            } : null,
            allDone,
        };
    }

    /** First-run welcome: the vault variant follows opening the app straight into the vault. */
    function firstRunWelcomeModel(mode, platform = '') {
        if (mode === 'vault') {
            return {
                vault: true,
                title: 'You’re ready to protect files',
                subtitle: 'No account needed. Your files are protected on this computer, and you can add an account later.',
                steps: [
                    { title: '1. Save your recovery kit', desc: 'Your way back in if this computer is lost.' },
                    { title: '2. Protect a folder', desc: 'Its files are encrypted in place.' },
                    { title: `3. Open it in ${fileManager(platform).name}`, desc: 'Work with your files as usual; they stay encrypted.' },
                ],
            };
        }
        return {
            vault: false,
            title: 'Welcome to HybridCipher',
            subtitle: 'Secure collaboration that stays secure as your team grows.',
            steps: [
                { title: '1. Start', desc: 'Start on this device right away, or sign in to use your files on other devices.' },
                { title: '2. Verify devices', desc: 'Confirm fingerprints so only trusted devices can join.' },
                { title: '3. Enroll folders', desc: 'Pick the folders you want protected and shared.' },
            ],
        };
    }

    function guideStorageKey(identity) {
        return `${GUIDE_STORAGE_PREFIX}${String(identity || '').toLowerCase()}`;
    }

    /** Per vault or account: whether the guide was dismissed and whether a folder was ever mounted. */
    function readGuideState(storageLike, identity) {
        const fallback = { dismissed: false, mountedOnce: false };
        if (!identity) return fallback;
        try {
            const parsed = JSON.parse(storageLike?.getItem?.(guideStorageKey(identity)) || 'null');
            return {
                dismissed: parsed?.dismissed === true,
                mountedOnce: parsed?.mountedOnce === true,
            };
        } catch (_error) {
            return fallback;
        }
    }

    function saveGuideState(storageLike, identity, changes) {
        if (!identity) return readGuideState(storageLike, identity);
        const next = { ...readGuideState(storageLike, identity), ...changes };
        try {
            storageLike?.setItem?.(guideStorageKey(identity), JSON.stringify(next));
        } catch (_error) {
            // Storage can be unavailable; the guide then simply starts over next launch.
        }
        return next;
    }

    const api = {
        GUIDE_STORAGE_PREFIX,
        buildGettingStartedModel,
        firstRunWelcomeModel,
        readGuideState,
        saveGuideState,
    };

    global.HybridCipherGettingStartedUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
