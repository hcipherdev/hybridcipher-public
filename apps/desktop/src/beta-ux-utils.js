(function (global) {
    function normalizeLines(lines = []) {
        return Array.isArray(lines)
            ? lines.map(line => String(line || ''))
            : [String(lines || '')];
    }

    function classifyEnrollmentFailure({ folderPath = '', lines = [] } = {}) {
        const normalizedLines = normalizeLines(lines);
        const text = normalizedLines.join('\n').toLowerCase();

        if (/permission denied|operation not permitted|access denied|not authorized/.test(text)) {
            return {
                kind: 'permission-denied',
                title: 'HybridCipher could not access this folder',
                detail: `Check macOS folder permissions or Full Disk Access, then try protecting "${folderPath}" again.`,
                retryLabel: 'Choose another folder',
            };
        }

        if (/already enrolled|already protected|already exists/.test(text)) {
            return {
                kind: 'already-enrolled',
                title: 'This folder is already protected',
                detail: 'Refresh the protected-folder list and open the existing entry instead of enrolling it again.',
                retryLabel: 'Refresh folders',
            };
        }

        if (/no such file|not found|does not exist|missing/.test(text)) {
            return {
                kind: 'missing-path',
                title: 'HybridCipher could not find this folder',
                detail: `The selected path no longer exists or is unavailable: "${folderPath}". Choose the folder again and retry.`,
                retryLabel: 'Choose folder again',
            };
        }

        return {
            kind: 'generic',
            title: 'HybridCipher could not protect this folder',
            detail: 'Review the terminal output for the exact CLI error, then retry after correcting the path or permissions.',
            retryLabel: 'Try again',
        };
    }

    function buildForceUnmountConfirmation({
        folderLabel = 'all mounted folders',
        folderPath = '',
        unsafeReasons = [],
    } = {}) {
        const reasons = Array.isArray(unsafeReasons) ? unsafeReasons.filter(Boolean) : [];
        const detailLines = [
            `You are about to force unmount ${folderLabel}.`,
            folderPath ? `Path: ${folderPath}` : '',
            reasons.length > 0 ? `Unsafe state: ${reasons.join(' ')}` : '',
            '',
            'This may cause file loss or leave the newest local changes unprotected.',
            'Type FORCE to confirm that you want to continue.'
        ].filter(Boolean);

        return {
            title: `Force unmount ${folderLabel}`,
            message: `Force unmount ${folderLabel}?`,
            detail: detailLines.join('\n'),
            confirmationToken: 'FORCE',
        };
    }

    function buildMountProgressModel({
        folderLabel = 'folder',
        folderPath = '',
        elapsedMs = 0,
        continueEnableMs = 10000,
    } = {}) {
        const remainingMs = Math.max(0, Number(continueEnableMs || 0) - Number(elapsedMs || 0));
        const remainingSecs = Math.ceil(remainingMs / 1000);
        const canContinue = remainingMs <= 0;

        return {
            title: `Mounting ${folderLabel}`,
            folderLabel,
            folderPath,
            status: canContinue ? 'Mounting folder in background...' : 'Starting mount...',
            hint: canContinue
                ? 'You can continue in background and keep using the app while HybridCipher finishes mounting this folder.'
                : `Continue in background available in ${remainingSecs}s while HybridCipher initializes this folder.`,
            canContinue,
        };
    }

    function buildMountTimeoutMessage({
        folderLabel = 'folder',
        folderPath = '',
        inBackground = false,
    } = {}) {
        const modePrefix = inBackground
            ? `Mount for ${folderLabel} did not finish in the background.`
            : `Mount for ${folderLabel} did not finish.`;

        return [
            modePrefix,
            folderPath ? `Folder: ${folderPath}.` : '',
            'Review the embedded terminal output for the mount command, then retry if needed.',
            'Before retrying, check whether the folder is already mounted.'
        ].filter(Boolean).join(' ');
    }

    const api = {
        classifyEnrollmentFailure,
        buildForceUnmountConfirmation,
        buildMountProgressModel,
        buildMountTimeoutMessage,
    };

    global.HybridCipherBetaUxUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
