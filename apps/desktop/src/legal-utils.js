(function (global) {
    const LEGAL_ACCEPTANCE_STORAGE_KEY = 'hybridcipher_legal_acceptance_v1';

    function normalizeOptionalString(value, maxLength = 128) {
        if (value == null) {
            return null;
        }
        const text = String(value).trim();
        if (!text) {
            return null;
        }
        return text.slice(0, maxLength);
    }

    function readStoredLegalAcceptance(storageLike) {
        const raw = storageLike?.getItem?.(LEGAL_ACCEPTANCE_STORAGE_KEY);
        if (!raw) {
            return null;
        }

        try {
            const parsed = JSON.parse(raw);
            const version = normalizeOptionalString(parsed?.version, 64);
            const acceptedAt = normalizeOptionalString(parsed?.acceptedAt, 64);
            if (!version || !acceptedAt) {
                return null;
            }
            return { version, acceptedAt };
        } catch (_error) {
            return null;
        }
    }

    function hasAcceptedLegalVersion(storageLike, version) {
        const normalizedVersion = normalizeOptionalString(version, 64);
        if (!normalizedVersion) {
            return false;
        }
        const stored = readStoredLegalAcceptance(storageLike);
        return stored?.version === normalizedVersion;
    }

    function saveLegalAcceptance(storageLike, version, acceptedAt = new Date().toISOString()) {
        const normalizedVersion = normalizeOptionalString(version, 64);
        const normalizedAcceptedAt = normalizeOptionalString(acceptedAt, 64);

        if (!normalizedVersion || !normalizedAcceptedAt) {
            throw new Error('version and acceptedAt are required');
        }

        const record = {
            version: normalizedVersion,
            acceptedAt: normalizedAcceptedAt,
        };

        storageLike?.setItem?.(LEGAL_ACCEPTANCE_STORAGE_KEY, JSON.stringify(record));
        return record;
    }

    const api = {
        LEGAL_ACCEPTANCE_STORAGE_KEY,
        readStoredLegalAcceptance,
        hasAcceptedLegalVersion,
        saveLegalAcceptance,
    };

    global.HybridCipherLegalUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
