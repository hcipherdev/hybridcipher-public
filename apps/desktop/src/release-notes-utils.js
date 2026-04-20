(function (global) {
    const RELEASE_NOTES_STATE_STORAGE_KEY = 'hybridcipher_release_notes_state_v1';

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

    function normalizeState(candidate) {
        const installedVersion = normalizeOptionalString(candidate?.installedVersion, 64);
        if (!installedVersion) {
            return null;
        }
        if (!Object.prototype.hasOwnProperty.call(candidate || {}, 'releaseNotesShownVersion')) {
            return null;
        }
        const releaseNotesShownVersion = normalizeOptionalString(candidate?.releaseNotesShownVersion, 64);
        return {
            installedVersion,
            releaseNotesShownVersion,
        };
    }

    function readStoredReleaseNotesState(storageLike) {
        const raw = storageLike?.getItem?.(RELEASE_NOTES_STATE_STORAGE_KEY);
        if (!raw) {
            return null;
        }

        try {
            return normalizeState(JSON.parse(raw));
        } catch (_error) {
            return null;
        }
    }

    function saveReleaseNotesState(storageLike, state) {
        const normalizedState = normalizeState(state);
        if (!normalizedState) {
            throw new Error('installedVersion is required');
        }
        storageLike?.setItem?.(RELEASE_NOTES_STATE_STORAGE_KEY, JSON.stringify(normalizedState));
        return normalizedState;
    }

    function finalizeReleaseNotesVersion(storageLike, currentVersion) {
        const normalizedVersion = normalizeOptionalString(currentVersion, 64);
        if (!normalizedVersion) {
            throw new Error('currentVersion is required');
        }

        const currentState = readStoredReleaseNotesState(storageLike) || {
            installedVersion: normalizedVersion,
            releaseNotesShownVersion: null,
        };

        return saveReleaseNotesState(storageLike, {
            installedVersion: normalizedVersion,
            releaseNotesShownVersion: currentState.releaseNotesShownVersion,
        });
    }

    function parseVersion(version) {
        const normalized = normalizeOptionalString(version, 64);
        if (!normalized) {
            return [];
        }
        return normalized
            .replace(/^v/i, '')
            .split('.')
            .map((part) => Number.parseInt(part, 10))
            .map((value) => (Number.isFinite(value) ? value : 0));
    }

    function compareVersions(left, right) {
        const leftParts = parseVersion(left);
        const rightParts = parseVersion(right);
        const length = Math.max(leftParts.length, rightParts.length);
        for (let index = 0; index < length; index += 1) {
            const leftValue = leftParts[index] ?? 0;
            const rightValue = rightParts[index] ?? 0;
            if (leftValue > rightValue) {
                return 1;
            }
            if (leftValue < rightValue) {
                return -1;
            }
        }
        return 0;
    }

    function normalizeReleaseEntry(entry) {
        const version = normalizeOptionalString(entry?.version, 64);
        if (!version) {
            return null;
        }

        const normalizeItems = (items) => (
            Array.isArray(items)
                ? items.map(item => normalizeOptionalString(item, 240)).filter(Boolean)
                : []
        );

        return {
            version,
            published_at: normalizeOptionalString(entry?.published_at, 64) || '',
            highlights: normalizeItems(entry?.highlights),
            important_changes: normalizeItems(entry?.important_changes),
            fixes: normalizeItems(entry?.fixes),
        };
    }

    function buildSection(id, title, releases, fieldName, sectionItemLimit) {
        const items = [];

        for (const release of releases) {
            for (const text of release[fieldName]) {
                items.push({ version: release.version, text });
                if (items.length >= sectionItemLimit) {
                    return { id, title, items };
                }
            }
        }

        if (items.length === 0) {
            return null;
        }

        return { id, title, items };
    }

    function buildReleaseNotesModal({
        currentVersion,
        previousVersion,
        releases,
        sectionItemLimit = 3,
    }) {
        const normalizedCurrentVersion = normalizeOptionalString(currentVersion, 64);
        const normalizedPreviousVersion = normalizeOptionalString(previousVersion, 64);
        const limitedItemCount = Math.max(1, Number.parseInt(sectionItemLimit, 10) || 3);
        const normalizedReleases = Array.isArray(releases)
            ? releases.map(normalizeReleaseEntry).filter(Boolean)
            : [];

        const relevantReleases = normalizedReleases
            .filter((release) => compareVersions(release.version, normalizedPreviousVersion) > 0)
            .filter((release) => compareVersions(release.version, normalizedCurrentVersion) <= 0)
            .sort((left, right) => compareVersions(right.version, left.version));

        const sections = [
            buildSection('highlights', 'Highlights', relevantReleases, 'highlights', limitedItemCount),
            buildSection('important-changes', 'Important changes', relevantReleases, 'important_changes', limitedItemCount),
            buildSection('fixes', 'Fixes', relevantReleases, 'fixes', limitedItemCount),
        ].filter(Boolean);

        if (sections.length === 0) {
            return null;
        }

        return {
            title: `What’s new in v${normalizedCurrentVersion}`,
            intro: normalizedPreviousVersion
                ? `Updated from v${normalizedPreviousVersion}. Here are the most important changes in this release.`
                : 'Here are the most important changes in this release.',
            sections,
        };
    }

    function resolveReleaseNotesStartup(storageLike, {
        currentVersion,
        releases,
        sectionItemLimit = 3,
    } = {}) {
        const normalizedCurrentVersion = normalizeOptionalString(currentVersion, 64);
        if (!normalizedCurrentVersion) {
            return {
                shouldShow: false,
                reason: 'missing-current-version',
                currentVersion: null,
                previousVersion: null,
                modal: null,
            };
        }

        const storedState = readStoredReleaseNotesState(storageLike);
        if (!storedState) {
            saveReleaseNotesState(storageLike, {
                installedVersion: normalizedCurrentVersion,
                releaseNotesShownVersion: null,
            });
            return {
                shouldShow: false,
                reason: 'fresh-install',
                currentVersion: normalizedCurrentVersion,
                previousVersion: null,
                modal: null,
            };
        }

        if (storedState.installedVersion === normalizedCurrentVersion) {
            return {
                shouldShow: false,
                reason: 'current-version',
                currentVersion: normalizedCurrentVersion,
                previousVersion: storedState.installedVersion,
                modal: null,
            };
        }

        if (storedState.releaseNotesShownVersion === normalizedCurrentVersion) {
            saveReleaseNotesState(storageLike, {
                installedVersion: normalizedCurrentVersion,
                releaseNotesShownVersion: normalizedCurrentVersion,
            });
            return {
                shouldShow: false,
                reason: 'already-shown',
                currentVersion: normalizedCurrentVersion,
                previousVersion: normalizedCurrentVersion,
                modal: null,
            };
        }

        const normalizedReleases = Array.isArray(releases)
            ? releases.map(normalizeReleaseEntry).filter(Boolean)
            : [];
        const hasCurrentVersionNotes = normalizedReleases.some(
            (release) => release.version === normalizedCurrentVersion
        );

        if (!hasCurrentVersionNotes) {
            saveReleaseNotesState(storageLike, {
                installedVersion: normalizedCurrentVersion,
                releaseNotesShownVersion: storedState.releaseNotesShownVersion,
            });
            return {
                shouldShow: false,
                reason: 'missing-current-version-notes',
                currentVersion: normalizedCurrentVersion,
                previousVersion: storedState.installedVersion,
                modal: null,
            };
        }

        const modal = buildReleaseNotesModal({
            currentVersion: normalizedCurrentVersion,
            previousVersion: storedState.installedVersion,
            releases: normalizedReleases,
            sectionItemLimit,
        });

        if (!modal) {
            saveReleaseNotesState(storageLike, {
                installedVersion: normalizedCurrentVersion,
                releaseNotesShownVersion: storedState.releaseNotesShownVersion,
            });
            return {
                shouldShow: false,
                reason: 'empty-notes',
                currentVersion: normalizedCurrentVersion,
                previousVersion: storedState.installedVersion,
                modal: null,
            };
        }

        saveReleaseNotesState(storageLike, {
            installedVersion: storedState.installedVersion,
            releaseNotesShownVersion: normalizedCurrentVersion,
        });

        return {
            shouldShow: true,
            reason: 'show-update-notes',
            currentVersion: normalizedCurrentVersion,
            previousVersion: storedState.installedVersion,
            modal,
        };
    }

    const api = {
        RELEASE_NOTES_STATE_STORAGE_KEY,
        readStoredReleaseNotesState,
        saveReleaseNotesState,
        resolveReleaseNotesStartup,
        finalizeReleaseNotesVersion,
    };

    global.HybridCipherReleaseNotesUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
