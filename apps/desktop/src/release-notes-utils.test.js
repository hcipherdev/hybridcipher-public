const test = require('node:test');
const assert = require('node:assert/strict');

const {
    RELEASE_NOTES_STATE_STORAGE_KEY,
    readStoredReleaseNotesState,
    saveReleaseNotesState,
    resolveReleaseNotesStartup,
    finalizeReleaseNotesVersion,
} = require('./release-notes-utils');

function createStorage(seed = {}) {
    const map = { ...seed };
    return {
        getItem(key) {
            return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
        },
        setItem(key, value) {
            map[key] = String(value);
        },
        removeItem(key) {
            delete map[key];
        },
        dump() {
            return { ...map };
        },
    };
}

test('readStoredReleaseNotesState returns null for missing or invalid data', () => {
    assert.equal(readStoredReleaseNotesState(createStorage()), null);
    assert.equal(
        readStoredReleaseNotesState(
            createStorage({ [RELEASE_NOTES_STATE_STORAGE_KEY]: '{not-json' })
        ),
        null
    );
    assert.equal(
        readStoredReleaseNotesState(
            createStorage({
                [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({ installedVersion: '0.1.0' }),
            })
        ),
        null
    );
});

test('saveReleaseNotesState persists installed and shown versions', () => {
    const storage = createStorage();
    const record = saveReleaseNotesState(storage, {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: '0.1.0',
    });

    assert.deepEqual(record, {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: '0.1.0',
    });
    assert.deepEqual(readStoredReleaseNotesState(storage), record);
});

test('resolveReleaseNotesStartup treats a missing record as a fresh install and stores current version', () => {
    const storage = createStorage();

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        releases: [
            {
                version: '0.1.0',
                published_at: '2026-03-25',
                highlights: ['New desktop release notes'],
                important_changes: [],
                fixes: [],
            },
        ],
    });

    assert.equal(result.shouldShow, false);
    assert.equal(result.reason, 'fresh-install');
    assert.deepEqual(readStoredReleaseNotesState(storage), {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: null,
    });
});

test('resolveReleaseNotesStartup skips when the installed version matches current version', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.1.0',
            releaseNotesShownVersion: '0.1.0',
        }),
    });

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        releases: [],
    });

    assert.equal(result.shouldShow, false);
    assert.equal(result.reason, 'current-version');
});

test('resolveReleaseNotesStartup shows concise notes for an update and marks the version as shown immediately', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.0.9',
            releaseNotesShownVersion: '0.0.9',
        }),
    });

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        releases: [
            {
                version: '0.0.9',
                published_at: '2026-03-20',
                highlights: ['Older note'],
                important_changes: [],
                fixes: [],
            },
            {
                version: '0.1.0',
                published_at: '2026-03-25',
                highlights: ['Safer unmount confirmation', 'Mount progress now names the folder'],
                important_changes: ['Folder enrollment errors explain permissions and already-protected cases'],
                fixes: ['Terminal prompt echo cleanup is more reliable'],
            },
        ],
    });

    assert.equal(result.shouldShow, true);
    assert.equal(result.previousVersion, '0.0.9');
    assert.equal(result.modal.title, 'What’s new in v0.1.0');
    assert.equal(
        result.modal.intro,
        'Updated from v0.0.9. Here are the most important changes in this release.'
    );
    assert.deepEqual(
        result.modal.sections.map(section => section.id),
        ['highlights', 'important-changes', 'fixes']
    );
    assert.deepEqual(
        readStoredReleaseNotesState(storage),
        {
            installedVersion: '0.0.9',
            releaseNotesShownVersion: '0.1.0',
        }
    );
});

test('resolveReleaseNotesStartup aggregates skipped versions in newest-first order and caps section items', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.0.8',
            releaseNotesShownVersion: null,
        }),
    });

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        sectionItemLimit: 2,
        releases: [
            {
                version: '0.0.9',
                published_at: '2026-03-20',
                highlights: ['Older highlight'],
                important_changes: ['Older important change'],
                fixes: ['Older fix'],
            },
            {
                version: '0.1.0',
                published_at: '2026-03-25',
                highlights: ['Newest highlight', 'Second newest highlight'],
                important_changes: ['Newest important change'],
                fixes: ['Newest fix'],
            },
        ],
    });

    assert.equal(result.shouldShow, true);
    assert.deepEqual(
        result.modal.sections.find(section => section.id === 'highlights').items,
        [
            { version: '0.1.0', text: 'Newest highlight' },
            { version: '0.1.0', text: 'Second newest highlight' },
        ]
    );
});

test('resolveReleaseNotesStartup silently advances the installed version when no current-version notes are bundled', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.0.9',
            releaseNotesShownVersion: null,
        }),
    });

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        releases: [
            {
                version: '0.0.9',
                published_at: '2026-03-20',
                highlights: ['Older note'],
                important_changes: [],
                fixes: [],
            },
        ],
    });

    assert.equal(result.shouldShow, false);
    assert.equal(result.reason, 'missing-current-version-notes');
    assert.deepEqual(readStoredReleaseNotesState(storage), {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: null,
    });
});

test('resolveReleaseNotesStartup advances the installed version when the current version was already shown', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.0.9',
            releaseNotesShownVersion: '0.1.0',
        }),
    });

    const result = resolveReleaseNotesStartup(storage, {
        currentVersion: '0.1.0',
        releases: [],
    });

    assert.equal(result.shouldShow, false);
    assert.equal(result.reason, 'already-shown');
    assert.deepEqual(readStoredReleaseNotesState(storage), {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: '0.1.0',
    });
});

test('finalizeReleaseNotesVersion persists the installed version after dismissal', () => {
    const storage = createStorage({
        [RELEASE_NOTES_STATE_STORAGE_KEY]: JSON.stringify({
            installedVersion: '0.0.9',
            releaseNotesShownVersion: '0.1.0',
        }),
    });

    finalizeReleaseNotesVersion(storage, '0.1.0');

    assert.deepEqual(readStoredReleaseNotesState(storage), {
        installedVersion: '0.1.0',
        releaseNotesShownVersion: '0.1.0',
    });
});
