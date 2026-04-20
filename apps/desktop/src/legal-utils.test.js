const test = require('node:test');
const assert = require('node:assert/strict');

const {
    LEGAL_ACCEPTANCE_STORAGE_KEY,
    readStoredLegalAcceptance,
    hasAcceptedLegalVersion,
    saveLegalAcceptance,
} = require('./legal-utils');

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

test('readStoredLegalAcceptance returns null for missing or invalid data', () => {
    assert.equal(readStoredLegalAcceptance(createStorage()), null);
    assert.equal(
        readStoredLegalAcceptance(
            createStorage({ [LEGAL_ACCEPTANCE_STORAGE_KEY]: '{not-json' })
        ),
        null
    );
    assert.equal(
        readStoredLegalAcceptance(
            createStorage({
                [LEGAL_ACCEPTANCE_STORAGE_KEY]: JSON.stringify({ acceptedAt: '2026-03-24T12:00:00.000Z' }),
            })
        ),
        null
    );
});

test('hasAcceptedLegalVersion matches stored version exactly', () => {
    const storage = createStorage({
        [LEGAL_ACCEPTANCE_STORAGE_KEY]: JSON.stringify({
            version: '2026-03-24',
            acceptedAt: '2026-03-24T12:00:00.000Z',
        }),
    });

    assert.equal(hasAcceptedLegalVersion(storage, '2026-03-24'), true);
    assert.equal(hasAcceptedLegalVersion(storage, '2026-03-25'), false);
    assert.equal(hasAcceptedLegalVersion(storage, ''), false);
});

test('saveLegalAcceptance persists version and accepted timestamp', () => {
    const storage = createStorage();
    const record = saveLegalAcceptance(storage, '2026-03-24', '2026-03-24T12:34:56.000Z');

    assert.deepEqual(record, {
        version: '2026-03-24',
        acceptedAt: '2026-03-24T12:34:56.000Z',
    });
    assert.deepEqual(readStoredLegalAcceptance(storage), record);
});

test('saveLegalAcceptance rejects missing version values', () => {
    const storage = createStorage();
    assert.throws(() => saveLegalAcceptance(storage, ''), /version and acceptedAt are required/);
});
