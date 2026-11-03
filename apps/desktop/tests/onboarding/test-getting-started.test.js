// Tests buildGettingStartedModel, firstRunWelcomeModel, readGuideState and saveGuideState in src/getting-started-utils.js.
const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildGettingStartedModel,
    firstRunWelcomeModel,
    readGuideState,
    saveGuideState,
} = require('../../src/getting-started-utils.js');

function memoryStorage() {
    const values = new Map();
    return {
        getItem: key => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => values.set(key, String(value)),
    };
}

const ids = model => model.steps.map(step => step.id);
const next = model => model.steps.find(step => step.primary)?.id;

test('the vault guide walks through kit, first folder and mounting', () => {
    const start = buildGettingStartedModel({ mode: 'vault', platform: 'macos' });
    assert.deepEqual(ids(start), ['kit', 'folder', 'mount']);
    assert.equal(next(start), 'kit');
    assert.equal(start.steps[0].action, 'open-local-kit');
    assert.equal(start.title, 'Get started');
    assert.equal(start.progress, '0 of 3 done');
    assert.equal(start.optional.action, 'open-local-upgrade');
    assert.equal(start.steps.filter(step => step.primary).length, 1, 'only the next step has a button');

    const kit = buildGettingStartedModel({ mode: 'vault', platform: 'macos', kitSaved: true });
    assert.equal(next(kit), 'folder');
    assert.equal(kit.steps[1].action, 'add-protected-folder');

    const folder = buildGettingStartedModel({ mode: 'vault', platform: 'macos', kitSaved: true, folderCount: 2 });
    assert.equal(next(folder), 'mount');
    assert.equal(folder.steps[1].detail, '2 folders are protected.');
    assert.equal(folder.steps[2].action, 'mount-first-folder');

    const done = buildGettingStartedModel({ mode: 'vault', platform: 'macos', kitSaved: true, folderCount: 1, mounted: true });
    assert.equal(done.allDone, true);
    assert.equal(done.title, 'You’re all set');
    assert.equal(next(done), undefined);
    assert.match(done.steps[2].detail, /encrypted automatically/);
});

test('account steps leave out the kit and hide status nobody knows yet', () => {
    const unknown = buildGettingStartedModel({ mode: 'account' });
    assert.deepEqual(ids(unknown), ['folder', 'mount'], 'no false tick or cross while status is unknown');
    assert.equal(unknown.optional, null);

    const known = buildGettingStartedModel({ mode: 'account', mfaEnabled: true, deviceVerified: false });
    assert.deepEqual(ids(known), ['folder', 'mount', 'mfa', 'device']);
    assert.equal(next(known), 'folder', 'a step already done further down never jumps the queue');
    assert.equal(known.steps.find(step => step.id === 'mfa').done, true);

    const rest = buildGettingStartedModel({ mode: 'account', folderCount: 1, mounted: true, mfaEnabled: true, deviceVerified: false });
    assert.equal(next(rest), 'device');
    assert.equal(rest.steps.at(-1).action, 'open-devices');
});

test('Team has its own To-do panel, and a dismissed guide stays hidden', () => {
    assert.equal(buildGettingStartedModel({ mode: 'team' }).visible, false);
    assert.equal(buildGettingStartedModel({ mode: 'vault', dismissed: true }).visible, false);
    assert.equal(buildGettingStartedModel({ mode: 'vault' }).visible, true);
});

test('the mount step names the platform’s file manager', () => {
    const label = platform => buildGettingStartedModel({ mode: 'vault', platform }).steps[2];
    assert.equal(label('macos').label, 'Open it in Finder');
    assert.match(label('macos').detail, /Locations/);
    assert.equal(label('windows').label, 'Open it in File Explorer');
    assert.match(label('windows').detail, /navigation pane/);
    assert.equal(label('linux').label, 'Open it in your file manager');
});

test('the first-run welcome explains next steps in the vault and keeps the account copy otherwise', () => {
    const vault = firstRunWelcomeModel('vault', 'windows');
    assert.equal(vault.vault, true);
    assert.equal(vault.steps.length, 3);
    assert.match(vault.steps[2].title, /File Explorer/);
    const account = firstRunWelcomeModel('account');
    assert.equal(account.vault, false);
    assert.equal(account.title, 'Welcome to HybridCipher');
});

test('guide state is kept per vault or account and survives broken storage', () => {
    const storage = memoryStorage();
    assert.deepEqual(readGuideState(storage, 'vault:abc'), { dismissed: false, mountedOnce: false });
    saveGuideState(storage, 'vault:abc', { mountedOnce: true });
    saveGuideState(storage, 'vault:abc', { dismissed: true });
    assert.deepEqual(readGuideState(storage, 'vault:abc'), { dismissed: true, mountedOnce: true });
    assert.deepEqual(readGuideState(storage, 'Me@Example.test'), { dismissed: false, mountedOnce: false });
    saveGuideState(storage, 'Me@Example.test', { dismissed: true });
    assert.equal(readGuideState(storage, 'me@example.test').dismissed, true, 'emails ignore case');

    storage.setItem('hybridcipher_getting_started_v1:broken', '{not json');
    assert.deepEqual(readGuideState(storage, 'broken'), { dismissed: false, mountedOnce: false });
    const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
    assert.deepEqual(saveGuideState(throwing, 'x', { dismissed: true }), { dismissed: true, mountedOnce: false },
        'blocked storage still answers for this session');
    assert.deepEqual(readGuideState(storage, null), { dismissed: false, mountedOnce: false }, 'no identity, nothing saved');
});
