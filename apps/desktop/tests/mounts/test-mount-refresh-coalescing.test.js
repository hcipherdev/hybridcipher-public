// Tests that refreshActiveMounts() in src/app.js shares one list_active_mounts request between overlapping calls, so polling cannot pile up requests behind a slow provider check.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const begin = source.indexOf('    async refreshActiveMounts(');
const finish = source.indexOf('    async maybeShowRecoveryPrompts(', begin);
assert.ok(begin >= 0 && finish > begin, 'Cannot extract refreshActiveMounts');

function appWith(invoke) {
    const App = Function('invoke', `return class { ${source.slice(begin, finish)} }`)(invoke);
    const app = new App();
    let renders = 0;
    Object.assign(app, {
        isLoggedIn: true,
        activeMountsByRootId: {},
        activeMountDetailsByRootId: {},
        reconciliationStartedAtByRootId: {},
        captureWorkspaceReadContext: () => () => true,
        notifyMissingKeyFolders() {},
        syncSelectedFolderMountUi() {},
        updateSidebarMountSummary() {},
        renderFolderList() { renders += 1; },
    });
    return { app, renders: () => renders };
}

test('overlapping refreshes make one backend request', async () => {
    let calls = 0;
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const { app, renders } = appWith(async () => {
        calls += 1;
        await gate;
        return { success: true, data: [{ root_id: 'r1', mountpoint: '/m/r1', backend: 'sync' }] };
    });

    const first = app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    const second = app.refreshActiveMounts({ renderFolderList: true, suppressRecoveryPrompt: true });
    const third = app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    release();
    const results = await Promise.all([first, second, third]);

    assert.equal(calls, 1);
    assert.deepEqual(results.map(result => result.r1), ['/m/r1', '/m/r1', '/m/r1']);
    assert.equal(renders(), 1, 'a caller that asked for a render still gets one');

    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    assert.equal(calls, 2, 'a later refresh asks the backend again');
});

test('a failed refresh does not block the next one', async () => {
    let calls = 0;
    const { app } = appWith(async () => {
        calls += 1;
        throw new Error('backend unavailable');
    });
    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    await app.refreshActiveMounts({ suppressRecoveryPrompt: true });
    assert.equal(calls, 2);
});
