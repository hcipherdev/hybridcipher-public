// Tests runUnmountBatch(), storeUnmountFolder() and applyUnmountProgress() in src/app.js: the window opens before the unsaved-changes check, cancel and force are honoured, results apply without events, background runs report once, and a second request joins the running batch.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildUnmountProgressModel } = uiScope.HybridCipherUiUtils;

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const extract = (from, to) => {
    const begin = source.indexOf(from);
    const finish = source.indexOf(to, begin);
    assert.ok(begin >= 0 && finish > begin, `Cannot extract ${from.trim()}`);
    return source.slice(begin, finish);
};
const methods = extract('    async runUnmountBatch(', '    unmountPlatform() {')
    + extract('    storeUnmountFolder(', '    refreshUnmountUi() {');
const plain = value => JSON.parse(JSON.stringify(value));

function appWith({ decision = 'safe', response, beforeResult = null } = {}) {
    const calls = { invoke: [], notifications: [], events: [] };
    const invoke = async (command, args) => {
        calls.invoke.push([command, args]);
        if (command !== 'unmount_mounts') return { success: true };
        if (beforeResult) await beforeResult(app);
        return response;
    };
    const App = Function('invoke', 'buildUnmountProgressModelValue', `return class { ${methods} }`)(invoke, buildUnmountProgressModel);
    const app = new App();
    let windowVisible = false;
    Object.assign(app, {
        activeMountDetailsByRootId: { a: {}, b: {} },
        unmountingRootIds: new Set(),
        mountSessions: {},
        unmountBatch: null,
        captureAccountReadContext: () => () => true,
        unmountFolderName: rootId => ({ a: 'Taxes', b: 'Specs' })[rootId] || rootId,
        async promptUnsafeUnmountDecision(options) {
            calls.events.push(['precheck', windowVisible, plain(options.rootIds)]);
            return decision;
        },
        showUnmountWindow() {
            windowVisible = true;
            if (this.unmountBatch) this.unmountBatch.background = false;
            calls.events.push(['show']);
        },
        hideUnmountWindow() { windowVisible = false; calls.events.push(['hide']); },
        isUnmountWindowVisible: () => windowVisible,
        closeUnmountWindow() { windowVisible = false; },
        renderUnmountWindow() {},
        refreshUnmountUi() {},
        async refreshActiveMounts() {},
        async refreshMountCenter() {},
        updateTerminalCwdDisplay() {},
        unmountPlatform: () => 'macos',
        showNotification(message, type, options = {}) { calls.notifications.push([message, type, Boolean(options.onAction)]); },
    });
    return { app, calls, isVisible: () => windowVisible };
}

const ok = folders => ({ success: true, data: { batch_id: 7, folders } });

test('the window opens before the unsaved-changes check, then every folder unmounts', async () => {
    const { app, calls } = appWith({ response: ok([
        { batch_id: 7, root_id: 'a', status: 'done' },
        { batch_id: 7, root_id: 'b', status: 'done' },
    ]) });

    assert.equal(await app.runUnmountBatch({ rootIds: null }), true);
    assert.deepEqual(calls.events[0], ['show']);
    assert.deepEqual(calls.events[1], ['precheck', true, null]);
    assert.deepEqual(plain(calls.invoke), [['unmount_mounts', { rootIds: null, force: false }]]);
    assert.equal(app.unmountBatch.phase, 'done');
    assert.equal(app.unmountingRootIds.size, 0);
    assert.equal(calls.notifications[0][1], 'success');
});

test('cancelling the check unmounts nothing and closes the window', async () => {
    const { app, calls, isVisible } = appWith({ decision: 'cancel' });

    assert.equal(await app.runUnmountBatch({ rootIds: ['a'] }), false);
    assert.equal(calls.invoke.length, 0);
    assert.equal(isVisible(), false);
    assert.equal(app.unmountBatch, null);
    assert.equal(app.unmountingRootIds.size, 0);
});

test('a force decision, or a caller that already checked, is passed through', async () => {
    const forced = appWith({ decision: 'force', response: ok([{ batch_id: 7, root_id: 'a', status: 'done' }]) });
    await forced.app.runUnmountBatch({ rootIds: ['a'] });
    assert.deepEqual(plain(forced.calls.invoke[0]), ['unmount_mounts', { rootIds: ['a'], force: true }]);

    const quit = appWith({ response: ok([{ batch_id: 7, root_id: 'a', status: 'done' }, { batch_id: 7, root_id: 'b', status: 'done' }]) });
    await quit.app.runUnmountBatch({ rootIds: null, force: true, skipPrecheck: true, allowBackground: false });
    assert.ok(!quit.calls.events.some(event => event[0] === 'precheck'));
    assert.equal(quit.calls.invoke[0][1].force, true);
});

test('the final result applies even when no progress event arrived', async () => {
    const { app } = appWith({ response: ok([
        { batch_id: 7, root_id: 'a', status: 'done' },
        { batch_id: 7, root_id: 'b', status: 'failed', error: 'not safe to unmount', error_code: 'UNMOUNT_NOT_SAFE' },
    ]) });

    assert.equal(await app.runUnmountBatch({ rootIds: null }), false);
    assert.equal(app.unmountBatch.folders.a.status, 'done');
    assert.equal(app.unmountBatch.folders.b.status, 'failed');
    assert.equal(app.unmountBatch.folders.b.name, 'Specs', 'the app’s own name is kept');
});

test('progress events update rows; events from another batch are ignored', async () => {
    const { app } = appWith({
        response: ok([{ batch_id: 7, root_id: 'a', status: 'done' }, { batch_id: 7, root_id: 'b', status: 'done' }]),
        beforeResult: async current => {
            current.applyUnmountProgress({ batch_id: 7, root_id: 'a', status: 'running', step: 'removing' });
            assert.equal(current.unmountBatch.folders.a.step, 'removing');
            current.applyUnmountProgress({ batch_id: 9, root_id: 'b', status: 'failed' });
            assert.equal(current.unmountBatch.folders.b.status, 'queued');
        },
    });

    assert.equal(await app.runUnmountBatch({ rootIds: null }), true);
});

test('a background run that fails reports once, with a way back to the window', async () => {
    const { app, calls } = appWith({
        response: ok([{ batch_id: 7, root_id: 'a', status: 'failed', error: 'refused' }, { batch_id: 7, root_id: 'b', status: 'done' }]),
        beforeResult: async current => {
            current.unmountBatch.background = true;
            current.hideUnmountWindow();
        },
    });

    assert.equal(await app.runUnmountBatch({ rootIds: null }), false);
    assert.equal(calls.notifications.length, 1);
    assert.deepEqual(calls.notifications[0], ['1 folder couldn’t be unmounted. 1 of 2 unmounted.', 'error', true]);
});

test('a second request while one runs joins it instead of starting another', async () => {
    let release = () => {};
    const { app, calls } = appWith({
        response: ok([{ batch_id: 7, root_id: 'a', status: 'done' }, { batch_id: 7, root_id: 'b', status: 'done' }]),
        beforeResult: () => new Promise(resolve => { release = resolve; }),
    });

    const first = app.runUnmountBatch({ rootIds: null });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual([...app.unmountingRootIds].sort(), ['a', 'b'], 'its folders cannot be mounted meanwhile');
    const second = app.runUnmountBatch({ rootIds: ['a'] });
    release();
    assert.equal(await first, true);
    assert.equal(await second, true);
    assert.equal(calls.invoke.filter(([command]) => command === 'unmount_mounts').length, 1);
});
