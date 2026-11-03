// Tests app.js refreshJoinCardIfDue(), which re-publishes this device's join card every 12 hours so key rotations can reach it.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function method(name) {
    const start = new RegExp(`^    (?:async )?${name}\\(`, 'm').exec(source);
    assert.ok(start, name);
    const boundary = /\r?\n    }\r?\n/g;
    boundary.lastIndex = start.index;
    const end = boundary.exec(source);
    assert.ok(end, name);
    return source.slice(start.index, end.index + end[0].length);
}

const HOUR = 60 * 60 * 1000;

function environment(results) {
    const calls = [];
    const invoke = async command => {
        calls.push(command);
        const next = results.shift();
        if (next instanceof Error) throw next;
        return next;
    };
    const methods = vm.runInNewContext(`({${method('refreshJoinCardIfDue')}})`, { invoke, console: { warn() {} } });
    const app = Object.assign({ isLoggedIn: true, currentUser: 'owner@example.com' }, methods);
    return { app, calls };
}

test('a successful refresh waits 12 hours before publishing again', async () => {
    const { app, calls } = environment([{ success: true, data: true }, { success: true, data: true }]);
    assert.equal(await app.refreshJoinCardIfDue(0), true);
    assert.equal(await app.refreshJoinCardIfDue(11 * HOUR), false);
    assert.equal(await app.refreshJoinCardIfDue(12 * HOUR), true);
    assert.deepEqual(calls, ['refresh_join_card', 'refresh_join_card']);
});

test('a failed refresh retries after an hour instead of every session check', async () => {
    const { app, calls } = environment([{ success: false, error: 'offline' }, new Error('network'), { success: true, data: true }]);
    assert.equal(await app.refreshJoinCardIfDue(0), false);
    assert.equal(await app.refreshJoinCardIfDue(30 * 60 * 1000), false);
    assert.equal(await app.refreshJoinCardIfDue(HOUR), false);
    assert.equal(await app.refreshJoinCardIfDue(2 * HOUR), true);
    assert.equal(calls.length, 3);
});

test('switching accounts refreshes the new account immediately and logged-out sessions never publish', async () => {
    const { app, calls } = environment([{ success: true, data: true }, { success: true, data: true }]);
    await app.refreshJoinCardIfDue(0);
    app.currentUser = 'member@example.com';
    assert.equal(await app.refreshJoinCardIfDue(HOUR), true);
    app.isLoggedIn = false;
    assert.equal(await app.refreshJoinCardIfDue(30 * HOUR), false);
    assert.equal(calls.length, 2);
});

test('concurrent session checks publish once', async () => {
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const calls = [];
    const invoke = async command => { calls.push(command); await gate; return { success: true, data: true }; };
    const methods = vm.runInNewContext(`({${method('refreshJoinCardIfDue')}})`, { invoke, console: { warn() {} } });
    const app = Object.assign({ isLoggedIn: true, currentUser: 'owner@example.com' }, methods);
    const first = app.refreshJoinCardIfDue(0);
    assert.equal(await app.refreshJoinCardIfDue(0), false);
    release();
    assert.equal(await first, true);
    assert.equal(calls.length, 1);
});
