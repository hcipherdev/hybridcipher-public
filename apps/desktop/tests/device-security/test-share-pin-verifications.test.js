// Tests app.js sharePinVerificationsIfDue(): the session check shares this computer's device verifications every 12 hours per account, hourly after a failure, never twice at once.
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

function environment(run) {
    const methods = vm.runInNewContext(`({${method('sharePinVerificationsIfDue')}})`, { console: { warn() {} } });
    const calls = [];
    const app = Object.assign({
        isLoggedIn: true,
        currentUser: 'chen@example.com',
        async runBundledCliArgs(args) { calls.push(args.join(' ')); return run(); },
    }, methods);
    return { app, calls };
}

test('verifications are shared twice a day, and an hour after a failure', async () => {
    const HOUR = 60 * 60 * 1000;
    let fail = false;
    const { app, calls } = environment(async () => { if (fail) throw new Error('offline'); return { status: 0 }; });
    assert.equal(await app.sharePinVerificationsIfDue(0), true);
    assert.equal(calls[0], 'pin publish-attestations --no-color');
    assert.equal(await app.sharePinVerificationsIfDue(11 * HOUR), false);
    fail = true;
    assert.equal(await app.sharePinVerificationsIfDue(12 * HOUR), false);
    fail = false;
    assert.equal(await app.sharePinVerificationsIfDue(12.5 * HOUR), false);
    assert.equal(await app.sharePinVerificationsIfDue(13 * HOUR), true);
    // Another account shares at once.
    app.currentUser = 'xing@example.com';
    assert.equal(await app.sharePinVerificationsIfDue(13.1 * HOUR), true);
    assert.equal(calls.length, 4);
});

test('nothing runs while signed out or while a share is still running', async () => {
    let release;
    const { app, calls } = environment(() => new Promise(resolve => { release = resolve; }));
    const first = app.sharePinVerificationsIfDue(0);
    assert.equal(await app.sharePinVerificationsIfDue(1), false);
    release({ status: 0 });
    assert.equal(await first, true);
    app.isLoggedIn = false;
    assert.equal(await app.sharePinVerificationsIfDue(100 * 60 * 60 * 1000), false);
    assert.equal(calls.length, 1);
});
