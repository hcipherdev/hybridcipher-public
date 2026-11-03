// Tests offerSetUpDeviceAgain() and its DEVICE_IDENTITY_UNREADABLE branch in handleLogin() in src/app.js.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

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

function app({ choice = true, password = 'pw', result = { success: true, data: '/replaced' } } = {}) {
    const calls = [];
    const invoke = async (command, args) => {
        calls.push({ command, args });
        if (result instanceof Error) throw result;
        return result;
    };
    const instance = new (Function('invoke', `return class { ${method('offerSetUpDeviceAgain')} }`)(invoke))();
    const notices = [];
    Object.assign(instance, {
        showActionPrompt: async () => choice,
        promptForText: async (_message, options) => {
            assert.equal(options.inputType, 'password');
            return password;
        },
        showNotification: (message, level) => notices.push({ message, level }),
    });
    return { instance, calls, notices };
}

test('cancelling either step leaves the device untouched', async () => {
    for (const options of [{ choice: false }, { choice: null }, { password: null }]) {
        const { instance, calls } = app(options);
        assert.equal(await instance.offerSetUpDeviceAgain('me@example.com'), false);
        assert.deepEqual(calls, []);
    }
});

test('confirmed reset moves the identity aside and lets sign-in retry', async () => {
    const { instance, calls, notices } = app();
    assert.equal(await instance.offerSetUpDeviceAgain('me@example.com'), true);
    assert.deepEqual(calls, [{ command: 'set_up_device_again', args: { email: 'me@example.com', password: 'pw' } }]);
    assert.equal(notices.at(-1).level, 'info');
});

test('a refused or failed reset stops sign-in and shows why', async () => {
    for (const result of [{ success: false, error: 'Password does not match existing account' }, new Error('ipc down')]) {
        const { instance, notices } = app({ result });
        assert.equal(await instance.offerSetUpDeviceAgain('me@example.com'), false);
        assert.equal(notices.at(-1).level, 'error');
        assert.match(notices.at(-1).message, /Password does not match|ipc down/);
    }
});

test('login offers the reset only for an unreadable identity and retries after it', () => {
    const login = method('handleLogin');
    assert.match(
        login,
        /errorCode === 'DEVICE_IDENTITY_UNREADABLE'\) \{\s*if \(await this\.offerSetUpDeviceAgain\(email\)\) \{\s*continue;\s*\}\s*return;/
    );
});
