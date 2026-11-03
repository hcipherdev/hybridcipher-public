// Tests app.js loadUnverifiedDevicesQueue() and loadDevicesNotVerifiedHere(): the unverified list behind "Devices to set up" also holds group devices this computer has not verified (from the rotation check), once each, with a five-minute cache for background counts, and redraws the list only while it is open.
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

function environment({ serverDevices = [], preflight = [] } = {}) {
    const methods = vm.runInNewContext(
        `({${['loadUnverifiedDevicesQueue', 'loadDevicesNotVerifiedHere'].map(method).join(',\n')}})`,
        {
            invoke: async () => ({ success: true, data: serverDevices }),
            document: { getElementById: () => ({}) },
            Date,
            console,
        }
    );
    const state = { preflightRuns: 0, rendered: 0 };
    const app = Object.assign({
        currentUser: 'owner@example.com',
        workspaceGroupContext: { group_id: 'team-group' },
        captureWorkspaceReadContext: () => () => true,
        setQueueDetailsMessage() {},
        setQueueDetailsPagination() {},
        activeQueueDetails: 'access',
        updateTeamAttention() {},
        renderDeviceAccessQueuePage() { state.rendered += 1; },
        async loadRotationPreflight() { state.preflightRuns += 1; return preflight; },
    }, methods);
    return { app, state };
}

const xps = { user_id: 'u-xing', email: 'xing@example.com', device_id: 'device_97209c', reason_code: 'not_verified_here', reason: 'Not verified on this computer' };

test('devices verified elsewhere but not here join the queue once', async () => {
    const { app, state } = environment({
        serverDevices: [{ user_id: 'u-bo', email: 'bo@example.com', device_id: 'device_new' }],
        preflight: [xps, { ...xps, device_id: 'device_new' }, { ...xps, device_id: 'device_old', reason_code: 'pin_expired' }],
    });
    await app.loadUnverifiedDevicesQueue();
    assert.equal(app.unverifiedDevicesCache.map(device => device.device_id).join(','), 'device_new,device_97209c');
    assert.equal(app.unverifiedDevicesCache[1].reason_code, 'not_verified_here');
    assert.equal(state.rendered, 1);
    // With another list open, a reload leaves that list alone.
    app.activeQueueDetails = 'stale';
    await app.loadUnverifiedDevicesQueue();
    assert.equal(state.rendered, 1);
});

test('background counts reuse the check for five minutes; opening the queue runs it again', async () => {
    const { app, state } = environment({ preflight: [xps] });
    await app.loadUnverifiedDevicesQueue({ suppressDetails: true });
    await app.loadUnverifiedDevicesQueue({ suppressDetails: true });
    assert.equal(state.preflightRuns, 1);
    await app.loadUnverifiedDevicesQueue();
    assert.equal(state.preflightRuns, 2);
    assert.equal((await app.loadDevicesNotVerifiedHere({ now: Date.now() + 6 * 60 * 1000 })).length, 1);
    assert.equal(state.preflightRuns, 3);
    // Another group never reuses this group's answer.
    app.workspaceGroupContext = { group_id: 'other-group' };
    await app.loadDevicesNotVerifiedHere();
    assert.equal(state.preflightRuns, 4);
});

test('an unavailable check leaves the server list as it is', async () => {
    const { app, state } = environment({ serverDevices: [{ device_id: 'device_new' }], preflight: null });
    await app.loadUnverifiedDevicesQueue();
    assert.equal(app.unverifiedDevicesCache.length, 1);
});
