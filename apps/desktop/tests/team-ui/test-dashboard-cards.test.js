// Tests app.js group page status targets, People/Coverage summaries and the Server identity panel (parseServerIdentityDetails, verifyServerSafetyNumber).
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

function environment(invoke = async () => ({ success: true, data: [] })) {
    const nodes = new Map();
    const node = id => {
        if (!nodes.has(id)) {
            const classes = new Set(['hidden']);
            nodes.set(id, { id, textContent: '', innerHTML: '', style: {}, disabled: false,
                classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains: key => classes.has(key) } });
        }
        return nodes.get(id);
    };
    const names = ['captureWorkspaceReadContext', 'openDashboardCardTarget', 'setDashboardCardLink',
        'refreshAdminTeamMembersSummary', 'refreshAdminCoverageSummary', 'refreshAdminServerStatusSummary', 'parseServerTrustStatus',
        'summarizeServerTrustStatus', 'parseServerIdentityDetails', 'openServerIdentityModal', 'closeServerIdentityModal',
        'renderServerIdentityModal', 'verifyServerSafetyNumber'];
    const methods = vm.runInNewContext(`({${names.map(method).join(',\n')}})`, {
        invoke, console, Date, Number, document: { getElementById: node },
    });
    const calls = [];
    const record = name => function (...args) { calls.push([name, ...args]); return true; };
    const app = Object.assign({
        isLoggedIn: true, workspaceSwitchSequence: 1, desktopAccountGeneration: 1, currentUser: 'owner@example.com',
        notifications: [], showNotification(message) { this.notifications.push(message); },
        formatCount: value => String(value), formatRelativeAge: () => 'just now', stripAnsi: value => value,
        quoteCliArg: value => `"${value}"`,
        selectAdminTab: record('tab'),
        showCoverageView: record('coverage'), showDeviceAccessQueue: record('issue-queue'),
        showStaleDevicesQueue: record('stale-queue'), showUnverifiedDevicesQueue: record('unverified-queue'),
        async runDashboardCliCommand(command) { calls.push(['cli', command]); return true; },
        async promptForText() { return this.promptAnswer; },
    }, methods);
    return { app, node, calls };
}

const trustOutput = (decision) => [
    '=== Server Identity ===',
    'ℹ Server: https://api.hybridcipher.com',
    'ℹ Fingerprint (SHA-256): ab12cd34',
    'ℹ Safety number: 12345 67890 11121',
    decision,
].join('\n');

test('each status row opens the screen where its numbers can be acted on', async () => {
    const { app, node, calls } = environment(async () => ({ success: true, data: {} }));
    app.runCliStatusCommand = async () => trustOutput('Server identity user-verified');
    app.openDashboardCardTarget('people');
    app.openDashboardCardTarget('coverage');
    assert.deepEqual(calls.map(([name]) => name), ['tab', 'coverage']);
    assert.equal(calls[0][1], 'people');
    assert.equal(calls[1][1].autoStartScan, false);
    await app.openDashboardCardTarget('server');
    assert.equal(node('serverIdentityModal').style.display, 'flex');
});

test('the People summary counts people and links inactive devices', async () => {
    const { app, node } = environment(async command => command === 'get_stale_devices'
        ? { success: true, data: [{ device_id: 'old' }] }
        : { success: true, data: [
            { email: 'owner@example.com', devices: [{ device_id: 'mac' }, { device_id: 'old' }] },
            { email: 'bo@example.com', devices: [{ device_id: 'xps' }] },
            { email: 'new@example.com', devices: [] },
        ] });
    await app.refreshAdminTeamMembersSummary();
    assert.equal(node('adminTeamMembersValue').textContent, '3 people');
    assert.equal(node('adminTeamMembersMeta').textContent, '2 active devices · 1 without an active device');
    assert.equal(node('adminTeamMembersInactiveLink').textContent, '1 inactive device →');
    assert.equal(node('adminTeamMembersInactiveLink').classList.contains('hidden'), false);
});

test('the Coverage row says how many files are not protected on this device', async () => {
    const { app, node } = environment(async () => ({ success: true, data: [
        { state: 'active', kind: 'folder', tracked_files: 8, orphaned_files: 0, unmanaged_files: 2 },
    ] }));
    await app.refreshAdminCoverageSummary();
    assert.equal(node('adminCoverageStatus').textContent, '80% covered');
    assert.equal(node('adminCoverageAttentionLink').textContent, '2 files not protected →');
    const clean = environment(async () => ({ success: true, data: [{ state: 'active', kind: 'folder', tracked_files: 5 }] }));
    await clean.app.refreshAdminCoverageSummary();
    assert.equal(clean.node('adminCoverageAttentionLink').classList.contains('hidden'), true);
});

test('Server identity panel shows the pinned identity and offers verification only when needed', async () => {
    const { app, node } = environment();
    app.runCliStatusCommand = async () => trustOutput('Server matches pinned fingerprint (TOFU)');
    await app.openServerIdentityModal();
    assert.equal(node('serverIdentityModal').style.display, 'flex');
    assert.equal(node('serverIdentityConnection').textContent, 'Connected');
    assert.equal(node('serverIdentityUrl').textContent, 'https://api.hybridcipher.com');
    assert.equal(node('serverIdentitySafetyNumber').textContent, '12345 67890 11121');
    assert.equal(node('serverIdentityFingerprint').textContent, 'ab12cd34');
    assert.match(node('serverIdentityTrust').textContent, /Compare the safety number/);
    assert.equal(node('serverIdentityVerifyBtn').disabled, false);
    assert.match(node('adminServerStatusValue').innerHTML, /^Connected · Verify safety number/);

    app.runCliStatusCommand = async () => trustOutput('Server identity user-verified');
    await app.openServerIdentityModal();
    assert.equal(node('serverIdentityVerifyBtn').disabled, true);
    assert.equal(node('serverIdentityVerifyBtn').textContent, 'Already verified');
    assert.match(node('adminServerStatusValue').innerHTML, /^Connected · Verified/);
});

test('an unreachable server is reported instead of blank identity fields', async () => {
    const { app, node } = environment();
    app.runCliStatusCommand = async () => { throw new Error('connection refused'); };
    await app.openServerIdentityModal();
    assert.equal(node('serverIdentityConnection').textContent, 'Could not reach the server');
    assert.equal(node('serverIdentityVerifyBtn').disabled, true);
});

test('verifying a safety number accepts digits only and runs the CLI verification', async () => {
    const { app, calls } = environment();
    app.runCliStatusCommand = async () => trustOutput('Server identity user-verified');
    app.promptAnswer = '12345 abc';
    await app.verifyServerSafetyNumber();
    assert.equal(calls.some(([name]) => name === 'cli'), false);
    assert.match(app.notifications[0], /digits only/);

    app.promptAnswer = ' 12345 67890 ';
    await app.verifyServerSafetyNumber();
    assert.deepEqual(calls.find(([name]) => name === 'cli'), ['cli', 'hybridcipher server-trust verify --safety-number "1234567890"']);

    calls.length = 0;
    app.promptAnswer = null;
    await app.verifyServerSafetyNumber();
    assert.equal(calls.length, 0);
});
