// Tests reviewRotationSkips(), loadRotationPreflight(), buildRotationCheckRow(), showRotationSkipDialog(), beginRekeyFlow(), confirmMemberRemoval() and reviewRotationSkipsWithProgress() in src/app-team-methods.js, which let admins verify, remove or skip devices that cannot get a new key before a rotation, with a progress window during the check and the rotation as one operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');

function environment(invoke) {
    const nodes = new Map();
    function node(id) {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, { id, value: '', innerHTML: '', textContent: '', style: {}, attributes: {}, dataset: {}, children: [],
                listeners: new Map(),
                classList: { toggle(key, force) { if (force) classes.add(key); else classes.delete(key); }, contains: key => classes.has(key) },
                setAttribute(key, value) { this.attributes[key] = value; }, removeAttribute(key) { delete this.attributes[key]; },
                toggleAttribute() {}, querySelector() { return node(`${id}-label`); }, querySelectorAll() { return []; },
                appendChild(child) { this.children.push(child); },
                addEventListener(event, callback) { this.listeners.set(event, callback); },
                removeEventListener(event, callback) { if (this.listeners.get(event) === callback) this.listeners.delete(event); },
                focus() {} });
        }
        return nodes.get(id);
    }
    const window = { document: { getElementById: node, querySelectorAll: () => [], createElement: tag => node(`new-${tag}-${nodes.size}`),
        addEventListener() {} }, localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
        setTimeout: callback => setImmediate(callback), setInterval: () => 0, clearInterval() {}, addEventListener() {}, invoke };
    vm.runInNewContext(source, { window });
    const original = { setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {}, async loadEnrolledFolders() {},
        refreshAdminDashboard() {}, async refreshAdminGroupStatus() {}, async refreshTeamDirectory() {}, async logout() { return true; },
        showWelcomeScreen() {}, openCreateGroupModal() {}, addEnrolledFolder() {}, async showDevicesView() {},
        async refreshPersonalDevicesOverview() {}, async refreshWorkspaceHomeStatus() {}, showCoverageView() {},
        async refreshCoverageCenter() {} };
    const tasks = [];
    const app = Object.assign({ currentUser: 'owner@example.com', isLoggedIn: true, activeWorkspaceType: 'team',
        teamLicenseStatus: { workspace: 'team', can_write: true, online: true, organization: { id: 'org-1', name: 'Research', role: 'owner' } },
        workspaceGroupContext: { group_id: 'team-group', name: 'Research', organization_id: 'org-1', role: 'owner', readiness: 'ready' },
        workspaceContextReady: true, showNotification() {}, updateSidebarViewButtons() {}, renderTeamLicenseSettings() {},
        async refreshPendingTeamRequests() {}, escapeHtml: value => String(value), escapeHtmlAttr: value => String(value),
        async showActionPrompt() { return true; },
        buildStaleDeviceRow(device, options) { return { device, options }; },
        currentDeviceTrust: { account: 'owner@example.com', device: undefined, status: { approved: true, can_revoke_other_devices: true } },
    }, window.HybridCipherTeamMethods.create(original));
    app.runTeamTask = async (request, title) => { tasks.push({ ...request, title }); return { ok: true }; };
    return { app, node, tasks };
}

const stale = (device_id, extra = {}) => ({ device_id, user_id: 'u-owner', email: 'owner@example.com', reasons: ['Join card expired on 2026-10-04'], ...extra });
const tick = () => new Promise(resolve => setImmediate(resolve));

test('a rotation with no inactive devices runs without the extra dialog or skipping', async () => {
    const { app, node, tasks } = environment(async () => ({ success: true, data: [] }));
    await app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    assert.equal(node('rotationSkipModal').style.display, undefined);
    assert.equal(tasks.length, 1);
    assert.equal(tasks[0].kind, 'rotate_keys');
    assert.equal(tasks[0].skip_unreachable, false);
});

test('inactive devices are listed and the admin can rotate without them', async () => {
    const { app, node, tasks } = environment(async () => ({ success: true, data: [stale('desktop-old')] }));
    const flow = app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    await tick(); await tick();
    assert.equal(node('rotationSkipModal').style.display, 'flex');
    assert.equal(node('rotationSkipList').children[0].device.device_id, 'desktop-old');
    assert.match(node('rotationSkipSummary').textContent, /1 device can't get the new key from this computer/);
    assert.equal(node('confirmRotationSkipBtn').textContent, 'Rotate without them');
    node('confirmRotationSkipBtn').listeners.get('click')();
    await flow;
    assert.equal(node('rotationSkipModal').style.display, 'none');
    assert.equal(tasks[0].skip_unreachable, true);
    // Listeners are detached so a later dialog does not resolve twice.
    assert.equal(node('confirmRotationSkipBtn').listeners.has('click'), false);
});

test('cancelling the dialog does not rotate', async () => {
    const { app, node, tasks } = environment(async () => ({ success: true, data: [stale('desktop-old')] }));
    const flow = app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    await tick(); await tick();
    node('rotationSkipBackdrop').listeners.get('click')();
    await flow;
    assert.equal(tasks.length, 0);
});

test('removing every listed device lets the rotation run normally', async () => {
    let audit = [stale('desktop-old')];
    const { app, node, tasks } = environment(async () => ({ success: true, data: audit }));
    const flow = app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    await tick(); await tick();
    audit = [];
    await node('rotationSkipList').children[0].options.onRemoved();
    assert.match(node('rotationSkipSummary').textContent, /Nothing listed blocks the rotation any more/);
    assert.equal(node('confirmRotationSkipBtn').textContent, 'Rotate keys');
    node('confirmRotationSkipBtn').listeners.get('click')();
    await flow;
    assert.equal(tasks[0].skip_unreachable, false);
});

test('removing a member ignores their own devices and passes the skip choice to the rotation', async () => {
    const devices = [stale('leaving-laptop', { user_id: 'u-bo', email: 'bo@example.com' }), stale('desktop-old')];
    const { app, node, tasks } = environment(async () => ({ success: true, data: devices }));
    const removal = app.confirmMemberRemoval({ user_id: 'u-bo', email: 'bo@example.com' });
    await tick(); await tick();
    assert.deepEqual(node('rotationSkipList').children.map(row => row.device.device_id), ['desktop-old']);
    node('confirmRotationSkipBtn').listeners.get('click')();
    assert.equal(await removal, true);
    assert.equal(tasks[0].kind, 'remove_access');
    assert.equal(tasks[0].skip_unreachable, true);
});

test('an unavailable device audit leaves the decision to the rotation itself', async () => {
    const { app, tasks } = environment(async () => { throw new Error('offline'); });
    await app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    assert.equal(tasks[0].skip_unreachable, false);
});

test('the device check shows a progress window that closes before any dialog, and the rotation is one operation', async () => {
    const steps = [];
    const { app, node, tasks } = environment(async () => ({ success: true, data: [] }));
    app.showActionProgressModal = message => steps.push(['checking', message]);
    app.hideActionProgressModal = () => steps.push(['hide']);
    app.refreshAdminKeyVersionsSummary = () => steps.push(['refresh-keys']);
    app.refreshLeftoverKeyFiles = () => steps.push(['refresh-files']);
    app.reportKeyReceiptsIfDue = async () => { steps.push(['receipt']); return true; };
    app.moveFilesToCurrentKey = async () => { steps.push(['move']); };
    await app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    // "Checking devices…" covers the gap; the operation itself fetches the key and moves the files.
    assert.deepEqual(steps.map(step => step[0]), ['checking', 'hide', 'refresh-keys', 'refresh-files']);
    assert.match(steps[0][1], /Checking devices/);
    assert.equal(tasks[0].kind, 'rotate_keys');

    // With devices to review, the progress window closes before the review dialog opens.
    steps.length = 0;
    const withStale = environment(async () => ({ success: true, data: [stale('desktop-old')] }));
    withStale.app.showActionProgressModal = () => steps.push('checking');
    withStale.app.hideActionProgressModal = () => steps.push('hide');
    const flow = withStale.app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    await tick(); await tick();
    assert.equal(withStale.node('rotationSkipModal').style.display, 'flex');
    assert.deepEqual(steps, ['checking', 'hide']);
    withStale.node('confirmRotationSkipBtn').listeners.get('click')();
    await flow;

    // Removing someone works the same way; a failed operation refreshes nothing.
    steps.length = 0;
    assert.equal(await app.confirmMemberRemoval({ user_id: 'u-bo', email: 'bo@example.com' }), true);
    assert.deepEqual(steps.map(step => step[0]), ['checking', 'hide', 'refresh-keys', 'refresh-files']);
    steps.length = 0;
    app.runTeamTask = async () => null;
    await app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    assert.deepEqual(steps.map(step => step[0]), ['checking', 'hide']);
    assert.equal(node('rotationSkipModal').style.display, undefined);
});

test('devices this computer has not verified are listed with Verify now, and verifying them clears the way', async () => {
    const { app, node, tasks } = environment(async () => ({ success: true, data: [] }));
    let preflight = [{ user_id: 'u-xing', email: 'xing@example.com', device_id: 'device_97209c', device_name: 'xps13',
        reason_code: 'not_verified_here', reason: 'Not verified on this computer' }];
    const cliCalls = [];
    app.runBundledCliArgs = async args => {
        cliCalls.push(args.join(' '));
        return { status: 0, stdout: `Initializing secure session management...\n${JSON.stringify({ group_id: 'g', devices: preflight })}\n` };
    };
    const opened = [];
    app.openAdminPinVerifyModal = options => opened.push(options);

    const flow = app.beginRekeyFlow({ title: 'Rotate', message: 'Rotate?' });
    await tick(); await tick();
    assert.equal(node('rotationSkipModal').style.display, 'flex');
    assert.equal(cliCalls[0], 'rekey preflight --json --no-color');
    const row = node('rotationSkipList').children[0];
    assert.match(row.innerHTML, /xps13/);
    assert.match(row.innerHTML, /Not verified on this computer/);
    const verify = row.children[0];
    assert.equal(verify.textContent, 'Verify now');

    verify.listeners.get('click')();
    assert.equal(opened[0].userId, 'u-xing');
    assert.equal(opened[0].deviceId, 'device_97209c');

    // Once verified, the check finds nothing and the rotation runs without skipping anyone.
    preflight = [];
    await opened[0].onVerified();
    assert.match(node('rotationSkipSummary').textContent, /Nothing listed blocks the rotation any more/);
    node('confirmRotationSkipBtn').listeners.get('click')();
    await flow;
    assert.equal(tasks[0].skip_unreachable, false);
});

test('a device the server flags and the check also lists appears once', async () => {
    const inactive = stale('device_a', { reasons: ['Last seen 40 days ago'] });
    const { app, node } = environment(async command => ({ success: true, data: command === 'get_stale_devices' ? [inactive] : [] }));
    app.runBundledCliArgs = async () => ({ status: 0, stdout: JSON.stringify({ devices: [
        { user_id: 'u-owner', device_id: 'device_a', reason_code: 'join_card_expired', reason: 'Join card expired at 1 Oct' },
        { user_id: 'u-bo', device_id: 'device_b', reason_code: 'pin_expired', reason: 'Pinned key expired at 2 Oct' },
    ] }) });
    const flow = app.reviewRotationSkips();
    await tick(); await tick();
    const rows = node('rotationSkipList').children;
    assert.equal(rows.length, 2);
    assert.equal(rows[0].device.device_id, 'device_a');
    assert.match(rows[1].innerHTML, /Pinned key expired/);
    assert.equal(rows[1].children.length, 0, 'only unverified devices get Verify now');
    node('cancelRotationSkipBtn').listeners.get('click')();
    const review = await flow;
    assert.equal(review.proceed, false);
    assert.equal(review.skipUnreachable, false);
});

test('a failing check leaves only the server list', async () => {
    const { app } = environment(async () => ({ success: true, data: [] }));
    app.runBundledCliArgs = async () => { throw new Error('No authenticated session'); };
    assert.equal(await app.loadRotationPreflight(), null);
    const review = await app.reviewRotationSkips();
    assert.equal(review.proceed, true);
    assert.equal(review.skipUnreachable, false);
});
