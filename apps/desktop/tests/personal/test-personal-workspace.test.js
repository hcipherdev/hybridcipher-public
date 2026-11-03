// Verify Personal always selects its authoritative default and repairs cannot leak across account/device/workspace changes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');
const markup = fs.readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');
const chooserClasses = /<div class="([^"]+)" id="workspaceSelectionModal"/.exec(markup)[1].split(/\s+/);
function environment(invoke = async () => {}) {
    const nodes = new Map();
    const values = new Map();
    const documentListeners = new Map();
    const intervals = new Map();
    let nextNodeId = 0;
    const node = id => {
        if (!nodes.has(id)) {
            const classes = new Set(id === 'workspaceSelectionModal' ? chooserClasses : []);
            const created = { value: '', textContent: '', style: {}, attributes: {}, listeners: new Map(), children: [],
                classList: { toggle(key, force) { force ? classes.add(key) : classes.delete(key); }, contains(key) { return classes.has(key); } },
                setAttribute(key, value) { this.attributes[key] = value; }, toggleAttribute(key, force) { force ? this.attributes[key] = '' : delete this.attributes[key]; },
                querySelector() { return node(`${id}-label`); }, addEventListener(event, fn) { this.listeners.set(event, fn); }, focus() {},
                removeEventListener(event, fn) { if (this.listeners.get(event) === fn) this.listeners.delete(event); },
                appendChild(child) { this.children.push(child); if (!this.value) this.value = child.value; },
                dispatchEvent(event) { this.listeners.get(event.type)?.(event); },
            };
            let html = '';
            Object.defineProperty(created, 'innerHTML', {
                get() { return html; },
                set(value) { html = value; if (value === '') { this.children.length = 0; this.value = ''; } },
            });
            nodes.set(id, created);
        }
        return nodes.get(id);
    };
    const window = { invoke, document: { getElementById: node, querySelectorAll: () => [], createElement: type => node(`${type}-${nextNodeId++}`),
            addEventListener(event, fn) { documentListeners.set(event, fn); },
            removeEventListener(event, fn) { if (documentListeners.get(event) === fn) documentListeners.delete(event); } },
        localStorage: { getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
        setInterval(fn) { const id = intervals.size + 1; intervals.set(id, fn); return id; }, clearInterval(id) { intervals.delete(id); }, addEventListener() {} };
    vm.runInNewContext(source, { window });
    const original = { setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {},
        async loadEnrolledFolders() {}, refreshAdminDashboard() {}, async refreshAdminGroupStatus() {}, async refreshTeamDirectory() {},
        async logout() { this.isLoggedIn = false; return true; }, showWelcomeScreen() {}, openCreateGroupModal() {},
        async addEnrolledFolder() { this.enrollments = (this.enrollments || 0) + 1; }, async showDevicesView() {},
        async refreshPersonalDevicesOverview() {}, async refreshWorkspaceHomeStatus() {}, showCoverageView() {}, async refreshCoverageCenter() {} };
    const app = Object.assign({ currentUser: 'owner@example.test', currentDeviceId: 'device-one', isLoggedIn: true,
        desktopAccountGeneration: 1, workspaceSwitchSequence: 1, activeWorkspaceType: 'personal', appMode: 'individual',
        teamLicenseStatus: { workspace: 'team', online: true, can_write: true, organization: { id: 'org', role: 'owner' } },
        workspaceGroupContext: { group_id: null, organization_id: null, readiness: 'unresolved' }, workspaceContextReady: false,
        showNotification() {}, clearFolderSelectionForGroupSwitch() {}, updateSidebarViewButtons() {}, renderFolderList() {},
        workspacePreferenceKey() { return `workspace_${this.currentUser}`; },
        async showConfirmDialog() { return false; },
        currentDeviceTrust: { account: 'owner@example.test', device: 'device-one', status: { approved: true, can_revoke_other_devices: true } },
    }, window.HybridCipherTeamMethods.create(original));
    return { app, node, values, documentListeners, intervals };
}
const ready = () => ({ group_id: 'default', name: 'Personal default', organization_id: null, role: 'owner', readiness: 'ready', groups: [{ id: 'default' }] });
const deferred = () => { let resolve; const promise = new Promise(finish => { resolve = finish; }); return { promise, resolve }; };
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

test('the real workspace chooser shows its markup modal and cleans up after Continue', async () => {
    const { app, node, documentListeners } = environment();
    const modal = node('workspaceSelectionModal');
    assert.equal(modal.classList.contains('hidden'), true);
    const chosen = app.chooseWorkspaceRecord('Repair Personal workspace', 'Choose your existing default.',
        [{ id: 'legacy', label: 'Default Group' }]);
    assert.equal(modal.classList.contains('hidden'), false);
    assert.equal(modal.style.display, 'flex');
    assert.equal(modal.attributes['aria-hidden'], 'false');
    assert.equal(node('workspaceSelectionSelect').children[0].textContent, 'Default Group');
    node('workspaceSelectionForm').dispatchEvent({ type: 'submit', preventDefault() {} });
    assert.equal(await chosen, 'legacy');
    assert.equal(modal.classList.contains('hidden'), true);
    assert.equal(modal.style.display, 'none');
    assert.equal(modal.attributes['aria-hidden'], 'true');
    assert.equal(documentListeners.has('keydown'), false);
    assert.equal(node('workspaceSelectionForm').listeners.has('submit'), false);
    assert.equal(node('workspaceSelectionCancelBtn').listeners.has('click'), false);
    assert.equal(node('workspaceSelectionSelect').children.length, 0);
});

test('a superseded chooser cannot close its replacement after cancellation', async () => {
    const { app, node } = environment();
    const first = app.chooseWorkspaceRecord('First', '', [{ id: 'first', label: 'First' }]);
    const staleCancel = app.cancelWorkspaceSelection;
    const second = app.chooseWorkspaceRecord('Second', '', [{ id: 'second', label: 'Second' }]);
    assert.equal(await first, null);
    staleCancel();
    assert.equal(node('workspaceSelectionModal').style.display, 'flex');
    node('workspaceSelectionCancelBtn').dispatchEvent({ type: 'click' });
    assert.equal(await second, null);
});

test('focus and license refresh leave the active Personal repair chooser open until Continue', async () => {
    const calls = [];
    const group = { id: 'legacy', name: 'Default Group', role: 'owner', organization_id: null };
    const { app, node } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_personal_workspace') return { state: 'unresolved', candidates: [group] };
        if (command === 'repair_personal_default_group') return { state: 'available', personal_default_group_id: group.id, group };
        if (command === 'get_workspace_group_context') return { ...ready(), group_id: group.id };
        throw new Error(`Unexpected background call: ${command}`);
    });
    const sequence = app.workspaceSwitchSequence;
    const repair = app.repairPersonalWorkspace();
    await nextTurn();
    assert.equal(node('workspaceSelectionModal').style.display, 'flex');
    await Promise.all([app.refreshWorkspaceAfterReconnect(), app.refreshTeamLicenseStatus({ silent: true }),
        app.ensurePersonalWorkspaceReady(), app.checkWorkspaceReadiness({ manual: false })]);
    assert.equal(app.workspaceSwitchSequence, sequence);
    assert.equal(node('workspaceSelectionModal').style.display, 'flex');
    assert.deepEqual(calls.map(([command]) => command), ['get_personal_workspace']);
    node('workspaceSelectionForm').dispatchEvent({ type: 'submit', preventDefault() {} });
    assert.equal(await repair, true);
    assert.equal(calls[1][0], 'repair_personal_default_group');
    assert.equal(calls[1][1].groupId, group.id);
    assert.equal(app.workspaceGroupContext.group_id, group.id);
});

test('license responses and directory refreshes already in flight cannot cancel a later Personal repair', async () => {
    for (const waitAt of ['license', 'directory']) {
        const pending = deferred();
        const calls = [];
        const group = { id: 'legacy', name: 'Default Group', role: 'owner', organization_id: null };
        let repaired = false;
        const { app, node } = environment(async command => {
            calls.push(command);
            if (command === 'get_workspace_group_context') return repaired ? { ...ready(), group_id: group.id }
                : { group_id: null, organization_id: null, readiness: 'unresolved' };
            if (command === 'get_team_license_status') return waitAt === 'license' ? pending.promise : app.teamLicenseStatus;
            if (command === 'get_personal_workspace') return { state: 'unresolved', candidates: [group] };
            if (command === 'repair_personal_default_group') {
                repaired = true;
                return { state: 'available', personal_default_group_id: group.id, group };
            }
            throw new Error(command);
        });
        app.renderTeamLicenseSettings = () => {};
        app.refreshTeamDirectory = async () => { if (waitAt === 'directory') await pending.promise; };
        app.prepareTeamWorkspace = async () => { throw new Error('Background must not switch or prepare Team during repair'); };
        const license = app.refreshTeamLicenseStatus({ silent: true });
        await nextTurn();
        const sequence = app.workspaceSwitchSequence;
        const repair = app.repairPersonalWorkspace();
        await nextTurn();
        assert.equal(node('workspaceSelectionModal').style.display, 'flex', waitAt);
        pending.resolve(app.teamLicenseStatus);
        assert.equal(await license, null, waitAt);
        assert.equal(app.workspaceSwitchSequence, sequence, waitAt);
        assert.equal(app.activeWorkspaceType, 'personal', waitAt);
        assert.equal(node('workspaceSelectionModal').style.display, 'flex', waitAt);
        node('workspaceSelectionForm').dispatchEvent({ type: 'submit', preventDefault() {} });
        assert.equal(await repair, true, waitAt);
        assert.equal(calls.filter(command => command === 'repair_personal_default_group').length, 1, waitAt);
    }
});

test('an explicit user workspace switch still cancels the Personal repair chooser without assignment', async () => {
    const calls = [];
    const { app, node } = environment(async command => {
        calls.push(command);
        if (command === 'get_personal_workspace') return { state: 'unresolved', candidates: [{ id: 'legacy', role: 'owner' }] };
        if (command === 'get_workspace_group_context') return { ...ready(), group_id: 'team', organization_id: 'org' };
        throw new Error('Cancelled repair must not assign a default');
    });
    const repair = app.repairPersonalWorkspace();
    await nextTurn();
    assert.equal(node('workspaceSelectionModal').style.display, 'flex');
    assert.equal(await app.selectWorkspaceType('team'), true);
    assert.equal(await repair, false);
    assert.equal(node('workspaceSelectionModal').style.display, 'none');
    assert.equal(app.activeWorkspaceType, 'team');
    // The Team owner lands on the Team overview, whose reads are the only other calls.
    assert.equal(app.activeWorkspaceView, 'home');
    const overviewReads = new Set(['get_group_summaries', 'get_team_directory', 'get_group_members', 'get_pending_group_adds', 'get_group_member_details']);
    assert.deepEqual(calls.filter(command => !overviewReads.has(command)), ['get_personal_workspace', 'get_workspace_group_context']);
});

test('recovery submission and completion pause background selection but permit the owned explicit Personal selection', async () => {
    for (const flag of ['savedCodeRecoveryInFlight', 'savedCodeRecoveryCompletionInFlight']) {
        const calls = [];
        const { app } = environment(async command => { calls.push(command); return ready(); });
        app[flag] = 7;
        const sequence = app.workspaceSwitchSequence;
        await app.refreshWorkspaceAfterReconnect();
        await app.refreshTeamLicenseStatus();
        assert.equal(await app.ensurePersonalWorkspaceReady(), false);
        assert.equal(await app.checkWorkspaceReadiness({ manual: false }), false);
        assert.equal(app.workspaceSwitchSequence, sequence);
        assert.deepEqual(calls, []);
        assert.equal(await app.selectWorkspaceType('personal'), true);
        assert.equal(app.workspaceSwitchSequence, sequence + 1);
        assert.deepEqual(calls, ['get_workspace_group_context']);
    }
});

test('readiness polling pauses during recovery completion and discards a preceding response', async () => {
    const response = deferred();
    const { app, intervals } = environment(async command => { assert.equal(command, 'get_workspace_group_context'); return response.promise; });
    app.workspaceGroupContext = { ...ready(), readiness: 'waiting_for_device_approval' };
    app.startWorkspaceReadinessPolling();
    assert.equal(intervals.size, 1);
    const poll = [...intervals.values()][0]();
    app.savedCodeRecoveryCompletionInFlight = 7;
    response.resolve(ready());
    await poll;
    assert.equal(app.workspaceGroupContext.readiness, 'waiting_for_device_approval');
    app.startWorkspaceReadinessPolling();
    assert.equal(intervals.size, 0);
});

test('repair resumes eligible Welcome polling only after releasing its owned setup token', async () => {
    const group = { id: 'legacy', role: 'owner', organization_id: null };
    const { app, intervals } = environment(async command => {
        if (command === 'get_personal_workspace') return { state: 'available', personal_default_group_id: group.id, group };
        if (command === 'get_workspace_group_context') return { ...ready(), group_id: group.id, readiness: 'waiting_for_device_approval' };
        throw new Error(command);
    });
    assert.equal(await app.repairPersonalWorkspace(), false);
    assert.equal(app.personalRepairInFlight, null);
    assert.equal(intervals.size, 1);
    assert.equal(app.workspaceReadinessTimer.scope.groupId, group.id);
    app.stopWorkspaceReadinessPolling();
});

test('only the owned recovery completion attempt can reconcile Team during the handoff', async () => {
    const response = deferred();
    const calls = [];
    const { app } = environment(async command => { calls.push(command); return response.promise; });
    app.activeWorkspaceType = 'team';
    app.workspaceGroupContext = { ...ready(), organization_id: 'org', readiness: 'waiting_for_device_approval' };
    app.savedCodeRecoveryAttempt = 7;
    app.savedCodeRecoveryCompletionInFlight = 7;
    assert.equal(await app.reconcileWorkspaceState(), false);
    assert.equal(await app.reconcileWorkspaceState({ recoveryCompletionAttempt: 6 }), false);
    assert.deepEqual(calls, []);
    const owned = app.reconcileWorkspaceState({ recoveryCompletionAttempt: 7 });
    app.savedCodeRecoveryAttempt = 8;
    app.savedCodeRecoveryCompletionInFlight = 8;
    response.resolve({ ...ready(), organization_id: 'org' });
    assert.equal(await owned, false);
    assert.equal(app.workspaceGroupContext.readiness, 'waiting_for_device_approval');
    assert.deepEqual(calls, ['get_workspace_group_context']);
});

test('account clearing invalidates a recovery attempt and erases its modal credentials', () => {
    const { app, node } = environment();
    app.savedCodeRecoveryAttempt = 4;
    app.savedCodeRecoveryInFlight = true;
    app.savedCodeRecoveryCompletionInFlight = 4;
    app.closeRecoveryAutoBackupModal = () => { assert.equal(app.savedCodeRecoveryInFlight, false); app.recoveryClosed = true; };
    app.closeTeamActivationModal = () => {};
    node('recoveryAutoBackupPasswordInput').value = 'test-password';
    node('recoveryAutoBackupCodeInput').value = 'test-code';
    app.clearTeamUiState();
    assert.equal(app.savedCodeRecoveryAttempt, 5);
    assert.equal(app.savedCodeRecoveryInFlight, false);
    assert.equal(app.savedCodeRecoveryCompletionInFlight, null);
    assert.equal(app.recoveryClosed, true);
    assert.equal(node('recoveryAutoBackupPasswordInput').value, '');
    assert.equal(node('recoveryAutoBackupCodeInput').value, '');
});

test('Team to Personal ignores saved, active and forced nondefault selections', async () => {
    const calls = [];
    const { app, values } = environment(async (command, args) => { calls.push([command, args]); assert.equal(command, 'get_workspace_group_context'); return ready(); });
    app.activeWorkspaceType = 'team'; app.appMode = 'team'; app.workspaceGroupContext = { group_id: 'team-old', organization_id: 'org', readiness: 'ready' };
    values.set(app.groupPreferenceKey('personal'), 'shared-old');
    values.set(app.groupPreferenceKey('team'), 'team-old');
    assert.equal(await app.selectWorkspaceType('personal', { forceGroupId: 'shared-forced' }), true);
    assert.equal(app.workspaceGroupContext.group_id, 'default');
    assert.equal(app.activeWorkspaceType, 'personal');
    assert.equal(values.get(app.groupPreferenceKey('personal')), 'default');
    assert.equal(values.get(app.groupPreferenceKey('team')), 'team-old');
    assert.deepEqual(calls.map(([command]) => command), ['get_workspace_group_context']);
});

test('stale group-switch controls in Personal cannot dispatch a generic switch operation', async () => {
    const { app } = environment(async () => { throw new Error('No native calls expected'); });
    app.runDesktopOperation = async () => { throw new Error('No group switch expected'); };
    assert.equal(await app.switchTeamGroup('shared-group'), false);
    assert.equal(await app.openTeamGroup('shared-group'), false);
    assert.equal(app.activeWorkspaceType, 'personal');
});

test('repair chooses only an owned non-organization candidate and reloads default context', async () => {
    const calls = [];
    const candidate = { id: 'chosen', name: 'Owned legacy group', role: 'owner', organization_id: null };
    const { app } = environment(async (command, args) => {
        calls.push([command, args]);
        if (command === 'get_personal_workspace') return { state: 'unresolved', candidates: [candidate,
            { id: 'team', role: 'owner', organization_id: 'org' }, { id: 'shared', role: 'member', organization_id: null }] };
        if (command === 'repair_personal_default_group') return { state: 'available', personal_default_group_id: 'chosen', group: candidate };
        if (command === 'get_workspace_group_context') return { ...ready(), group_id: 'chosen' };
        throw new Error(command);
    });
    app.chooseWorkspaceRecord = async (_title, _note, items) => { assert.equal(items.length, 1); assert.equal(items[0].id, 'chosen'); return 'chosen'; };
    assert.equal(await app.repairPersonalWorkspace(), true);
    const request = calls.find(([command]) => command === 'repair_personal_default_group')[1];
    assert.equal(request.action, 'assign'); assert.equal(request.groupId, 'chosen'); assert.equal(request.expectedAccountEmail, app.currentUser);
    assert.equal(app.workspaceGroupContext.group_id, 'chosen');
    assert.equal(app.personalRepairInFlight, null);
});

test('guided repair adopts its own Personal selection sequence before waiting for readiness', async () => {
    for (const alreadyAssigned of [false, true]) {
        const context = deferred();
        const group = { id: 'chosen', name: 'Legacy default', role: 'owner', organization_id: null };
        const assigned = { state: 'available', personal_default_group_id: group.id, group };
        const { app } = environment(async command => {
            if (command === 'get_personal_workspace') return alreadyAssigned ? assigned : { state: 'unresolved', candidates: [group] };
            if (command === 'repair_personal_default_group') return assigned;
            if (command === 'get_workspace_group_context') return context.promise;
            throw new Error(command);
        });
        app.chooseWorkspaceRecord = async () => group.id;
        const selectionScope = { sequence: app.workspaceSwitchSequence };
        const original = selectionScope.sequence;
        const repair = app.repairPersonalWorkspace({ selectionScope });
        await nextTurn();
        assert.equal(selectionScope.sequence, original + 1);
        assert.equal(selectionScope.sequence, app.workspaceSwitchSequence);
        context.resolve({ ...ready(), group_id: group.id });
        assert.equal(await repair, true);
        assert.equal(selectionScope.sequence, original + 1);
    }
});

test('guided repair does not adopt an unrelated sequence or report another workspace ready', async () => {
    const context = deferred();
    const group = { id: 'chosen', role: 'owner', organization_id: null };
    const { app } = environment(async command => {
        if (command === 'get_personal_workspace') return { state: 'available', personal_default_group_id: group.id, group };
        if (command === 'get_workspace_group_context') return context.promise;
        throw new Error(command);
    });
    const selectionScope = { sequence: app.workspaceSwitchSequence };
    const repair = app.repairPersonalWorkspace({ selectionScope });
    await nextTurn();
    const ownedSequence = selectionScope.sequence;
    app.activeWorkspaceType = 'team'; app.workspaceSwitchSequence++;
    app.workspaceGroupContext = { ...ready(), organization_id: 'org' }; app.workspaceContextReady = true;
    context.resolve(ready());
    assert.equal(await repair, false);
    assert.equal(selectionScope.sequence, ownedSequence);
    assert.notEqual(selectionScope.sequence, app.workspaceSwitchSequence);
});

test('a superseded guided repair cannot start another metadata request', async () => {
    const { app } = environment(async () => { throw new Error('Stale repair must not fetch or mutate'); });
    assert.equal(await app.repairPersonalWorkspace({ selectionScope: { sequence: app.workspaceSwitchSequence - 1 } }), false);
    assert.equal(app.personalRepairInFlight, undefined);
});

test('empty candidates require explicit creation confirmation', async () => {
    for (const confirmed of [false, true]) {
        const calls = [];
        const { app } = environment(async (command, args) => {
            calls.push([command, args]);
            if (command === 'get_personal_workspace') return { state: 'missing', candidates: [] };
            if (command === 'repair_personal_default_group') return { state: 'available', personal_default_group_id: 'default', group: { id: 'default' } };
            if (command === 'get_workspace_group_context') return ready();
            throw new Error(command);
        });
        app.showConfirmDialog = async (_title, message) => { assert.match(message, /does not restore files/); return confirmed; };
        assert.equal(await app.repairPersonalWorkspace(), confirmed);
        const mutation = calls.find(([command]) => command === 'repair_personal_default_group');
        assert.equal(Boolean(mutation), confirmed);
        if (confirmed) assert.equal(mutation[1].action, 'create');
    }
});

test('late Personal repair reads and chooser answers cannot mutate another scope', async () => {
    for (const change of ['account', 'device', 'generation', 'workspace', 'sequence']) {
        const read = deferred();
        const calls = [];
        const { app } = environment(async command => { calls.push(command); assert.equal(command, 'get_personal_workspace'); return read.promise; });
        const repair = app.repairPersonalWorkspace();
        if (change === 'account') app.currentUser = 'another@example.test';
        if (change === 'device') app.currentDeviceId = 'device-two';
        if (change === 'generation') app.desktopAccountGeneration++;
        if (change === 'workspace') app.activeWorkspaceType = 'team';
        if (change === 'sequence') app.workspaceSwitchSequence++;
        read.resolve({ state: 'missing', candidates: [] });
        assert.equal(await repair, false, change);
        assert.deepEqual(calls, ['get_personal_workspace']);
    }
    const choice = deferred();
    const { app } = environment(async command => { assert.equal(command, 'get_personal_workspace'); return { state: 'unresolved', candidates: [{ id: 'owned', role: 'owner', organization_id: null }] }; });
    app.chooseWorkspaceRecord = () => choice.promise;
    const repair = app.repairPersonalWorkspace(); await nextTurn();
    app.currentDeviceId = 'replacement-device'; choice.resolve('owned');
    assert.equal(await repair, false);
});

test('late native repair completion cannot reselect after switching to Team', async () => {
    const mutation = deferred();
    const calls = [];
    const { app } = environment(async command => {
        calls.push(command);
        if (command === 'get_personal_workspace') return { state: 'missing', candidates: [] };
        if (command === 'repair_personal_default_group') return mutation.promise;
        throw new Error('Stale response cannot load Personal');
    });
    app.showConfirmDialog = async () => true;
    const repair = app.repairPersonalWorkspace(); await nextTurn();
    app.activeWorkspaceType = 'team'; app.workspaceSwitchSequence++;
    mutation.resolve({ state: 'available', personal_default_group_id: 'default', group: { id: 'default' } });
    assert.equal(await repair, false);
    assert.equal(app.activeWorkspaceType, 'team');
    assert.deepEqual(calls, ['get_personal_workspace', 'repair_personal_default_group']);
});

test('missing-key notice offers saved-code recovery in a temporary session without group operations', () => {
    const { app, node } = environment();
    app.sessionPersistent = false;
    app.workspaceGroupContext = { ...ready(), readiness: 'waiting_for_device_approval' };
    app.openRecoveryAutoBackupModal = () => { app.recoveryOpened = true; };
    app.applyAppMode();
    assert.equal(node('personalSetupNotice').classList.contains('hidden'), false);
    assert.equal(node('personalSetupRecoverBtn').classList.contains('hidden'), false);
    assert.equal(node('personalSetupRepairBtn').classList.contains('hidden'), true);
    app.openPersonalRecovery(); assert.equal(app.recoveryOpened, true);
    app.activeWorkspaceType = 'team'; app.recoveryOpened = false;
    app.openPersonalRecovery(); assert.equal(app.recoveryOpened, false);
});

test('Personal Check status reloads unresolved identity before accepting enrollment', async () => {
    const calls = [];
    const { app } = environment(async command => { calls.push(command); assert.equal(command, 'get_workspace_group_context'); return ready(); });
    assert.equal(await app.checkPersonalWorkspaceStatus(), true);
    assert.equal(app.workspaceGroupContext.group_id, 'default');
    assert.deepEqual(calls, ['get_workspace_group_context']);
});

test('Settings recovery fetch opens native recovery before temporary-login and readiness gates', async () => {
    const { app } = environment(async () => { throw new Error('Recovery modal should not launch CLI operations'); });
    app.sessionPersistent = false;
    app.parseGeneratedCliArgs = command => command.split(' ').slice(1);
    app.closeSettingsModal = () => { app.settingsClosed = true; };
    app.openRecoveryAutoBackupModal = () => { app.recoveryOpened = true; };
    assert.equal(await app.runSettingsCliCommand('hybridcipher recovery fetch'), true);
    assert.equal(app.recoveryOpened, true); assert.equal(app.settingsClosed, true);
    app.recoveryOpened = false;
    assert.equal(await app.runSettingsCliCommand('hybridcipher initialize-group'), false);
    assert.equal(app.recoveryOpened, false);
});

test('Personal notice distinguishes trusted device state from unavailable encryption keys', () => {
    const { app, node } = environment();
    app.workspaceGroupContext = { ...ready(), readiness: 'waiting_for_device_approval' };
    app.personalDevicesOverview = { device_trust: { device_id: app.currentDeviceId, approved: true, fingerprint_verified: true } };
    app.renderPersonalWorkspaceNotice();
    assert.match(node('personalSetupMessage').textContent, /trusted, but.*keys are missing/);
    app.personalDevicesOverview.device_trust.device_id = 'different-device';
    app.renderPersonalWorkspaceNotice();
    assert.doesNotMatch(node('personalSetupMessage').textContent, /device is trusted/);
});
