// Tests native saved-code recovery, explicit Personal repair, key readiness, and stale account/workspace responses.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const workspaceSource = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');
function method(name) {
    const start = new RegExp(`^    (?:async )?${name}\\(`, 'm').exec(source);
    assert.ok(start, name);
    const boundary = /\r?\n    }\r?\n/g;
    boundary.lastIndex = start.index;
    const end = boundary.exec(source);
    assert.ok(end, name);
    return source.slice(start.index, end.index + end[0].length);
}
function environment(invoke) {
    const nodes = new Map();
    const node = id => {
        if (!nodes.has(id)) {
            const classes = new Set();
            nodes.set(id, {value:'', textContent:'', innerHTML:'', style:{}, attributes:{},
                classList:{toggle(key,force) {force ? classes.add(key) : classes.delete(key);}, contains:key => classes.has(key)},
                setAttribute(key,value) {this.attributes[key] = value;},
                toggleAttribute(key,force) {force ? this.attributes[key] = '' : delete this.attributes[key];},
                querySelector() {return node(`${id}-label`);}, addEventListener() {}, focus() {}});
        }
        return nodes.get(id);
    };
    node('recoveryAutoBackupPasswordInput').value = ' account password ';
    node('recoveryAutoBackupCodeInput').value = 'saved encryption code';
    node('submitRecoveryAutoBackupBtn');
    const methods = vm.runInNewContext(`({${['handleRecoveryAutoBackupSubmit', 'updateRecoveryAutoBackupSubmitState', 'closeRecoveryAutoBackupModal'].map(method).join(',\n')}})`, {
        invoke, document:{getElementById:node},
    });
    const errors = [], notifications = [];
    let reconciled = 0, selected = 0, closed = 0;
    const app = Object.assign({isLoggedIn:true, currentUser:'a@example.com', currentDeviceId:'device',
        desktopAccountGeneration:1, workspaceSwitchSequence:1, activeWorkspaceType:'personal', persistentSession:false,
        workspaceGroupContext:ready(), workspaceContextReady:true,
        workspaceUiModel() {return {hasGroupContext:Boolean(this.workspaceGroupContext?.group_id), resolved:this.workspaceContextReady};},
        setRecoveryAutoBackupError:message => errors.push(message), updateSecurityBanner() {}, hideSecurityPanel() {},
        renderPersonalWorkspaceNotice() {},
        showNotification:message => notifications.push(message),
        async reconcileWorkspaceState() {reconciled++;}, async promptForText() {return '123456';},
        async selectWorkspaceType() {selected++;this.workspaceSwitchSequence++;return this.workspaceContextReady;},
    }, methods);
    const close = app.closeRecoveryAutoBackupModal;
    app.closeRecoveryAutoBackupModal = function () {
        const blocked = this.savedCodeRecoveryInFlight;
        close.call(this);
        if (!blocked) closed++;
    };
    return {app, nodes, node, errors, notifications, reconciled:() => reconciled, selected:() => selected, closed:() => closed};
}
function workspaceEnvironment(invoke) {
    const env = environment(invoke);
    const values = new Map();
    const window = {invoke, document:{getElementById:env.node, querySelectorAll:() => [], addEventListener() {}},
        localStorage:{getItem:key => values.get(key) || null, setItem:(key,value) => values.set(key,value)},
        setInterval:() => 1, clearInterval() {}, addEventListener() {}};
    vm.runInNewContext(workspaceSource, {window});
    const original = {setupEventListeners() {}, applyAppMode() {}, updateWorkspaceHomeSummary() {},
        async loadEnrolledFolders() {this.foldersLoaded = (this.foldersLoaded || 0) + 1;},
        refreshAdminDashboard() {}, async refreshAdminGroupStatus() {}, async refreshTeamDirectory() {},
        async logout() {}, showWelcomeScreen() {}, openCreateGroupModal() {}, async addEnrolledFolder() {},
        async showDevicesView() {}, async refreshPersonalDevicesOverview() {}, async refreshWorkspaceHomeStatus() {},
        showCoverageView() {}, async refreshCoverageCenter() {}};
    Object.assign(env.app, {appMode:'individual',
        workspaceGroupContext:{group_id:null, organization_id:null, readiness:'unresolved'}, workspaceContextReady:false,
        teamLicenseStatus:{workspace:'team', online:true, can_write:true, organization:{id:'org', role:'owner'}},
        clearFolderSelectionForGroupSwitch() {}, updateSidebarViewButtons() {}, renderFolderList() {},
        workspacePreferenceKey() {return `workspace_${this.currentUser}`;},
        async showConfirmDialog() {throw new Error('Recovery must not create a group without explicit confirmation');},
    }, window.HybridCipherTeamMethods.create(original));
    return env;
}
function ready(id = 'default') {
    return {group_id:id, organization_id:null, name:'Personal default', role:'owner', readiness:'ready', groups:[{id}]};
}
const unresolved = () => ({group_id:null, organization_id:null, readiness:'unresolved', groups:[]});
const owned = () => ({id:'legacy-owned', name:'Existing encrypted files', role:'owner', organization_id:null});
const deferred = () => {let resolve;const promise = new Promise(finish => {resolve = finish;});return {promise,resolve};};
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
function completed(readiness = 'ready') {
    return {success:true, data:{readiness, trust:{approved:true, fingerprint_verified:true}, imported_epochs:3,
        security_status:{recovery_backup_ok:true}, auto_backup_available:false}};
}

test('temporary login restores keys natively without a further trust prompt', async () => {
    const calls = [];
    const env = environment(async (command,args) => {calls.push({command,args});return completed();});
    env.app.promptForText = () => {throw new Error('Pinned saved-code recovery must not ask for MFA');};
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.deepEqual(calls.map(call => call.command), ['restore_saved_code_recovery']);
    assert.equal(calls[0].args.password, ' account password ');
    assert.equal(calls[0].args.expectedAccountEmail, 'a@example.com');
    assert.equal(env.selected(), 1);
    assert.match(env.notifications[0], /fully trusted.*keys are ready/);
});

test('older backup uses one legacy verification then retries the same encryption code', async () => {
    const calls = [];
    let restores = 0;
    const env = environment(async (command,args) => {
        calls.push({command,args});
        if (command === 'restore_saved_code_recovery') return ++restores === 1
            ? {success:false,error_code:'RECOVERY_MIGRATION_REQUIRED'} : completed();
        if (command === 'start_device_trust_confirmation') return {success:true,data:{otp_required:false}};
        return {success:true,data:{approved:true,fingerprint_verified:true}};
    });
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.deepEqual(calls.map(call => call.command), ['restore_saved_code_recovery','start_device_trust_confirmation',
        'complete_device_trust_confirmation','restore_saved_code_recovery']);
    assert.equal(calls[2].args.mfaCode, '123456');
    assert.equal(calls[3].args.recoveryCode, calls[0].args.recoveryCode);
});

test('stale backup reports trust success and requests newer keys before enrollment', async () => {
    const env = environment(async () => completed('missing_current_epoch'));
    env.app.workspaceContextReady = false;
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.match(env.notifications[0], /fully trusted.*historical keys.*newer backup or a Welcome/);
    assert.doesNotMatch(env.notifications[0], /Recovery complete/);
    assert.equal(env.app.personalDevicesOverview.device_trust.approved, true);
});

test('optional backup storage failure leaves recovered keys ready and reports the warning', async () => {
    const result = completed();
    result.data.backup_warning = 'Encryption keys recovered. Automatic backup credentials could not be saved.';
    const env = environment(async () => result);
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.match(env.notifications[0], /Recovery complete/);
    assert.match(env.notifications[1], /Automatic backup credentials could not be saved/);
    assert.equal(env.selected(), 1);
});

test('local key persistence failure displays successful trust without claiming recovery complete', async () => {
    const env = environment(async () => completed('key_installation_failed'));
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.match(env.notifications[0], /fully trusted.*keys could not be saved.*retry recovery/);
    assert.doesNotMatch(env.notifications[0], /Recovery complete|keys are restored/);
    assert.equal(env.app.personalDevicesOverview.device_trust.fingerprint_verified, true);
});

test('account or workspace changes discard delayed recovery results', async () => {
    for (const change of [app => {app.currentUser = 'b@example.com';app.desktopAccountGeneration++;},
        app => {app.activeWorkspaceType = 'team';app.workspaceSwitchSequence++;}, app => {app.currentDeviceId = 'other';}]) {
        let finish;
        const env = environment(() => new Promise(resolve => {finish = resolve;}));
        const pending = env.app.handleRecoveryAutoBackupSubmit();
        change(env.app);
        finish(completed());
        await pending;
        assert.equal(env.reconciled(), 0);
        assert.equal(env.closed(), 0);
        assert.equal(env.notifications.length, 0);
        assert.equal(env.app.securityStatus, undefined);
    }
});

test('invalid recovery cannot report completion and duplicate submissions stay disabled', async () => {
    let finish, calls = 0;
    const env = environment(() => {calls++;return new Promise(resolve => {finish = resolve;});});
    const pending = env.app.handleRecoveryAutoBackupSubmit();
    env.app.updateRecoveryAutoBackupSubmitState();
    assert.equal(env.nodes.get('submitRecoveryAutoBackupBtn').disabled, true);
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(calls, 1);
    finish({success:false,error:'Invalid credentials'});
    await pending;
    assert.equal(env.reconciled(), 0);
    assert.equal(env.notifications.length, 0);
    assert.equal(env.errors.at(-1), 'Invalid credentials');
    assert.equal(env.app.savedCodeRecoveryInFlight, false);
});

test('native credential rejection preserves its actionable message', async () => {
    const env = environment(async () => {throw 'The backup requires a newer encryption key';});
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(env.errors.at(-1), 'The backup requires a newer encryption key');
    assert.equal(env.notifications.length, 0);
});

test('recovery reloads a missing Personal context before reporting usable keys', async () => {
    const calls = [];
    const read = deferred();
    const env = workspaceEnvironment(async command => {
        calls.push(command);
        if (command === 'restore_saved_code_recovery') return completed();
        if (command === 'get_workspace_group_context') return read.promise;
        throw new Error(command);
    });
    const pending = env.app.handleRecoveryAutoBackupSubmit();
    await nextTurn();
    assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context']);
    assert.equal(env.notifications.length, 0);
    assert.equal(env.app.workspaceUiModel().resolved, false);
    read.resolve(ready());
    await pending;
    assert.equal(env.app.workspaceGroupContext.group_id, 'default');
    assert.equal(env.app.workspaceUiModel().canWrite, true);
    assert.equal(env.app.foldersLoaded, 1);
    assert.match(env.notifications[0], /Recovery complete.*Personal encryption keys are ready/);
    assert.equal(env.app.personalDevicesOverview.device_trust.approved, true);
});

test('saved-code recovery guides an unresolved account through explicit owned-group repair', async () => {
    const calls = [];
    let repaired = false, choices = 0;
    const env = workspaceEnvironment(async (command,args) => {
        calls.push({command,args});
        if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
        if (command === 'get_workspace_group_context') return repaired ? ready('legacy-owned') : unresolved();
        if (command === 'get_personal_workspace') return {state:'unresolved', candidates:[owned()]};
        if (command === 'repair_personal_default_group') {
            assert.equal(args.action, 'assign');
            assert.equal(args.groupId, 'legacy-owned');
            assert.equal(args.expectedAccountEmail, 'a@example.com');
            repaired = true;
            return {state:'available', personal_default_group_id:'legacy-owned', group:owned()};
        }
        throw new Error(command);
    });
    env.app.chooseWorkspaceRecord = async (_title,_note,items) => {
        choices++;
        assert.deepEqual(Array.from(items, item => item.id), ['legacy-owned']);
        assert.equal(calls.some(call => call.command === 'repair_personal_default_group'), false);
        assert.equal(env.notifications.some(message => /Recovery complete/.test(message)), false);
        return 'legacy-owned';
    };
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(choices, 1);
    assert.deepEqual(calls.map(call => call.command), ['restore_saved_code_recovery', 'get_workspace_group_context',
        'get_personal_workspace', 'repair_personal_default_group', 'get_workspace_group_context']);
    assert.equal(env.app.workspaceGroupContext.group_id, 'legacy-owned');
    assert.equal(env.app.workspaceUiModel().canWrite, true);
    assert.equal(env.notifications.filter(message => /Recovery complete/.test(message)).length, 1);
    assert.equal(env.app.personalDevicesOverview.device_trust.fingerprint_verified, true);
});

test('canceling post-recovery repair retains trust without assigning or claiming enrollment readiness', async () => {
    for (const readiness of ['personal_setup_required', 'ready']) {
        const calls = [];
        const env = workspaceEnvironment(async command => {
            calls.push(command);
            if (command === 'restore_saved_code_recovery') return completed(readiness);
            if (command === 'get_workspace_group_context') return unresolved();
            if (command === 'get_personal_workspace') return {state:'unresolved', candidates:[owned()]};
            throw new Error('Canceling the chooser must not mutate Personal setup');
        });
        let choices = 0;
        env.app.chooseWorkspaceRecord = async () => {choices++;return null;};
        await env.app.handleRecoveryAutoBackupSubmit();
        assert.equal(choices, 1, readiness);
        assert.equal(calls.includes('repair_personal_default_group'), false);
        assert.equal(env.app.workspaceUiModel().resolved, false);
        assert.equal(env.app.personalDevicesOverview.device_trust.approved, true);
        assert.equal(env.notifications.some(message => /Recovery complete|keys are ready/.test(message)), false);
        assert.equal(env.errors.at(-1), '');
    }
});

test('recovery discards a previously ready Personal context when the authoritative default is unresolved', async () => {
    const calls = [];
    const env = workspaceEnvironment(async command => {
        calls.push(command);
        if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
        if (command === 'get_workspace_group_context') return unresolved();
        if (command === 'get_personal_workspace') return {state:'unresolved', candidates:[owned()]};
        throw new Error('Repair cancellation must not assign the stale ready group');
    });
    env.app.workspaceGroupContext = ready('stale-ready');
    env.app.workspaceContextReady = true;
    let choices = 0;
    env.app.chooseWorkspaceRecord = async () => {choices++;return null;};
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(choices, 1);
    assert.equal(env.app.workspaceGroupContext.group_id, null);
    assert.equal(env.app.workspaceUiModel().resolved, false);
    assert.equal(env.notifications.some(message => /Recovery complete/.test(message)), false);
    assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context', 'get_personal_workspace']);
});

test('unavailable Personal metadata retains recovered trust and offers status retry without a repair chooser', async () => {
    const calls = [];
    const result = completed('personal_workspace_unavailable');
    result.data.personal_workspace_error = 'Personal workspace request timed out';
    const env = workspaceEnvironment(async command => {calls.push(command);return result;});
    env.app.chooseWorkspaceRecord = async () => {throw new Error('Unknown Personal identity must not offer a repair');};
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.deepEqual(calls, ['restore_saved_code_recovery']);
    assert.match(env.notifications[0], /fully trusted.*keys are restored.*could not be loaded.*check status/);
    assert.equal(env.app.personalWorkspaceError, result.data.personal_workspace_error);
    assert.equal(env.app.personalDevicesOverview.device_trust.approved, true);
    assert.equal(env.notifications.some(message => /Recovery complete/.test(message)), false);
});

test('a resolver failure after successful recovery does not open a repair or misreport key failure', async () => {
    const calls = [];
    const env = workspaceEnvironment(async command => {
        calls.push(command);
        if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
        if (command === 'get_workspace_group_context') throw 'Cannot reach Personal workspace';
        throw new Error('A failed identity read must not open repair');
    });
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context']);
    assert.match(env.notifications[0], /fully trusted.*keys are restored.*could not be loaded/);
    assert.equal(env.app.personalWorkspaceError, 'Cannot reach Personal workspace');
    assert.equal(env.app.personalDevicesOverview.device_trust.approved, true);
});

test('late post-recovery Personal resolution cannot update a different account or workspace', async () => {
    for (const change of [app => {app.currentUser = 'b@example.com';app.desktopAccountGeneration++;},
        app => {app.activeWorkspaceType = 'team';app.workspaceSwitchSequence++;},
        app => {app.currentDeviceId = 'other';}, app => {app.desktopAccountGeneration++;}]) {
        const read = deferred(), calls = [];
        const env = workspaceEnvironment(async command => {
            calls.push(command);
            if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
            if (command === 'get_workspace_group_context') return read.promise;
            throw new Error('Stale recovery must not open repair');
        });
        const pending = env.app.handleRecoveryAutoBackupSubmit();
        await nextTurn();
        change(env.app);
        const currentTrust = {device_trust:{approved:false}};
        env.app.personalDevicesOverview = currentTrust;
        read.resolve(ready());
        await pending;
        assert.equal(env.app.personalDevicesOverview, currentTrust);
        assert.equal(env.notifications.length, 0);
        assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context']);
    }
});

test('late post-recovery chooser selection cannot repair another account or switch back from Team', async () => {
    for (const change of [app => {app.currentUser = 'b@example.com';app.desktopAccountGeneration++;},
        app => {app.activeWorkspaceType = 'team';app.workspaceSwitchSequence++;}]) {
        const choice = deferred(), calls = [];
        const env = workspaceEnvironment(async command => {
            calls.push(command);
            if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
            if (command === 'get_workspace_group_context') return unresolved();
            if (command === 'get_personal_workspace') return {state:'unresolved', candidates:[owned()]};
            throw new Error('A stale chooser must not assign a group');
        });
        env.app.chooseWorkspaceRecord = () => choice.promise;
        const pending = env.app.handleRecoveryAutoBackupSubmit();
        await nextTurn();
        change(env.app);
        const currentTrust = {device_trust:{approved:false}};
        env.app.personalDevicesOverview = currentTrust;
        choice.resolve('legacy-owned');
        await pending;
        assert.equal(env.app.personalDevicesOverview, currentTrust);
        assert.equal(calls.includes('repair_personal_default_group'), false);
        assert.equal(env.notifications.some(message => /Recovery complete/.test(message)), false);
    }
});

test('recovery inside Team refreshes Team readiness without launching Personal repair', async () => {
    for (const readiness of ['personal_setup_required', 'personal_workspace_unavailable']) {
        const calls = [];
        const env = workspaceEnvironment(async (command,args) => {
            calls.push({command,args});
            if (command === 'restore_saved_code_recovery') return completed(readiness);
            if (command === 'get_workspace_group_context') return {...ready('team'), organization_id:'org'};
            throw new Error('Team recovery must not repair or select Personal');
        });
        env.app.activeWorkspaceType = 'team';
        env.app.workspaceGroupContext = {...ready('team'), organization_id:'org', readiness:'waiting_for_device_approval'};
        env.app.workspaceContextReady = false;
        await env.app.handleRecoveryAutoBackupSubmit();
        assert.equal(env.app.activeWorkspaceType, 'team');
        assert.equal(env.app.workspaceUiModel().resolved, true);
        assert.equal(calls[1].args.workspace, 'team');
        assert.match(env.notifications[0], /keys are ready in this workspace/);
        assert.deepEqual(calls.map(call => call.command), ['restore_saved_code_recovery', 'get_workspace_group_context']);
    }
});

test('an active operation prevents claiming Personal readiness from the previous context', async () => {
    const calls = [];
    const env = workspaceEnvironment(async command => {
        calls.push(command);
        assert.equal(command, 'restore_saved_code_recovery');
        return completed('personal_setup_required');
    });
    env.app.workspaceGroupContext = ready('previous');
    env.app.workspaceContextReady = true;
    env.app.desktopOperationStarting = true;
    env.app.openDesktopOperation = () => {};
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(env.notifications.some(message => /Recovery complete/.test(message)), false);
    assert.match(env.notifications.at(-1), /fully trusted.*Complete the current operation.*check Personal status/);
    assert.deepEqual(calls, ['restore_saved_code_recovery']);
});

test('background refresh and duplicate recovery cannot interrupt Personal resolution or its repair chooser', async () => {
    const read = deferred(), choice = deferred(), calls = [];
    let repaired = false;
    const env = workspaceEnvironment(async command => {
        calls.push(command);
        if (command === 'restore_saved_code_recovery') return completed('personal_setup_required');
        if (command === 'get_workspace_group_context') return repaired ? ready('legacy-owned') : read.promise;
        if (command === 'get_personal_workspace') return {state:'unresolved', candidates:[owned()]};
        if (command === 'repair_personal_default_group') {
            repaired = true;
            return {state:'available', personal_default_group_id:'legacy-owned', group:owned()};
        }
        throw new Error('A background refresh must not start during recovery completion');
    });
    env.app.chooseWorkspaceRecord = () => choice.promise;
    const pending = env.app.handleRecoveryAutoBackupSubmit();
    await nextTurn();
    const sequence = env.app.workspaceSwitchSequence;
    const attempt = env.app.savedCodeRecoveryAttempt;
    assert.equal(env.app.savedCodeRecoveryInFlight, false);
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, attempt);
    assert.equal(env.closed(), 1);
    assert.equal(env.node('recoveryAutoBackupModal').style.display, 'none');
    assert.equal(env.node('recoveryAutoBackupPasswordInput').value, '');
    assert.equal(env.node('recoveryAutoBackupCodeInput').value, '');
    // Re-entered credentials must remain disabled until the guided setup finishes.
    env.node('recoveryAutoBackupPasswordInput').value = 'another password';
    env.node('recoveryAutoBackupCodeInput').value = 'another code';
    env.app.updateRecoveryAutoBackupSubmitState();
    assert.equal(env.node('submitRecoveryAutoBackupBtn').disabled, true);
    await env.app.handleRecoveryAutoBackupSubmit();
    const backgroundRefresh = () => Promise.all([
        env.app.refreshTeamLicenseStatus({silent:true}), env.app.refreshWorkspaceAfterReconnect(),
        env.app.ensurePersonalWorkspaceReady(), env.app.checkWorkspaceReadiness({manual:false}),
    ]);
    await backgroundRefresh();
    assert.equal(env.app.workspaceSwitchSequence, sequence);
    assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context']);
    read.resolve(unresolved());
    await nextTurn();
    assert.equal(env.app.personalRepairInFlight !== null, true);
    await backgroundRefresh();
    assert.equal(env.app.workspaceSwitchSequence, sequence);
    assert.deepEqual(calls, ['restore_saved_code_recovery', 'get_workspace_group_context', 'get_personal_workspace']);
    choice.resolve('legacy-owned');
    await pending;
    assert.equal(env.app.workspaceGroupContext.group_id, 'legacy-owned');
    assert.equal(env.app.workspaceUiModel().resolved, true);
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, null);
    assert.equal(env.app.savedCodeRecoveryInFlight, false);
    assert.equal(env.node('submitRecoveryAutoBackupBtn').disabled, false);
    assert.equal(env.notifications.filter(message => /Recovery complete/.test(message)).length, 1);
});

test('an old completion cannot clear a new account recovery token after account reset', async () => {
    const firstRead = deferred(), secondRead = deferred();
    const env = workspaceEnvironment(async (command,args) => {
        if (command === 'restore_saved_code_recovery') return completed();
        if (command === 'get_workspace_group_context') return args.expectedAccountEmail === 'a@example.com'
            ? firstRead.promise : secondRead.promise;
        throw new Error(command);
    });
    const first = env.app.handleRecoveryAutoBackupSubmit();
    await nextTurn();
    const firstAttempt = env.app.savedCodeRecoveryAttempt;
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, firstAttempt);
    env.app.clearTeamUiState();
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, null);
    env.app.currentUser = 'b@example.com';
    env.node('recoveryAutoBackupPasswordInput').value = 'new account password';
    env.node('recoveryAutoBackupCodeInput').value = 'new account code';
    const second = env.app.handleRecoveryAutoBackupSubmit();
    await nextTurn();
    const secondAttempt = env.app.savedCodeRecoveryAttempt;
    assert.notEqual(secondAttempt, firstAttempt);
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, secondAttempt);
    firstRead.resolve(ready('old-account'));
    await first;
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, secondAttempt);
    assert.equal(env.notifications.length, 0);
    secondRead.resolve(ready('new-account'));
    await second;
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, null);
    assert.equal(env.app.workspaceGroupContext.group_id, 'new-account');
    assert.equal(env.notifications.filter(message => /Recovery complete/.test(message)).length, 1);
});

test('recovery resumes readiness polling after releasing its completion guard when current keys remain missing', async () => {
    const env = workspaceEnvironment(async command => {
        if (command === 'restore_saved_code_recovery') return completed('missing_current_epoch');
        if (command === 'get_workspace_group_context') return {...ready(), readiness:'waiting_for_device_approval'};
        throw new Error(command);
    });
    await env.app.handleRecoveryAutoBackupSubmit();
    assert.equal(env.app.savedCodeRecoveryCompletionInFlight, null);
    assert.equal(env.app.workspaceUiModel().resolved, false);
    assert.equal(env.app.workspaceReadinessTimer.scope.groupId, 'default');
    assert.equal(env.app.workspaceReadinessTimer.scope.sequence, env.app.workspaceSwitchSequence);
    assert.match(env.notifications[0], /historical keys.*newer backup or a Welcome/);
});
