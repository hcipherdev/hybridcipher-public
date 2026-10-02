// Account-scoped Team navigation, resumable setup, and dialog-based desktop operations.
(function (global) {
    const finished = new Set(['succeeded', 'failed', 'cancelled']);
    const adminRoles = new Set(['owner', 'admin']);
    const writeRoles = new Set(['owner', 'admin', 'writer', 'member']);
    const unwrap = value => {
        if (value?.success === false) throw new Error(value.error || 'Operation failed');
        return value?.success === true ? value.data : value;
    };
    const call = (command, args = {}) => (global.HybridCipherTauri?.invoke || global.invoke)(command, args);
    const element = id => global.document?.getElementById(id);
    const show = (id, visible) => element(id)?.classList.toggle('hidden', !visible);
    const text = (id, value) => { if (element(id)) element(id).textContent = value || ''; };
    const pause = ms => new Promise(resolve => global.setTimeout(resolve, ms));

    function workspaceModel(type, license, context, ready, directoryRole) {
        const team = type === 'team';
        const organization = license?.organization;
        const matches = Boolean(context?.group_id) && (team
            ? Boolean(context.organization_id) && (!organization?.id || context.organization_id === organization.id)
            : !context.organization_id);
        const resolved = Boolean(ready && matches);
        const orgAdmin = team && adminRoles.has(organization?.role || directoryRole);
        const groupAdmin = resolved && adminRoles.has(context.role);
        return {
            title: team ? `${organization?.name || 'Team'} · Team Workspace` : 'Personal Workspace',
            administrationTitle: `${organization?.name || 'Team'} · Team administration`,
            hasGroupContext: matches,
            resolved,
            canAdminister: team && (orgAdmin || groupAdmin),
            canCreate: team && orgAdmin && Boolean(license?.can_write),
            canAdministerGroup: team && groupAdmin && Boolean(license?.can_write && license?.online),
            canWrite: resolved && (!team || Boolean(license?.can_write)) && writeRoles.has(context?.role || 'owner'),
            contextLabel: matches ? `${context.name || 'Group'} · ${context.role || 'Member'}${resolved ? '' : ' · Setup pending'}` : 'Workspace group is not ready',
        };
    }

    function create(original) {
        const base = {};
        for (const key of ['setupEventListeners', 'applyAppMode', 'updateWorkspaceHomeSummary',
            'loadEnrolledFolders', 'refreshAdminDashboard', 'refreshAdminGroupStatus',
            'refreshTeamDirectory', 'logout', 'showWelcomeScreen', 'openCreateGroupModal', 'addEnrolledFolder',
            'showDevicesView', 'refreshPersonalDevicesOverview', 'refreshWorkspaceHomeStatus',
            'showCoverageView', 'refreshCoverageCenter', 'showFileBrowserView']) base[key] = original[key];
        return {
            setupEventListeners() {
                base.setupEventListeners.call(this);
                const bind = (id, event, fn) => element(id)?.addEventListener(event, fn);
                bind('desktopOperationsBtn', 'click', () => this.openDesktopOperation());
                bind('closeDesktopOperationBtn', 'click', () => this.closeDesktopOperation());
                bind('desktopOperationCloseBtn', 'click', () => this.closeDesktopOperation());
                bind('desktopOperationInputForm', 'submit', e => { e.preventDefault(); this.answerDesktopOperation(false); });
                bind('desktopOperationDeclineBtn', 'click', () => this.answerDesktopOperation(true));
                bind('desktopOperationChooseFileBtn', 'click', () => this.chooseOperationFile());
                bind('desktopOperationRetryBtn', 'click', () => this.retryDesktopOperation());
                bind('teamSetupRetryBtn', 'click', () => this.prepareTeamWorkspace({ showDialog: true }));
                bind('teamSetupDevicesBtn', 'click', () => this.showDevicesView());
                bind('adminRenameGroupBtn', 'click', () => this.renameSelectedGroup());
                bind('adminDeleteGroupBtn', 'click', () => this.deleteSelectedGroup());
                bind('closeAddGroupMemberBtn', 'click', () => { element('addGroupMemberModal').style.display = 'none'; });
                bind('groupMemberInviteOrganizationBtn', 'click', () => { element('addGroupMemberModal').style.display = 'none'; this.openSettingsModal(); element('teamInviteEmail')?.focus(); });
                bind('addGroupMemberForm', 'submit', async event => {
                    event.preventDefault();
                    const context = this.addMemberDialogContext;
                    if (!context || context.account !== this.currentUser || context.groupId !== this.workspaceGroupContext?.group_id) return;
                    const user = element('groupMemberSelect')?.value;
                    if (!user) return;
                    element('groupMemberAddBtn')?.toggleAttribute('disabled', true);
                    try {
                        const ok = await this.runDashboardCliCommand(`hybridcipher add-member ${this.quoteCliArg(user)}`, { title: 'Add group member' });
                        if (ok) element('addGroupMemberModal').style.display = 'none';
                    } finally { element('groupMemberAddBtn')?.toggleAttribute('disabled', false); }
                });
            },

            workspaceUiModel() {
                return workspaceModel(this.activeWorkspaceType, this.teamLicenseStatus,
                    this.workspaceGroupContext, this.workspaceContextReady, this.teamDirectoryRole);
            },

            setAdminPanelVisible(visible) {
                if (visible && this.workspaceUiModel().canAdminister) this.setWorkspaceView('admin');
                else if (this.activeWorkspaceView === 'admin') this.setWorkspaceView('home');
            },

            toggleAdminPanel() {
                if (!this.workspaceUiModel().canAdminister) return;
                this.setWorkspaceView('admin');
                this.refreshAdminDashboard();
            },

            setWorkspaceView(view) {
                const next = view === 'admin' && !this.workspaceUiModel().canAdminister ? 'home' : view;
                this.activeWorkspaceView = next;
                this.adminPanelVisible = next === 'admin';
                this.terminalVisible = next === 'terminal';
                const views = { home: 'workspaceHome', 'folder-detail': 'folderDetailView', devices: 'devicesCenterView',
                    coverage: 'coverageCenterView', admin: 'adminDashboard', terminal: 'terminalContainer', 'file-browser': 'fileBrowser' };
                for (const [name, id] of Object.entries(views)) {
                    const node = element(id);
                    if (node) { node.style.display = name === next ? 'flex' : 'none'; node.setAttribute('aria-hidden', String(name !== next)); }
                }
                element('workspace')?.classList.toggle('admin-panel-visible', this.adminPanelVisible);
                element('mainContent')?.classList.toggle('terminal-visible', this.terminalVisible);
                const admin = element('adminPanelBtn');
                if (admin) { admin.setAttribute('aria-pressed', String(this.adminPanelVisible)); admin.querySelector('.btn-label').textContent = 'Team administration'; }
                this.updateSidebarViewButtons();
                element('sidebarFilesBtn')?.setAttribute('aria-pressed', String(next === 'file-browser'));
                this.updateWorkspaceLabels();
            },

            applyAppMode() {
                base.applyAppMode.call(this);
                const model = this.workspaceUiModel();
                const admin = element('adminPanelBtn');
                if (admin) { admin.classList.toggle('hidden', !model.canAdminister); admin.setAttribute('aria-hidden', String(!model.canAdminister)); admin.tabIndex = model.canAdminister ? 0 : -1; }
                element('adminCreateGroupBtn')?.toggleAttribute('disabled', !model.canCreate);
                for (const id of ['adminAddMemberBtn', 'adminRemoveMemberBtn', 'adminRekeyStartBtn', 'adminRekeyMigrationBtn', 'adminRekeyCutoverBtn', 'adminRekeyFallbackBtn', 'adminRenameGroupBtn', 'adminDeleteGroupBtn'])
                    element(id)?.toggleAttribute('disabled', !model.canAdministerGroup);
                for (const id of ['addFolderBtn', 'homeAddFolderBtn', 'adminEnrollFolderBtn']) element(id)?.toggleAttribute('disabled', !model.canWrite);
                for (const id of ['homeRunCoverageScanBtn', 'adminCoverageScanBtn', 'adminVerifyMembershipBtn', 'adminCoverageSampleAuditBtn', 'adminCoverageFullAuditBtn', 'adminCoverageVerifyBtn'])
                    element(id)?.toggleAttribute('disabled', !model.resolved);
                this.updateWorkspaceLabels();
            },

            updateWorkspaceLabels() {
                const model = this.workspaceUiModel();
                text('workspaceHomeTitle', model.title);
                text('teamAdministrationTitle', model.administrationTitle);
                text('workspaceContextLabel', model.contextLabel);
                const label = element('adminDashboard')?.querySelector('.dashboard-subtitle');
                if (label) label.textContent = model.contextLabel;
                const teamOption = element('workspaceSelector')?.querySelector('option[value="team"]');
                if (teamOption) teamOption.textContent = this.teamLicenseStatus?.organization?.name || 'Team';
                show('teamSetupNotice', this.activeWorkspaceType === 'team' && !model.resolved);
                text('teamSetupMessage', this.teamSetupMessage || 'Loading the Team workspace…');
                show('teamSetupRetryBtn', !this.teamSetupInProgress && Boolean(this.teamLicenseStatus?.online && this.teamLicenseStatus?.can_write)
                    && this.teamLicenseStatus?.organization?.role === 'owner');
                show('teamSetupDevicesBtn', this.workspaceGroupContext?.readiness === 'waiting_for_device_approval'
                    || this.teamSetupErrorCode === 'device_approval_required');
            },

            updateWorkspaceHomeSummary() { base.updateWorkspaceHomeSummary.call(this); this.updateWorkspaceLabels(); },
            async showDevicesView(options = {}) {
                if (!this.workspaceUiModel().hasGroupContext) {
                    this.showNotification('Load or select a group in this workspace before opening Devices.', 'warning'); return;
                }
                return base.showDevicesView?.call(this, options);
            },
            async refreshPersonalDevicesOverview(options = {}) {
                if (!this.workspaceUiModel().hasGroupContext) { this.personalDevicesOverview = null; return; }
                return base.refreshPersonalDevicesOverview?.call(this, options);
            },
            async refreshWorkspaceHomeStatus(options = {}) {
                if (!this.workspaceUiModel().hasGroupContext) { this.homeStatusSnapshot = null; this.updateWorkspaceHomeSummary(); return; }
                return base.refreshWorkspaceHomeStatus?.call(this, options);
            },
            showFileBrowserView() {
                if (!this.workspaceUiModel().resolved) { this.showNotification('Complete workspace setup before opening Files.', 'warning'); return; }
                return base.showFileBrowserView?.call(this);
            },
            showCoverageView(options = {}) {
                if (!this.workspaceUiModel().resolved) { this.showNotification('Complete workspace setup before checking coverage.', 'warning'); return; }
                return base.showCoverageView?.call(this, options);
            },
            async refreshCoverageCenter(options = {}) {
                if (!this.workspaceUiModel().resolved) { this.coverageCenterSnapshot = null; return; }
                return base.refreshCoverageCenter?.call(this, options);
            },
            handleGlobalSearch(event) { this.folderSearchQuery = event?.target?.value || ''; this.closeCommandPalette(); this.renderFolderList(); },
            handleCommandPaletteKeydown(event) {
                if (event?.key === 'Escape') { this.folderSearchQuery = ''; event.target.value = ''; this.closeCommandPalette(); this.renderFolderList(); }
            },

            groupPreferenceKey(type = this.activeWorkspaceType) { return `${this.workspacePreferenceKey()}_group_${type}`; },
            clearWorkspaceContext() {
                this.workspaceContextReady = false;
                this.workspaceGroupContext = null;
                this.enrolledFolders = [];
                this.homeStatusSnapshot = null;
                this.personalDevicesOverview = null;
                this.coverageCenterSnapshot = null;
                this.coverageCenterState = { loading: false, error: null,
                    scanState: { state: 'idle', processed: 0, total: 0, rootProgress: {} } };
                this.addMemberDialogContext = null;
                this.cancelWorkspaceSelection?.();
                for (const id of ['addGroupMemberModal', 'removeMemberModal', 'switchGroupModal', 'listGroupsModal', 'listMembersModal', 'verifyMembershipModal'])
                    if (element(id)) element(id).style.display = 'none';
                for (const id of ['switchGroupList', 'listGroupsList', 'listMembersList', 'removeMemberList', 'devicesCenterContent', 'coverageCenterContent']) text(id, '');
                this.clearFolderSelectionForGroupSwitch();
                this.applyAppMode();
                this.updateWorkspaceHomeSummary();
            },

            async selectWorkspaceType(type, { forceGroupId = null, showDialog = false } = {}) {
                if (type === 'team' && this.teamLicenseStatus?.workspace !== 'team') return false;
                const account = this.currentUser;
                const sequence = (this.workspaceSwitchSequence || 0) + 1;
                this.workspaceSwitchSequence = sequence;
                this.activeWorkspaceType = type === 'team' ? 'team' : 'personal';
                this.appMode = this.activeWorkspaceType === 'team' ? 'team' : 'individual';
                this.clearWorkspaceContext();
                this.setWorkspaceView('home');
                this.teamSetupMessage = 'Loading workspace group…';
                try {
                    let context = unwrap(await call('get_workspace_group_context', { workspace: this.activeWorkspaceType,
                        selectionSequence: sequence, expectedAccountEmail: account }));
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                    const preferred = forceGroupId || global.localStorage.getItem(this.groupPreferenceKey());
                    if (preferred && context?.group_id !== preferred) {
                        await this.runDesktopOperation({ kind: 'switch_group', group_id: preferred, title: 'Switch group' }, { showDialog });
                        if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                        context = unwrap(await call('get_workspace_group_context', { workspace: this.activeWorkspaceType,
                            selectionSequence: sequence, expectedAccountEmail: account }));
                    }
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return false;
                    if (preferred && context?.group_id !== preferred) throw new Error('The selected group is not ready on this device. Open Devices to complete approval, then retry.');
                    this.workspaceGroupContext = context;
                    this.workspaceContextReady = context?.readiness === 'ready';
                    const model = this.workspaceUiModel();
                    this.workspaceContextReady = model.resolved;
                    if (!model.resolved) {
                        this.teamSetupMessage = context?.readiness === 'waiting_for_device_approval'
                            ? 'Waiting for approval from a trusted device. Open Devices to complete setup.'
                            : context?.readiness === 'deleted' ? 'The default group was deleted. Create or select another Team group.'
                            : 'No usable group is available in this workspace yet.';
                    } else {
                        global.localStorage.setItem(this.workspacePreferenceKey(), this.activeWorkspaceType);
                        global.localStorage.setItem(this.groupPreferenceKey(), context.group_id);
                        await this.loadEnrolledFolders({ suppressErrorNotification: true });
                    }
                    this.applyAppMode();
                    return model.resolved;
                } catch (error) {
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return false;
                    this.teamSetupMessage = `Could not load this workspace: ${error.message || error}. Retry when connected.`;
                    this.applyAppMode();
                    if (!showDialog) this.showNotification(this.teamSetupMessage, 'warning');
                    return false;
                }
            },

            async refreshTeamLicenseStatus({ silent = false } = {}) {
                if (!this.isLoggedIn) return null;
                const account = this.currentUser;
                try {
                    const status = unwrap(await call('get_team_license_status'));
                    if (this.currentUser !== account || !this.isLoggedIn) return null;
                    this.teamLicenseStatus = status;
                    this.renderTeamLicenseSettings();
                    await this.refreshTeamDirectory();
                    if (this.currentUser !== account || !this.isLoggedIn) return null;
                    const first = !this.workspaceChoiceLoaded;
                    this.workspaceChoiceLoaded = true;
                    const choice = status?.workspace === 'team'
                        ? (first ? global.localStorage.getItem(this.workspacePreferenceKey()) || 'team' : this.activeWorkspaceType) : 'personal';
                    if (status?.workspace === 'team' && status.online && status.can_write && status.organization?.role === 'owner'
                        && this.teamSetupCompletedOrganizationId !== status.organization.id)
                        await this.prepareTeamWorkspace({ showDialog: false, select: choice === 'team' });
                    else if (first || choice !== this.activeWorkspaceType || !this.workspaceContextReady)
                        await this.selectWorkspaceType(choice);
                    if (this.currentUser !== account || !this.isLoggedIn) return null;
                    this.applyAppMode();
                    await this.refreshPendingTeamRequests(status?.workspace === 'team' && status.online && status.can_write);
                    return status;
                } catch (error) {
                    if (this.currentUser !== account) return null;
                    text('teamLicenseNote', `License status unavailable: ${error.message || error}`);
                    if (!silent) this.showNotification('Could not refresh workspace access.', 'warning');
                    return null;
                }
            },

            async prepareTeamWorkspace({ showDialog = true, select = true } = {}) {
                if (this.teamSetupInProgress) return false;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                this.teamSetupInProgress = true;
                this.teamSetupErrorCode = null;
                try {
                    const result = await this.runDesktopOperation({ kind: 'team_setup', title: 'Preparing Team workspace' }, {
                        showDialog, onUpdate: operation => { if (this.currentUser === account) { this.teamSetupMessage = operation.phase; this.updateWorkspaceLabels(); } },
                    });
                    if (this.currentUser !== account) return false;
                    if (result?.readiness === 'waiting_for_device_approval') {
                        const error = new Error('Approve this device from a trusted device in the group.');
                        error.code = 'device_approval_required'; throw error;
                    }
                    this.teamSetupCompletedOrganizationId = this.teamLicenseStatus?.organization?.id;
                    this.teamSetupMessage = result?.readiness === 'deleted' ? 'The default group was deleted. Create another group to continue.' : '';
                    if ((select || result?.first_setup) && sequence === this.workspaceSwitchSequence) await this.selectWorkspaceType('team', {
                        forceGroupId: result?.first_setup || !global.localStorage.getItem(this.groupPreferenceKey('team')) ? result?.group_id : null,
                    });
                    return true;
                } catch (error) {
                    if (this.currentUser !== account) return false;
                    this.teamSetupErrorCode = error.code;
                    this.teamSetupMessage = error.code === 'device_approval_required'
                        ? 'Waiting for approval from a trusted device. Open Devices to complete setup.'
                        : `Team activated; workspace setup pending. ${error.message}`;
                    if (select && sequence === this.workspaceSwitchSequence) {
                        this.activeWorkspaceType = 'team'; this.appMode = 'team'; this.clearWorkspaceContext(); this.setWorkspaceView('home');
                        try {
                            const context = unwrap(await call('get_workspace_group_context', { workspace: 'team',
                                selectionSequence: sequence || 0, expectedAccountEmail: account }));
                            if (this.currentUser === account && sequence === this.workspaceSwitchSequence) this.workspaceGroupContext = context;
                        } catch (_) { /* Preserve the actionable setup error. */ }
                    }
                    return false;
                } finally {
                    if (this.currentUser === account) { this.teamSetupInProgress = false; this.updateWorkspaceLabels(); }
                }
            },

            async activateTeamFromSettings() {
                if (this.teamActivationInProgress) return;
                const name = element('teamOrganizationName')?.value.trim() || '';
                const code = element('teamUnlockCode')?.value.trim() || '';
                if (!name || !code) { this.showNotification('Enter an organization name and Team code.', 'warning'); return; }
                this.teamActivationInProgress = true;
                const account = this.currentUser;
                try {
                    const status = unwrap(await call('redeem_team_code', { code, organizationName: name }));
                    if (this.currentUser !== account) return;
                    element('teamUnlockCode').value = '';
                    this.teamLicenseStatus = status;
                    this.activeWorkspaceType = 'team'; this.appMode = 'team'; this.workspaceChoiceLoaded = true;
                    this.clearWorkspaceContext(); this.renderTeamLicenseSettings(); this.closeSettingsModal();
                    global.localStorage.setItem(this.workspacePreferenceKey(), 'team');
                    await this.prepareTeamWorkspace({ showDialog: true });
                    if (this.currentUser === account && this.isLoggedIn) await this.refreshTeamDirectory();
                } catch (error) { if (this.currentUser === account) this.showNotification(`Team activation failed: ${error.message || error}`, 'error'); }
                finally { if (this.currentUser === account) this.teamActivationInProgress = false; }
            },

            async refreshTeamDirectory() {
                if (this.teamLicenseStatus?.workspace !== 'team') return;
                const account = this.currentUser;
                try {
                    const directory = unwrap(await call('get_team_directory'));
                    if (this.currentUser !== account || !this.isLoggedIn) return;
                    this.teamDirectoryRole = directory?.role;
                    const list = element('teamDirectoryList');
                    const canAdminister = this.teamLicenseStatus?.can_write && adminRoles.has(directory.role);
                    text('teamDirectoryNote', directory.online ? 'Owner and pending invitations count toward seats.' : 'Saved member list. Requests will be checked after reconnecting.');
                    const row = (label, kind, id, action) => `<div class="team-request-row"><span>${this.escapeHtml(label)}</span>`
                        + (canAdminister && kind ? `<button type="button" class="btn btn-secondary btn-small" data-team-directory-kind="${kind}" data-team-directory-id="${this.escapeHtmlAttr(id)}">${action}</button>` : '') + '</div>';
                    if (list) {
                        list.innerHTML = (directory.members || []).map(member => row(`${member.email} (${member.role})`, member.role === 'owner' ? null : 'remove_member', member.user_id, 'Remove member')).join('')
                            + (directory.invitations || []).filter(invitation => invitation.status === 'pending' && Date.parse(invitation.expires_at) > Date.now())
                                .map(invitation => row(`${invitation.email} (invitation pending)`, 'cancel_invitation', invitation.id, 'Cancel invitation')).join('');
                        if (!list.innerHTML) list.textContent = 'Member list is available after connecting.';
                        list.querySelectorAll('[data-team-directory-kind]').forEach(button => button.addEventListener('click', async () => {
                            if (this.currentUser !== account) return;
                            const confirmed = await this.showConfirmDialog('Confirm organization change', 'This request changes organization access. Continue?');
                            if (!confirmed || this.currentUser !== account) return;
                            button.disabled = true;
                            try {
                                await call('queue_team_admin_request', { kind: button.dataset.teamDirectoryKind, targetId: button.dataset.teamDirectoryId, email: null, groupName: null, description: null });
                                if (this.currentUser !== account) return;
                                await this.refreshPendingTeamRequests(Boolean(this.teamLicenseStatus?.online));
                                if (this.currentUser !== account) return;
                                await this.refreshTeamLicenseStatus({ silent: true });
                            } catch (error) { if (this.currentUser === account) this.showNotification(error.message || String(error), 'error'); }
                            finally { if (this.currentUser === account) button.disabled = false; }
                        }));
                    }
                    this.renderTeamLicenseSettings(); this.applyAppMode();
                } catch (_) { if (this.currentUser === account) { this.teamDirectoryRole = null; this.applyAppMode(); } }
            },

            async openAddGroupMemberDialog() {
                if (!this.workspaceUiModel().canAdministerGroup) return;
                const modal = element('addGroupMemberModal');
                const select = element('groupMemberSelect');
                modal.style.display = 'flex';
                select.innerHTML = '';
                text('groupMemberDirectoryNote', 'Loading organization members…');
                element('groupMemberAddBtn')?.toggleAttribute('disabled', true);
                const account = this.currentUser;
                this.addMemberDialogContext = { account, groupId: this.workspaceGroupContext?.group_id };
                try {
                    const directory = unwrap(await call('get_team_directory'));
                    if (this.currentUser !== account) return;
                    const placeholder = global.document.createElement('option');
                    placeholder.value = ''; placeholder.textContent = 'Choose a member'; select.appendChild(placeholder);
                    for (const member of directory.members || []) {
                        const option = global.document.createElement('option');
                        option.value = member.user_id; option.textContent = member.email || member.user_id; select.appendChild(option);
                    }
                    text('groupMemberDirectoryNote', directory.online ? 'Invite new people to the organization before adding them here.' : 'Connect to add a member. This is the saved organization list.');
                    element('groupMemberAddBtn')?.toggleAttribute('disabled', !directory.online || !(directory.members || []).length);
                } catch (error) { if (this.currentUser === account) text('groupMemberDirectoryNote', `Could not load organization members: ${error.message || error}`); }
            },

            async addEnrolledFolder(...args) {
                if (!this.workspaceUiModel().canWrite) { this.showNotification('Select a ready workspace with write access before adding a protected folder.', 'warning'); return; }
                return base.addEnrolledFolder.apply(this, args);
            },

            async loadEnrolledFolders(options = {}) {
                if (!this.workspaceContextReady) { this.enrolledFolders = []; this.renderFolderList(); return; }
                return base.loadEnrolledFolders.call(this, options);
            },
            refreshAdminDashboard() { if (this.workspaceContextReady) return base.refreshAdminDashboard.call(this); },
            async refreshAdminGroupStatus() {
                if (!this.workspaceContextReady) return;
                await base.refreshAdminGroupStatus.call(this);
                this.updateWorkspaceLabels();
            },

            async getActiveGroupContext() {
                const context = this.workspaceGroupContext;
                return { groupId: this.workspaceContextReady ? context?.group_id : null,
                    groupName: this.workspaceContextReady ? context?.name : null, role: context?.role, organizationId: context?.organization_id };
            },

            async submitSwitchGroupSelection(groupId) {
                if (!groupId || this.groupSwitchInProgress) return;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                this.groupSwitchInProgress = true;
                try {
                    await this.runDesktopOperation({ kind: 'switch_group', group_id: groupId, title: 'Switch group' });
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    const selected = await this.selectWorkspaceType(this.activeWorkspaceType, { forceGroupId: groupId });
                    if (selected) { this.closeSwitchGroupModal(); if (this.switchGroupCloseSettings) this.closeSettingsModal(); }
                } catch (_) { /* The operation dialog retains its error and retry. */ }
                finally { if (this.currentUser === account) this.groupSwitchInProgress = false; }
            },

            openCreateGroupModal() {
                if (this.groupCreationInProgress) { base.openCreateGroupModal.call(this); return; }
                this.createdGroupPendingId = null;
                this.groupCreationComplete = false; this.groupCreationQueued = false;
                element('createGroupName')?.toggleAttribute('disabled', false);
                element('createGroupDescription')?.toggleAttribute('disabled', false);
                element('submitCreateGroupBtn')?.toggleAttribute('disabled', false);
                text('createGroupError', ''); show('createGroupError', false); text('createGroupProgress', '');
                text('submitCreateGroupBtn', 'Create & initialize');
                base.openCreateGroupModal.call(this);
            },
            async handleCreateGroupSubmit(event) {
                event.preventDefault();
                if (this.groupCreationInProgress) return;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                const name = element('createGroupName')?.value.trim() || '';
                const description = element('createGroupDescription')?.value.trim() || '';
                if (!name) { text('createGroupError', 'Group name is required.'); show('createGroupError', true); return; }
                if (!this.workspaceUiModel().canCreate) { text('createGroupError', 'Your organization role or license does not allow group creation.'); show('createGroupError', true); return; }
                this.groupCreationInProgress = true;
                element('submitCreateGroupBtn')?.toggleAttribute('disabled', true);
                element('createGroupName')?.toggleAttribute('disabled', true);
                element('createGroupDescription')?.toggleAttribute('disabled', true);
                show('createGroupError', false);
                try {
                    if (!this.teamLicenseStatus?.online) {
                        await call('queue_team_admin_request', { kind: 'create_group', groupName: name, description });
                        if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                        text('createGroupProgress', 'Pending server approval. Review this request in Workspace license settings.');
                        await this.refreshPendingTeamRequests();
                        this.groupCreationQueued = true;
                    } else {
                        const request = this.createdGroupPendingId
                            ? { kind: 'initialize_group', group_id: this.createdGroupPendingId, title: 'Initialize group' }
                            : { kind: 'create_group', name, description, title: 'Create group' };
                        const result = await this.runDesktopOperation(request, { showDialog: false, onUpdate: operation => {
                            if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                            if (operation.group_id) this.createdGroupPendingId = operation.group_id;
                            text('createGroupProgress', operation.phase);
                        } });
                        if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                        this.createdGroupPendingId = result.group_id;
                        if (result.readiness === 'waiting_for_device_approval') {
                            const error = new Error('Group created. This device is waiting for approval from a trusted device. Open Devices, then retry initialization.');
                            error.code = 'device_approval_required'; error.group_id = result.group_id; throw error;
                        }
                        text('createGroupProgress', 'Encryption initialized. Loading the new group…');
                        const ready = await this.selectWorkspaceType('team', { forceGroupId: result.group_id });
                        if (this.currentUser !== account) return;
                        if (!ready) throw new Error('Group created; loading is pending. Retry initialization or review workspace setup.');
                        text('createGroupProgress', 'Group ready.');
                        text('submitCreateGroupBtn', 'Ready');
                        this.groupCreationComplete = true;
                    }
                } catch (error) {
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    if (error.group_id) this.createdGroupPendingId = error.group_id;
                    text('createGroupError', error.message); show('createGroupError', true);
                    text('submitCreateGroupBtn', this.createdGroupPendingId ? 'Retry initialization' : 'Retry');
                } finally {
                    if (this.currentUser !== account) return;
                this.groupCreationInProgress = false;
                    element('submitCreateGroupBtn')?.toggleAttribute('disabled', Boolean(this.groupCreationComplete || this.groupCreationQueued));
                    if (!this.createdGroupPendingId) { element('createGroupName')?.toggleAttribute('disabled', false); element('createGroupDescription')?.toggleAttribute('disabled', false); }
                }
            },

            async runDesktopOperation(request, { showDialog = true, onUpdate = null } = {}) {
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) {
                    this.openDesktopOperation(); throw new Error('Complete the current operation before starting another.');
                }
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                request = { ...request, expected_account_email: account,
                    ...(request.kind === 'switch_group' ? { selection_sequence: this.workspaceSwitchSequence || 0 } : {}) };
                this.desktopOperationRequest = { ...request };
                this.desktopOperationTitle = request.title || 'Operation';
                this.desktopOperationStarting = true;
                let snapshot;
                try { snapshot = unwrap(await call('start_desktop_operation', { request })); }
                finally { if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) this.desktopOperationStarting = false; }
                if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || !this.isLoggedIn) throw new Error('Account changed during the operation.');
                this.desktopOperation = snapshot;
                if (showDialog) this.openDesktopOperation();
                while (this.currentUser === account && generation === (this.desktopAccountGeneration || 0) && this.isLoggedIn) {
                    this.desktopOperation = snapshot;
                    this.renderDesktopOperation();
                    onUpdate?.(snapshot);
                    if (snapshot.status === 'needs_input') this.openDesktopOperation();
                    if (finished.has(snapshot.status)) break;
                    await pause(300);
                    if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || !this.isLoggedIn) break;
                    snapshot = unwrap(await call('get_desktop_operation', { operationId: snapshot.id }));
                }
                if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || !this.isLoggedIn) throw new Error('Account changed during the operation.');
                if (snapshot.status !== 'succeeded') {
                    const error = new Error(snapshot.error?.message || (snapshot.status === 'cancelled' ? 'Operation cancelled.' : 'Operation failed.'));
                    error.code = snapshot.error?.code; error.group_id = snapshot.group_id;
                    throw error;
                }
                return snapshot.result || {};
            },

            openDesktopOperation() { const modal = element('desktopOperationModal'); if (modal) modal.style.display = 'flex'; this.renderDesktopOperation(); },
            closeDesktopOperation() {
                if (element('desktopOperationModal')) element('desktopOperationModal').style.display = 'none';
                if (element('desktopOperationInput')) element('desktopOperationInput').value = '';
            },
            renderDesktopOperation() {
                const operation = this.desktopOperation;
                if (!operation) return;
                show('desktopOperationsBtn', true);
                text('desktopOperationTitle', this.desktopOperationTitle);
                text('desktopOperationPhase', operation.phase || (operation.status === 'succeeded' ? 'Complete' : 'Working…'));
                text('desktopOperationError', operation.error?.message);
                show('desktopOperationError', Boolean(operation.error));
                const progress = element('desktopOperationProgress');
                if (progress) { if (Number.isFinite(operation.progress)) { progress.max = 100; progress.value = operation.progress; } else progress.removeAttribute('value'); }
                show('desktopOperationProgress', !finished.has(operation.status));
                show('desktopOperationBackgroundNote', !finished.has(operation.status));
                const details = Array.isArray(operation.output) ? operation.output.join('\n') : '';
                text('desktopOperationOutput', details); show('desktopOperationDetails', Boolean(details));
                if (operation.status === 'succeeded' && details && element('desktopOperationDetails')) element('desktopOperationDetails').open = true;
                show('desktopOperationRetryBtn', operation.status === 'failed' && this.desktopOperationRequest?.kind !== 'cli');
                const inputRequest = operation.status === 'needs_input' ? operation.input_request : null;
                show('desktopOperationInputForm', Boolean(inputRequest));
                if (inputRequest && this.desktopInputRequestId !== inputRequest.id) {
                    this.desktopInputRequestId = inputRequest.id;
                    const input = element('desktopOperationInput');
                    text('desktopOperationInputLabel', inputRequest.message);
                    text('desktopOperationContinueBtn', inputRequest.kind === 'confirm' ? 'Confirm' : 'Continue');
                    if (input) { input.type = inputRequest.kind === 'password' ? 'password' : 'text'; input.value = inputRequest.default_value || ''; input.hidden = inputRequest.kind === 'confirm'; input.focus(); }
                    show('desktopOperationChooseFileBtn', inputRequest.kind === 'file');
                }
            },
            async chooseOperationFile() {
                const account = this.currentUser;
                const requestId = this.desktopOperation?.input_request?.id;
                const dialog = global.__TAURI__?.dialog || global.HybridCipherTauri?.dialog;
                if (!dialog?.open) { this.showNotification('File selection is unavailable.', 'error'); return; }
                const path = await dialog.open({ multiple: false, directory: false, title: 'Choose file' });
                if (this.currentUser === account && this.desktopOperation?.input_request?.id === requestId && path && element('desktopOperationInput')) element('desktopOperationInput').value = path;
            },
            async answerDesktopOperation(decline) {
                const operation = this.desktopOperation;
                const account = this.currentUser;
                const inputRequest = operation?.input_request;
                if (!inputRequest) return;
                const input = element('desktopOperationInput');
                const value = decline ? null : inputRequest.kind === 'confirm' ? 'true' : input?.value || '';
                if (input) input.value = '';
                element('desktopOperationContinueBtn')?.toggleAttribute('disabled', true);
                try {
                    const snapshot = unwrap(await call('answer_desktop_operation', { operationId: operation.id, answer: { request_id: inputRequest.id, value } }));
                    if (this.currentUser !== account || this.desktopOperation?.id !== operation.id) return;
                    this.desktopOperation = snapshot; this.renderDesktopOperation();
                }
                catch (error) { if (this.currentUser === account) { text('desktopOperationError', error.message || String(error)); show('desktopOperationError', true); } }
                finally { if (this.currentUser === account) element('desktopOperationContinueBtn')?.toggleAttribute('disabled', false); }
            },
            async retryDesktopOperation() {
                const previous = this.desktopOperation;
                const request = previous?.group_id && this.desktopOperationRequest?.kind === 'create_group'
                    ? { kind: 'initialize_group', group_id: previous.group_id, title: 'Initialize group' } : this.desktopOperationRequest;
                if (!request) return;
                try { await this.runDesktopOperation(request); await this.selectWorkspaceType(this.activeWorkspaceType, { forceGroupId: request.group_id || null }); }
                catch (_) { /* Retained in the operation dialog. */ }
            },

            async runSettingsCliCommand(command, options = {}) {
                if (this.sessionPersistent === false) {
                    this.showNotification('This action requires a persistent login. Turn on Remember me and sign in again.', 'warning'); return false;
                }
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                if (options.confirmTitle && !(await this.showConfirmDialog(options.confirmTitle, options.confirmMessage))) return false;
                if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                const args = this.parseGeneratedCliArgs(command);
                if (command.includes(' && ')) throw new Error('This action requires a typed operation.');
                const context = this.workspaceGroupContext;
                const exempt = ['server-trust', 'list-groups', 'current-user', 'keystore-status'];
                const completesSetup = args[0] === 'process-welcome-messages';
                const model = this.workspaceUiModel();
                if (!args.includes('-h') && !args.includes('--help') && !exempt.includes(args[0])
                    && !(completesSetup ? model.hasGroupContext : model.resolved)) {
                    this.showNotification('Select a ready group in this workspace before continuing.', 'warning'); return false;
                }
                try {
                    if (options.closeSettingsModal !== false) this.closeSettingsModal();
                    await this.runDesktopOperation({ kind: 'cli', args, group_id: args.includes('-h') || args.includes('--help') ? null : context?.group_id || null, title: options.title || this.cliActionTitle(args) });
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                    if (completesSetup && !(await this.selectWorkspaceType(this.activeWorkspaceType, { forceGroupId: context.group_id }))) return false;
                    if (this.currentUser !== account || !this.isLoggedIn) return false;
                    if (this.workspaceContextReady) await this.loadEnrolledFolders({ suppressErrorNotification: true });
                    this.refreshAdminDashboard();
                    return true;
                } catch (error) { if (this.currentUser === account && !this.desktopOperation?.error) this.showNotification(error.message || String(error), 'error'); return false; }
            },
            quoteCliArg(value) { return `"${String(value ?? '').replace(/"/g, '""')}"`; },
            async runCliStatusCommand(command) {
                const data = await this.runBundledCliArgs(this.parseGeneratedCliArgs(command));
                return `${data.stdout || ''}\n${data.stderr || ''}`.trim();
            },
            async runCliCommandRaw(command) {
                const account = this.currentUser;
                const result = await this.runDesktopOperation({ kind: 'cli', args: this.parseGeneratedCliArgs(command),
                    group_id: this.workspaceGroupContext?.group_id || null, title: 'Workspace operation' });
                if (this.currentUser !== account || !this.isLoggedIn) throw new Error('Account changed during the operation.');
                return { status: result.exit_status || 0,
                    stdout: Array.isArray(result.output) ? result.output.join('\n') : String(result.output || ''), stderr: '' };
            },
            async chooseWorkspaceRecord(title, note, items) {
                this.cancelWorkspaceSelection?.();
                const modal = element('workspaceSelectionModal');
                const select = element('workspaceSelectionSelect');
                const form = element('workspaceSelectionForm');
                const cancel = element('workspaceSelectionCancelBtn');
                const backdrop = modal.querySelector('.modal-backdrop');
                select.innerHTML = '';
                for (const item of items) {
                    const option = global.document.createElement('option');
                    option.value = item.id; option.textContent = item.label; select.appendChild(option);
                }
                text('workspaceSelectionTitle', title); text('workspaceSelectionNote', note);
                modal.style.display = 'flex'; select.focus();
                return new Promise(resolve => {
                    const finish = value => {
                        modal.style.display = 'none'; select.innerHTML = '';
                        form.removeEventListener('submit', submit); cancel.removeEventListener('click', close);
                        backdrop.removeEventListener('click', close); global.document.removeEventListener('keydown', keydown);
                        this.cancelWorkspaceSelection = null; resolve(value);
                    };
                    const submit = event => { event.preventDefault(); finish(select.value); };
                    const close = () => finish(null);
                    const keydown = event => { if (event.key === 'Escape') { event.preventDefault(); close(); } };
                    this.cancelWorkspaceSelection = close;
                    form.addEventListener('submit', submit); cancel.addEventListener('click', close);
                    backdrop.addEventListener('click', close); global.document.addEventListener('keydown', keydown);
                });
            },
            async renameSelectedGroup() {
                if (!this.workspaceUiModel().canAdministerGroup) return;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                const context = this.workspaceGroupContext;
                const name = await this.promptForText('Enter the new group name.', { title: 'Rename group', defaultValue: context.name, submitLabel: 'Rename' });
                if (!name?.trim() || this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                const ok = await this.runDashboardCliCommand(`hybridcipher rename-group ${this.quoteCliArg(context.group_id)} --name ${this.quoteCliArg(name.trim())}`, { title: 'Rename group' });
                if (ok && this.currentUser === account && sequence === this.workspaceSwitchSequence) await this.selectWorkspaceType('team');
            },
            async deleteSelectedGroup() {
                if (!this.workspaceUiModel().canAdministerGroup) return;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                const context = this.workspaceGroupContext;
                const confirmed = await this.showConfirmDialog('Delete group', `Delete ${context.name || 'this group'} and revoke its server access? The default group will not be recreated. Export any needed data before deleting.`);
                if (!confirmed || this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                const ok = await this.runDashboardCliCommand(`hybridcipher delete-group ${this.quoteCliArg(context.group_id)} --yes`, { title: 'Delete group' });
                if (ok && this.currentUser === account && sequence === this.workspaceSwitchSequence) {
                    global.localStorage.removeItem(this.groupPreferenceKey('team'));
                    await this.selectWorkspaceType('team');
                }
            },
            async verifyMembershipWithDialog() {
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                try {
                    const members = unwrap(await call('get_group_member_details')) || [];
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    const user = await this.chooseWorkspaceRecord('Verify membership', 'Choose a member to inspect their signed group membership.',
                        [{ id: 'self', label: 'My membership' }, ...members.map(member => ({ id: member.user_id, label: member.email || member.user_id }))]);
                    if (!user || this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    await this.runDashboardCliCommand(`hybridcipher verify-membership${user === 'self' ? '' : ` --user ${this.quoteCliArg(user)}`}`, { title: 'Membership verification report' });
                } catch (error) { if (this.currentUser === account) this.showNotification(error.message || String(error), 'error'); }
            },
            async verifyCoverageWithDialog() {
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                try {
                    const files = unwrap(await call('list_coverage_verification_files')) || [];
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    if (!files.length) { this.showNotification('No tracked files are available for proof verification. Protect files in this group first.', 'info'); return; }
                    const file = await this.chooseWorkspaceRecord('Verify protection proof', 'Choose a tracked file in this group.',
                        files.map(file => ({ id: file.file_id, label: file.path || file.relative_path || file.file_id })));
                    if (!file || this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return;
                    await this.runDashboardCliCommand(`hybridcipher coverage verify ${this.quoteCliArg(file)}`, { title: 'File verification report' });
                } catch (error) { if (this.currentUser === account) this.showNotification(error.message || String(error), 'error'); }
            },
            runDashboardCliCommand(command, options = {}) { return this.runSettingsCliCommand(command, { ...options, closeSettingsModal: false }); },
            cliActionTitle(args) {
                const labels = { 'add-member': 'Add group member', 'remove-member': 'Remove group member', 'verify-membership': 'Verify membership',
                    'process-welcome-messages': 'Complete device setup', 'pending-devices': 'Pending devices', coverage: 'Protection coverage',
                    rekey: 'Group key update', 'server-trust': 'Server trust', pin: 'Trusted devices', recovery: 'Recovery backup' };
                return labels[args[0]] || 'Workspace operation';
            },

            async beginRekeyFlow({ title, message }) {
                const confirmed = await this.showActionPrompt(title, message, { primaryLabel: 'Start rekey', secondaryLabel: 'Not now' });
                if (confirmed !== true) return;
                await this.runDashboardCliCommand('hybridcipher rekey start --activation-delay immediate --local-migration defer', { title: 'Prepare new group keys' });
            },
            async showMigrationDeferredPrompt() {
                const run = await this.showActionPrompt('Migration deferred', 'You can migrate the protected files now or return to Team administration later.',
                    { primaryLabel: 'Migrate now', secondaryLabel: 'Later' });
                if (run === true) await this.runDashboardCliCommand('hybridcipher coverage migrate --all --yes', { title: 'Migrate protected files' });
            },

            clearTeamUiState() {
                this.cancelWorkspaceSelection?.();
                this.desktopAccountGeneration = (this.desktopAccountGeneration || 0) + 1;
                this.workspaceSwitchSequence = (this.workspaceSwitchSequence || 0) + 1;
                this.desktopOperationStarting = false; this.addMemberDialogContext = null;
                this.desktopOperation = null; this.desktopOperationRequest = null; this.desktopInputRequestId = null;
                this.workspaceGroupContext = null; this.workspaceContextReady = false; this.teamDirectoryRole = null;
                this.teamSetupInProgress = false; this.teamSetupMessage = ''; this.teamSetupErrorCode = null; this.teamSetupCompletedOrganizationId = null;
                this.createdGroupPendingId = null; this.groupCreationInProgress = false; this.groupSwitchInProgress = false; this.teamActivationInProgress = false;
                this.closeDesktopOperation(); show('desktopOperationsBtn', false);
                for (const id of ['teamUnlockCode', 'teamInvitationCode', 'teamInviteEmail', 'desktopOperationInput', 'createGroupName', 'createGroupDescription']) if (element(id)) element(id).value = '';
                for (const id of ['teamDirectoryList', 'teamPendingRequestsList', 'switchGroupList', 'listGroupsList', 'listMembersList', 'removeMemberList', 'desktopOperationOutput']) text(id, '');
                for (const modal of global.document?.querySelectorAll('.modal') || []) modal.style.display = 'none';
            },
            async logout() { const result = await base.logout.call(this); if (result) this.clearTeamUiState(); return result; },
            showWelcomeScreen(...args) { this.clearTeamUiState(); return base.showWelcomeScreen.apply(this, args); },
        };
    }
    global.HybridCipherTeamMethods = { create, workspaceModel, unwrap };
    if (typeof module !== 'undefined') module.exports = global.HybridCipherTeamMethods;
})(typeof window !== 'undefined' ? window : globalThis);
