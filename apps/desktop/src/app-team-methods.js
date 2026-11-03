// Account-scoped Team navigation, resumable setup, and dialog-based desktop operations.
(function (global) {
    const finished = new Set(['succeeded', 'failed', 'cancelled']);
    const adminRoles = new Set(['owner', 'admin']);
    const writeRoles = new Set(['owner', 'admin', 'writer', 'member']);
    const retryableKinds = new Set(['team_setup', 'create_group', 'initialize_group', 'switch_group']);
    // One window switch fires focus and visibilitychange, and switching back and forth used to
    // exhaust the account's server rate limit; refocusing refreshes at most this often.
    const resumeRefreshMinMs = 30 * 1000;
    const unwrap = value => {
        if (value?.success === false) throw new Error(value.error || 'Operation failed');
        return value?.success === true ? value.data : value;
    };
    const call = (command, args = {}) => (global.HybridCipherTauri?.invoke || global.invoke)(command, args);
    const element = id => global.document?.getElementById(id);
    const show = (id, visible) => {
        const node = element(id);
        if (!node) return;
        node.classList.toggle('hidden', !visible);
        node.style.display = visible ? '' : 'none';
        node.setAttribute('aria-hidden', String(!visible));
    };
    const showModal = (id, visible) => {
        show(id, visible);
        if (element(id)) element(id).style.display = visible ? 'flex' : 'none';
    };
    const text = (id, value) => { if (element(id)) element(id).textContent = value || ''; };
    // Lists that refresh in the background keep their nodes, and keyboard focus, while nothing in them changed.
    const renderedMarkup = new WeakMap();
    const setMarkup = (node, markup) => {
        if (!node || (renderedMarkup.get(node) === markup && node.childElementCount)) return;
        node.innerHTML = markup;
        renderedMarkup.set(node, markup);
    };
    const pause = ms => new Promise(resolve => global.setTimeout(resolve, ms));
    // The server refuses Team administration from an unverified device with 428 device_trust_required.
    const deviceTrustRefusal = /device_trust_required|\b428\b|precondition required/i;
    const recoverableError = error => {
        if (!error) return false;
        const message = String(error.message || '').toLowerCase();
        if (/approval|required.*license|license.*revoked|activate team|not authorized|permission|forbidden|invalid|deleted|not available to this account/.test(message)) return false;
        return ['network', 'offline', 'timeout', 'group_setup_failed'].includes(error.code)
            || /network|connect|timed? out|timeout|unavailable|temporar|retry/.test(message);
    };

    const deviceTrustMessages = {
        untrusted: 'Team administration is available after this device is verified. Ask someone on a trusted device to verify its fingerprint, or confirm it with your password.',
        unavailable: "Team administration is paused because this device's verification status couldn't be checked. Sign in again or reconnect, then press Check status.",
    };

    // Admin rights also need a verified device; until then an owner or admin device works as a member.
    // deviceTrust is 'trusted', 'untrusted', 'unavailable' (the server couldn't be asked) or 'unknown' (not checked yet).
    function workspaceModel(type, license, context, ready, directoryRole, deviceTrust = 'unknown') {
        const team = type === 'team';
        const organization = license?.organization;
        const teamAccess = team && license?.workspace === 'team' && Boolean(organization?.id);
        const matches = Boolean(context?.group_id) && (team
            ? teamAccess && context.organization_id === organization.id
            : !context.organization_id);
        const resolved = Boolean(ready && matches);
        const orgAdminRole = teamAccess && adminRoles.has(organization?.role || directoryRole);
        const groupAdminRole = resolved && adminRoles.has(context.role);
        const deviceTrusted = deviceTrust === 'trusted';
        const orgAdmin = orgAdminRole && deviceTrusted;
        const groupAdmin = groupAdminRole && deviceTrusted;
        return {
            needsDeviceVerification: (orgAdminRole || groupAdminRole) && deviceTrust === 'untrusted',
            deviceTrustUnavailable: (orgAdminRole || groupAdminRole) && deviceTrust === 'unavailable',
            title: team ? organization?.name || 'Team' : 'Personal Workspace',
            administrationTitle: matches ? context.name || 'Group' : 'Group',
            hasGroupContext: matches,
            resolved,
            canAdminister: teamAccess && (orgAdmin || groupAdmin),
            canCreate: team && orgAdmin && Boolean(license?.can_write),
            canManageMembers: teamAccess && orgAdmin,
            canAdministerGroup: teamAccess && groupAdmin && Boolean(license?.can_write && license?.online),
            canWrite: resolved && (!team || Boolean(license?.can_write)) && writeRoles.has(context?.role || 'owner'),
            contextLabel: matches ? `${context.name || 'Group'} · ${context.role || 'Member'}${resolved ? '' : ' · Setup pending'}` : 'Workspace group is not ready',
        };
    }

    function create(original) {
        const base = {};
        for (const key of ['setupEventListeners', 'applyAppMode', 'updateWorkspaceHomeSummary',
            'loadEnrolledFolders', 'refreshAdminDashboard', 'refreshAdminGroupStatus',
            'logout', 'showWelcomeScreen', 'openCreateGroupModal', 'addEnrolledFolder',
            'showDevicesView', 'refreshPersonalDevicesOverview', 'refreshWorkspaceHomeStatus',
            'showCoverageView', 'refreshCoverageCenter', 'showWorkspaceHome', 'performSessionHealthCheck']) base[key] = original[key];
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
                bind('teamSetupRetryBtn', 'click', () => { if (this.canRetryTeamSetup()) this.prepareTeamWorkspace({ showDialog: true }); });
                bind('teamSetupCompleteBtn', 'click', () => { if (this.canCompleteTeamSetup()) this.prepareTeamWorkspace({ showDialog: true }); });
                bind('teamSetupCheckStatusBtn', 'click', () => this.checkWorkspaceReadiness());
                bind('teamDeviceTrustFingerprintBtn', 'click', event => { event?.stopPropagation?.(); this.openSecurityPanel?.(); });
                bind('teamDeviceTrustConfirmBtn', 'click', () => this.confirmCurrentDeviceTrust());
                bind('teamDeviceTrustCheckBtn', 'click', () => this.refreshCurrentDeviceTrust());
                bind('settingsOpenTeamBtn', 'click', async () => {
                    if (!this.isLoggedIn) return;
                    if (this.teamLicenseStatus?.workspace === 'team' && this.teamLicenseStatus.organization?.id) {
                        this.closeSettingsModal();
                        await this.openEntitledTeamWorkspace();
                    } else this.openTeamActivationModal();
                });
                bind('closeTeamActivationBtn', 'click', () => this.closeTeamActivationModal());
                bind('teamActivationCancelBtn', 'click', () => this.closeTeamActivationModal());
                bind('teamOpenWorkspaceBtn', 'click', () => this.openEntitledTeamWorkspace());
                element('teamActivationModal')?.querySelector('.modal-backdrop')?.addEventListener('click', () => this.closeTeamActivationModal());
                bind('teamSetupDevicesBtn', 'click', () => this.showDevicesView());
                bind('personalSetupRecoverBtn', 'click', () => this.openPersonalRecovery());
                bind('personalSetupRepairBtn', 'click', () => this.repairPersonalWorkspace());
                bind('personalSetupCheckStatusBtn', 'click', () => this.checkPersonalWorkspaceStatus());
                bind('personalSetupDevicesBtn', 'click', () => this.showDevicesView());
                bind('adminRenameGroupBtn', 'click', () => { this.setGroupSettingsMenuOpen(false); this.renameSelectedGroup(); });
                bind('adminDeleteGroupBtn', 'click', () => { this.setGroupSettingsMenuOpen(false); this.deleteSelectedGroup(); });
                bind('adminGroupSettingsBtn', 'click', event => {
                    event?.stopPropagation?.();
                    this.setGroupSettingsMenuOpen(element('adminGroupSettingsMenu')?.classList.contains('hidden'));
                });
                global.document?.addEventListener?.('click', event => {
                    if (!element('adminGroupSettingsMenu')?.contains?.(event.target)) this.setGroupSettingsMenuOpen(false);
                });
                element('adminGroupSettingsMenu')?.addEventListener('keydown', event => {
                    if (event.key !== 'Escape') return;
                    this.setGroupSettingsMenuOpen(false);
                    element('adminGroupSettingsBtn')?.focus();
                });
                bind('sidebarOverviewBtn', 'click', () => this.openWorkspaceHome());
                bind('sidebarMembersBtn', 'click', () => this.showMembersView());
                bind('teamDirectoryMembersLink', 'click', () => { this.closeSettingsModal?.(); this.showMembersView(); });
                bind('membersRefreshBtn', 'click', () => this.refreshMembersCenter());
                bind('membersInviteBtn', 'click', () => this.openTeamInviteDialog());
                bind('closeTeamInviteBtn', 'click', () => this.closeTeamInviteDialog());
                bind('teamInviteCancelBtn', 'click', () => this.closeTeamInviteDialog());
                bind('teamInviteForm', 'submit', event => { event.preventDefault(); this.submitTeamInviteDialog(); });
                bind('membersSearch', 'input', () => this.renderMembersCenter());
                bind('membersFilter', 'click', event => {
                    const filter = event.target?.closest?.('[data-members-filter]')?.dataset.membersFilter;
                    if (filter) { this.membersFilter = filter; this.renderMembersCenter(); }
                });
                bind('membersList', 'click', event => this.handleMembersListClick(event));
                bind('sidebarNewGroupBtn', 'click', () => this.openCreateGroupModal());
                bind('homeNewGroupBtn', 'click', () => this.openCreateGroupModal());
                bind('sidebarGroupFilter', 'input', () => this.renderSidebarTeamNav());
                for (const id of ['sidebarGroupList', 'teamGroupCards']) {
                    element(id)?.addEventListener('click', event => {
                        const button = event.target?.closest?.('[data-group-id]');
                        if (button) this.openTeamGroup(button.dataset.groupId);
                    });
                }
                element('teamTodoList')?.addEventListener('click', event => {
                    const button = event.target?.closest?.('[data-todo-action]');
                    if (button) this.handleTeamTodoAction(button);
                });
                for (const button of global.document?.querySelectorAll?.('[data-people-filter]') || []) {
                    button.addEventListener('click', () => { this.peopleFilter = button.dataset.peopleFilter; this.renderPeopleList(); });
                }
                bind('adminPeopleSearch', 'input', () => this.renderPeopleList());
                global.addEventListener?.('focus', () => this.refreshWorkspaceAfterResume());
                global.addEventListener?.('online', () => this.refreshWorkspaceAfterReconnect());
                global.addEventListener?.('offline', () => this.stopWorkspaceReadinessPolling());
                global.document?.addEventListener?.('visibilitychange', () => {
                    if (global.document.hidden) this.stopWorkspaceReadinessPolling();
                    else this.refreshWorkspaceAfterResume();
                });
                const closeAddPerson = () => { element('addGroupMemberModal').style.display = 'none'; };
                bind('closeAddGroupMemberBtn', 'click', closeAddPerson);
                bind('groupMemberCancelBtn', 'click', closeAddPerson);
                bind('addGroupMemberForm', 'submit', async event => {
                    event.preventDefault();
                    const context = this.addMemberDialogContext;
                    if (!context || context.account !== this.currentUser || context.groupId !== this.workspaceGroupContext?.group_id) return;
                    const email = element('groupMemberEmail')?.value.trim().toLowerCase() || '';
                    if (!email) return;
                    element('groupMemberAddBtn')?.toggleAttribute('disabled', true);
                    try {
                        if (!(await this.confirmGroupInviteSeat(email))) return;
                        const result = await this.runTeamTask({ kind: 'add_person', email }, `Add ${email}`);
                        if (result) { closeAddPerson(); element('groupMemberEmail').value = ''; }
                    } finally { element('groupMemberAddBtn')?.toggleAttribute('disabled', false); }
                });
                element('adminPeopleList')?.addEventListener('click', event => {
                    const button = event.target?.closest?.('[data-people-action]');
                    if (button) this.handlePeopleAction(button);
                });
                bind('teamInvitationJoinBtn', 'click', () => this.joinInvitedTeam());
                bind('teamInvitationDismissBtn', 'click', () => {
                    if (this.teamInvitationOffer) (this.dismissedTeamInvitations ||= new Set()).add(this.teamInvitationOffer.id);
                    this.teamInvitationOffer = null; show('teamInvitationNotice', false);
                });
            },

            workspaceUiModel() {
                return workspaceModel(this.activeWorkspaceType, this.teamLicenseStatus,
                    this.workspaceGroupContext, this.workspaceContextReady, this.teamDirectoryRole, this.currentDeviceTrustState());
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

            // Everyone lands on Home; in a Team it is the Team overview, and each group opens its own page.
            showWorkspaceHome() {
                const result = base.showWorkspaceHome?.call(this);
                this.refreshTeamOverview();
                return result;
            },

            setWorkspaceView(view) {
                const next = view === 'admin' && !this.workspaceUiModel().canAdminister ? 'home' : view;
                this.activeWorkspaceView = next;
                this.adminPanelVisible = next === 'admin';
                this.terminalVisible = next === 'terminal';
                const views = { home: 'workspaceHome', 'folder-detail': 'folderDetailView', devices: 'devicesCenterView',
                    coverage: 'coverageCenterView', mounts: 'mountCenterView', members: 'membersCenterView', admin: 'adminDashboard', terminal: 'terminalContainer' };
                for (const [name, id] of Object.entries(views)) {
                    const node = element(id);
                    if (node) { node.style.display = name === next ? 'flex' : 'none'; node.setAttribute('aria-hidden', String(name !== next)); }
                }
                element('workspace')?.classList.toggle('admin-panel-visible', this.adminPanelVisible);
                element('mainContent')?.classList.toggle('terminal-visible', this.terminalVisible);
                if (next !== 'admin') this.setGroupSettingsMenuOpen(false);
                this.updateSidebarViewButtons();
                const homeBtn = element('sidebarHomeBtn');
                if (homeBtn) {
                    homeBtn.classList?.toggle('active', next === 'home');
                    homeBtn.setAttribute('aria-pressed', String(next === 'home'));
                }
                this.updateWorkspaceLabels();
            },

            teamNavigationVisible() {
                return Boolean(this.isLoggedIn && this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.workspace === 'team');
            },

            /**
             * Team sidebar: the overview, then every group in this workspace. The selected group is marked, and
             * its page opens from it; the folder list below belongs to that group. Personal keeps its Home button.
             */
            renderSidebarTeamNav(model = this.workspaceUiModel()) {
                const team = this.teamNavigationVisible();
                show('sidebarTeamNav', team);
                show('sidebarHomeSlot', !team);
                const context = this.workspaceGroupContext;
                text('sidebarFoldersTitle', team && model.hasGroupContext && context?.name ? `${context.name} folders` : 'Protected Folders');
                if (!team) return;
                const onHome = this.activeWorkspaceView === 'home';
                const overview = element('sidebarOverviewBtn');
                overview?.classList.toggle('active', onHome);
                overview?.setAttribute('aria-pressed', String(onHome));
                const membersVisible = this.canOpenMembersView(model);
                const onMembers = membersVisible && this.activeWorkspaceView === 'members';
                show('sidebarMembersBtn', membersVisible);
                element('sidebarMembersBtn')?.classList.toggle('active', onMembers);
                element('sidebarMembersBtn')?.setAttribute('aria-pressed', String(onMembers));
                const membersAttention = membersVisible ? this.membersAttentionCount() : 0;
                text('sidebarMembersBadge', membersAttention ? String(membersAttention) : '');
                show('sidebarMembersBadge', membersAttention > 0);
                text('sidebarOverviewLabel', model.canAdminister ? 'Team overview' : 'Team home');
                const attention = this.teamTodoItems().length;
                text('sidebarOverviewBadge', attention ? String(attention) : '');
                show('sidebarOverviewBadge', attention > 0);
                show('sidebarNewGroupBtn', model.canCreate);
                const groups = model.hasGroupContext && Array.isArray(context?.groups) ? context.groups : [];
                text('sidebarGroupsTitle', groups.length ? `Groups · ${groups.length}` : 'Groups');
                const filter = element('sidebarGroupFilter');
                show('sidebarGroupFilter', groups.length > 6 || Boolean(filter?.value));
                const list = element('sidebarGroupList');
                if (!list) return;
                const items = global.HybridCipherUiUtils?.buildSidebarGroupItems?.({ groups, activeGroupId: context?.group_id,
                    query: filter?.value || '', attentionCount: attention }) || [];
                const groupPage = this.activeWorkspaceView === 'admin';
                setMarkup(list, items.length ? items.map(item => '<li>'
                    + `<button class="sidebar-group-item${item.selected ? ' selected' : ''}${item.selected && groupPage ? ' active' : ''}" type="button"`
                    + ` data-group-id="${this.escapeHtmlAttr(item.id)}"${item.selected ? ` aria-current="${groupPage ? 'page' : 'true'}"` : ''}>`
                    + `<span class="group-mark" data-tone="${item.tone}" aria-hidden="true">${this.escapeHtml(item.initial)}</span>`
                    + `<span class="sidebar-group-name">${this.escapeHtml(item.name)}</span>`
                    + (item.badge ? `<span class="sidebar-nav-badge" aria-label="${this.escapeHtmlAttr(`${item.badge} to do`)}">${this.escapeHtml(item.badge)}</span>` : '')
                    + '</button></li>').join('')
                    : `<li class="sidebar-group-empty">${groups.length ? 'No group matches.' : 'Loading groups…'}</li>`);
            },

            /** Opens a group from the sidebar or the overview: switches to it first, then shows its page (admins) or Home. */
            async openTeamGroup(groupId) {
                if (this.activeWorkspaceType !== 'team' || !groupId) return false;
                if (groupId !== this.workspaceGroupContext?.group_id && !(await this.switchTeamGroup(groupId))) return false;
                if (this.workspaceUiModel().canAdminister) this.toggleAdminPanel();
                else this.showWorkspaceHome();
                return true;
            },

            /** Opens one tab of the selected group's page, for example from a Team overview to-do. */
            openAdminTab(name) {
                if (!this.workspaceUiModel().canAdminister) return;
                this.toggleAdminPanel();
                this.selectAdminTab?.(name);
            },

            setGroupSettingsMenuOpen(open) {
                const menu = element('adminGroupSettingsMenu');
                if (!menu || open === !menu.classList.contains('hidden')) return;
                show('adminGroupSettingsMenu', Boolean(open));
                element('adminGroupSettingsBtn')?.setAttribute('aria-expanded', String(Boolean(open)));
                if (open) menu.querySelector?.('button:not([disabled])')?.focus();
            },

            applyAppMode() {
                base.applyAppMode.call(this);
                const model = this.workspaceUiModel();
                const team = this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.workspace === 'team';
                if (this.activeWorkspaceView === 'members' && !this.canOpenMembersView(model)) this.setWorkspaceView('home');
                // Entitled accounts switch both ways from the header; Team panels stay hidden in Personal.
                show('workspaceSelector', this.teamLicenseStatus?.workspace === 'team' && Boolean(this.teamLicenseStatus.organization?.id));
                show('workspaceLicenseBadge', team && !this.teamLicenseStatus?.can_write);
                for (const id of ['sidebarNewGroupBtn', 'homeNewGroupBtn']) element(id)?.toggleAttribute('disabled', !model.canCreate);
                for (const id of ['adminAddMemberBtn', 'adminRekeyStartBtn', 'adminRekeyMigrationBtn', 'adminRenameGroupBtn', 'adminDeleteGroupBtn'])
                    element(id)?.toggleAttribute('disabled', !model.canAdministerGroup);
                // Personal can recheck its keys from Add Folder without exposing Team setup controls.
                for (const id of ['addFolderBtn', 'homeAddFolderBtn', 'settingsEnrollFolderBtn', 'adminEnrollFolderBtn'])
                    element(id)?.toggleAttribute('disabled', this.activeWorkspaceType === 'team' ? !model.canWrite || Boolean(this.folderEnrollmentInFlight)
                        : !this.isLoggedIn || Boolean(this.folderEnrollmentInFlight));
                for (const id of ['homeRunCoverageScanBtn', 'adminCoverageScanBtn', 'adminVerifyMembershipBtn', 'adminCoverageSampleAuditBtn', 'adminCoverageFullAuditBtn', 'adminCoverageVerifyBtn'])
                    element(id)?.toggleAttribute('disabled', !model.resolved);
                this.updateWorkspaceLabels();
            },

            updateWorkspaceLabels() {
                const model = this.workspaceUiModel();
                const team = this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.workspace === 'team';
                text('workspaceHomeTitle', model.title);
                text('workspaceHomeEyebrow', !team ? 'Workspace Home' : model.canAdminister ? 'Team overview' : 'Team home');
                text('teamAdministrationTitle', model.administrationTitle);
                text('adminGroupBreadcrumb', `${this.teamLicenseStatus?.organization?.name || 'Team'} / Groups`);
                const context = this.workspaceGroupContext;
                const facts = model.hasGroupContext ? global.HybridCipherUiUtils?.describeGroupFacts?.({
                    summary: this.teamGroupSummary(context.group_id), role: context.role,
                    folderCount: model.resolved && Array.isArray(this.enrolledFolders) ? this.enrolledFolders.length : null }) : '';
                text('adminGroupMeta', [facts, model.hasGroupContext && !model.resolved ? 'Setup pending' : ''].filter(Boolean).join(' · '));
                text('workspaceContextLabel', team ? model.contextLabel : '');
                show('workspaceContextLabel', team);
                this.renderSidebarTeamNav(model);
                this.renderTeamOverview(model);
                const teamOption = element('workspaceSelector')?.querySelector('option[value="team"]');
                if (teamOption) teamOption.textContent = this.teamLicenseStatus?.organization?.name || 'Team';
                show('teamSetupNotice', team && !model.resolved);
                show('teamDeviceTrustNotice', team && (model.needsDeviceVerification || model.deviceTrustUnavailable));
                text('teamDeviceTrustMessage', deviceTrustMessages[model.deviceTrustUnavailable ? 'unavailable' : 'untrusted']);
                show('teamDeviceTrustFingerprintBtn', !model.deviceTrustUnavailable);
                show('teamDeviceTrustConfirmBtn', !model.deviceTrustUnavailable);
                // Recomputed while waiting, so this device's code shows up once it has loaded.
                text('teamSetupMessage', team && this.workspaceGroupContext?.readiness === 'waiting_for_device_approval'
                    ? this.teamMissingKeyMessage() : this.teamSetupMessage || 'Loading the Team workspace…');
                show('teamSetupRetryBtn', this.canRetryTeamSetup());
                show('teamSetupCompleteBtn', this.canCompleteTeamSetup());
                show('teamSetupCheckStatusBtn', team && model.hasGroupContext && !model.resolved
                    && this.workspaceGroupContext?.readiness === 'waiting_for_device_approval');
                show('teamSetupDevicesBtn', team && !model.resolved && (this.workspaceGroupContext?.readiness === 'waiting_for_device_approval'
                    || this.teamSetupErrorCode === 'device_approval_required'));
                this.renderPersonalWorkspaceNotice();
                const entitled = this.teamLicenseStatus?.workspace === 'team' && Boolean(this.teamLicenseStatus.organization?.id);
                show('teamOpenWorkspaceBtn', entitled);
                show('teamActivationForm', !entitled); show('teamInvitationAcceptance', !entitled);
                this.updateDesktopActivityVisibility();
            },

            canPrepareTeamWorkspace() {
                const license = this.teamLicenseStatus;
                return Boolean(this.isLoggedIn && license?.workspace === 'team' && license.organization?.id
                    && license.online && license.can_write && !license.revoked && license.organization.role === 'owner'
                    && this.currentDeviceTrusted());
            },
            canRetryTeamSetup() {
                const readiness = this.workspaceGroupContext?.readiness;
                return this.activeWorkspaceType === 'team' && this.canPrepareTeamWorkspace() && !this.teamSetupInProgress
                    && !this.workspaceUiModel().resolved && !['waiting_for_device_approval', 'deleted'].includes(readiness)
                    && recoverableError(this.teamSetupError);
            },
            canCompleteTeamSetup() {
                return this.activeWorkspaceType === 'team' && this.canPrepareTeamWorkspace() && !this.teamSetupInProgress
                    && !this.workspaceUiModel().resolved && this.workspaceGroupContext?.readiness === 'uninitialized' && !this.teamSetupError;
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
            showCoverageView(options = {}) {
                if (!this.workspaceUiModel().resolved) { this.showNotification('Complete workspace setup before checking coverage.', 'warning'); return; }
                return base.showCoverageView?.call(this, options);
            },
            async refreshCoverageCenter(options = {}) {
                if (!this.workspaceUiModel().resolved) { this.coverageCenterSnapshot = null; return; }
                return base.refreshCoverageCenter?.call(this, options);
            },

            groupPreferenceKey(type = this.activeWorkspaceType) { return `${this.workspacePreferenceKey()}_group_${type}`; },
            clearWorkspaceContext() {
                this.stopWorkspaceReadinessPolling();
                this.workspaceWelcomeAcquisitionAttempts = null;
                this.closeDesktopOperation({ acknowledge: false });
                this.clearFinishedDesktopOperation();
                this.workspaceContextReady = false;
                this.workspaceGroupContext = null;
                this.personalWorkspaceError = null;
                this.personalWorkspaceSnapshot = null;
                this.enrolledFolders = [];
                this.homeStatusSnapshot = null;
                this.personalDevicesOverview = null;
                this.coverageCenterSnapshot = null;
                this.coverageCenterState = { loading: false, error: null,
                    scanState: { state: 'idle', processed: 0, total: 0, rootProgress: {} } };
                this.addMemberDialogContext = null;
                this.cancelWorkspaceSelection?.();
                for (const id of ['addGroupMemberModal', 'verifyMembershipModal'])
                    if (element(id)) element(id).style.display = 'none';
                for (const id of ['devicesCenterContent', 'coverageCenterContent', 'adminPeopleList']) text(id, '');
                // Queues and people belong to the previous group; the overview must not offer its actions.
                this.pendingDevicesCache = []; this.staleDevicesCache = []; this.unverifiedDevicesCache = [];
                this.peopleRowsCache = null;
                this.clearFolderSelectionForGroupSwitch();
                this.applyAppMode();
                this.updateWorkspaceHomeSummary();
            },

            async selectWorkspaceType(type, { forceGroupId = null, showDialog = false, preserveOnFailure = false, shouldSelect = null, persistSelection = true } = {}) {
                if (type === 'team' && this.teamLicenseStatus?.workspace !== 'team') return false;
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) {
                    const selector = element('workspaceSelector');
                    if (selector) selector.value = this.activeWorkspaceType;
                    this.openDesktopOperation();
                    this.showNotification('Complete the current operation before switching workspace or group.', 'warning');
                    return false;
                }
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const sequence = (this.workspaceSwitchSequence || 0) + 1;
                this.workspaceSwitchSequence = sequence;
                this.workspaceWelcomeAcquisitionAttempts = null;
                const workspace = type === 'team' ? 'team' : 'personal';
                const previousWorkspace = this.activeWorkspaceType;
                const previous = { context: this.workspaceGroupContext, ready: this.workspaceContextReady,
                    folders: this.enrolledFolders, home: this.homeStatusSnapshot, devices: this.personalDevicesOverview,
                    coverage: this.coverageCenterSnapshot, view: this.activeWorkspaceView };
                const preserve = preserveOnFailure && previousWorkspace !== workspace;
                const current = () => this.currentUser === account && this.workspaceSwitchSequence === sequence
                    && this.currentDeviceId === device && generation === (this.desktopAccountGeneration || 0) && this.isLoggedIn;
                this.stopWorkspaceReadinessPolling();
                if (!preserve) {
                    this.activeWorkspaceType = workspace;
                    this.appMode = workspace === 'team' ? 'team' : 'individual';
                    this.clearWorkspaceContext(); this.setWorkspaceView('home');
                }
                this.teamSetupMessage = 'Loading workspace group…';
                try {
                    let context = unwrap(await call('get_workspace_group_context', { workspace,
                        selectionSequence: sequence, expectedAccountEmail: account }));
                    if (!current()) return false;
                    // Personal selection is restored and validated by the backend. A stale
                    // frontend preference must not override its usable Personal group.
                    const preferred = workspace === 'team' ? (forceGroupId || global.localStorage.getItem(this.groupPreferenceKey(workspace))) : null;
                    if (preferred && context?.group_id !== preferred) {
                        await this.runDesktopOperation({ kind: 'switch_group', group_id: preferred, title: 'Switch group' }, { showDialog });
                        if (!current()) return false;
                        context = unwrap(await call('get_workspace_group_context', { workspace,
                            selectionSequence: sequence, expectedAccountEmail: account }));
                    }
                    if (!current()) return false;
                    if (preferred && context?.group_id !== preferred) throw new Error('The selected group is not ready on this device. Open Devices to complete approval, then retry.');
                    if (preserve) {
                        if (shouldSelect && !shouldSelect()) throw new Error('Team activation was cancelled.');
                        const candidate = workspaceModel(workspace, this.teamLicenseStatus, context, context?.readiness === 'ready', this.teamDirectoryRole, this.currentDeviceTrustState());
                        if (!candidate.hasGroupContext || !['ready', 'waiting_for_device_approval', 'uninitialized', 'deleted'].includes(context.readiness))
                            throw new Error('The Team workspace is unavailable. Retry after reconnecting.');
                        this.activeWorkspaceType = workspace; this.appMode = workspace === 'team' ? 'team' : 'individual';
                        this.clearWorkspaceContext(); this.setWorkspaceView('home');
                    }
                    this.workspaceGroupContext = context;
                    this.workspaceContextReady = context?.readiness === 'ready';
                    const model = this.workspaceUiModel();
                    this.workspaceContextReady = model.resolved;
                    if (!model.resolved) {
                        this.teamSetupMessage = context?.readiness === 'waiting_for_device_approval'
                            ? this.teamMissingKeyMessage()
                            : context?.readiness === 'deleted' ? 'The default group was deleted. Create or select another Team group.'
                            : 'No usable group is available in this workspace yet.';
                    } else {
                        if (persistSelection) global.localStorage.setItem(this.workspacePreferenceKey(), this.activeWorkspaceType);
                        global.localStorage.setItem(this.groupPreferenceKey(), context.group_id);
                        await this.loadEnrolledFolders({ suppressErrorNotification: true });
                    }
                    this.applyAppMode();
                    if (this.activeWorkspaceView === 'home') this.refreshTeamOverview();
                    this.startWorkspaceReadinessPolling();
                    return model.resolved;
                } catch (error) {
                    if (!current()) return false;
                    if (preserve) {
                        try { await call('get_workspace_group_context', { workspace: previousWorkspace,
                            selectionSequence: sequence, expectedAccountEmail: account }); } catch (_) { /* Keep the existing workspace UI. */ }
                        if (!current()) return false;
                        this.activeWorkspaceType = previousWorkspace; this.appMode = previousWorkspace === 'team' ? 'team' : 'individual';
                        this.workspaceGroupContext = previous.context; this.workspaceContextReady = previous.ready;
                        this.enrolledFolders = previous.folders; this.homeStatusSnapshot = previous.home;
                        this.personalDevicesOverview = previous.devices; this.coverageCenterSnapshot = previous.coverage;
                        this.setWorkspaceView(previous.view || 'home');
                    }
                    this.teamSetupMessage = `Could not load this workspace: ${error.message || error}. Retry when connected.`;
                    if (workspace === 'personal') this.personalWorkspaceError = error.message || String(error);
                    this.applyAppMode();
                    this.startWorkspaceReadinessPolling();
                    if (!showDialog) this.showNotification(this.teamSetupMessage, 'warning');
                    return false;
                }
            },

            stopWorkspaceReadinessPolling() {
                if (this.workspaceReadinessTimer) global.clearInterval?.(this.workspaceReadinessTimer.id);
                this.workspaceReadinessTimer = null;
            },
            personalWorkspaceSetupInProgress() {
                return Boolean(this.personalRepairInFlight || this.savedCodeRecoveryInFlight || this.savedCodeRecoveryCompletionInFlight);
            },
            startWorkspaceReadinessPolling() {
                const context = this.workspaceGroupContext;
                if (!this.isLoggedIn || !context?.group_id || context.readiness !== 'waiting_for_device_approval'
                    || this.personalWorkspaceSetupInProgress()
                    || !this.workspaceUiModel().hasGroupContext || !global.setInterval
                    || global.document?.hidden || global.navigator?.onLine === false
                    || (this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.online === false)) {
                    this.stopWorkspaceReadinessPolling(); return;
                }
                const scope = { account: this.currentUser, generation: this.desktopAccountGeneration || 0,
                    sequence: this.workspaceSwitchSequence, workspace: this.activeWorkspaceType, groupId: context.group_id };
                const old = this.workspaceReadinessTimer?.scope;
                if (old && Object.keys(scope).every(key => old[key] === scope[key])) return;
                this.stopWorkspaceReadinessPolling();
                const timer = { scope, inFlight: false, attempts: 0, startedAt: Date.now() };
                timer.id = global.setInterval(async () => {
                    if (this.workspaceReadinessTimer !== timer || timer.inFlight) return;
                    if (!this.isLoggedIn || this.currentUser !== scope.account || (this.desktopAccountGeneration || 0) !== scope.generation
                        || this.workspaceSwitchSequence !== scope.sequence || this.activeWorkspaceType !== scope.workspace
                        || this.workspaceGroupContext?.group_id !== scope.groupId || timer.attempts >= 30 || Date.now() - timer.startedAt >= 300000) {
                        this.stopWorkspaceReadinessPolling(); return;
                    }
                    if (global.document?.hidden || global.navigator?.onLine === false
                        || this.personalWorkspaceSetupInProgress()
                        || (this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.online === false)) return;
                    timer.inFlight = true;
                    timer.attempts += 1;
                    try { await this.reconcileWorkspaceState({ readOnly: true, refreshFolders: false }); }
                    finally {
                        timer.inFlight = false;
                        if (this.workspaceReadinessTimer === timer && (timer.attempts >= 30 || Date.now() - timer.startedAt >= 300000))
                            this.stopWorkspaceReadinessPolling();
                    }
                }, 10000);
                this.workspaceReadinessTimer = timer;
            },
            async checkWorkspaceReadiness({ manual = true } = {}) {
                if (this.workspaceStatusRefreshInFlight || this.personalWorkspaceSetupInProgress()
                    || !this.isLoggedIn || !this.workspaceUiModel().hasGroupContext) return false;
                this.workspaceStatusRefreshInFlight = true;
                const token = Symbol('workspace-status'); this.workspaceStatusRefreshToken = token;
                element('teamSetupCheckStatusBtn')?.toggleAttribute('disabled', true);
                try {
                    if (manual && this.activeWorkspaceType === 'team') await this.refreshCurrentDeviceTrust();
                    return await this.reconcileWorkspaceState({ readOnly: !manual });
                }
                finally {
                    if (this.workspaceStatusRefreshToken === token) {
                        this.workspaceStatusRefreshInFlight = false; this.workspaceStatusRefreshToken = null;
                        element('teamSetupCheckStatusBtn')?.toggleAttribute('disabled', false);
                    }
                }
            },
            async refreshWorkspaceAfterResume() {
                if (!this.isLoggedIn || global.document?.hidden) return;
                const now = Date.now();
                if (now - (this.workspaceResumeRefreshAt || 0) < resumeRefreshMinMs) return;
                this.workspaceResumeRefreshAt = now;
                await this.refreshWorkspaceAfterReconnect();
            },
            async refreshWorkspaceAfterReconnect() {
                if (!this.isLoggedIn || global.document?.hidden || global.navigator?.onLine === false
                    || this.personalWorkspaceSetupInProgress()
                    || this.workspaceStatusRefreshInFlight || this.workspaceReconnectRefreshInFlight || this.teamActivationInProgress || this.teamSetupInProgress) return;
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const token = Symbol('workspace-reconnect'); this.workspaceReconnectRefreshInFlight = token;
                try {
                    await this.refreshTeamLicenseStatus({ silent: true });
                    if (this.currentUser !== account || (this.desktopAccountGeneration || 0) !== generation || !this.isLoggedIn
                        || this.personalWorkspaceSetupInProgress()) return;
                    await this.checkWorkspaceReadiness({ manual: false });
                    this.startWorkspaceReadinessPolling();
                } finally { if (this.workspaceReconnectRefreshInFlight === token) this.workspaceReconnectRefreshInFlight = null; }
            },
            async reconcileWorkspaceState({ readOnly = false, refreshDevices = true, refreshHome = true, refreshFolders = true,
                recoveryCompletionAttempt = null } = {}) {
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const sequence = this.workspaceSwitchSequence;
                const workspace = this.activeWorkspaceType;
                const groupId = this.workspaceGroupContext?.group_id;
                const current = () => this.isLoggedIn && this.currentUser === account
                    && (this.desktopAccountGeneration || 0) === generation && this.workspaceSwitchSequence === sequence
                    && this.currentDeviceId === device && this.activeWorkspaceType === workspace && this.workspaceGroupContext?.group_id === groupId
                    && (!this.personalWorkspaceSetupInProgress() || (recoveryCompletionAttempt !== null
                        && recoveryCompletionAttempt === this.savedCodeRecoveryCompletionInFlight
                        && recoveryCompletionAttempt === this.savedCodeRecoveryAttempt
                        && !this.savedCodeRecoveryInFlight && !this.personalRepairInFlight));
                if (!groupId || !current()) return false;
                try {
                    const context = unwrap(await call('get_workspace_group_context', { workspace,
                        selectionSequence: sequence, expectedAccountEmail: account, readOnly }));
                    if (!current() || context?.group_id !== groupId) return false;
                    const wasReady = this.workspaceContextReady;
                    this.workspaceGroupContext = context;
                    this.workspaceContextReady = context.readiness === 'ready';
                    this.workspaceContextReady = this.workspaceUiModel().resolved;
                    if (this.workspaceContextReady) {
                        if (workspace === 'personal') this.personalWorkspaceError = null;
                        this.teamSetupMessage = ''; this.teamSetupErrorCode = null; this.teamSetupError = null;
                    }
                    this.applyAppMode();
                    if (!wasReady && this.workspaceContextReady && this.activeWorkspaceView === 'home') this.refreshTeamOverview();
                    this.startWorkspaceReadinessPolling();
                    const refreshes = [];
                    const priorDevices = this.personalDevicesOverview;
                    if (refreshDevices) refreshes.push(this.refreshPersonalDevicesOverview({ suppressErrorNotification: true }));
                    if (refreshHome) refreshes.push(this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true }));
                    if (refreshFolders && this.workspaceContextReady) refreshes.push(this.loadEnrolledFolders({ suppressErrorNotification: true }));
                    await Promise.allSettled(refreshes);
                    if (!current()) return false;
                    const freshDevices = refreshDevices && this.personalDevicesOverview !== priorDevices;
                    const trust = freshDevices ? this.personalDevicesOverview?.device_trust : null;
                    const epoch = context.groups?.find(group => group.id === groupId)?.current_epoch_id;
                    if (readOnly && context.readiness === 'waiting_for_device_approval' && trust?.approved === true
                        && trust.device_id === device && /^[a-f0-9]{64}$/i.test(trust.identity_key_sha256 || '') && typeof epoch === 'string' && epoch) {
                        const scope = JSON.stringify([account, generation, sequence, workspace, groupId]);
                        if (this.workspaceWelcomeAcquisitionAttempts?.scope !== scope)
                            this.workspaceWelcomeAcquisitionAttempts = { scope, keys: new Set() };
                        const key = JSON.stringify([trust.identity_key_sha256.toLowerCase(), groupId, epoch]);
                        if (!this.workspaceWelcomeAcquisitionAttempts.keys.has(key)) {
                            // Approval permits one attempt to collect the issued Welcome;
                            // a failed acquisition remains an explicit Check status action.
                            this.workspaceWelcomeAcquisitionAttempts.keys.add(key);
                            return await this.reconcileWorkspaceState({ readOnly: false, refreshDevices: false, refreshHome,
                                refreshFolders: true, recoveryCompletionAttempt });
                        }
                    }
                    this.updateWorkspaceLabels();
                    return true;
                } catch (error) {
                    if (current() && workspace === 'personal') this.personalWorkspaceError = error.message || String(error);
                    return false;
                }
            },

            async ensurePersonalWorkspaceReady({ manual = false, selectionScope = null } = {}) {
                if (!this.isLoggedIn || this.activeWorkspaceType !== 'personal') return false;
                if (this.personalWorkspaceSetupInProgress()) return false;
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) return false;
                if (this.workspaceUiModel().resolved) return true;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const existing = this.personalWorkspaceRefresh;
                const matches = refresh => refresh && refresh.account === account && refresh.device === device
                    && refresh.generation === generation && refresh.sequence === this.workspaceSwitchSequence;
                if (matches(existing)) {
                    const ready = await existing.promise;
                    if (!this.isLoggedIn || this.activeWorkspaceType !== 'personal' || !matches(existing)) return false;
                    if (manual && !existing.manual && !this.workspaceUiModel().resolved)
                        return this.ensurePersonalWorkspaceReady({ manual: true, selectionScope });
                    return ready && this.workspaceUiModel().resolved;
                }
                const refresh = { account, device, generation, sequence: this.workspaceSwitchSequence, manual };
                this.personalWorkspaceRefresh = refresh;
                this.personalWorkspaceError = null;
                const current = () => this.isLoggedIn && this.activeWorkspaceType === 'personal'
                    && this.currentUser === account && this.currentDeviceId === device
                    && (this.desktopAccountGeneration || 0) === generation && this.workspaceSwitchSequence === refresh.sequence;
                refresh.promise = (async () => {
                    if (this.workspaceUiModel().hasGroupContext) {
                        if (!await this.reconcileWorkspaceState({ readOnly: !manual, refreshDevices: !manual, refreshHome: false, refreshFolders: true })) return false;
                    } else {
                        const selection = this.selectWorkspaceType('personal', { showDialog: true, persistSelection: Boolean(this.workspaceChoiceLoaded) });
                        refresh.sequence = this.workspaceSwitchSequence;
                        if (selectionScope) selectionScope.sequence = refresh.sequence;
                        if (!await selection) return false;
                    }
                    if (!current()) return false;
                    if (this.workspaceUiModel().resolved) this.personalWorkspaceError = null;
                    return this.workspaceUiModel().resolved;
                })().finally(() => { if (this.personalWorkspaceRefresh === refresh) this.personalWorkspaceRefresh = null; });
                return refresh.promise;
            },

            personalEnrollmentBlockingReason() {
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status)))
                    return 'Complete the current operation before adding a protected folder.';
                if (this.personalWorkspaceError) return `Could not load your Personal account: ${this.personalWorkspaceError}`;
                const context = this.workspaceGroupContext;
                if (context?.organization_id) return 'Your Personal encryption group could not be loaded. Reconnect and try again.';
                if (context?.readiness === 'waiting_for_device_approval')
                    return 'Your Personal encryption keys are not available on this device yet. Recover with your password and saved code, or open Devices to complete setup.';
                if (['missing', 'deleted', 'unresolved'].includes(context?.readiness))
                    return 'Your Personal default group needs repair. Open Personal workspace repair before adding a protected folder.';
                if (context?.readiness === 'uninitialized')
                    return 'Personal encryption setup is incomplete. Complete account setup before adding a protected folder.';
                if (this.workspaceUiModel().resolved && !writeRoles.has(context?.role || 'owner'))
                    return 'This Personal group is read-only for your account. Folder protection requires write access.';
                return 'Your Personal encryption group could not be found. Reconnect and sign in again.';
            },

            // Trust is cached per account and device; an unknown status never grants admin rights,
            // but a failed check is reported as unavailable rather than as an unverified device.
            currentDeviceTrustEntry() {
                const entry = this.currentDeviceTrust;
                return entry && entry.account === this.currentUser && entry.device === this.currentDeviceId ? entry : null;
            },
            currentDeviceTrustStatus() { return this.currentDeviceTrustEntry()?.status || null; },
            currentDeviceTrusted() { return this.currentDeviceTrustStatus()?.can_revoke_other_devices === true; },
            currentDeviceTrustState() {
                const entry = this.currentDeviceTrustEntry();
                if (entry?.status) return entry.status.can_revoke_other_devices === true ? 'trusted' : 'untrusted';
                return entry?.unavailable ? 'unavailable' : 'unknown';
            },
            async refreshCurrentDeviceTrust() {
                if (!this.isLoggedIn) return null;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                let status;
                try { status = unwrap(await call('get_device_trust_status')); } catch (_) {
                    const cached = this.currentDeviceTrustStatus();
                    if (!cached && this.isLoggedIn && this.currentUser === account && this.currentDeviceId === device) {
                        this.currentDeviceTrust = { account, device, status: null, unavailable: true };
                        this.updateWorkspaceLabels();
                    }
                    return cached;
                }
                if (!this.isLoggedIn || this.currentUser !== account || this.currentDeviceId !== device || !status) return null;
                const wasTrusted = this.currentDeviceTrusted();
                this.currentDeviceTrust = { account, device, status };
                if (wasTrusted !== this.currentDeviceTrusted()) {
                    if (this.activeWorkspaceView === 'admin' && !this.workspaceUiModel().canAdminister) this.setWorkspaceView('home');
                    if (this.activeWorkspaceView === 'members' && !this.canOpenMembersView()) this.setWorkspaceView('home');
                    this.applyAppMode();
                    if (this.activeWorkspaceView === 'home') this.refreshTeamOverview();
                }
                this.updateWorkspaceLabels();
                const cached = this.currentDeviceFingerprint;
                if (cached?.account === account && cached.device === device) this.renderStatusDeviceFingerprint?.(cached.fingerprint);
                return status;
            },
            async confirmCurrentDeviceTrust() {
                if (await this.ensureDeviceManagementTrust?.('approve')) await this.refreshCurrentDeviceTrust();
            },

            // An approved device without the current key usually missed a key rotation.
            // The user's own trusted device gives this one access; a group admin is the backup.
            teamMissingKeyMessage() {
                const group = this.workspaceGroupContext?.name || 'this group';
                const code = this.currentDeviceCodeHint?.() || '';
                return this.currentDeviceTrustStatus()?.approved === true
                    ? `This device doesn't have the current key for ${group}. It probably missed the latest key rotation. On another of your devices, press Give access next to this one (Home or Devices).${code} No other device? Ask a group admin. Then press Check status here.`
                    : `This device doesn't have the key for ${group} yet. On another of your devices, press Give access next to this one (Home or Devices) and compare the code.${code} No other device? Ask a group admin. Then press Check status.`;
            },

            teamEnrollmentBlockingReason() {
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status)))
                    return 'Complete the current operation before adding a protected folder.';
                const license = this.teamLicenseStatus;
                if (license?.workspace !== 'team' || !license.organization?.id) return "Team access isn't available on this account.";
                const model = this.workspaceUiModel();
                const context = this.workspaceGroupContext;
                const group = context?.name || 'This group';
                if (!model.hasGroupContext) return 'No Team group is selected on this device. Choose a group, then try again.';
                if (context.readiness === 'waiting_for_device_approval') return this.teamMissingKeyMessage();
                if (context.readiness === 'uninitialized')
                    return license.organization.role === 'owner' ? 'Finish Team setup before adding a protected folder.'
                        : `${group} hasn't been set up yet. Ask a Team admin.`;
                if (context.readiness === 'deleted') return `${group} was deleted. Choose another group.`;
                if (!model.resolved) return `${group} isn't ready on this device yet. Press Check status, then try again.`;
                if (license.revoked) return "The Team license was revoked. Existing files stay readable, but you can't add folders.";
                if (!license.can_write) return "Team access couldn't be confirmed. Reconnect to the internet, then try again.";
                if (!writeRoles.has(context.role || 'owner'))
                    return `Your role in ${group} is ${context.role}, which can't add protected folders. Ask a Team admin.`;
                return 'Select a ready workspace with write access before adding a protected folder.';
            },

            capturePersonalActionContext() {
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const sequence = this.workspaceSwitchSequence;
                return { account, device, generation, sequence,
                    current: () => this.isLoggedIn && this.activeWorkspaceType === 'personal'
                        && this.currentUser === account && this.currentDeviceId === device
                        && (this.desktopAccountGeneration || 0) === generation && this.workspaceSwitchSequence === sequence };
            },

            renderPersonalWorkspaceNotice() {
                const model = this.workspaceUiModel();
                const personal = this.isLoggedIn && this.activeWorkspaceType === 'personal';
                const pending = personal && !model.resolved;
                const readiness = this.workspaceGroupContext?.readiness;
                const needsRepair = ['missing', 'deleted', 'unresolved'].includes(readiness);
                let message = 'Loading your Personal default group…';
                if (this.personalRepairInFlight) message = 'Repairing your Personal workspace…';
                else if (this.personalWorkspaceError) message = `Could not load Personal workspace: ${this.personalWorkspaceError}. Reconnect and check again.`;
                else if (readiness === 'waiting_for_device_approval') {
                    const trust = this.personalDevicesOverview?.device_trust;
                    const trusted = Boolean(this.currentDeviceId) && trust?.device_id === this.currentDeviceId && trust?.approved === true && trust?.fingerprint_verified === true;
                    const code = this.currentDeviceCodeHint?.() || '';
                    message = trusted ? 'This device is trusted, but its Personal encryption keys are missing. On another of your devices, press Give access next to this one, or recover with your password and saved code.'
                        : `This device is missing Personal encryption keys. On another of your devices, press Give access next to this one and compare the code.${code} Or recover with your password and saved code.`;
                }
                else if (readiness === 'uninitialized') message = 'Personal encryption setup is incomplete. Complete account setup before adding protected folders.';
                else if (readiness === 'deleted') message = 'Your Personal default group was deleted. Repair Personal workspace to select an owned group or explicitly create a new one.';
                else if (needsRepair) message = 'Your Personal default group could not be identified. Repair Personal workspace to select an owned group or create a default when none are available.';
                show('personalSetupNotice', pending);
                text('personalSetupMessage', message);
                show('personalSetupRecoverBtn', pending && (readiness === 'waiting_for_device_approval' || needsRepair));
                show('personalSetupRepairBtn', pending && needsRepair);
                show('personalSetupCheckStatusBtn', pending);
                show('personalSetupDevicesBtn', pending && model.hasGroupContext && readiness === 'waiting_for_device_approval');
                for (const id of ['personalSetupRepairBtn', 'personalSetupCheckStatusBtn', 'personalSetupRecoverBtn'])
                    element(id)?.toggleAttribute('disabled', Boolean(this.personalRepairInFlight));
            },

            openPersonalRecovery() {
                if (!this.isLoggedIn || this.activeWorkspaceType !== 'personal' || this.personalRepairInFlight) return;
                this.openRecoveryAutoBackupModal?.();
            },

            async checkPersonalWorkspaceStatus() {
                if (!this.isLoggedIn || this.activeWorkspaceType !== 'personal' || this.personalRepairInFlight) return false;
                return this.ensurePersonalWorkspaceReady({ manual: true });
            },

            async repairPersonalWorkspace({ selectionScope = null } = {}) {
                if (!this.isLoggedIn || this.activeWorkspaceType !== 'personal' || this.personalRepairInFlight
                    || this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) return false;
                const scope = this.capturePersonalActionContext();
                if (selectionScope && selectionScope.sequence !== scope.sequence) return false;
                let repairSequence = scope.sequence;
                const selectPersonal = async () => {
                    if (!scope.current()) return false;
                    const selection = this.selectWorkspaceType('personal');
                    const sequence = this.workspaceSwitchSequence;
                    repairSequence = sequence;
                    if (selectionScope) selectionScope.sequence = sequence;
                    const selected = await selection;
                    return Boolean(selected) && this.isLoggedIn && this.activeWorkspaceType === 'personal'
                        && this.currentUser === scope.account && this.currentDeviceId === scope.device
                        && (this.desktopAccountGeneration || 0) === scope.generation
                        && this.workspaceSwitchSequence === sequence && this.workspaceUiModel().resolved;
                };
                const token = Symbol('personal-repair');
                this.personalRepairInFlight = token;
                this.renderPersonalWorkspaceNotice();
                try {
                    const snapshot = unwrap(await call('get_personal_workspace', { expectedAccountEmail: scope.account }));
                    if (!scope.current()) return false;
                    this.personalWorkspaceSnapshot = snapshot;
                    if (snapshot?.state === 'available') {
                        return await selectPersonal();
                    }
                    const candidates = (snapshot?.candidates || []).filter(group => group?.id && !group.organization_id && group.role === 'owner');
                    let request;
                    if (candidates.length) {
                        const groupId = await this.chooseWorkspaceRecord('Repair Personal workspace',
                            'Choose an owned group to become the default Personal always uses. Existing encrypted files keep their original group.',
                            candidates.map(group => ({ id: group.id, label: group.name || 'Personal group' })));
                        if (!scope.current() || !groupId || !candidates.some(group => group.id === groupId)) return false;
                        request = { action: 'assign', groupId };
                    } else {
                        const confirmed = await this.showConfirmDialog('Create Personal default group',
                            'Create a new Personal default group? This starts a new encryption group and does not restore files from a missing or deleted group.');
                        if (!confirmed || !scope.current()) return false;
                        request = { action: 'create' };
                    }
                    const repaired = unwrap(await call('repair_personal_default_group', { ...request, expectedAccountEmail: scope.account }));
                    if (!scope.current()) return false;
                    if (repaired?.state !== 'available' || !repaired.group?.id || repaired.personal_default_group_id !== repaired.group.id)
                        throw new Error('Personal repair did not return an available default group. Reconnect and try again.');
                    this.personalWorkspaceSnapshot = repaired;
                    return await selectPersonal();
                } catch (error) {
                    if (scope.current()) this.showNotification(`Personal workspace repair failed: ${error.message || error}`, 'warning');
                    return false;
                } finally {
                    if (this.personalRepairInFlight === token) {
                        this.personalRepairInFlight = null;
                        this.renderPersonalWorkspaceNotice();
                        if (this.isLoggedIn && this.currentUser === scope.account && this.currentDeviceId === scope.device
                            && (this.desktopAccountGeneration || 0) === scope.generation && this.activeWorkspaceType === 'personal'
                            && this.workspaceSwitchSequence === repairSequence) this.startWorkspaceReadinessPolling();
                    }
                }
            },

            async refreshTeamLicenseStatus(options = {}) {
                if (!this.isLoggedIn) return null;
                if (this.personalWorkspaceSetupInProgress()) return this.teamLicenseStatus || null;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const existing = this.teamLicenseRefresh;
                if (existing && existing.account === account && existing.device === device && existing.generation === generation
                    && existing.sequence === this.workspaceSwitchSequence && existing.workspace === this.activeWorkspaceType)
                    return existing.promise;
                const personal = this.activeWorkspaceType === 'personal' ? this.ensurePersonalWorkspaceReady() : Promise.resolve();
                const refresh = { account, device, generation, sequence: this.workspaceSwitchSequence, workspace: this.activeWorkspaceType };
                this.teamLicenseRefresh = refresh;
                const status = Promise.resolve().then(() => call('get_team_license_status', { expectedAccountEmail: account, expectedDeviceId: device })).then(unwrap);
                // Handle early rejection while the independent Personal read is still pending.
                status.catch(() => {});
                refresh.promise = (async () => {
                    await personal;
                    if (!this.isLoggedIn || this.currentUser !== account || this.currentDeviceId !== device
                        || (this.desktopAccountGeneration || 0) !== generation || this.workspaceSwitchSequence !== refresh.sequence
                        || this.activeWorkspaceType !== refresh.workspace || this.personalWorkspaceSetupInProgress()) return null;
                    return this.loadTeamLicenseStatus(options, refresh, status);
                })().finally(() => { if (this.teamLicenseRefresh === refresh) this.teamLicenseRefresh = null; });
                return refresh.promise;
            },

            async loadTeamLicenseStatus({ silent = false } = {}, refresh, statusPromise) {
                if (!this.isLoggedIn || this.personalWorkspaceSetupInProgress()) return null;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const current = () => this.currentUser === account && this.currentDeviceId === device && this.isLoggedIn
                    && generation === (this.desktopAccountGeneration || 0) && this.workspaceSwitchSequence === refresh.sequence
                    && this.activeWorkspaceType === refresh.workspace && !this.personalWorkspaceSetupInProgress();
                try {
                    const status = await statusPromise;
                    if (!current()) return null;
                    this.teamLicenseStatus = status;
                    this.renderTeamLicenseSettings();
                    // Owner setup and admin views depend on this device's trust.
                    if (status?.workspace === 'team') await this.refreshCurrentDeviceTrust();
                    if (!current()) return null;
                    await this.refreshTeamDirectory();
                    if (!current()) return null;
                    const first = !this.workspaceChoiceLoaded;
                    this.workspaceChoiceLoaded = true;
                    const choice = status?.workspace === 'team'
                        ? (first ? global.localStorage.getItem(this.workspacePreferenceKey()) || 'team' : this.activeWorkspaceType) : 'personal';
                    if (choice === 'team' && choice === this.activeWorkspaceType && this.workspaceGroupContext?.readiness === 'waiting_for_device_approval')
                        await this.reconcileWorkspaceState({ readOnly: true, refreshFolders: false });
                    else if (choice === 'team' && status?.workspace === 'team' && status.online && status.can_write && status.organization?.role === 'owner'
                        && this.currentDeviceTrusted() && this.teamSetupAttemptedOrganizationId !== status.organization.id) {
                        // prepareTeamWorkspace already rejects a selection superseded during setup. Passing
                        // `current` here would always cancel it, because selecting Team advances the
                        // switch sequence that `current` pins, reverting a saved Team choice to Personal.
                        await this.prepareTeamWorkspace({ showDialog: false, select: choice === 'team' });
                        if (this.personalWorkspaceSetupInProgress()) return null;
                        refresh.sequence = this.workspaceSwitchSequence; refresh.workspace = this.activeWorkspaceType;
                    }
                    else if (choice !== this.activeWorkspaceType || (choice === 'team' && !this.workspaceContextReady)) {
                        const selection = this.selectWorkspaceType(choice);
                        refresh.sequence = this.workspaceSwitchSequence; refresh.workspace = this.activeWorkspaceType;
                        await selection;
                    }
                    if (!current()) return null;
                    this.applyAppMode();
                    await this.refreshPendingTeamRequests(status?.workspace === 'team' && status.online && status.can_write);
                    if (status?.workspace !== 'team' && status?.online !== false) this.refreshTeamInvitations(status).catch(() => {});
                    else show('teamInvitationNotice', false);
                    return status;
                } catch (error) {
                    if (!current()) return null;
                    text('teamLicenseNote', `License status unavailable: ${error.message || error}`);
                    if (!silent) this.showNotification('Could not refresh workspace access.', 'warning');
                    return null;
                }
            },

            async prepareTeamWorkspace({ showDialog = true, select = true, shouldSelect = null } = {}) {
                if (this.teamSetupInProgress || !this.canPrepareTeamWorkspace()) return false;
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const sequence = this.workspaceSwitchSequence;
                const current = () => this.isLoggedIn && this.currentUser === account
                    && generation === (this.desktopAccountGeneration || 0) && sequence === this.workspaceSwitchSequence;
                this.teamSetupInProgress = true;
                this.teamSetupAttemptedOrganizationId = this.teamLicenseStatus.organization.id;
                this.teamSetupErrorCode = null; this.teamSetupError = null;
                try {
                    const result = await this.runDesktopOperation({ kind: 'team_setup', workspace: 'team', title: 'Preparing Team workspace' }, {
                        showDialog, onUpdate: operation => { if (current()) { this.teamSetupMessage = operation.phase; this.updateWorkspaceLabels(); } },
                    });
                    if (!current()) return false;
                    if (result?.readiness === 'waiting_for_device_approval') {
                        this.teamSetupErrorCode = 'device_approval_required';
                        this.teamSetupMessage = this.teamMissingKeyMessage();
                    } else {
                        this.teamSetupCompletedOrganizationId = this.teamLicenseStatus?.organization?.id;
                        this.teamSetupMessage = result?.readiness === 'deleted' ? 'The default group was deleted. Create another group to continue.' : '';
                    }
                    if (select && current()) {
                        if (shouldSelect && !shouldSelect()) return false;
                        const selected = await this.selectWorkspaceType('team', {
                            forceGroupId: result?.first_setup || !global.localStorage.getItem(this.groupPreferenceKey('team')) ? result?.group_id : null,
                            preserveOnFailure: true,
                            shouldSelect,
                        });
                        if (!selected && this.activeWorkspaceType !== 'team') return false;
                    }
                    return true;
                } catch (error) {
                    if (!current()) return false;
                    this.teamSetupErrorCode = error.code;
                    this.teamSetupError = { code: error.code, message: error.message || String(error) };
                    this.teamSetupMessage = error.code === 'device_approval_required'
                        ? this.teamMissingKeyMessage()
                        : `Team activated; workspace setup pending. ${error.message}`;
                    return false;
                } finally {
                    if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) { this.teamSetupInProgress = false; this.updateWorkspaceLabels(); }
                }
            },

            openTeamActivationModal() {
                if (!this.isLoggedIn) return;
                const entitled = this.teamLicenseStatus?.workspace === 'team' && Boolean(this.teamLicenseStatus.organization?.id);
                text('teamActivationError', ''); show('teamActivationError', false);
                show('teamOpenWorkspaceBtn', entitled);
                show('teamActivationForm', !entitled); show('teamInvitationAcceptance', !entitled);
                text('teamActivationTitle', entitled ? 'Team workspace' : 'Activate Team');
                this.closeSettingsModal(); showModal('teamActivationModal', true);
                element(entitled ? 'teamOpenWorkspaceBtn' : 'teamOrganizationName')?.focus();
            },
            closeTeamActivationModal() {
                showModal('teamActivationModal', false);
                this.teamActivationAttempt = null;
                for (const id of ['teamUnlockCode', 'teamInvitationCode']) if (element(id)) element(id).value = '';
            },
            async openEntitledTeamWorkspace({ attempt = null } = {}) {
                if (!this.isLoggedIn || this.teamLicenseStatus?.workspace !== 'team' || !this.teamLicenseStatus.organization?.id) return false;
                const shouldSelect = () => !attempt || this.teamActivationAttempt === attempt;
                if (!shouldSelect()) return false;
                if (!this.currentDeviceTrustStatus()) await this.refreshCurrentDeviceTrust();
                if (!shouldSelect()) return false;
                const selected = this.canPrepareTeamWorkspace() && this.teamSetupCompletedOrganizationId !== this.teamLicenseStatus.organization.id
                    ? await this.prepareTeamWorkspace({ showDialog: true, shouldSelect }) : await this.selectWorkspaceType('team', { preserveOnFailure: true, shouldSelect, showDialog: true });
                if (selected || this.activeWorkspaceType === 'team') this.closeTeamActivationModal();
                return selected;
            },
            async finishTeamActivation(status, account, generation, attempt = null) {
                if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || !this.isLoggedIn) return false;
                if (attempt && this.teamActivationAttempt !== attempt) return false;
                if (status?.workspace !== 'team' || !status.organization?.id || !status.online || !status.can_write || status.revoked)
                    throw new Error('Team access could not be verified. Retry after reconnecting.');
                this.teamLicenseStatus = status;
                this.workspaceChoiceLoaded = true;
                this.renderTeamLicenseSettings();
                const selected = await this.openEntitledTeamWorkspace({ attempt });
                if (attempt && this.teamActivationAttempt !== attempt && this.activeWorkspaceType !== 'team') return false;
                if (!selected && this.activeWorkspaceType !== 'team') throw new Error(this.teamSetupMessage || 'Team setup could not complete. Retry after reconnecting.');
                if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0)) return false;
                await this.refreshTeamDirectory();
                return true;
            },

            async activateTeamFromSettings() {
                if (this.teamActivationInProgress) return;
                const name = element('teamOrganizationName')?.value.trim() || '';
                const code = element('teamUnlockCode')?.value.trim() || '';
                if (!name || !code) { this.showNotification('Enter an organization name and Team code.', 'warning'); return; }
                this.teamActivationInProgress = true;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const attempt = Symbol('team-activation'); this.teamActivationAttempt = attempt;
                try {
                    const status = unwrap(await call('redeem_team_code', { code, organizationName: name,
                        expectedAccountEmail: account, expectedDeviceId: device }));
                    if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || this.teamActivationAttempt !== attempt) return;
                    element('teamUnlockCode').value = '';
                    await this.finishTeamActivation(status, account, generation, attempt);
                } catch (error) { if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) {
                    text('teamActivationError', error.message || String(error)); show('teamActivationError', true);
                    this.showNotification(`Team activation failed: ${error.message || error}`, 'error');
                } }
                finally { if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) this.teamActivationInProgress = false; }
            },
            async acceptTeamInvitationFromSettings() {
                if (this.teamActivationInProgress) return;
                const code = element('teamInvitationCode')?.value.trim() || '';
                if (!code) { this.showNotification('Enter the invitation code.', 'warning'); return; }
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const attempt = Symbol('team-invitation'); this.teamActivationAttempt = attempt;
                this.teamActivationInProgress = true;
                try {
                    const accepted = unwrap(await call('accept_team_invitation', { code, expectedAccountEmail: account, expectedDeviceId: device }));
                    if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || this.teamActivationAttempt !== attempt) return;
                    const status = unwrap(await call('get_team_license_status', { expectedAccountEmail: account, expectedDeviceId: device }));
                    await this.finishTeamActivation(status, account, generation, attempt);
                    if (this.currentUser === account) this.announceJoinedGroups(accepted);
                } catch (error) { if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) {
                    text('teamActivationError', error.message || String(error)); show('teamActivationError', true);
                    this.showNotification(`Could not join Team: ${error.message || error}`, 'error');
                } }
                finally { if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) this.teamActivationInProgress = false; }
            },

            async refreshTeamDirectory() {
                if (this.teamLicenseStatus?.workspace !== 'team') return;
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const current = () => this.currentUser === account && this.isLoggedIn && generation === (this.desktopAccountGeneration || 0);
                try {
                    const directory = unwrap(await call('get_team_directory'));
                    if (!current()) return;
                    this.teamDirectoryRole = directory?.role;
                    show('teamDirectoryMembersLink', this.canOpenMembersView());
                    this.renderTeamLicenseSettings(); this.applyAppMode();
                } catch (_) { if (current()) { this.teamDirectoryRole = null; this.applyAppMode(); } }
            },

            async openAddGroupMemberDialog() {
                if (!this.workspaceUiModel().canAdministerGroup) return;
                const modal = element('addGroupMemberModal');
                const suggestions = element('groupMemberSuggestions');
                modal.style.display = 'flex';
                if (suggestions) suggestions.innerHTML = '';
                text('groupMemberDirectoryNote', '');
                const account = this.currentUser;
                this.addMemberDialogContext = { account, groupId: this.workspaceGroupContext?.group_id };
                element('groupMemberEmail')?.focus();
                try {
                    const directory = unwrap(await call('get_team_directory'));
                    if (this.currentUser !== account || !suggestions) return;
                    // People already in this group are listed on its People tab, not suggested again.
                    const cache = this.peopleRowsCache?.groupId === this.addMemberDialogContext?.groupId ? this.peopleRowsCache : null;
                    const inGroup = new Set((cache?.rows || []).filter(row => row.status === 'has_access').map(row => row.email));
                    for (const member of directory.members || []) {
                        if (!member.email || inGroup.has(String(member.email).trim().toLowerCase())) continue;
                        const option = global.document.createElement('option');
                        option.value = member.email; suggestions.appendChild(option);
                    }
                    if (!directory.online) text('groupMemberDirectoryNote', 'Connect to the server to add or invite people.');
                } catch (_) { /* Suggestions are optional; the action reports its own errors. */ }
            },

            /** Runs a task-level Team action for the selected group and refreshes the People list. */
            /** Runs a task for `request.group_id`, or the selected group when none is given. */
            async runTeamTask(request, title) {
                const groupId = request.group_id || this.workspaceGroupContext?.group_id;
                if (!groupId) { this.showNotification('Select a group first.', 'warning'); return null; }
                try {
                    const result = await this.runDesktopOperation({ ...request, group_id: groupId, title });
                    await this.refreshPeoplePanel();
                    this.refreshAdminDashboard();
                    return result;
                } catch (error) {
                    if (!this.desktopOperation?.error) this.showNotification(this.teamErrorText(error), 'error');
                    return null;
                }
            },
            teamErrorText(error) {
                const message = error?.message || String(error);
                if (!deviceTrustRefusal.test(message)) return message;
                this.refreshCurrentDeviceTrust();
                return 'Team administration needs a verified device. Verify this device from a trusted device, or confirm it with your password.';
            },

            /** The selected group's People rows; cached so the list filter and the Team overview reuse them. */
            async loadPeopleRows() {
                const groupId = this.workspaceGroupContext?.group_id;
                if (this.activeWorkspaceType !== 'team' || !groupId) { this.peopleRowsCache = null; return null; }
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const [directory, members, details] = await Promise.all([
                    call('get_team_directory').then(unwrap).catch(() => null),
                    call('get_group_members').then(response => (response?.success === false ? [] : unwrap(response) || [])).catch(() => []),
                    call('get_group_member_details').then(response => (response?.success === false ? null : unwrap(response))).catch(() => null),
                ]);
                if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0)
                    || groupId !== this.workspaceGroupContext?.group_id) return null;
                const memberDevices = Array.isArray(details) ? new Map(details.flatMap(member => [
                    [String(member.email || '').trim().toLowerCase(), member], [String(member.user_id || ''), member]])) : null;
                const rows = global.HybridCipherUiUtils?.buildPeopleRows?.({ directory, groupMembers: members,
                    groupId, currentUserEmail: this.currentUser, memberDevices }) || [];
                this.peopleRowsCache = { groupId, rows, online: Boolean(directory?.online) };
                return this.peopleRowsCache;
            },

            /** Organization owners and admins on a verified device, on a server that has the roster. */
            canOpenMembersView(model = this.workspaceUiModel()) {
                return this.activeWorkspaceType === 'team' && Boolean(model.canManageMembers) && !this.membersUnsupported;
            },

            /** Members with a device that needs attention, from the last roster this account loaded. */
            membersAttentionCount() {
                const cache = this.membersRoster;
                if (!cache || cache.account !== this.currentUser) return 0;
                return global.HybridCipherUiUtils?.buildMemberDeviceRows?.({ roster: cache.roster })?.counts.attention || 0;
            },

            async showMembersView() {
                if (!this.canOpenMembersView()) return;
                this.setWorkspaceView('members');
                // Opening the page tries the adds that failed earlier once more.
                for (const [key, outcome] of this.groupAccessAutoFailures || []) if (outcome) this.groupAccessAutoFailures.delete(key);
                this.renderSidebarTeamNav();
                this.renderMembersCenter();
                await this.refreshMembersCenter();
            },

            async refreshMembersCenter() {
                if (!this.canOpenMembersView()) return;
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const current = () => this.currentUser === account && this.isLoggedIn && generation === (this.desktopAccountGeneration || 0);
                this.membersLoading = true;
                this.renderMembersCenter();
                try {
                    const [response, directory] = await Promise.all([
                        call('get_team_member_devices'),
                        call('get_team_directory').then(unwrap).catch(() => null),
                        this.refreshPendingTeamRequests?.(Boolean(this.teamLicenseStatus?.online)),
                    ]);
                    if (!current()) return;
                    this.membersInvitations = { account, invitations: Array.isArray(directory?.invitations) ? directory.invitations : [],
                        online: Boolean(directory?.online) };
                    if (response?.success === false && response.error_code === 'TEAM_DEVICES_UNSUPPORTED') {
                        this.membersUnsupported = true;
                        if (this.activeWorkspaceView === 'members') this.setWorkspaceView('home');
                        return;
                    }
                    if (response?.success === false && response.error_code === 'device_trust_required') this.refreshCurrentDeviceTrust();
                    this.membersRoster = { account, roster: unwrap(response) };
                    this.membersError = null;
                } catch (error) {
                    if (current()) this.membersError = this.teamErrorText(error);
                } finally {
                    if (current()) {
                        this.membersLoading = false;
                        this.renderMembersCenter();
                        this.renderSidebarTeamNav();
                    }
                }
                if (current()) await this.autoFinishGroupAccess();
            },

            /** Members needing attention first; each row opens to its devices with their status and actions. */
            renderMembersCenter() {
                const list = element('membersList');
                if (!list) return;
                const cache = this.membersRoster?.account === this.currentUser ? this.membersRoster : null;
                const me = String(this.currentUser || '').trim().toLowerCase();
                const self = cache?.roster?.members?.find(member => String(member.email || '').trim().toLowerCase() === me);
                const invitations = this.membersInvitations?.account === this.currentUser ? this.membersInvitations.invitations : [];
                const { rows, counts, filter } = global.HybridCipherUiUtils?.buildMemberDeviceRows?.({
                    roster: cache?.roster, invitations, filter: this.membersFilter, query: element('membersSearch')?.value || '',
                    currentUserId: self?.user_id || null, currentDeviceId: this.currentDeviceId || null,
                    actorRole: this.teamLicenseStatus?.organization?.role || this.teamDirectoryRole || 'admin',
                }) || { rows: [], counts: {}, filter: 'all' };
                const labels = { all: 'All', attention: 'Needs attention', needs_access: 'Needs group access', invited: 'Invited', pending: 'Needs approval', unverified: 'Unverified', missing_key: 'Missed key', stale: 'Stale' };
                for (const button of global.document?.querySelectorAll?.('[data-members-filter]') || []) {
                    const key = button.dataset.membersFilter;
                    const selected = key === filter;
                    button.classList.toggle('active', selected);
                    button.setAttribute('aria-pressed', String(selected));
                    button.textContent = key !== 'all' && counts[key] ? `${labels[key]} · ${counts[key]}` : labels[key];
                }
                if (!cache) {
                    text('membersSummary', this.membersError || (this.membersLoading ? 'Loading members and devices…' : ''));
                    setMarkup(list, '');
                    return;
                }
                const seats = this.teamLicenseStatus?.organization;
                text('membersSummary', [
                    `${counts.members} ${counts.members === 1 ? 'member' : 'members'} · ${counts.devices} ${counts.devices === 1 ? 'device' : 'devices'}`,
                    counts.invited ? `${counts.invited} invited` : '',
                    seats?.seat_limit ? `${seats.seats_used} of ${seats.seat_limit} seats used` : '',
                    counts.attention ? `${counts.attention} need${counts.attention === 1 ? 's' : ''} attention` : 'every device is trusted',
                    this.membersLoading ? 'refreshing…' : '', this.membersError || '',
                ].filter(Boolean).join(' · '));
                // Rows that need attention start open; the admin's own choice wins after that.
                const expanded = this.membersExpanded ||= new Map();
                const busy = this.membersRevokeInFlight;
                const deviceRow = (row, device) => `<li class="member-device" data-status="${device.status}"${device.ownerCanSetUp ? ' data-owner-handles="true"' : ''}>`
                    + '<div class="member-device-main">'
                    + `<span class="member-device-name">${this.escapeHtml(device.name)}${device.isCurrent ? ' <span class="device-row-badge current">This device</span>' : ''}</span>`
                    + `<span class="member-device-meta">${this.escapeHtml([device.activity, ...device.reasons].filter(Boolean).join(' · '))}</span>`
                    + '</div>'
                    + `<span class="device-row-badge status-${device.status}${device.ownerCanSetUp ? ' owner-handles' : ''}">${this.escapeHtml(device.label)}</span>`
                    + '<span class="member-device-actions">'
                    // This device's own trust is fixed in Devices; keys and approvals on the group's Devices tab.
                    + (device.isCurrent && device.status === 'unverified'
                        ? '<button type="button" class="btn btn-secondary btn-small" data-members-action="own-devices">Open Devices</button>' : '')
                    + ((device.status === 'pending' || device.status === 'missing_key') && (device.missingKeyGroups[0] || row.groups.length)
                        ? `<button type="button" class="btn btn-secondary btn-small" data-members-action="open-group" data-group-id="${this.escapeHtmlAttr(device.missingKeyGroups[0]?.id || '')}" data-user-id="${this.escapeHtmlAttr(row.userId)}">Open group to approve</button>` : '')
                    + (device.canRevoke
                        ? `<button type="button" class="btn btn-secondary btn-small" data-members-action="revoke" data-user-id="${this.escapeHtmlAttr(row.userId)}" data-device-id="${this.escapeHtmlAttr(device.id)}"${busy ? ' disabled' : ''}>${busy === device.id ? 'Revoking…' : 'Revoke'}</button>` : '')
                    + '</span></li>';
                const canAdminister = Boolean(this.teamLicenseStatus?.can_write);
                const adminGroups = this.adminGroupIds();
                const button = (action, label, data = {}) => `<button type="button" class="btn btn-secondary btn-small" data-members-action="${action}"`
                    + Object.entries(data).map(([key, value]) => ` data-${key}="${this.escapeHtmlAttr(value)}"`).join('') + `>${this.escapeHtml(label)}</button>`;
                // A group admin's app finishes these adds by itself; Finish appears only when that failed.
                const pendingGroupRow = (row, group) => {
                    const failure = this.groupAccessAutoFailures?.get(`${row.userId}:${group.id}`);
                    const mine = canAdminister && adminGroups.has(group.id);
                    const status = !row.devices.length ? `Gets ${group.name} after their first sign-in`
                        : mine && failure ? `Couldn't finish adding to ${group.name}: ${failure}`
                            : mine ? `Finishing access to ${group.name}…`
                                : `Waiting for an admin of ${group.name}; their app finishes this automatically`;
                    return '<li class="member-pending-group">'
                        + `<span>${this.escapeHtml(status)}</span>`
                        + (mine && failure && row.devices.length
                            ? button('finish-group', 'Finish', { 'group-id': group.id, 'user-id': row.userId, email: row.email }) : '')
                        + '</li>';
                };
                const invitationRow = row => `<div class="member-invitation-row" data-invitation-id="${this.escapeHtmlAttr(row.invitationId)}">`
                    + `<span class="people-avatar" aria-hidden="true">${this.escapeHtml(row.email.charAt(0).toUpperCase())}</span>`
                    + '<span class="people-row-main">'
                    + `<span class="people-row-email">${this.escapeHtml(row.email)}</span>`
                    + `<span class="people-row-status">${this.escapeHtml(row.summary)}</span>`
                    + '</span>'
                    + (canAdminister ? button('invite-groups', 'Add to group…', { 'invitation-id': row.invitationId, email: row.email })
                        + button('cancel-invite', 'Cancel invitation', { 'invitation-id': row.invitationId, email: row.email }) : '')
                    + '</div>';
                setMarkup(list, rows.length ? rows.map(row => {
                    if (row.kind === 'invitation') return invitationRow(row);
                    const open = expanded.has(row.userId) ? expanded.get(row.userId) : row.attention;
                    return `<details class="member-row" data-user-id="${this.escapeHtmlAttr(row.userId)}"${row.attention ? ' data-attention="true"' : ''}${open ? ' open' : ''}>`
                        + '<summary class="member-row-summary">'
                        + `<span class="people-avatar" aria-hidden="true">${this.escapeHtml(row.email.charAt(0).toUpperCase())}</span>`
                        + '<span class="people-row-main">'
                        + `<span class="people-row-email">${this.escapeHtml(row.email)}${row.isSelf ? ' (you)' : ''}</span>`
                        + `<span class="people-row-status">${this.escapeHtml([row.role, row.groups.length ? row.groups.join(', ') : 'No groups'].join(' · '))}</span>`
                        + `<span class="people-row-devices${row.attention ? ' has-inactive' : ''}">${this.escapeHtml(row.summary)}</span>`
                        + '</span>'
                        + (row.worst ? `<span class="device-row-badge status-${row.worst}${row.worst !== 'trusted' && !row.attention ? ' owner-handles' : ''}">${this.escapeHtml(row.worstLabel)}</span>` : '')
                        + '</summary>'
                        + (row.pendingGroups.length ? `<ul class="member-pending-groups">${row.pendingGroups.map(group => pendingGroupRow(row, group)).join('')}</ul>` : '')
                        + (row.devices.length ? `<ul class="member-device-list">${row.devices.map(device => deviceRow(row, device)).join('')}</ul>`
                            : '<p class="member-device-empty">No devices registered yet.</p>')
                        + (canAdminister && !row.isSelf ? '<div class="member-row-actions">'
                            + button('member-groups', 'Add to group…', { 'user-id': row.userId, email: row.email })
                            + (row.role !== 'owner' ? button('remove-member', 'Remove from Team', { 'user-id': row.userId, email: row.email }) : '')
                            + '</div>' : '')
                        + '</details>';
                }).join('') : `<div class="people-empty">${counts.members || counts.invited ? 'No one here matches.' : 'No members yet.'}</div>`);
                for (const details of list.querySelectorAll?.('details.member-row') || []) {
                    details.addEventListener('toggle', () => expanded.set(details.dataset.userId, details.open));
                }
            },

            async handleMembersListClick(event) {
                const button = event.target?.closest?.('[data-members-action]');
                if (!button || button.disabled) return;
                const action = button.dataset.membersAction;
                if (action === 'own-devices') { this.showDevicesView(); return; }
                if (action === 'open-group') await this.openGroupApprovals(button.dataset.groupId, button.dataset.userId);
                if (action === 'revoke') await this.revokeMemberDevice(button.dataset.userId, button.dataset.deviceId);
                if (action === 'finish-group') await this.finishMemberGroupAccess(button);
                if (action === 'member-groups') await this.openTeamInviteDialog({ userId: button.dataset.userId, email: button.dataset.email });
                if (action === 'invite-groups') await this.openTeamInviteDialog({ invitationId: button.dataset.invitationId, email: button.dataset.email });
                if (action === 'remove-member') await this.removeTeamMember(button.dataset.userId, button.dataset.email);
                if (action === 'cancel-invite') await this.cancelTeamInvitation(button.dataset.invitationId, button.dataset.email);
            },

            /** Opens the group's Devices tab with "Approve new devices", where waiting and missed-key devices get the key. */
            async openGroupApprovals(groupId, userId) {
                const member = this.membersRoster?.roster?.members?.find(entry => entry.user_id === userId);
                const target = groupId || member?.groups?.[0]?.id;
                if (!target) return false;
                const groups = Array.isArray(this.workspaceGroupContext?.groups) ? this.workspaceGroupContext.groups : [];
                if (groups.length && !groups.some(group => group.id === target)) {
                    const name = member?.groups?.find(group => group.id === target)?.name || 'that group';
                    this.showNotification(`You are not in ${name}. Ask one of its admins to approve the device from the group's Devices tab.`, 'warning');
                    return false;
                }
                if (!(await this.openTeamGroup(target)) || this.activeWorkspaceView !== 'admin') return false;
                this.selectAdminTab?.('devices');
                await this.showDeviceAccessQueue?.();
                return true;
            },

            /**
             * Signs the device out and removes it, then offers a key rotation for each of the member's
             * groups (the existing rotation flow, with its device check), so the device cannot open new files.
             */
            async revokeMemberDevice(userId, deviceId) {
                const member = this.membersRoster?.roster?.members?.find(entry => entry.user_id === userId);
                const device = member?.devices?.find(entry => entry.device_id === deviceId);
                if (!member || !device || this.membersRevokeInFlight) return false;
                const name = device.device_name || device.device_id;
                const confirmed = await this.showActionPrompt(`Revoke ${name}?`,
                    `${name} (${member.email}) will be signed out and removed. It keeps files it already opened; rotate the group keys afterwards so it cannot open new ones.`,
                    { primaryLabel: 'Revoke device', secondaryLabel: 'Cancel' });
                if (confirmed !== true) return false;
                const account = this.currentUser;
                this.membersRevokeInFlight = deviceId;
                this.renderMembersCenter();
                let result = null;
                try {
                    result = unwrap(await call('admin_revoke_member_device', { userId, deviceId }));
                } catch (error) {
                    if (this.currentUser === account) this.showNotification(this.teamErrorText(error), 'error');
                } finally {
                    if (this.currentUser === account) { this.membersRevokeInFlight = null; this.renderMembersCenter(); }
                }
                if (!result || this.currentUser !== account) return false;
                this.showNotification(`${name} was revoked and signed out.`, 'success');
                await this.refreshMembersCenter();
                const groups = (result.group_ids || []).map(id => (member.groups || []).find(group => group.id === id) || { id, name: 'a group' });
                await this.offerKeyRotations(groups, name, account);
                return true;
            },

            /** Offers the existing rotation flow for each group, one at a time, then returns to Members & devices. */
            async offerKeyRotations(groups, removedName, account = this.currentUser) {
                for (const group of groups) {
                    if (this.currentUser !== account) return;
                    if (group.id !== this.workspaceGroupContext?.group_id && !(await this.switchTeamGroup(group.id))) continue;
                    await this.beginRekeyFlow({ title: `Rotate keys for ${group.name}?`,
                        message: `${removedName} was removed. Rotating ${group.name}'s keys stops it from opening files added from now on.` });
                }
                if (groups.length && this.currentUser === account) await this.showMembersView();
            },

            /** "Uses 1 seat · 3 of 5 left", from the last license status. */
            teamSeatLine() {
                const organization = this.teamLicenseStatus?.organization;
                if (!organization?.seat_limit) return '';
                const free = organization.seat_limit - organization.seats_used;
                return free > 0 ? `Uses 1 seat · ${free} of ${organization.seat_limit} left`
                    : 'No seats are free. Remove a member or cancel an invitation first.';
            },

            /** Before Add person invites someone outside the Team, the admin confirms the seat it uses. */
            async confirmGroupInviteSeat(email) {
                const directory = await call('get_team_directory').then(unwrap).catch(() => null);
                const same = entry => String(entry?.email || '').trim().toLowerCase() === email;
                if ((directory?.members || []).some(same)) return true;
                if ((directory?.invitations || []).some(invite => same(invite) && invite.status === 'pending')) return true;
                if (!directory?.online) {
                    this.showNotification('Connect to the server to invite someone who is not in the Team yet.', 'warning');
                    return false;
                }
                const group = this.workspaceGroupContext?.name || 'this group';
                return (await this.showActionPrompt('Invite to the Team?',
                    `${email} isn't in your Team yet. Continuing adds them to the Team (${this.teamSeatLine() || 'uses 1 seat'}) and gives them access to ${group} when they accept.`,
                    { primaryLabel: 'Invite and use a seat', secondaryLabel: 'Cancel' })) === true;
            },

            /** Team groups this admin is in; only a group member can finish adding someone to it. */
            async teamInviteGroups() {
                const summaries = await this.loadTeamGroupSummaries();
                const organization = this.teamLicenseStatus?.organization?.id;
                return (summaries?.groups || []).filter(group => group?.id && (!organization || group.organization_id === organization));
            },

            /**
             * One dialog for three jobs: invite someone new to the Team (optionally with groups), choose
             * groups for a member (`userId`), or add groups to an open invitation (`invitationId`).
             */
            async openTeamInviteDialog(target = null) {
                if (!this.canOpenMembersView()) return;
                const account = this.currentUser;
                const context = this.teamInviteContext = { account, target, done: false };
                const isNew = !target;
                text('teamInviteTitle', isNew ? 'Invite to Team' : `Add ${target.email} to groups`);
                text('teamInviteIntro', isNew ? 'Inviting someone uses one seat. Choose groups now, or add them to groups later.'
                    : target.invitationId ? 'They get these groups after they join.'
                        : 'People with a device get access now; anyone without one gets it after their first sign-in.');
                show('teamInviteEmailGroup', isNew);
                if (element('teamInviteEmail')) element('teamInviteEmail').value = '';
                text('teamInviteSeats', isNew ? this.teamSeatLine() : '');
                show('teamInviteCode', false); show('teamInviteCodeLabel', false);
                text('teamInviteSubmitBtn', isNew ? 'Invite' : 'Add to groups');
                element('teamInviteSubmitBtn')?.toggleAttribute('disabled', false);
                setMarkup(element('teamInviteGroups'), '<p class="form-hint">Loading groups…</p>');
                showModal('teamInviteModal', true);
                (isNew ? element('teamInviteEmail') : element('teamInviteSubmitBtn'))?.focus();
                const groups = await this.teamInviteGroups();
                if (this.teamInviteContext !== context || this.currentUser !== account) return;
                const member = target?.userId ? this.membersRoster?.roster?.members?.find(entry => entry.user_id === target.userId) : null;
                const taken = new Set([...(member?.groups || []), ...(member?.pending_groups || [])].map(group => group.id));
                const choices = groups.filter(group => !taken.has(group.id));
                setMarkup(element('teamInviteGroups'), choices.length
                    ? choices.map(group => `<label><input type="checkbox" value="${this.escapeHtmlAttr(group.id)}"> ${this.escapeHtml(group.name)}</label>`).join('')
                    : `<p class="form-hint">${groups.length ? 'They are already in every group you are in.' : 'You are not in any Team group yet.'}</p>`);
            },

            closeTeamInviteDialog() {
                this.teamInviteContext = null;
                if (element('teamInviteCode')) element('teamInviteCode').value = '';
                showModal('teamInviteModal', false);
            },

            async submitTeamInviteDialog() {
                const context = this.teamInviteContext;
                if (!context || context.account !== this.currentUser) return;
                if (context.done) { this.closeTeamInviteDialog(); return; }
                const groupIds = [...(element('teamInviteGroups')?.querySelectorAll?.('input[type="checkbox"]:checked') || [])].map(input => input.value);
                const submit = element('teamInviteSubmitBtn');
                submit?.toggleAttribute('disabled', true);
                try {
                    if (!context.target) await this.inviteToTeam(context, groupIds);
                    else if (!groupIds.length) this.showNotification('Choose at least one group.', 'warning');
                    else if (context.target.invitationId) {
                        for (const groupId of groupIds) unwrap(await call('add_team_group_grant', { target: 'invitation', targetId: context.target.invitationId, groupId }));
                        this.closeTeamInviteDialog();
                        const access = await this.stageInvitationAccess(context.target.invitationId, context.target.email, groupIds, context.account);
                        if (this.currentUser === context.account) this.showNotification(`${context.target.email} was added to the invitation. ${this.invitationAccessText(access)}`.trim(), 'success');
                    } else await this.addMemberToGroups(context, groupIds);
                } catch (error) {
                    if (this.currentUser === context.account) this.showNotification(this.teamErrorText(error), 'error');
                } finally {
                    submit?.toggleAttribute('disabled', false);
                }
                if (this.currentUser === context.account) await this.refreshMembersCenter();
            },

            /** Online, the server reserves the seat and returns the code; offline, an invitation without groups waits in the queue. */
            async inviteToTeam(context, groupIds) {
                const email = element('teamInviteEmail')?.value.trim().toLowerCase() || '';
                if (!(this.isValidEmail?.(email) ?? /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))) {
                    this.showNotification('Enter a valid email address.', 'warning');
                    return;
                }
                if (this.teamLicenseStatus?.online === false) {
                    if (groupIds.length) {
                        this.showNotification('Connect to the server to invite someone to a group. Without groups, the invitation can wait until you reconnect.', 'warning');
                        return;
                    }
                    await call('queue_team_admin_request', { kind: 'invite_member', email, targetId: null, groupName: null, description: null });
                    this.showNotification('Invitation saved. The server checks it after you reconnect.', 'info');
                    this.closeTeamInviteDialog();
                    return;
                }
                const invited = unwrap(await call('invite_team_member', { email, groupIds }));
                if (this.teamInviteContext !== context) return;
                context.done = true;
                const output = element('teamInviteCode');
                if (output) { output.value = invited?.invitation_code || ''; show('teamInviteCode', true); show('teamInviteCodeLabel', true); output.select?.(); }
                text('teamInviteSubmitBtn', 'Done');
                text('teamInviteSeats', '');
                await this.refreshTeamLicenseStatus?.({ silent: true });
                const access = await this.stageInvitationAccess(invited?.invitation_id, email, groupIds, context.account);
                if (this.currentUser !== context.account) return;
                this.showNotification(`Seat reserved. ${this.invitationAccessText(access)}Copy the invitation code and send it to them securely.`, 'success');
            },

            /**
             * Gives an invited person's existing devices the key of each group this admin administers,
             * kept with the invitation so they get access the moment they accept. Returns one outcome per
             * group: `on_accept`, or `after_signup` when a group admin's app finishes after they join.
             */
            async stageInvitationAccess(invitationId, email, groupIds, account = this.currentUser) {
                const admin = this.adminGroupIds();
                const outcomes = [];
                for (const groupId of groupIds) {
                    if (this.currentUser !== account) break;
                    if (!invitationId || !admin.has(groupId)) { outcomes.push('after_signup'); continue; }
                    try {
                        const result = await this.runDesktopOperation({ kind: 'stage_invitation_access', invitation_id: invitationId, email,
                            group_id: groupId, title: `Prepare ${email}'s access` }, { showDialog: false });
                        outcomes.push(result?.access === 'on_accept' ? 'on_accept' : 'after_signup');
                    } catch (_) { outcomes.push('after_signup'); }
                }
                return outcomes;
            },
            invitationAccessText(outcomes) {
                if (!outcomes.length) return '';
                return outcomes.every(outcome => outcome === 'on_accept') ? 'They get their groups as soon as they accept. '
                    : 'They get their groups after they sign up and accept; a group admin\'s app finishes adding them. ';
            },

            /** Groups this account administers, from the group list; only their admins hold the key to hand out. */
            adminGroupIds() {
                const summaries = this.teamGroupSummaries?.account === this.currentUser ? this.teamGroupSummaries.groups : [];
                return new Set(summaries.filter(group => group?.user_role === 'admin').map(group => group.id));
            },

            /** The minute-by-minute session check also finishes group adds while this admin's app is open. */
            async performSessionHealthCheck(...args) {
                const result = await base.performSessionHealthCheck?.apply(this, args);
                if (result) this.autoFinishGroupAccess({ refresh: true });
                return result;
            },

            /**
             * Finishes the group adds an admin chose earlier, for people who have joined and have a device,
             * in groups this account administers. The invite was the admin's approval, so this runs without
             * asking. Each (member, group) is tried once per page visit; a failure shows Finish with the reason.
             */
            async autoFinishGroupAccess({ refresh = false } = {}) {
                const busy = () => this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status));
                if (this.groupAccessAutoFinishInFlight || !this.isLoggedIn || !this.canOpenMembersView() || !this.teamLicenseStatus?.can_write
                    || this.teamLicenseStatus?.online === false || global.navigator?.onLine === false || global.document?.hidden || busy()) return 0;
                const account = this.currentUser;
                const generation = this.desktopAccountGeneration || 0;
                const current = () => this.currentUser === account && this.isLoggedIn && generation === (this.desktopAccountGeneration || 0);
                const attempts = this.groupAccessAutoFailures ||= new Map();
                this.groupAccessAutoFinishInFlight = true;
                let tried = 0;
                try {
                    if (refresh) {
                        const response = await call('get_team_member_devices');
                        if (!current() || response?.success === false) return 0;
                        this.membersRoster = { account, roster: unwrap(response) };
                    }
                    const roster = this.membersRoster?.account === account ? this.membersRoster.roster : null;
                    const waiting = (Array.isArray(roster?.members) ? roster.members : []).flatMap(member =>
                        (member.devices?.length && Array.isArray(member.pending_groups) ? member.pending_groups : [])
                            .filter(group => group?.id && !attempts.has(`${member.user_id}:${group.id}`))
                            .map(group => ({ member, group })));
                    if (!waiting.length) return 0;
                    await this.loadTeamGroupSummaries();
                    if (!current()) return 0;
                    const admin = this.adminGroupIds();
                    const names = new Map((this.teamGroupSummaries?.groups || []).map(group => [group.id, group.name]));
                    const todo = waiting.filter(({ group }) => admin.has(group.id));
                    for (const { member, group } of todo) {
                        if (!current() || busy()) break;
                        const key = `${member.user_id}:${group.id}`;
                        const name = group.name || names.get(group.id) || 'the group';
                        tried += 1;
                        try {
                            await this.runDesktopOperation({ kind: 'add_member', email: member.email, group_id: group.id,
                                title: `Give ${member.email} access to ${name}` }, { showDialog: false });
                            attempts.set(key, null);
                            if (current()) this.showNotification(`${member.email} now has access to ${name}.`, 'success');
                        } catch (error) {
                            if (!current()) break;
                            attempts.set(key, this.teamErrorText(error));
                        }
                    }
                } catch (_) {
                    // The next pass tries again.
                } finally {
                    if (current()) this.groupAccessAutoFinishInFlight = false;
                }
                if (tried && current()) {
                    if (this.activeWorkspaceView === 'members') await this.refreshMembersCenter();
                    else this.renderSidebarTeamNav();
                }
                return tried;
            },

            /** After joining: which groups opened at once, and which wait for a group admin's app. */
            announceJoinedGroups(result) {
                const joined = Array.isArray(result?.groups_joined) ? result.groups_joined.length : 0;
                const waiting = (Array.isArray(result?.groups_waiting) ? result.groups_waiting : []).map(group => group?.name).filter(Boolean);
                if (joined) this.showNotification(`You have access to ${joined === 1 ? 'your group' : `${joined} groups`} in this Team.`, 'success');
                if (waiting.length) this.showNotification(`An admin of ${waiting.join(', ')} finishes adding you automatically the next time their app is open.`, 'info');
            },

            /** Members with a device get access now; for anyone without one, the server keeps a note for any group admin. */
            async addMemberToGroups(context, groupIds) {
                const member = this.membersRoster?.roster?.members?.find(entry => entry.user_id === context.target.userId);
                const names = new Map((this.teamGroupSummaries?.groups || []).map(group => [group.id, group.name]));
                this.closeTeamInviteDialog();
                for (const groupId of groupIds) {
                    if (this.currentUser !== context.account) return;
                    if (member?.devices?.length) {
                        await this.runTeamTask({ kind: 'add_member', email: context.target.email, group_id: groupId },
                            `Give ${context.target.email} access to ${names.get(groupId) || 'the group'}`);
                    } else {
                        unwrap(await call('add_team_group_grant', { target: 'member', targetId: context.target.userId, groupId }));
                    }
                }
                if (!member?.devices?.length) this.showNotification(`${context.target.email} gets access after their first sign-in, once an admin of each group finishes adding them.`, 'info');
            },

            async finishMemberGroupAccess(button) {
                const { groupId, email, userId } = button.dataset;
                if (!groupId || !email) return;
                this.groupAccessAutoFailures?.delete(`${userId}:${groupId}`);
                button.disabled = true;
                try { await this.runTeamTask({ kind: 'add_member', email, group_id: groupId }, `Give ${email} access`); }
                finally { button.disabled = false; }
                await this.refreshMembersCenter();
            },

            /** Queues the removal (sent now when online), then offers key rotation for their groups once the server accepted it. */
            async removeTeamMember(userId, email) {
                const member = this.membersRoster?.roster?.members?.find(entry => entry.user_id === userId);
                if (!member) return false;
                const groups = member.groups || [];
                const confirmed = await this.showActionPrompt('Remove from Team?',
                    `${email} loses their seat and is taken out of ${groups.length ? groups.map(group => group.name).join(', ') : 'every group'}. `
                    + 'Group keys already on their devices still open files they could open before; rotate each group\'s keys to stop them opening files added from now on.',
                    { primaryLabel: 'Remove from Team', secondaryLabel: 'Cancel' });
                if (confirmed !== true) return false;
                const account = this.currentUser;
                const accepted = await this.sendTeamRequest({ kind: 'remove_member', targetId: userId });
                if (this.currentUser !== account) return false;
                await this.refreshMembersCenter();
                if (!accepted) return false;
                this.showNotification(`${email} was removed from the Team.`, 'success');
                const ownGroups = new Set((this.teamGroupSummaries?.groups || []).map(group => group.id))
                await this.offerKeyRotations(groups.filter(group => ownGroups.has(group.id)), email, account);
                return true;
            },

            async cancelTeamInvitation(invitationId, email) {
                if (!(await this.showConfirmDialog('Cancel invitation?', `${email} will no longer be able to join, and the seat is released.`))) return false;
                const account = this.currentUser;
                const accepted = await this.sendTeamRequest({ kind: 'cancel_invitation', targetId: invitationId });
                if (this.currentUser === account) await this.refreshMembersCenter();
                return accepted;
            },

            /**
             * Saves an organization request in the offline queue and, when online, sends it right away.
             * Returns whether the server accepted it; a queued request shows under "Waiting for the server".
             */
            async sendTeamRequest({ kind, targetId }) {
                try {
                    const entry = unwrap(await call('queue_team_admin_request', { kind, targetId, email: null, groupName: null, description: null }));
                    if (this.teamLicenseStatus?.online === false) {
                        this.showNotification('Saved. The server checks this after you reconnect.', 'info');
                        return false;
                    }
                    const requests = unwrap(await call('sync_team_admin_requests')) || [];
                    const result = requests.find(item => item?.request?.id === entry?.request?.id);
                    // Accepted right away: nothing left to report, so it does not linger in the queue.
                    if (result?.status === 'accepted') await call('dismiss_team_admin_request', { requestId: entry.request.id }).catch(() => {});
                    await this.refreshPendingTeamRequests?.();
                    await this.refreshTeamLicenseStatus?.({ silent: true });
                    if (result?.status === 'rejected') this.showNotification(result.last_error || 'The server refused this change.', 'error');
                    return result?.status === 'accepted';
                } catch (error) {
                    this.showNotification(this.teamErrorText(error), 'error');
                    return false;
                }
            },

            async refreshPeoplePanel() {
                if (this.activeWorkspaceType !== 'team' || !this.workspaceGroupContext?.group_id) {
                    text('adminPeopleList', ''); show('adminPeopleAttention', false); return;
                }
                if (await this.loadPeopleRows()) { this.renderPeopleList(); this.renderSidebarTeamNav(); this.renderTeamOverview(); }
            },

            /** People who need an admin come first; "Needs action" and the search narrow the list without reloading it. */
            renderPeopleList() {
                const list = element('adminPeopleList');
                const cache = this.peopleRowsCache;
                if (!list || !cache || cache.groupId !== this.workspaceGroupContext?.group_id) return;
                const needsAction = row => row.status === 'ready_to_add' || row.inactiveDevices > 0;
                const filter = this.peopleFilter === 'attention' ? 'attention' : 'all';
                for (const button of global.document?.querySelectorAll?.('[data-people-filter]') || []) {
                    const selected = button.dataset.peopleFilter === filter;
                    button.classList.toggle('active', selected);
                    button.setAttribute('aria-pressed', String(selected));
                }
                const query = String(element('adminPeopleSearch')?.value || '').trim().toLowerCase();
                const rows = cache.rows.filter(row => (filter === 'all' || needsAction(row)) && (!query || row.email.includes(query)));
                const canManage = this.workspaceUiModel().canAdministerGroup;
                const labels = { add: 'Give access', remove: 'Remove access', cancel_invite: 'Cancel invitation' };
                list.innerHTML = rows.length ? rows.map(row => `<div class="people-row" data-status="${row.status}">`
                    + `<span class="people-avatar" aria-hidden="true">${this.escapeHtml(row.email.charAt(0).toUpperCase())}</span>`
                    + `<div class="people-row-main"><span class="people-row-email">${this.escapeHtml(row.email)}</span>`
                    + `<span class="people-row-status">${this.escapeHtml(row.label)}</span>`
                    + (row.devicesLabel ? `<span class="people-row-devices${row.inactiveDevices ? ' has-inactive' : ''}">${this.escapeHtml(row.devicesLabel)}</span>` : '')
                    + '</div>'
                    + (canManage && row.action ? `<button type="button" class="btn ${row.status === 'ready_to_add' ? 'btn-primary' : 'btn-secondary'} btn-small"`
                        + ` data-people-action="${row.action}" data-email="${this.escapeHtmlAttr(row.email)}"`
                        + ` data-user-id="${this.escapeHtmlAttr(row.userId || '')}" data-invitation-id="${this.escapeHtmlAttr(row.invitationId || '')}">${labels[row.action]}</button>` : '')
                    + '</div>').join('')
                    : cache.rows.length ? '<div class="people-empty">No one here matches.</div>'
                        : '<div class="people-empty">Only you can open this group. Use Add person to share it.</div>';
                const ready = cache.rows.filter(row => row.status === 'ready_to_add').length;
                // Devices their owner can set up aren't the admin's to approve.
                const devices = global.HybridCipherUiUtils?.adminDeviceReminders?.({ pendingDevices: this.pendingDevicesCache }).pending.length
                    ?? (Array.isArray(this.pendingDevicesCache) ? this.pendingDevicesCache.length : 0);
                const notes = [];
                if (ready) notes.push(`${ready === 1 ? '1 person has' : `${ready} people have`} joined and ${ready === 1 ? 'is' : 'are'} waiting for access.`);
                if (devices) notes.push(`${devices === 1 ? '1 device is' : `${devices} devices are`} waiting for approval in Devices.`);
                text('adminPeopleAttention', notes.join(' ')); show('adminPeopleAttention', notes.length > 0);
                text('adminTabPeopleBadge', ready ? String(ready) : ''); show('adminTabPeopleBadge', ready > 0);
                text('adminPeopleNote', cache.online ? 'Who can open this group, and who is still joining.'
                    : 'Saved list. Connect to the server to make changes.');
            },

            teamGroupSummary(groupId) {
                const summaries = this.teamGroupSummaries;
                if (!groupId || summaries?.account !== this.currentUser) return null;
                return summaries.groups.find(group => String(group?.id) === String(groupId)) || null;
            },

            /** People and key versions for the group cards and the group page; reused for a minute. */
            async loadTeamGroupSummaries({ force = false } = {}) {
                const account = this.currentUser;
                const cached = this.teamGroupSummaries;
                if (!force && cached?.account === account && Date.now() - cached.loadedAt < 60000) return cached;
                try {
                    const groups = unwrap(await call('get_group_summaries'));
                    if (this.currentUser !== account || !Array.isArray(groups)) return null;
                    this.teamGroupSummaries = { account, groups, loadedAt: Date.now() };
                    return this.teamGroupSummaries;
                } catch (_) { return null; }
            },

            /** What waits on an admin in the selected group, for the overview list and the sidebar count. */
            teamTodoItems(model = this.workspaceUiModel()) {
                if (!this.teamNavigationVisible() || !model.canAdminister || !model.resolved) return [];
                const people = this.peopleRowsCache?.groupId === this.workspaceGroupContext?.group_id ? this.peopleRowsCache.rows : [];
                return global.HybridCipherUiUtils?.buildTeamTodoItems?.({ groupName: this.workspaceGroupContext?.name || 'This group', people,
                    pendingDevices: this.pendingDevicesCache, unverifiedDevices: this.unverifiedDevicesCache,
                    staleDevices: this.staleDevicesCache }) || [];
            },

            /** Team Home: admins see what waits on them, then the groups; members see the groups they belong to. */
            renderTeamOverview(model = this.workspaceUiModel()) {
                const team = this.teamNavigationVisible();
                show('teamOverview', team);
                if (!team) return;
                const admin = model.canAdminister && model.resolved;
                show('teamTodoPanel', admin);
                if (admin) {
                    const items = this.teamTodoItems(model);
                    text('teamTodoCount', items.length ? String(items.length) : '');
                    text('teamTodoNote', `Waiting on you in ${this.workspaceGroupContext?.name || 'the selected group'}.`);
                    const list = element('teamTodoList');
                    setMarkup(list, items.length ? items.map(item => `<li class="team-todo-item" data-kind="${item.kind}">`
                        + `<div class="team-todo-copy"><span class="team-todo-title">${this.escapeHtml(item.title)}</span>`
                        + `<span class="team-todo-detail">${this.escapeHtml(item.detail)}</span></div>`
                        + `<button type="button" class="btn ${item.kind === 'stale' ? 'btn-secondary' : 'btn-primary'} btn-small"`
                        + ` data-todo-action="${item.action}" data-device-id="${this.escapeHtmlAttr(item.deviceId || '')}"`
                        + ` data-email="${this.escapeHtmlAttr(item.email || '')}">${this.escapeHtml(item.actionLabel)}</button></li>`).join('')
                        : '<li class="team-todo-empty">Nothing is waiting on you here.</li>');
                }
                text('teamGroupsTitle', model.canAdminister ? 'Groups' : 'Your groups');
                text('teamGroupsNote', model.canAdminister ? 'Open a group to manage its people, devices and keys.'
                    : 'Need access to another group? Ask a Team admin.');
                show('homeNewGroupBtn', model.canCreate);
                const cards = element('teamGroupCards');
                if (!cards) return;
                const context = this.workspaceGroupContext;
                const groups = model.hasGroupContext && Array.isArray(context?.groups) ? context.groups : [];
                const items = global.HybridCipherUiUtils?.buildTeamGroupCards?.({ groups, activeGroupId: context?.group_id,
                    summaries: this.teamGroupSummaries?.account === this.currentUser ? this.teamGroupSummaries.groups : [],
                    attentionCount: admin ? this.teamTodoItems(model).length : 0, showKeyVersion: model.canAdminister }) || [];
                setMarkup(cards, items.length ? items.map(card => '<li>'
                    + `<button type="button" class="team-group-card${card.selected ? ' selected' : ''}" data-group-id="${this.escapeHtmlAttr(card.id)}"`
                    + `${card.selected ? ' aria-current="true"' : ''}>`
                    + `<span class="group-mark" data-tone="${card.tone}" aria-hidden="true">${this.escapeHtml(card.initial)}</span>`
                    + `<span class="team-group-card-copy"><span class="team-group-card-name">${this.escapeHtml(card.name)}</span>`
                    + (card.facts ? `<span class="team-group-card-facts">${this.escapeHtml(card.facts)}</span>` : '') + '</span>'
                    + (card.status ? `<span class="team-group-card-status">${this.escapeHtml(card.status)}</span>` : '')
                    + '</button></li>').join('')
                    : '<li class="team-group-empty">No groups yet.</li>');
            },

            /** Loads what the Team overview shows. Every read is optional; whatever arrives is rendered. */
            async refreshTeamOverview() {
                if (!this.teamNavigationVisible()) return;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                const model = this.workspaceUiModel();
                const reads = [this.loadTeamGroupSummaries()];
                if (model.canAdminister && model.resolved) reads.push(this.refreshOperationsQueues?.(), this.loadPeopleRows());
                await Promise.allSettled(reads);
                if (this.currentUser !== account || this.workspaceSwitchSequence !== sequence) return;
                this.updateWorkspaceLabels();
            },

            /** A Team overview to-do acts on the selected group directly, or opens the tab that can. */
            async handleTeamTodoAction(button) {
                const { todoAction: action, deviceId, email } = button.dataset;
                if (button.disabled || !this.workspaceUiModel().canAdminister) return;
                button.disabled = true;
                try {
                    if (action === 'give_access' && email) await this.runTeamTask({ kind: 'add_member', email }, `Give ${email} access`);
                    else if (action === 'approve_device' && deviceId) {
                        const device = (this.pendingDevicesCache || []).find(entry => entry.device_id === deviceId);
                        if (device && this.giveDeviceAccess) await this.giveDeviceAccess(device);
                        else await this.issueWelcomeForDevice?.(deviceId);
                    }
                    else if (action === 'verify_device') {
                        const device = (this.unverifiedDevicesCache || []).find(entry => entry.device_id === deviceId);
                        if (device) this.verifyUnverifiedDevice?.(device);
                    } else if (action === 'review_stale') {
                        this.showStaleDevicesQueue?.();
                        this.openAdminTab('devices');
                    }
                } finally { button.disabled = false; }
                if (this.activeWorkspaceView === 'home') this.refreshTeamOverview();
            },

            async handlePeopleAction(button) {
                const { peopleAction: action, email, userId, invitationId } = button.dataset;
                if (!this.workspaceUiModel().canAdministerGroup || button.disabled) return;
                button.disabled = true;
                try {
                    if (action === 'add') await this.runTeamTask({ kind: 'add_member', email }, `Give ${email} access`);
                    else if (action === 'remove') await this.confirmMemberRemoval({ user_id: userId, email });
                    else if (action === 'cancel_invite') {
                        if (!(await this.showConfirmDialog('Cancel invitation?', `${email} will no longer be able to join, and the seat is released.`))) return;
                        await call('queue_team_admin_request', { kind: 'cancel_invitation', targetId: invitationId, email: null, groupName: null, description: null });
                        await this.refreshPendingTeamRequests(Boolean(this.teamLicenseStatus?.online));
                        await this.refreshPeoplePanel();
                    }
                } catch (error) { this.showNotification(this.teamErrorText(error), 'error'); }
                finally { button.disabled = false; }
            },

            /** Removing someone rotates the group keys in the same action unless the admin opts out. */
            async confirmMemberRemoval(member) {
                const label = member?.email || member?.user_id;
                if (!label || !this.workspaceUiModel().canAdministerGroup) return false;
                const confirmed = await this.showActionPrompt('Remove access?',
                    `${label} will lose access to this group. The group keys are rotated too, so they cannot open files added from now on.`,
                    { primaryLabel: 'Remove access', secondaryLabel: 'Cancel' });
                if (confirmed !== true) return false;
                const review = await this.reviewRotationSkipsWithProgress({ excludeMember: member.user_id || member.email });
                if (!review.proceed) return false;
                const result = await this.runTeamTask({ kind: 'remove_access', member: member.user_id || member.email, rotate_keys: true,
                    skip_unreachable: review.skipUnreachable }, `Remove ${label}`);
                if (result) this.refreshAfterRotation();
                return Boolean(result);
            },

            /** Shows invitations addressed to this account so people can join without an invitation code. */
            async refreshTeamInvitations(status = this.teamLicenseStatus) {
                const account = this.currentUser;
                if (!this.isLoggedIn || status?.workspace === 'team' || this.teamActivationInProgress) {
                    this.teamInvitationOffer = null; show('teamInvitationNotice', false); return;
                }
                try {
                    const invitations = unwrap(await call('list_my_team_invitations')) || [];
                    if (this.currentUser !== account) return;
                    const offer = invitations.find(invite => !this.dismissedTeamInvitations?.has(invite.id)) || null;
                    this.teamInvitationOffer = offer;
                    if (offer) text('teamInvitationMessage', `${offer.invited_by || 'A Team owner'} invited you to join ${offer.organization_name}.`);
                    show('teamInvitationNotice', Boolean(offer));
                } catch (_) { if (this.currentUser === account) show('teamInvitationNotice', false); }
            },

            async joinInvitedTeam() {
                const offer = this.teamInvitationOffer;
                if (!offer || this.teamActivationInProgress) return;
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const attempt = Symbol('team-invitation'); this.teamActivationAttempt = attempt;
                this.teamActivationInProgress = true;
                element('teamInvitationJoinBtn')?.toggleAttribute('disabled', true);
                try {
                    const accepted = unwrap(await call('accept_my_team_invitation', { invitationId: offer.id, expectedAccountEmail: account, expectedDeviceId: device }));
                    if (this.currentUser !== account || generation !== (this.desktopAccountGeneration || 0) || this.teamActivationAttempt !== attempt) return;
                    this.teamInvitationOffer = null; show('teamInvitationNotice', false);
                    const status = unwrap(await call('get_team_license_status', { expectedAccountEmail: account, expectedDeviceId: device }));
                    await this.finishTeamActivation(status, account, generation, attempt);
                    if (this.currentUser === account) this.announceJoinedGroups(accepted);
                } catch (error) {
                    if (this.currentUser === account) this.showNotification(`Could not join Team: ${error.message || error}`, 'error');
                } finally {
                    if (this.currentUser === account && generation === (this.desktopAccountGeneration || 0)) this.teamActivationInProgress = false;
                    element('teamInvitationJoinBtn')?.toggleAttribute('disabled', false);
                }
            },

            async addEnrolledFolder(...args) {
                if (this.folderEnrollmentInFlight || !this.isLoggedIn) return;
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) {
                    this.showNotification('Complete the current operation before adding a protected folder.', 'warning'); return;
                }
                const account = this.currentUser;
                const device = this.currentDeviceId;
                const generation = this.desktopAccountGeneration || 0;
                const workspace = this.activeWorkspaceType;
                if (workspace === 'personal') {
                    // Clicking a Personal action is an explicit workspace choice. A late
                    // entitlement response must not replace it with the default Team choice.
                    this.workspaceChoiceLoaded = true;
                    global.localStorage.setItem(this.workspacePreferenceKey(), 'personal');
                }
                const token = Symbol('folder-enrollment'); this.folderEnrollmentInFlight = token;
                this.applyAppMode();
                try {
                    const selectionScope = { sequence: this.workspaceSwitchSequence };
                    let ready = true;
                    if (workspace === 'personal') {
                        ready = await this.ensurePersonalWorkspaceReady({ manual: true, selectionScope });
                    }
                    if (!this.isLoggedIn || this.currentUser !== account || this.currentDeviceId !== device
                        || (this.desktopAccountGeneration || 0) !== generation || this.activeWorkspaceType !== workspace
                        || this.workspaceSwitchSequence !== selectionScope.sequence) return;
                    if (!ready || !this.workspaceUiModel().canWrite) {
                        this.showNotification(workspace === 'personal' ? this.personalEnrollmentBlockingReason()
                            : this.teamEnrollmentBlockingReason(), 'warning');
                        return;
                    }
                    return await base.addEnrolledFolder.apply(this, args);
                } finally {
                    if (this.folderEnrollmentInFlight === token) { this.folderEnrollmentInFlight = null; this.applyAppMode(); }
                }
            },

            async loadEnrolledFolders(options = {}) {
                if (!this.workspaceContextReady) { this.enrolledFolders = []; this.renderFolderList(); return; }
                return base.loadEnrolledFolders.call(this, options);
            },
            refreshAdminDashboard() {
                if (!this.workspaceContextReady) return undefined;
                // The People list is loaded only while the group page is on screen.
                if (this.adminPanelVisible) {
                    this.refreshPeoplePanel().catch(() => {});
                    this.loadTeamGroupSummaries().then(() => this.updateWorkspaceLabels()).catch(() => {});
                }
                return base.refreshAdminDashboard.call(this);
            },
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

            /** Makes another Team group the selected one. Resolves true once that group is loaded. */
            async switchTeamGroup(groupId) {
                if (this.activeWorkspaceType !== 'team' || !groupId || this.groupSwitchInProgress) return false;
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                this.groupSwitchInProgress = true;
                try {
                    // A quick switch runs without the operation dialog; a failure stays in Activity with its retry.
                    await this.runDesktopOperation({ kind: 'switch_group', group_id: groupId, title: 'Switch group' }, { showDialog: false });
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence) return false;
                    return await this.selectWorkspaceType(this.activeWorkspaceType, { forceGroupId: groupId });
                } catch (error) {
                    if (this.currentUser === account) this.showNotification(`Could not open that group: ${this.teamErrorText(error)}`, 'warning');
                    return false;
                } finally { if (this.currentUser === account) this.groupSwitchInProgress = false; }
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
                this.desktopOperationContext = { account, generation, sequence: this.workspaceSwitchSequence,
                    workspace: this.activeWorkspaceType, groupId: this.workspaceGroupContext?.group_id || null };
                this.desktopOperationAcknowledgedId = null;
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
                if (showDialog && !this.desktopOperationDialogOpen()) this.notifyBackgroundOperation(snapshot);
                if (snapshot.status !== 'succeeded') {
                    const error = new Error(snapshot.error?.message || (snapshot.status === 'cancelled' ? 'Operation cancelled.' : 'Operation failed.'));
                    error.code = snapshot.error?.code; error.group_id = snapshot.group_id;
                    throw error;
                }
                return snapshot.result || {};
            },

            desktopOperationDialogOpen() {
                return element('desktopOperationModal')?.style.display === 'flex';
            },
            /** An operation the user sent to the background says how it ended. */
            notifyBackgroundOperation(snapshot) {
                const title = this.desktopOperationTitle || 'Operation';
                if (snapshot.status === 'succeeded') {
                    const summary = global.HybridCipherUiUtils?.describeTeamTaskResult?.(snapshot.result) || [];
                    const moved = summary.find(line => /^Moved \d/.test(line));
                    this.showNotification?.(`${title} finished${moved ? ` · ${moved}` : '.'}`, 'success');
                } else if (snapshot.status === 'failed') {
                    this.showNotification?.(`${title} failed: ${snapshot.error?.message || 'see Activity'}`, 'error');
                }
            },
            desktopOperationContextIsCurrent() {
                const scope = this.desktopOperationContext;
                return Boolean(scope && this.isLoggedIn && scope.account === this.currentUser
                    && scope.generation === (this.desktopAccountGeneration || 0) && scope.sequence === this.workspaceSwitchSequence
                    && scope.workspace === this.activeWorkspaceType && scope.groupId === (this.workspaceGroupContext?.group_id || null));
            },
            clearFinishedDesktopOperation() {
                if (this.desktopOperationStarting || (this.desktopOperation && !finished.has(this.desktopOperation.status))) return false;
                this.desktopOperation = null; this.desktopOperationRequest = null; this.desktopOperationContext = null;
                this.desktopOperationAcknowledgedId = null; this.desktopOperationTitle = null; this.desktopInputRequestId = null;
                for (const id of ['desktopOperationOutput', 'desktopOperationError', 'desktopOperationInputLabel', 'desktopOperationSummary']) text(id, '');
                for (const id of ['desktopOperationRetryBtn', 'desktopOperationInputForm', 'desktopOperationChooseFileBtn',
                    'desktopOperationDetails', 'desktopOperationSummary', 'desktopOperationError', 'desktopOperationProgress',
                    'desktopOperationBackgroundNote']) show(id, false);
                this.updateDesktopActivityVisibility();
                return true;
            },
            updateDesktopActivityVisibility() {
                const operation = this.desktopOperation;
                const visible = this.activeWorkspaceType === 'team' && this.teamLicenseStatus?.workspace === 'team'
                    && this.desktopOperationContextIsCurrent() && operation
                    && (!finished.has(operation.status) || operation.status === 'failed' || this.desktopOperationAcknowledgedId !== operation.id);
                show('desktopOperationsBtn', Boolean(visible));
                // While it runs, Activity says what it is doing (and how far), so a background move shows.
                const running = Boolean(visible) && !finished.has(operation.status);
                const percent = Number.isFinite(operation?.progress) ? ` ${Math.round(operation.progress)}%` : '';
                const label = element('desktopOperationsBtn')?.querySelector?.('.btn-label');
                if (label) label.textContent = running ? `${operation.phase || 'Working…'}${percent}` : 'Activity';
            },
            canRetryDesktopOperation() {
                return Boolean(this.desktopOperationContextIsCurrent() && this.desktopOperation?.status === 'failed'
                    && retryableKinds.has(this.desktopOperationRequest?.kind) && recoverableError(this.desktopOperation.error)
                    && !this.desktopOperationStarting && (this.desktopOperationRequest.kind !== 'team_setup' || this.canPrepareTeamWorkspace()));
            },
            openDesktopOperation() {
                if (!this.desktopOperation || !this.desktopOperationContextIsCurrent()) return;
                showModal('desktopOperationModal', true); this.renderDesktopOperation();
            },
            closeDesktopOperation({ acknowledge = true } = {}) {
                showModal('desktopOperationModal', false);
                if (element('desktopOperationInput')) element('desktopOperationInput').value = '';
                if (acknowledge && ['succeeded', 'cancelled'].includes(this.desktopOperation?.status))
                    this.desktopOperationAcknowledgedId = this.desktopOperation.id;
                this.updateDesktopActivityVisibility();
            },
            renderDesktopOperation() {
                const operation = this.desktopOperation;
                if (!operation) return;
                this.updateDesktopActivityVisibility();
                if (!this.desktopOperationContextIsCurrent()) return;
                text('desktopOperationTitle', this.desktopOperationTitle);
                text('desktopOperationPhase', operation.phase || (operation.status === 'succeeded' ? 'Complete' : 'Working…'));
                text('desktopOperationError', operation.error?.message);
                show('desktopOperationError', Boolean(operation.error));
                const progress = element('desktopOperationProgress');
                if (progress) { if (Number.isFinite(operation.progress)) { progress.max = 100; progress.value = operation.progress; } else progress.removeAttribute('value'); }
                show('desktopOperationProgress', !finished.has(operation.status));
                show('desktopOperationBackgroundNote', !finished.has(operation.status));
                text('desktopOperationCloseBtn', finished.has(operation.status) ? 'Close' : 'Continue in background');
                const details = Array.isArray(operation.output) ? operation.output.join('\n') : '';
                text('desktopOperationOutput', details); show('desktopOperationDetails', Boolean(details));
                // Results read as plain sentences; the CLI transcript stays under "Technical details".
                const utils = global.HybridCipherUiUtils;
                const taskSummary = operation.status === 'succeeded' ? (utils?.describeTeamTaskResult?.(operation.result) || []) : [];
                const summary = operation.status === 'succeeded'
                    ? (taskSummary.length ? taskSummary : (utils?.summarizeOperationOutput?.(operation.output) || [])) : [];
                const summaryList = element('desktopOperationSummary');
                if (typeof summaryList?.replaceChildren === 'function') summaryList.replaceChildren(...summary.map(line => {
                    const item = global.document.createElement('li'); item.textContent = line; return item;
                }));
                show('desktopOperationSummary', summary.length > 0);
                show('desktopOperationRetryBtn', this.canRetryDesktopOperation());
                const inputRequest = operation.status === 'needs_input' ? operation.input_request : null;
                show('desktopOperationInputForm', Boolean(inputRequest));
                show('desktopOperationChooseFileBtn', inputRequest?.kind === 'file');
                if (!inputRequest) {
                    this.desktopInputRequestId = null;
                    if (element('desktopOperationInput')) element('desktopOperationInput').value = '';
                }
                if (inputRequest && this.desktopInputRequestId !== inputRequest.id) {
                    this.desktopInputRequestId = inputRequest.id;
                    const input = element('desktopOperationInput');
                    text('desktopOperationInputLabel', inputRequest.message);
                    text('desktopOperationContinueBtn', inputRequest.kind === 'confirm' ? 'Confirm' : 'Continue');
                    if (input) { input.type = inputRequest.kind === 'password' ? 'password' : 'text'; input.value = inputRequest.default_value || ''; input.hidden = inputRequest.kind === 'confirm'; input.focus(); }
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
                if (!inputRequest || operation.status !== 'needs_input' || !this.desktopOperationContextIsCurrent()) return;
                const input = element('desktopOperationInput');
                const value = decline ? null : inputRequest.kind === 'confirm' ? 'true' : input?.value || '';
                if (input) input.value = '';
                element('desktopOperationContinueBtn')?.toggleAttribute('disabled', true);
                try {
                    const snapshot = unwrap(await call('answer_desktop_operation', { operationId: operation.id, answer: { request_id: inputRequest.id, value } }));
                    if (this.currentUser !== account || this.desktopOperation?.id !== operation.id || !this.desktopOperationContextIsCurrent()) return;
                    this.desktopOperation = snapshot; this.renderDesktopOperation();
                }
                catch (error) { if (this.currentUser === account) { text('desktopOperationError', error.message || String(error)); show('desktopOperationError', true); } }
                finally { if (this.currentUser === account) element('desktopOperationContinueBtn')?.toggleAttribute('disabled', false); }
            },
            async retryDesktopOperation() {
                if (!this.canRetryDesktopOperation()) return false;
                const previous = this.desktopOperation;
                const scope = this.desktopOperationContext;
                const request = previous?.group_id && this.desktopOperationRequest?.kind === 'create_group'
                    ? { kind: 'initialize_group', group_id: previous.group_id, title: 'Initialize group' } : this.desktopOperationRequest;
                if (!request) return;
                try {
                    await this.runDesktopOperation(request);
                    if (this.currentUser !== scope.account || scope.generation !== (this.desktopAccountGeneration || 0)
                        || scope.sequence !== this.workspaceSwitchSequence || scope.workspace !== this.activeWorkspaceType) return false;
                    await this.selectWorkspaceType(this.activeWorkspaceType, { forceGroupId: request.group_id || null });
                    return true;
                }
                catch (_) { /* Retained in the operation dialog. */ }
            },

            async runSettingsCliCommand(command, options = {}) {
                const args = this.parseGeneratedCliArgs(command);
                if (args[0] === 'recovery' && args[1] === 'fetch' && !args.includes('-h') && !args.includes('--help') && !command.includes(' && ')) {
                    if (!this.isLoggedIn || typeof this.openRecoveryAutoBackupModal !== 'function') return false;
                    if (options.closeSettingsModal !== false) this.closeSettingsModal();
                    this.openRecoveryAutoBackupModal();
                    return true;
                }
                if (this.sessionPersistent === false) {
                    this.showNotification('This action requires a persistent login. Turn on Remember me and sign in again.', 'warning'); return false;
                }
                const account = this.currentUser;
                const sequence = this.workspaceSwitchSequence;
                if (options.confirmTitle && !(await this.showConfirmDialog(options.confirmTitle, options.confirmMessage))) return false;
                if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                if (command.includes(' && ')) throw new Error('This action requires a typed operation.');
                const context = this.workspaceGroupContext;
                const exempt = ['server-trust', 'list-groups', 'current-user', 'keystore-status'];
                const completesSetup = args[0] === 'process-welcome-messages';
                const changesDeviceTrust = args[0] === 'issue-welcome' || (args[0] === 'pin' && args[1] === 'verify');
                const model = this.workspaceUiModel();
                if (!args.includes('-h') && !args.includes('--help') && !exempt.includes(args[0])
                    && !(completesSetup ? model.hasGroupContext : model.resolved)) {
                    this.showNotification('Select a ready group in this workspace before continuing.', 'warning'); return false;
                }
                try {
                    if (options.closeSettingsModal !== false) this.closeSettingsModal();
                    await this.runDesktopOperation({ kind: 'cli', args, group_id: args.includes('-h') || args.includes('--help') ? null : context?.group_id || null, title: options.title || this.cliActionTitle(args) });
                    if (this.currentUser !== account || sequence !== this.workspaceSwitchSequence || !this.isLoggedIn) return false;
                    if ((completesSetup || changesDeviceTrust) && !(await this.reconcileWorkspaceState())) return false;
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
                showModal('workspaceSelectionModal', true); select.focus();
                return new Promise(resolve => {
                    let settled = false;
                    const finish = value => {
                        if (settled) return;
                        settled = true;
                        showModal('workspaceSelectionModal', false); select.innerHTML = '';
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
                const labels = { 'add-member': 'Add member', 'remove-member': 'Remove member', 'verify-membership': 'Check membership proof',
                    'process-welcome-messages': 'Complete device setup', 'pending-devices': 'Devices waiting for approval', coverage: 'Protection coverage',
                    rekey: 'Rotate group keys', 'server-trust': 'Server identity', pin: 'Pinned device keys', recovery: 'Recovery backup',
                    'rename-group': 'Rename group', 'delete-group': 'Delete group', 'audit-devices': 'Device check' };
                return labels[args[0]] || 'Workspace operation';
            },

            /**
             * One continuous flow: confirm, check devices (with a progress window, so the app never
             * looks stuck), then a single operation that rotates the key, puts this computer on it
             * and moves its files with a progress bar. That operation can continue in the background.
             */
            async beginRekeyFlow({ title, message }) {
                const confirmed = await this.showActionPrompt(title, message, { primaryLabel: 'Rotate keys', secondaryLabel: 'Not now' });
                if (confirmed !== true) return;
                const review = await this.reviewRotationSkipsWithProgress();
                if (!review.proceed) return;
                const result = await this.runTeamTask({ kind: 'rotate_keys', skip_unreachable: review.skipUnreachable }, 'Rotate group keys');
                if (result) this.refreshAfterRotation();
            },

            /** The device check before a rotation, with a progress window until its dialog (if any) opens. */
            async reviewRotationSkipsWithProgress(options = {}) {
                this.showActionProgressModal?.('Checking devices before rotating…');
                try {
                    return await this.reviewRotationSkips({ ...options, beforeDialog: () => this.hideActionProgressModal?.() });
                } finally {
                    this.hideActionProgressModal?.();
                }
            },

            /** The rotation operation already moved this computer's files; refresh what shows them. */
            refreshAfterRotation() {
                this.refreshAdminKeyVersionsSummary?.();
                this.refreshLeftoverKeyFiles?.();
            },

            /**
             * Before a rotation, lets the admin remove or knowingly skip inactive devices
             * instead of the rotation failing on them. Resolves `{ proceed, skipUnreachable }`.
             */
            async reviewRotationSkips({ excludeMember = null, beforeDialog = null } = {}) {
                const leaving = String(excludeMember || '').trim().toLowerCase();
                // The member being removed loses group access anyway.
                const staying = device => !leaving || ![device.user_id, device.email].some(value => String(value || '').toLowerCase() === leaving);
                const load = async () => {
                    const inactive = (unwrap(await call('get_stale_devices')) || []).filter(staying);
                    // The rotation's own checks also find devices this computer has not verified,
                    // which the server cannot know about.
                    const checked = ((await this.loadRotationPreflight()) || [])
                        .filter(staying)
                        .filter(device => !inactive.some(entry => entry.device_id === device.device_id))
                        .map(device => ({ ...device, rotation_check: true }));
                    return [...inactive, ...checked];
                };
                let devices;
                try { devices = await load(); } catch (_) {
                    // Without the audit the rotation still runs its own device checks and reports them.
                    return { proceed: true, skipUnreachable: false };
                }
                if (!devices.length) return { proceed: true, skipUnreachable: false };
                beforeDialog?.();
                const remaining = await this.showRotationSkipDialog(devices, load);
                if (remaining === null) return { proceed: false, skipUnreachable: false };
                return { proceed: true, skipUnreachable: remaining > 0 };
            },

            /**
             * Devices a rotation from this computer would stop on (`rekey preflight`), or null when
             * the check is unavailable; the rotation itself still checks and names them.
             */
            async loadRotationPreflight() {
                if (typeof this.runBundledCliArgs !== 'function') return null;
                try {
                    const data = await this.runBundledCliArgs(['rekey', 'preflight', '--json', '--no-color']);
                    const line = String(data?.stdout || '').split(/\r?\n/).reverse().find(text => text.trim().startsWith('{'));
                    const devices = line ? JSON.parse(line).devices : null;
                    return Array.isArray(devices) ? devices : null;
                } catch (_) {
                    return null;
                }
            },

            /** A device the rotation check found: what is wrong, and Verify now when this computer has not verified it. */
            buildRotationCheckRow(device, { onVerified = null } = {}) {
                const row = global.document.createElement('div');
                row.className = 'queue-device-row queue-device-row-stale';
                const name = device.device_name || device.device_id;
                const identity = [device.device_name ? device.device_id : '', device.email || 'Unknown member'].filter(Boolean).join(' · ');
                const notVerified = device.reason_code === 'not_verified_here';
                // A skipped device is repaired by its owner's other device; only one whose owner has
                // none shows up in the admin's to-do afterwards.
                const hint = notVerified
                    ? "Verify it here (compare its fingerprint with its owner) so it gets the new key now, or rotate without it: its owner's other device sends it the key, and it appears in your to-do only if they have none."
                    : 'Rotating without it skips this device; it catches up once the problem is fixed and it is approved.';
                row.innerHTML = `
                    <div class="queue-device-info">
                        <div class="queue-device-user">${this.escapeHtml(name)}</div>
                        <div class="queue-device-id">${this.escapeHtml(identity)}</div>
                        <div class="queue-device-reason">${this.escapeHtml(device.reason || '')}</div>
                        <div class="queue-device-hint">${this.escapeHtml(hint)}</div>
                    </div>
                `;
                if (notVerified && typeof this.openAdminPinVerifyModal === 'function') {
                    const button = global.document.createElement('button');
                    button.className = 'btn btn-secondary btn-small';
                    button.type = 'button';
                    button.textContent = 'Verify now';
                    button.addEventListener('click', () => this.openAdminPinVerifyModal({
                        userId: device.user_id, deviceId: device.device_id, onVerified,
                    }));
                    row.appendChild(button);
                }
                return row;
            },

            /** Resolves with the number of devices still listed when the admin continues, or null on cancel. */
            showRotationSkipDialog(devices, reload) {
                return new Promise(resolve => {
                    let current = devices;
                    const render = () => {
                        const list = element('rotationSkipList');
                        if (list) {
                            list.innerHTML = '';
                            current.forEach(device => list.appendChild(device.rotation_check
                                ? this.buildRotationCheckRow(device, { onVerified: refresh })
                                : this.buildStaleDeviceRow(device, { onRemoved: refresh })));
                        }
                        text('rotationSkipSummary', current.length
                            ? `${current.length === 1 ? "1 device can't" : `${current.length} devices can't`} get the new key from this computer right now.`
                            : 'Nothing listed blocks the rotation any more. Every remaining device gets the new key.');
                        text('confirmRotationSkipBtn', current.length ? 'Rotate without them' : 'Rotate keys');
                    };
                    const refresh = async () => {
                        try { current = await reload(); } catch (_) { /* Keep the last known list. */ }
                        render();
                    };
                    const controls = ['confirmRotationSkipBtn', 'cancelRotationSkipBtn', 'closeRotationSkipModalBtn', 'rotationSkipBackdrop'];
                    const handlers = [];
                    const finish = value => {
                        controls.forEach((id, index) => element(id)?.removeEventListener('click', handlers[index]));
                        showModal('rotationSkipModal', false);
                        resolve(value);
                    };
                    controls.forEach((id, index) => {
                        handlers[index] = () => finish(index === 0 ? current.length : null);
                        element(id)?.addEventListener('click', handlers[index]);
                    });
                    render();
                    showModal('rotationSkipModal', true);
                });
            },

            clearTeamUiState() {
                this.cancelWorkspaceSelection?.();
                this.currentDeviceTrust = null;
                this.currentDeviceFingerprint = null;
                this.missingKeyNotifiedRootIds = null;
                this.desktopAccountGeneration = (this.desktopAccountGeneration || 0) + 1;
                this.savedCodeRecoveryAttempt = (this.savedCodeRecoveryAttempt || 0) + 1;
                this.savedCodeRecoveryInFlight = false;
                this.savedCodeRecoveryCompletionInFlight = null;
                this.closeRecoveryAutoBackupModal?.();
                this.workspaceSwitchSequence = (this.workspaceSwitchSequence || 0) + 1;
                this.desktopOperationStarting = false; this.addMemberDialogContext = null;
                this.teamInvitationOffer = null; this.dismissedTeamInvitations = null; show('teamInvitationNotice', false);
                text('adminPeopleList', ''); show('adminPeopleAttention', false);
                this.membersRoster = null; this.membersError = null; this.membersLoading = false;
                this.membersUnsupported = false; this.membersExpanded = null; this.membersRevokeInFlight = null;
                this.groupAccessAutoFailures = null; this.groupAccessAutoFinishInFlight = false;
                text('membersList', ''); text('membersSummary', '');
                this.desktopOperation = null; this.desktopOperationRequest = null; this.desktopInputRequestId = null;
                this.desktopOperationContext = null; this.desktopOperationAcknowledgedId = null;
                this.workspaceGroupContext = null; this.workspaceContextReady = false; this.teamDirectoryRole = null;
                this.personalWorkspaceRefresh = null; this.personalWorkspaceError = null; this.teamLicenseRefresh = null; this.folderEnrollmentInFlight = null;
                this.personalWorkspaceSnapshot = null; this.personalRepairInFlight = null;
                this.workspaceWelcomeAcquisitionAttempts = null;
                this.teamSetupInProgress = false; this.teamSetupMessage = ''; this.teamSetupErrorCode = null; this.teamSetupError = null;
                this.teamSetupCompletedOrganizationId = null; this.teamSetupAttemptedOrganizationId = null;
                this.stopWorkspaceReadinessPolling(); this.closeTeamActivationModal();
                this.workspaceStatusRefreshInFlight = false; this.workspaceStatusRefreshToken = null; this.workspaceReconnectRefreshInFlight = null;
                this.createdGroupPendingId = null; this.groupCreationInProgress = false; this.groupSwitchInProgress = false; this.teamActivationInProgress = false;
                this.closeDesktopOperation(); show('desktopOperationsBtn', false);
                for (const id of ['teamUnlockCode', 'teamInvitationCode', 'teamInviteEmail', 'desktopOperationInput', 'createGroupName', 'createGroupDescription', 'recoveryAutoBackupPasswordInput', 'recoveryAutoBackupCodeInput']) if (element(id)) element(id).value = '';
                for (const id of ['membersPendingRequestsList', 'desktopOperationOutput', 'teamTodoList', 'teamGroupCards', 'sidebarGroupList']) text(id, '');
                this.teamGroupSummaries = null; this.peopleRowsCache = null; this.membersInvitations = null; this.teamInviteContext = null;
                for (const modal of global.document?.querySelectorAll('.modal') || []) modal.style.display = 'none';
            },
            async logout() { const result = await base.logout.call(this); if (result) this.clearTeamUiState(); return result; },
            showWelcomeScreen(...args) { this.clearTeamUiState(); return base.showWelcomeScreen.apply(this, args); },
        };
    }
    global.HybridCipherTeamMethods = { create, workspaceModel, unwrap };
    if (typeof module !== 'undefined') module.exports = global.HybridCipherTeamMethods;
})(typeof window !== 'undefined' ? window : globalThis);
