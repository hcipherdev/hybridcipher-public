// Accountless "On this device" vault: start (on its own on a fresh device), recovery kit, restore, creating an account from it, and moving it into an existing account.
(function (global) {
    const call = (command, args = {}) => (global.HybridCipherTauri?.invoke || global.invoke)(command, args);
    const element = id => global.document?.getElementById(id);
    const setHidden = (id, hidden) => element(id)?.classList.toggle('hidden', hidden);
    const setText = (id, value) => { const node = element(id); if (node) node.textContent = value || ''; };
    const showModal = (id, visible) => {
        const node = element(id);
        if (!node) return;
        node.classList.toggle('hidden', !visible);
        node.style.display = visible ? 'flex' : 'none';
    };
    const setMessage = (id, message) => {
        setText(id, message);
        setHidden(id, !message);
    };
    const KIT_FILTERS = [{ name: 'HybridCipher recovery kit', extensions: ['hcrk'] }];

    /** What the Home panel says about the recovery kit and account creation. */
    function vaultPanelModel(status) {
        const resuming = Boolean(status?.upgrade_email);
        return {
            kitSaved: Boolean(status?.kit_saved),
            kitText: status?.kit_saved
                ? 'Recovery kit saved. Keep the file and the key somewhere other than this computer. '
                    + 'If you lose them, you can make a new kit in Settings.'
                : 'No recovery kit yet. You’ll save one before protecting your first folder.',
            kitButton: status?.kit_saved ? 'Make a new recovery kit' : 'Save recovery kit',
            // Once saved, a new kit is only made from Settings, so Home doesn't invite repeat kits.
            showKitButton: !status?.kit_saved,
            settingsKitStatus: status?.kit_saved ? 'Saved' : 'Not saved yet',
            upgradeButton: resuming ? 'Finish creating your account' : 'Use on other devices',
            // Replacing the vault would abandon an account being created from it.
            canRestore: !resuming,
        };
    }

    /**
     * Shown before replacing a saved kit. The vault never rekeys, so the old kit still opens
     * every folder; making a new one doesn't cancel it, it only adds a second way in.
     */
    function replaceKitPromptModel() {
        return {
            title: 'You already have a recovery kit',
            message: 'Your current kit still opens every folder in this vault, including folders you add later. '
                + 'You only need a new one if you lost the kit file or its recovery key.',
            detail: 'Making a new kit doesn’t cancel the old one: anyone with the old file and its key can still open '
                + 'your files, so delete old copies once the new kit is saved. If you later create an account, '
                + 'you’ll need the key from this new kit, not an older one.',
            primaryLabel: 'Make a new kit',
        };
    }

    /** Which upgrade fields apply: a resumed upgrade already has its email and password chosen. */
    function upgradeFormModel(status) {
        const resuming = Boolean(status?.upgrade_email);
        return {
            resuming,
            email: status?.upgrade_email || '',
            title: resuming ? 'Finish creating your account' : 'Use your files on other devices',
            submitLabel: resuming ? 'Continue' : 'Create account',
            showPasswordConfirm: !resuming,
            showRecoveryCode: Boolean(status?.kit_saved),
            // Until the app signs in, nothing on the server uses the vault, so a wrong email can be undone.
            canChangeEmail: resuming && ['registered', 'storage_moved'].includes(status?.upgrade_phase),
        };
    }

    /** What Home says, while signed in, about a vault left on this device. */
    function mergePanelModel(status, currentEmail) {
        const movingTo = status?.merge_email || '';
        const mine = Boolean(movingTo) && movingTo.toLowerCase() === String(currentEmail || '').toLowerCase();
        if (movingTo && !mine) {
            return {
                visible: true, canMove: false, button: '',
                text: `Files on this device are moving into ${movingTo}. Sign in as ${movingTo} to finish.`,
            };
        }
        if (mine) {
            return {
                visible: true, canMove: true, button: 'Finish moving files',
                text: 'Moving the files you protected before signing in didn’t finish. Continue to make them part of your account.',
            };
        }
        if (status?.can_merge) {
            return {
                visible: true, canMove: true, button: 'Move them into your account',
                text: 'Folders you protected on this device before signing in aren’t part of your account yet. '
                    + 'Move them into your Personal workspace to open them with your account.',
            };
        }
        return { visible: false, canMove: false, button: '', text: '' };
    }

    function mergeProgressText(progress) {
        const name = String(progress?.folder || '').split(/[\\/]/).filter(Boolean).pop() || 'your folder';
        const position = progress?.folder_count > 1
            ? ` (folder ${progress.folder_index + 1} of ${progress.folder_count})` : '';
        if (progress?.phase === 'protecting') return `Protecting ${name} in your account${position}…`;
        const files = progress?.total_files ? `: ${progress.processed_files} of ${progress.total_files} files` : '';
        return `Moving ${name}${files}${position}…`;
    }

    function mergeDoneText(data) {
        const folders = Number(data?.protected_folders || 0);
        const moved = folders === 0 ? 'Your vault’s files are'
            : folders === 1 ? '1 folder is' : `${folders} folders are`;
        return `${moved} now part of your Personal workspace, protected by your account’s recovery key. `
            + 'Keep the vault’s recovery kit for any backups made before the move.';
    }

    /**
     * Home's status snapshot for a vault, built from the coverage snapshot. A null
     * coverage is a failed read, unless `pending` says it simply hasn't been read yet.
     */
    function localVaultHomeSnapshot(coverage, { pending = false } = {}) {
        return {
            local_vault: true,
            last_scan_at: coverage?.last_scan_at || null,
            scan_status_available: Boolean(coverage),
            unavailable_sections: coverage || pending ? [] : ['scan status'],
        };
    }

    function create(original) {
        // Snapshot the methods being wrapped; the result is assigned onto `original`.
        const base = {};
        for (const key of ['checkSession', 'showWorkspaceHome', 'showWelcomeScreen', 'addEnrolledFolder',
            'logout', 'showDevicesView', 'refreshSecurityStatus', 'scheduleSecurityStatusRefresh',
            'maybeShowMfaPrompt', 'refreshWorkspaceHomeStatus',
            'ensureSessionReady', 'startSessionHealthTimer', 'setupEventListeners',
            'handleEmailConfirmYes', 'handleEmailConfirmLater', 'handleEmailConfirmed',
            'closeEmailConfirmModal', 'runPostLegalStartupFlow']) base[key] = original[key] || (() => undefined);
        return {
            // ---------------------------------------------------------------- entry
            async checkSession(...args) {
                await base.checkSession.apply(this, args);
                let status = null;
                try {
                    const result = await call('local_vault_status');
                    status = result?.success ? result.data : null;
                } catch (error) {
                    console.warn('Local vault status unavailable:', error);
                }
                this.localVaultFreshDevice = Boolean(status?.fresh_device) && !this.isLoggedIn;
                if (!status?.available) return;
                if (status.storage_missing) {
                    this.localVaultMissing = true;
                    this.showNotification('This device’s vault files are missing. Restore it from your recovery kit, or start a new vault.', 'warning');
                    return;
                }
                if (this.isLoggedIn) {
                    // Signed in after an interrupted upgrade: its last steps still need the password.
                    if (!this.localVaultMode && status.upgrade_email) {
                        this.localVault = status;
                        this.openLocalUpgradeModal();
                        return;
                    }
                    if (!this.localVaultMode) this.renderLocalMergePanel(status);
                    return;
                }
                // Some of its files already belong to that account, so the vault doesn't open.
                if (status.merge_email) {
                    this.showNotification(`Files on this device are moving into ${status.merge_email}. `
                        + `Sign in as ${status.merge_email} to finish.`, 'info');
                    return;
                }
                if (status.active) await this.enterLocalVault(status);
            },

            // Runs only once the terms are accepted. On a device nothing has used yet, the app
            // opens straight into a vault instead of waiting for "Start on this device".
            async runPostLegalStartupFlow(...args) {
                if (this.localVaultFreshDevice && !this.isLoggedIn && !this.localVaultMode) {
                    this.localVaultFreshDevice = false;
                    await this.startLocalVault({ auto: true });
                }
                return base.runPostLegalStartupFlow.apply(this, args);
            },

            async startLocalVault({ auto = false } = {}) {
                if (this.localVaultStarting) return;
                this.localVaultStarting = true;
                try {
                    let result = await call('create_local_vault');
                    if (result?.error_code === 'LOCAL_VAULT_STORAGE_MISSING') {
                        const replace = await this.showConfirmDialog?.('Start a new vault?',
                            'The vault on this device is missing its files. A new vault can’t open folders the old one protected; '
                            + 'only its recovery kit can. To get those back, cancel and choose Restore instead.');
                        if (replace !== true) return;
                        result = await call('create_local_vault', { replaceMissing: true });
                    }
                    if (!result?.success) throw new Error(result?.error || 'Could not start on this device.');
                    this.localVaultMissing = false;
                    await this.enterLocalVault(result.data);
                    // Opened on its own: the welcome and the Home guide explain the next steps.
                    if (!auto) {
                        this.showNotification('You’re set up on this device. Add a folder to protect it, '
                            + 'or choose Restore a previous vault if you have a recovery kit.', 'success');
                    }
                } catch (error) {
                    // The welcome screen stays, so "Start on this device" can try again.
                    this.showNotification(error.message || String(error), auto ? 'warning' : 'error');
                } finally {
                    this.localVaultStarting = false;
                }
            },

            async enterLocalVault(status) {
                this.localVault = status;
                this.localVaultMode = true;
                this.currentUser = null;
                this.currentDeviceId = null;
                this.activeWorkspaceType = 'personal';
                this.workspaceGroupContext = {
                    group_id: status.group_id, organization_id: null, role: 'owner', readiness: 'ready',
                };
                this.workspaceContextReady = true;
                const welcome = element('welcomeScreen');
                if (welcome) welcome.style.display = 'none';
                const appContainer = element('appContainer');
                if (appContainer) {
                    appContainer.style.display = 'flex';
                    appContainer.classList.remove('register-overlay');
                    appContainer.setAttribute('data-local-vault', 'true');
                }
                // Before applyAppMode: it disables the Add Protected Folder buttons while signed out.
                this.isLoggedIn = true;
                this.applyAppMode?.();
                setHidden('localVaultHeaderBtn', false);
                setText('workspaceHomeTitle', 'Personal');
                setText('workspaceHomeLead', 'Add a protected folder to start securing files on this computer.');
                // Replaced once showWorkspaceHome reads the last scan time.
                this.homeStatusSnapshot = localVaultHomeSnapshot(null, { pending: true });
                this.renderLocalVaultPanel();
                await this.loadEnrolledFolders({ suppressErrorNotification: true });
                this.startMountStatusPolling?.();
                this.showWorkspaceHome();
                this.runAutoMount?.().catch(error => {
                    console.error('Auto-mount after opening the vault failed:', error);
                });
            },

            leaveLocalVaultUi() {
                this.localVaultMode = false;
                this.localUpgradeConfirm = null;
                this.localVault = null;
                this.homeStatusSnapshot = null;
                this.stopMountStatusPolling?.();
                element('appContainer')?.removeAttribute('data-local-vault');
                setHidden('localVaultHeaderBtn', true);
                setHidden('localVaultPanel', true);
                setHidden('settingsLocalKitSection', true);
                setHidden('settingsRecoverySection', false);
                for (const id of ['localRecoveryKitModal', 'localUpgradeModal', 'localRestoreModal']) showModal(id, false);
                this.resolveLocalKitWaiter(false);
            },

            renderLocalVaultPanel() {
                if (!this.localVaultMode) {
                    setHidden('localVaultPanel', true);
                    return;
                }
                const model = vaultPanelModel(this.localVault);
                setHidden('localVaultPanel', false);
                setText('localVaultKitStatus', model.kitText);
                element('localVaultKitStatus')?.setAttribute('data-kit-saved', String(model.kitSaved));
                setText('localVaultKitBtn', model.kitButton);
                setHidden('localVaultKitBtn', !model.showKitButton);
                setHidden('settingsLocalKitSection', false);
                // Account recovery backups don't exist without an account; the kit replaces them here.
                setHidden('settingsRecoverySection', true);
                setText('settingsLocalKitStatus', model.settingsKitStatus);
                setText('settingsLocalKitBtn', model.kitButton);
                setText('localVaultUpgradeBtn', model.upgradeButton);
                setHidden('localVaultRestoreBtn', !model.canRestore);
                setHidden('localVaultSignInBtn', !model.canRestore);
                this.renderGettingStarted?.();
            },

            async refreshLocalVaultStatus() {
                const result = await call('local_vault_status');
                if (result?.success && result.data?.active) {
                    this.localVault = result.data;
                    this.renderLocalVaultPanel();
                }
                return this.localVault;
            },

            // -------------------------------------------------- account-only paths
            showWorkspaceHome(...args) {
                if (!this.localVaultMode) return base.showWorkspaceHome.apply(this, args);
                this.setWorkspaceView('home');
                this.updateWorkspaceHomeSummary();
                this.renderLocalVaultPanel();
                this.refreshWorkspaceHomeStatus().catch(() => {});
            },
            showWelcomeScreen(...args) {
                if (this.localVaultMode) this.leaveLocalVaultUi();
                this.renderLocalMergePanel(null);
                return base.showWelcomeScreen.apply(this, args);
            },
            async addEnrolledFolder(...args) {
                if (this.localVaultMode && !this.localVault?.kit_saved) {
                    if (!(await this.requireLocalRecoveryKit())) return;
                }
                return base.addEnrolledFolder.apply(this, args);
            },
            async logout(...args) {
                if (this.localVaultMode) {
                    this.showNotification('You’re using this device without an account, so there’s nothing to sign out of.', 'info');
                    return false;
                }
                return base.logout.apply(this, args);
            },
            async showDevicesView(...args) {
                if (this.localVaultMode) return this.openLocalUpgradeModal();
                return base.showDevicesView.apply(this, args);
            },
            async refreshSecurityStatus(...args) {
                if (this.localVaultMode) return undefined;
                return base.refreshSecurityStatus.apply(this, args);
            },
            scheduleSecurityStatusRefresh(...args) {
                if (this.localVaultMode) return undefined;
                return base.scheduleSecurityStatusRefresh.apply(this, args);
            },
            async maybeShowMfaPrompt(...args) {
                if (this.localVaultMode) return undefined;
                return base.maybeShowMfaPrompt.apply(this, args);
            },
            // Home's account status needs a server session, so a vault reads only what this
            // device knows: when its protected folders were last scanned.
            async refreshWorkspaceHomeStatus(...args) {
                if (this.localVaultMode) {
                    const group = this.localVault?.group_id;
                    let coverage = null;
                    try {
                        const result = await call('get_coverage_center_snapshot');
                        coverage = result?.success ? result.data : null;
                    } catch (error) {
                        console.warn('Vault scan status unavailable:', error);
                    }
                    if (!this.localVaultMode || this.localVault?.group_id !== group) return undefined;
                    this.homeStatusSnapshot = localVaultHomeSnapshot(coverage);
                    this.updateWorkspaceHomeSummary();
                    return undefined;
                }
                const result = await base.refreshWorkspaceHomeStatus.apply(this, args);
                this.refreshLocalMergePanel().catch(() => {});
                return result;
            },
            // There is no account session to check, so a missing one must not sign the vault out.
            // Without this, regaining focus (for example after the kit save dialog) ran the
            // account session check, found no session and showed the login screen.
            async ensureSessionReady(...args) {
                if (this.localVaultMode) return null;
                return base.ensureSessionReady.apply(this, args);
            },
            startSessionHealthTimer(...args) {
                if (this.localVaultMode) return undefined;
                return base.startSessionHealthTimer.apply(this, args);
            },

            // --------------------------------------------------------- recovery kit
            requireLocalRecoveryKit() {
                this.resolveLocalKitWaiter(false);
                return new Promise(resolve => {
                    this.localKitWaiter = resolve;
                    this.openLocalRecoveryKitModal();
                });
            },
            resolveLocalKitWaiter(saved) {
                const resolve = this.localKitWaiter;
                this.localKitWaiter = null;
                resolve?.(saved);
            },
            openLocalRecoveryKitModal() {
                setHidden('localRecoveryKitIntro', false);
                setHidden('localRecoveryKitConfirm', true);
                setText('localRecoveryKitCode', '');
                if (element('localRecoveryKitCheckInput')) element('localRecoveryKitCheckInput').value = '';
                setMessage('localRecoveryKitError', '');
                showModal('localRecoveryKitModal', true);
                global.setTimeout?.(() => element('saveLocalRecoveryKitBtn')?.focus(), 0);
            },
            async openLocalRecoveryKitFromSettings() {
                this.closeSettingsModal?.();
                if (this.localVault?.kit_saved) {
                    const prompt = replaceKitPromptModel();
                    const confirmed = await this.showActionPrompt(prompt.title, prompt.message, {
                        detail: prompt.detail,
                        primaryLabel: prompt.primaryLabel,
                        secondaryLabel: 'Cancel',
                        focusSecondary: true,
                    });
                    if (confirmed !== true) return;
                }
                this.openLocalRecoveryKitModal();
            },
            closeLocalRecoveryKitModal() {
                setText('localRecoveryKitCode', '');
                showModal('localRecoveryKitModal', false);
                this.resolveLocalKitWaiter(false);
            },
            async saveLocalRecoveryKit() {
                const dialog = global.__TAURI__?.dialog;
                if (!dialog?.save) {
                    setMessage('localRecoveryKitError', 'The file picker is unavailable.');
                    return;
                }
                const savePath = await dialog.save({
                    title: 'Save your recovery kit',
                    defaultPath: 'HybridCipher Recovery Kit.hcrk',
                    filters: KIT_FILTERS,
                });
                if (!savePath) return;
                const result = await call('create_local_recovery_kit', { savePath });
                if (!result?.success) {
                    this.showNotification(result?.error || 'The recovery kit could not be saved.', 'error');
                    return;
                }
                setText('localRecoveryKitCode', result.data.recovery_code);
                setHidden('localRecoveryKitIntro', true);
                setHidden('localRecoveryKitConfirm', false);
                global.setTimeout?.(() => element('localRecoveryKitCheckInput')?.focus(), 0);
            },
            async copyLocalRecoveryKitCode() {
                const code = element('localRecoveryKitCode')?.textContent || '';
                try {
                    await global.navigator?.clipboard?.writeText(code);
                    this.showNotification('Recovery key copied. Paste it somewhere safe, then clear your clipboard.', 'info');
                } catch (error) {
                    this.showNotification('Copy failed. Select the key and copy it manually.', 'warning');
                }
            },
            async confirmLocalRecoveryKit(event) {
                event?.preventDefault?.();
                const lastCharacters = element('localRecoveryKitCheckInput')?.value || '';
                const result = await call('confirm_local_recovery_kit', { lastCharacters });
                if (!result?.success) {
                    setMessage('localRecoveryKitError', result?.error || 'Those characters don’t match.');
                    return;
                }
                this.localVault = result.data;
                setText('localRecoveryKitCode', '');
                showModal('localRecoveryKitModal', false);
                this.renderLocalVaultPanel();
                this.showNotification('Recovery kit saved.', 'success');
                this.resolveLocalKitWaiter(true);
            },

            // -------------------------------------------------------------- upgrade
            openLocalUpgradeModal() {
                const model = upgradeFormModel(this.localVault);
                setText('localUpgradeTitle', model.title);
                setText('submitLocalUpgradeBtn', model.submitLabel);
                const email = element('localUpgradeEmailInput');
                if (email) {
                    email.value = model.email;
                    email.disabled = model.resuming;
                }
                setHidden('localUpgradeConfirmGroup', !model.showPasswordConfirm);
                setHidden('localUpgradeCodeGroup', !model.showRecoveryCode);
                for (const id of ['localUpgradePasswordInput', 'localUpgradePasswordConfirmInput', 'localUpgradeCodeInput']) {
                    if (element(id)) element(id).value = '';
                }
                if (element('localUpgradeNoCodeInput')) element('localUpgradeNoCodeInput').checked = false;
                setMessage('localUpgradeStatus', model.resuming
                    ? `Enter the password you chose for ${model.email}. If you haven’t yet, open the confirmation link we emailed you.`
                    : '');
                setMessage('localUpgradeError', '');
                setHidden('localUpgradeResendBtn', !model.resuming);
                setHidden('localUpgradeSignInBtn', model.resuming);
                setHidden('localUpgradeChangeEmailBtn', !model.canChangeEmail);
                showModal('localUpgradeModal', true);
                global.setTimeout?.(() => element(model.resuming ? 'localUpgradePasswordInput' : 'localUpgradeEmailInput')?.focus(), 0);
            },
            closeLocalUpgradeModal() {
                for (const id of ['localUpgradePasswordInput', 'localUpgradePasswordConfirmInput', 'localUpgradeCodeInput']) {
                    if (element(id)) element(id).value = '';
                }
                showModal('localUpgradeModal', false);
            },
            localUpgradeInputError(model, email, password, confirm, code, noCode) {
                if (!model.resuming && !(this.isValidEmail?.(email) ?? email.includes('@'))) return 'Enter a valid email address.';
                if (!password) return 'Enter a password.';
                if (!model.resuming) {
                    const rules = this.evaluatePasswordRules?.(password);
                    if (rules && !Object.values(rules).every(Boolean)) {
                        return 'Use 12 or more characters with upper and lower case letters, a number and a symbol.';
                    }
                    if (password !== confirm) return 'Passwords do not match.';
                }
                if (model.showRecoveryCode && !noCode && !code) {
                    return 'Enter your recovery key, or choose “I don’t have it”.';
                }
                return '';
            },
            async submitLocalUpgrade(event) {
                event?.preventDefault?.();
                if (this.localUpgradeInFlight) return;
                const model = upgradeFormModel(this.localVault);
                const email = model.resuming ? model.email : (element('localUpgradeEmailInput')?.value || '').trim();
                const password = element('localUpgradePasswordInput')?.value || '';
                const confirm = element('localUpgradePasswordConfirmInput')?.value || '';
                const noCode = !model.showRecoveryCode || Boolean(element('localUpgradeNoCodeInput')?.checked);
                const code = noCode ? '' : (element('localUpgradeCodeInput')?.value || '').trim();
                const inputError = this.localUpgradeInputError(model, email, password, confirm, code, noCode);
                setMessage('localUpgradeError', inputError);
                if (inputError) return;
                this.localUpgradeInFlight = true;
                element('submitLocalUpgradeBtn')?.setAttribute('disabled', '');
                setMessage('localUpgradeStatus', 'Creating your account…');
                try {
                    await this.runLocalUpgrade(email, password, code || null);
                } finally {
                    this.localUpgradeInFlight = false;
                    element('submitLocalUpgradeBtn')?.removeAttribute('disabled');
                }
            },
            // Runs or resumes the upgrade. A pending confirmation opens the same Confirm Your Email
            // dialog as a normal registration; finishing it reruns the upgrade from there.
            async runLocalUpgrade(email, password, recoveryCode) {
                try {
                    const result = await call('upgrade_local_vault_to_account', { email, password, recoveryCode });
                    await this.refreshLocalVaultStatus().catch(() => {});
                    if (!result?.success) {
                        if (result?.error_code === 'ACCOUNT_EXISTS') {
                            this.closeLocalUpgradeModal();
                            await this.signInToExistingAccount(email, { exists: true });
                            return;
                        }
                        this.showLocalUpgradeError(result?.error || 'Your account could not be created.');
                        return;
                    }
                    if (result.data.status === 'confirm_email') {
                        this.closeLocalUpgradeModal();
                        this.openEmailConfirmModal?.(result.data.email, password);
                        this.localUpgradeConfirm = { recoveryCode };
                        return;
                    }
                    this.closeLocalUpgradeModal();
                    await this.finishLocalVaultUpgrade(result.data);
                } catch (error) {
                    this.showLocalUpgradeError(error.message || String(error));
                }
            },
            showLocalUpgradeError(message) {
                if (element('localUpgradeModal')?.style.display !== 'flex') this.openLocalUpgradeModal();
                setMessage('localUpgradeStatus', '');
                setMessage('localUpgradeError', message);
                this.applyLocalUpgradeProgressToForm();
            },

            // ------------------------------------------- email confirmation (shared dialog)
            async handleEmailConfirmYes(...args) {
                const pending = this.localUpgradeConfirm;
                if (!pending) return base.handleEmailConfirmYes.apply(this, args);
                const email = this.pendingRegistrationEmail;
                const password = this.pendingRegistrationPassword;
                if (!email || !password || this.localUpgradeInFlight) return undefined;
                const confirmed = this.confirmationVerified || await this.checkEmailConfirmationOnce?.();
                if (!confirmed) {
                    // The same prompt a normal registration shows; never the login dialog.
                    const resend = await this.showConfirmDialog?.('Not confirmed yet',
                        'We still do not see the confirmation. Would you like to resend the confirmation email?');
                    if (resend === true) await this.handleResendConfirmationEmail?.();
                    return undefined;
                }
                this.closeEmailConfirmModal();
                this.localUpgradeInFlight = true;
                try {
                    await this.runLocalUpgrade(email, password, pending.recoveryCode);
                } finally {
                    this.localUpgradeInFlight = false;
                }
                return undefined;
            },
            handleEmailConfirmLater(...args) {
                if (!this.localUpgradeConfirm) return base.handleEmailConfirmLater.apply(this, args);
                this.closeEmailConfirmModal();
                this.showNotification('Your files stay usable here. Choose “Finish creating your account” on Home after you confirm your email.', 'info');
                return undefined;
            },
            handleEmailConfirmed(...args) {
                const result = base.handleEmailConfirmed.apply(this, args);
                if (this.localUpgradeConfirm) setText('emailConfirmYesBtn', 'Continue');
                return result;
            },
            closeEmailConfirmModal(...args) {
                this.localUpgradeConfirm = null;
                return base.closeEmailConfirmModal.apply(this, args);
            },
            // Once the account exists its email is fixed and the password chosen; keep what's typed.
            applyLocalUpgradeProgressToForm() {
                const model = upgradeFormModel(this.localVault);
                if (!model.resuming) return;
                setText('localUpgradeTitle', model.title);
                setText('submitLocalUpgradeBtn', model.submitLabel);
                const email = element('localUpgradeEmailInput');
                if (email) {
                    email.value = model.email;
                    email.disabled = true;
                }
                setHidden('localUpgradeConfirmGroup', true);
                setHidden('localUpgradeSignInBtn', true);
                // Offered when the dialog is reopened, not right after the account was created.
                setHidden('localUpgradeChangeEmailBtn', true);
            },
            async changeLocalUpgradeEmail() {
                const email = this.localVault?.upgrade_email;
                if (!email || this.localUpgradeInFlight) return;
                const proceed = await this.showConfirmDialog?.('Use a different email?',
                    `The account for ${email} won’t be used. Your protected folders stay on this device, `
                    + 'and you can create an account with another email.');
                if (proceed !== true) return;
                this.localUpgradeInFlight = true;
                try {
                    const result = await call('cancel_local_vault_upgrade');
                    if (!result?.success) {
                        setMessage('localUpgradeError', result?.error || 'The email could not be changed.');
                        return;
                    }
                    this.localVault = result.data;
                    this.renderLocalVaultPanel();
                    this.openLocalUpgradeModal();
                    setMessage('localUpgradeStatus', `${email} won’t be used. Enter the email you want for your account.`);
                } finally {
                    this.localUpgradeInFlight = false;
                }
            },
            async resendLocalUpgradeEmail() {
                const email = this.localVault?.upgrade_email;
                if (!email) return;
                const result = await call('resend_confirmation_email', { email });
                this.showNotification(result?.success ? `Confirmation email sent to ${email}.` : (result?.error || 'The email could not be sent.'),
                    result?.success ? 'success' : 'error');
            },
            async finishLocalVaultUpgrade(data) {
                this.leaveLocalVaultUi();
                this.isLoggedIn = false;
                await base.checkSession.call(this);
                this.showNotification('Your account is ready. Folders you protected on this device are part of it now.', 'success');
                // Either dialog leads to the MFA prompt once acknowledged, as after a normal registration.
                if (data?.new_recovery_code) {
                    this.showRecoveryCodeModal?.(data.new_recovery_code);
                } else {
                    this.pendingMfaPrompt = true;
                    showModal('localRecoveryReminderModal', true);
                }
            },
            acknowledgeLocalRecoveryReminder() {
                showModal('localRecoveryReminderModal', false);
                this.scheduleMfaPrompt?.();
            },

            // ------------------------------------------- move into an existing account
            async signInToExistingAccount(email = '', { exists = false } = {}) {
                const lead = exists ? `${email} already has an account. ` : '';
                // A vault without a saved kit never protected a folder: nothing to move, and
                // signing in removes it, so there is nothing to confirm.
                const proceed = !this.localVault?.kit_saved && !exists ? true : await this.showConfirmDialog?.('Sign in to your account?',
                    `${lead}After you sign in, Home asks you to move the folders protected on this device into your `
                    + 'Personal workspace. Move them to keep using them with your account.');
                if (proceed !== true) {
                    if (exists) {
                        this.openLocalUpgradeModal();
                        if (element('localUpgradeEmailInput')) element('localUpgradeEmailInput').value = email;
                    }
                    return;
                }
                const closed = await call('close_local_vault');
                if (!closed?.success) {
                    this.showNotification(closed?.error || 'This device’s vault could not be closed.', 'error');
                    return;
                }
                this.closeLocalUpgradeModal();
                this.leaveLocalVaultUi();
                this.isLoggedIn = false;
                this.showWelcomeScreen?.();
                this.openLoginModal?.(email || null);
            },
            async refreshLocalMergePanel() {
                if (this.localVaultMode || !this.isLoggedIn) return this.renderLocalMergePanel(null);
                const result = await call('local_vault_status');
                this.renderLocalMergePanel(result?.success ? result.data : null);
            },
            renderLocalMergePanel(status) {
                this.localMergeStatus = status;
                const personal = (this.activeWorkspaceType || 'personal') === 'personal';
                const model = mergePanelModel(status, this.currentUser);
                setHidden('localMergePanel', !(model.visible && personal && this.isLoggedIn && !this.localVaultMode));
                setText('localMergePanelText', model.text);
                setText('localMergeBtn', model.button);
                setHidden('localMergeBtn', !model.canMove);
            },
            openLocalMergeModal() {
                setMessage('localMergeStatus', '');
                setMessage('localMergeError', '');
                showModal('localMergeModal', true);
            },
            closeLocalMergeModal() {
                if (this.localMergeInFlight) return;
                showModal('localMergeModal', false);
            },
            handleLocalMergeProgress(progress) {
                if (this.localMergeInFlight) setMessage('localMergeStatus', mergeProgressText(progress));
            },
            async submitLocalMerge() {
                if (this.localMergeInFlight) return;
                this.localMergeInFlight = true;
                for (const id of ['submitLocalMergeBtn', 'cancelLocalMergeBtn']) element(id)?.setAttribute('disabled', '');
                setMessage('localMergeError', '');
                setMessage('localMergeStatus', 'Getting ready…');
                let unlisten = null;
                try {
                    unlisten = await global.__TAURI__?.event?.listen?.('local_vault_merge_progress',
                        event => this.handleLocalMergeProgress(event?.payload || {}));
                    const result = await call('merge_local_vault_into_account');
                    if (!result?.success) {
                        setMessage('localMergeStatus', '');
                        setMessage('localMergeError', result?.error || 'The files could not be moved.');
                        return;
                    }
                    this.localMergeInFlight = false;
                    this.closeLocalMergeModal();
                    this.renderLocalMergePanel(null);
                    await this.loadEnrolledFolders?.({ suppressErrorNotification: true });
                    this.showNotification(mergeDoneText(result.data), 'success');
                } catch (error) {
                    setMessage('localMergeStatus', '');
                    setMessage('localMergeError', error.message || String(error));
                } finally {
                    if (typeof unlisten === 'function') unlisten();
                    this.localMergeInFlight = false;
                    for (const id of ['submitLocalMergeBtn', 'cancelLocalMergeBtn']) element(id)?.removeAttribute('disabled');
                }
            },

            // -------------------------------------------------------------- restore
            openLocalRestoreModal() {
                this.localRestorePath = null;
                setText('localRestoreFileName', 'No file chosen');
                if (element('localRestoreCodeInput')) element('localRestoreCodeInput').value = '';
                setMessage('localRestoreError', '');
                setText('localRestoreLead', this.localVaultMode
                    ? 'Replace the vault on this device with one you saved a recovery kit for. '
                        + 'This works only while the vault on this device protects no files.'
                    : 'Open files you protected on another computer without an account.');
                showModal('localRestoreModal', true);
            },
            closeLocalRestoreModal() {
                if (element('localRestoreCodeInput')) element('localRestoreCodeInput').value = '';
                showModal('localRestoreModal', false);
            },
            async chooseLocalRestoreFile() {
                const dialog = global.__TAURI__?.dialog;
                if (!dialog?.open) {
                    setMessage('localRestoreError', 'The file picker is unavailable.');
                    return;
                }
                const path = await dialog.open({ multiple: false, title: 'Choose your recovery kit', filters: KIT_FILTERS });
                if (!path) return;
                this.localRestorePath = String(path);
                setText('localRestoreFileName', this.localRestorePath.split(/[\\/]/).pop());
            },
            async submitLocalRestore(event) {
                event?.preventDefault?.();
                const recoveryCode = (element('localRestoreCodeInput')?.value || '').trim();
                if (!this.localRestorePath) return setMessage('localRestoreError', 'Choose your recovery kit file.');
                if (!recoveryCode) return setMessage('localRestoreError', 'Enter your recovery key.');
                const replacing = Boolean(this.localVaultMode);
                if (replacing) {
                    const proceed = await this.showConfirmDialog?.('Replace the vault on this device?',
                        'The vault on this device is removed and the one in your recovery kit takes its place. '
                        + 'Its own recovery kit will no longer be needed.');
                    if (proceed !== true) return;
                }
                const result = await call('restore_local_vault_from_kit', {
                    kitPath: this.localRestorePath, recoveryCode, ...(replacing ? { replaceEmpty: true } : {}),
                });
                if (!result?.success) {
                    setMessage('localRestoreError', result?.error || 'The vault could not be restored.');
                    // A failed replacement leaves the current vault in place; reopen it.
                    if (replacing) await this.refreshLocalVaultStatus();
                    return;
                }
                this.closeLocalRestoreModal();
                if (replacing) this.leaveLocalVaultUi();
                await this.enterLocalVault(result.data);
                this.showNotification('Your vault is restored on this device.', 'success');
            },

            // --------------------------------------------------------------- events
            setupEventListeners(...args) {
                const result = base.setupEventListeners.apply(this, args);
                const on = (id, event, handler) => element(id)?.addEventListener(event, handler);
                on('startLocalVaultBtn', 'click', () => this.startLocalVault());
                on('restoreLocalVaultBtn', 'click', () => this.openLocalRestoreModal());
                on('localVaultRestoreBtn', 'click', () => this.openLocalRestoreModal());
                on('localVaultSignInBtn', 'click', () => this.signInToExistingAccount());
                on('firstRunVaultSignInBtn', 'click', () => {
                    this.hideWelcomeOverlay?.();
                    this.signInToExistingAccount();
                });
                on('firstRunVaultRestoreBtn', 'click', () => {
                    this.hideWelcomeOverlay?.();
                    this.openLocalRestoreModal();
                });
                on('firstRunStartLocalBtn', 'click', () => {
                    this.hideWelcomeOverlay?.();
                    this.startLocalVault();
                });
                on('localVaultHeaderBtn', 'click', () => this.openLocalUpgradeModal());
                on('localVaultUpgradeBtn', 'click', () => this.openLocalUpgradeModal());
                on('localVaultKitBtn', 'click', () => this.openLocalRecoveryKitModal());
                on('settingsLocalKitBtn', 'click', () => this.openLocalRecoveryKitFromSettings());
                on('closeLocalRecoveryKitModalBtn', 'click', () => this.closeLocalRecoveryKitModal());
                on('saveLocalRecoveryKitBtn', 'click', () => this.saveLocalRecoveryKit());
                on('copyLocalRecoveryKitCodeBtn', 'click', () => this.copyLocalRecoveryKitCode());
                on('localRecoveryKitConfirm', 'submit', event => this.confirmLocalRecoveryKit(event));
                on('closeLocalUpgradeModalBtn', 'click', () => this.closeLocalUpgradeModal());
                on('cancelLocalUpgradeBtn', 'click', () => this.closeLocalUpgradeModal());
                on('localUpgradeForm', 'submit', event => this.submitLocalUpgrade(event));
                on('localUpgradeResendBtn', 'click', () => this.resendLocalUpgradeEmail());
                on('localUpgradeChangeEmailBtn', 'click', () => this.changeLocalUpgradeEmail());
                on('ackLocalRecoveryReminderBtn', 'click', () => this.acknowledgeLocalRecoveryReminder());
                on('closeLocalRecoveryReminderBtn', 'click', () => this.acknowledgeLocalRecoveryReminder());
                on('localUpgradeSignInBtn', 'click', () => this.signInToExistingAccount(
                    (element('localUpgradeEmailInput')?.value || '').trim()));
                on('localMergeBtn', 'click', () => this.openLocalMergeModal());
                on('closeLocalMergeModalBtn', 'click', () => this.closeLocalMergeModal());
                on('cancelLocalMergeBtn', 'click', () => this.closeLocalMergeModal());
                on('submitLocalMergeBtn', 'click', () => this.submitLocalMerge());
                on('closeLocalRestoreModalBtn', 'click', () => this.closeLocalRestoreModal());
                on('cancelLocalRestoreBtn', 'click', () => this.closeLocalRestoreModal());
                on('localRestoreFileBtn', 'click', () => this.chooseLocalRestoreFile());
                on('localRestoreForm', 'submit', event => this.submitLocalRestore(event));
                return result;
            },
        };
    }

    global.HybridCipherLocalVaultMethods = {
        create, vaultPanelModel, replaceKitPromptModel, upgradeFormModel, mergePanelModel, mergeProgressText, mergeDoneText,
    };
    if (typeof module !== 'undefined') module.exports = global.HybridCipherLocalVaultMethods;
})(typeof window !== 'undefined' ? window : globalThis);
