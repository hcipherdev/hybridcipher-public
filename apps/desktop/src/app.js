function resolveFallbackTauriInvoke() {
    const tauriGlobal = window.__TAURI__;

    if (!tauriGlobal) {
        return null;
    }

    return tauriGlobal.core?.invoke || tauriGlobal.tauri?.invoke || tauriGlobal.invoke || null;
}

async function invoke(command, args = {}) {
    const invokeFn = window.HybridCipherTauri?.invoke || resolveFallbackTauriInvoke();

    if (!invokeFn) {
        console.error('Tauri API is not available yet. Are you running inside the Tauri shell?');
        throw new Error('Tauri API is not available');
    }

    return invokeFn(command, args);
}

const securityUtils = window.HybridCipherSecurityUtils || {};
const escapeHtmlValue = typeof securityUtils.escapeHtml === 'function'
    ? securityUtils.escapeHtml
    : (value) => String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
const quoteShellArgValue = typeof securityUtils.quoteShellArg === 'function'
    ? securityUtils.quoteShellArg
    : (value) => {
        const text = String(value ?? '');
        if (text.length === 0) {
            return "''";
        }
        return `'${text.replace(/'/g, `'\"'\"'`)}'`;
    };
const uiUtils = window.HybridCipherUiUtils || {};
const getMountBackendLabelValue = (backend) => {
    switch (backend) {
        case 'macos-file-provider':
            return 'macOS File Provider';
        case 'windows-cloud-files':
            return 'Windows Cloud Files';
        case 'linux-fuse':
            return 'Linux FUSE';
        case 'sync':
            return 'Sync Mount';
        default:
            return null;
    }
};
const getEmbeddedTerminalHeaderTitleValue = typeof uiUtils.getEmbeddedTerminalHeaderTitle === 'function'
    ? uiUtils.getEmbeddedTerminalHeaderTitle
    : () => 'Embedded Terminal';
const getFolderRowStatusStateValue = typeof uiUtils.getFolderRowStatusState === 'function'
    ? uiUtils.getFolderRowStatusState
    : ({ isMounted = false, syncStatus = null, showSafetyAlert = false } = {}) => {
        if (!isMounted) {
            return {
                showMountedBadge: false,
                showAlertButton: false,
                healthDotTone: null,
            };
        }

        const status = syncStatus || {};
        const hasConflicts = Number(status.pending_conflict_count || 0) > 0;
        const hasRecoveryCopies = Number(status.recovered_pending_copy_count || 0) > 0;

        return {
            showMountedBadge: true,
            showAlertButton: Boolean(showSafetyAlert),
            healthDotTone: hasConflicts || hasRecoveryCopies ? 'red' : 'green',
        };
    };
const buildPostQuantumStatusModelValue = typeof uiUtils.buildPostQuantumStatusModel === 'function'
    ? uiUtils.buildPostQuantumStatusModel
    : ({
        protectedCount = null,
        isProtectedFolder = false,
        status = null,
        primaryText = null,
        secondaryText = null,
        explainerAvailable = true,
    } = {}) => {
        const normalizedProtectedCount = Number.isFinite(Number(protectedCount)) ? Number(protectedCount) : null;
        let resolvedStatus = status || null;
        let resolvedPrimaryText = primaryText || null;
        let resolvedSecondaryText = secondaryText || null;

        if (!resolvedStatus) {
            if (isProtectedFolder) {
                resolvedStatus = 'protected_now';
                resolvedPrimaryText = 'Protected now with post-quantum encryption';
                resolvedSecondaryText = 'Files in this protected folder are secured now with quantum-resistant encryption.';
            } else if (normalizedProtectedCount === null) {
                resolvedStatus = 'unknown';
                resolvedPrimaryText = 'Protection status unknown';
                resolvedSecondaryText = 'The app cannot confirm post-quantum protection for this session yet.';
            } else if (normalizedProtectedCount > 0) {
                resolvedStatus = 'protected_now';
                resolvedPrimaryText = 'Protected now';
                resolvedSecondaryText = 'Your protected folders are secured now with quantum-resistant encryption.';
            } else {
                resolvedStatus = 'needs_review';
                resolvedPrimaryText = 'Needs review';
                resolvedSecondaryText = 'Add a protected folder to start securing files now with post-quantum encryption.';
            }
        }

        const tone = resolvedStatus === 'protected_now'
            ? 'safe'
            : (resolvedStatus === 'needs_review' ? 'warning' : 'idle');

        return {
            status: resolvedStatus,
            tone,
            primaryText: resolvedPrimaryText || 'Protection status unknown',
            secondaryText: resolvedSecondaryText || 'The app cannot confirm post-quantum protection for this session yet.',
            explainerAvailable: Boolean(explainerAvailable),
            explainer: {
                title: 'Why post-quantum protection matters',
                body: 'Your protected files are secured with hybrid post-quantum encryption, designed to protect against today’s attackers and to remain secure even if stolen encrypted data is targeted by future quantum-capable systems.',
            },
            homeCard: {
                id: 'post-quantum',
                title: 'Post-quantum protection',
                tone,
                value: isProtectedFolder ? 'Protected now' : (resolvedStatus === 'unknown' ? 'Unknown' : resolvedPrimaryText),
                detail: normalizedProtectedCount === 0 && !isProtectedFolder
                    ? resolvedSecondaryText || 'Add a protected folder to start securing files now with post-quantum encryption.'
                    : (resolvedStatus === 'protected_now'
                        ? 'Your protected folders are secured now with quantum-resistant encryption.'
                        : (resolvedSecondaryText || 'The app cannot confirm post-quantum protection for this session yet.')),
                ctaAction: Boolean(explainerAvailable) ? 'show-post-quantum-explainer' : null,
                ctaLabel: 'Why this matters',
            },
            shellBadge: {
                label: resolvedStatus === 'protected_now'
                    ? 'Protected now'
                    : (resolvedStatus === 'needs_review' ? 'Protection needs review' : 'Protection status unknown'),
                eyebrow: 'Post-quantum protection',
                detail: resolvedStatus === 'protected_now'
                    ? 'Your protected folders are secured now with quantum-resistant encryption designed to resist future quantum attacks.'
                    : (resolvedSecondaryText || 'The app cannot confirm post-quantum protection for this session yet.'),
                action: resolvedStatus === 'needs_review'
                    ? 'open-post-quantum-attention'
                    : (Boolean(explainerAvailable) ? 'show-post-quantum-explainer' : null),
            },
            folderDetail: {
                isPostQuantumProtected: Boolean(isProtectedFolder || resolvedStatus === 'protected_now'),
                primaryText: isProtectedFolder
                    ? 'Protected now with post-quantum encryption'
                    : (resolvedStatus === 'protected_now' ? 'Protected now' : (resolvedPrimaryText || 'Protection status unknown')),
                secondaryText: isProtectedFolder
                    ? 'Files in this protected folder are secured now with quantum-resistant encryption.'
                    : (resolvedSecondaryText || 'The app cannot confirm post-quantum protection for this session yet.'),
            },
        };
    };
const buildWorkspaceHomeModelValue = typeof uiUtils.buildWorkspaceHomeModel === 'function'
    ? uiUtils.buildWorkspaceHomeModel
    : (snapshot = {}) => {
        const postQuantum = buildPostQuantumStatusModelValue({ protectedCount: Number(snapshot.protected_count || 0) });
        return {
            protectedCount: Number(snapshot.protected_count || 0),
            mountedCount: Number(snapshot.mounted_count || 0),
            postQuantum,
            summaryTone: 'safe',
            summaryLabel: 'Protected',
            cards: [postQuantum.homeCard],
            attentionItems: [],
        };
    };
const buildFolderCoverageModelValue = typeof uiUtils.buildFolderCoverageModel === 'function'
    ? uiUtils.buildFolderCoverageModel
    : ({ folder = {}, review = null } = {}) => {
        const fallbackPercent = Math.round(Number(review?.coverage_percent ?? (Number(folder.coverage_ratio || 0) * 100)));
        const fallbackTrackedFiles = Number(review?.tracked_files ?? folder.tracked_files ?? 0);
        const fallbackUnresolved = Number(
            review?.unresolved_item_count
            ?? (Number(folder.orphaned_files || 0) + Number(folder.unmanaged_files || 0))
        );
        return {
            coveragePercent: fallbackPercent,
            percentLabel: `${fallbackPercent}%`,
            trackedFiles: fallbackTrackedFiles,
            unresolvedItemCount: fallbackUnresolved,
        stateLabel: review?.state_label || 'Needs attention',
        summaryText: review?.summary_text || 'Review uncovered items in this folder.',
        stateTone: 'warning',
        groups: Array.isArray(review?.groups) ? review.groups : [],
        primaryCta: {
                id: fallbackUnresolved > 0
                ? 'review-uncovered-items'
                : 'run-coverage-scan',
                label: fallbackUnresolved > 0
                ? 'Review uncovered items'
                : 'Run scan again',
        },
        };
    };
const buildFolderDetailModelValue = typeof uiUtils.buildFolderDetailModel === 'function'
    ? uiUtils.buildFolderDetailModel
    : ({ folder = {}, mountInfo = null, isMounted = false, coverageReview = null } = {}) => ({
        displayName: folder.name || '',
        path: folder.path || '',
        isMounted: Boolean(isMounted),
        mountpoint: mountInfo?.mountpoint || null,
        backend: mountInfo?.backend || null,
        backendLabel: getMountBackendLabelValue(mountInfo?.backend || null),
        primaryAction: isMounted
            ? { id: 'open-mounted', label: 'Open mounted folder' }
            : { id: 'mount', label: 'Mount folder' },
        secondaryActions: [],
        attention: {
            conflicts: 0,
            recoveryCopies: 0,
            mountStatusLabel: isMounted ? 'Mounted' : 'Not mounted',
            unmountSafetyLabel: isMounted ? 'Checking...' : null,
            safeToUnmount: null,
        },
        showResolveConflicts: false,
        showResolveRecoveryCopies: false,
        trackedFiles: Number(folder.tracked_files || 0),
        coveragePercent: Math.round(Number(folder.coverage_ratio || 0) * 100),
        protection: buildPostQuantumStatusModelValue({ isProtectedFolder: Boolean(folder?.root_id || folder?.path) }).folderDetail,
        coverage: buildFolderCoverageModelValue({ folder, review: coverageReview }),
        healthTone: isMounted ? 'safe' : 'idle',
        lastScanAt: folder.last_scan || null,
    });
const buildCoverageCenterModelValue = typeof uiUtils.buildCoverageCenterModel === 'function'
    ? uiUtils.buildCoverageCenterModel
    : (snapshot = {}, runtime = {}) => ({
        isEmpty: !Array.isArray(snapshot?.folders) || snapshot.folders.length === 0,
        summary: {
            overallCoveragePercent: Number(snapshot?.overall_coverage_percent || 0),
            trackedFiles: Number(snapshot?.tracked_files || 0),
            orphanedFiles: Number(snapshot?.orphaned_files || 0),
            unmanagedFiles: Number(snapshot?.unmanaged_files || 0),
            folderCount: Number(snapshot?.enrolled_folder_count || 0),
            lastScanAt: snapshot?.last_scan_at || null,
            ipcState: snapshot?.ipc_state || 'inactive',
            scanState: runtime?.scanState?.state || 'idle',
        },
        folderRows: Array.isArray(snapshot?.folders) ? snapshot.folders : [],
        attentionItems: Array.isArray(snapshot?.attention_items) ? snapshot.attention_items : [],
        emptyState: {
            title: 'No protected folders yet',
            detail: 'Add a protected folder to start scanning protection coverage in the desktop app.',
        },
        scanBanner: {
            state: runtime?.scanState?.state || 'idle',
            processed: Number(runtime?.scanState?.processed || 0),
            total: Number(runtime?.scanState?.total || 0),
            percent: Number(runtime?.scanState?.total || 0) > 0
                ? Math.round((Number(runtime?.scanState?.processed || 0) / Number(runtime?.scanState?.total || 0)) * 100)
                : 0,
            rootCount: Object.keys(runtime?.scanState?.rootProgress || {}).length,
        },
    });
const buildPersonalDevicesModelValue = typeof uiUtils.buildPersonalDevicesModel === 'function'
    ? uiUtils.buildPersonalDevicesModel
    : ({ currentDeviceId = null, devices = [] } = {}) => ({
        currentDevice: devices.find(device => device?.device_id === currentDeviceId) || null,
        trustedDevices: [],
        setupDevices: [],
        reviewDevices: [],
        hasAttention: false,
    });
const terminalUtils = window.HybridCipherTerminalUtils || {};
const TERMINAL_RENDERER_XTERM = terminalUtils.TERMINAL_RENDERER_XTERM || 'xterm';
const TERMINAL_RENDERER_FALLBACK = terminalUtils.TERMINAL_RENDERER_FALLBACK || 'fallback';
const getStoredTerminalRendererValue = typeof terminalUtils.getStoredTerminalRenderer === 'function'
    ? terminalUtils.getStoredTerminalRenderer
    : () => TERMINAL_RENDERER_XTERM;
const isStoredTerminalDebugEnabledValue = typeof terminalUtils.isStoredTerminalDebugEnabled === 'function'
    ? terminalUtils.isStoredTerminalDebugEnabled
    : () => false;
const createTerminalDiagnosticSnapshotValue = typeof terminalUtils.createTerminalDiagnosticSnapshot === 'function'
    ? terminalUtils.createTerminalDiagnosticSnapshot
    : ({ tabId = null, sessionId = null, event = 'unknown' } = {}) => ({
        tabId,
        sessionId,
        event,
        textareaIsActive: false,
        xtermHasFocusClass: false,
        rows: null,
        cols: null,
        hostVisible: false,
        hostWidth: null,
        hostHeight: null,
        hostOccluded: null,
        occludingElementTag: null,
        occludingElementId: null,
        selectionOverlayCount: 0,
        termHasSelection: false,
        selectionTextLength: 0,
        activeElementTag: null,
        activeElementId: null,
    });
const betaUxUtils = window.HybridCipherBetaUxUtils || {};
const classifyEnrollmentFailureValue = typeof betaUxUtils.classifyEnrollmentFailure === 'function'
    ? betaUxUtils.classifyEnrollmentFailure
    : ({ folderPath = '' } = {}) => ({
        kind: 'generic',
        title: 'HybridCipher could not protect this folder',
        detail: `Review the terminal output for the exact CLI error, then retry after correcting the path or permissions for "${folderPath}".`,
        retryLabel: 'Try again',
    });
const buildForceUnmountConfirmationValue = typeof betaUxUtils.buildForceUnmountConfirmation === 'function'
    ? betaUxUtils.buildForceUnmountConfirmation
    : ({ folderLabel = 'all mounted folders' } = {}) => ({
        title: `Force unmount ${folderLabel}`,
        message: `Force unmount ${folderLabel}?`,
        detail: 'This may cause file loss. Type FORCE to confirm that you want to continue.',
        confirmationToken: 'FORCE',
    });
const buildMountProgressModelValue = typeof betaUxUtils.buildMountProgressModel === 'function'
    ? betaUxUtils.buildMountProgressModel
    : ({
        folderLabel = 'folder',
        folderPath = '',
        elapsedMs = 0,
        continueEnableMs = 10000,
    } = {}) => {
        const remainingMs = Math.max(0, Number(continueEnableMs || 0) - Number(elapsedMs || 0));
        const remainingSecs = Math.ceil(remainingMs / 1000);
        const canContinue = remainingMs <= 0;
        return {
            title: `Mounting ${folderLabel}`,
            folderLabel,
            folderPath,
            status: canContinue ? 'Mounting folder in background...' : 'Starting mount...',
            hint: canContinue
                ? 'You can continue in background and keep using the app while HybridCipher finishes mounting this folder.'
                : `Continue in background available in ${remainingSecs}s while HybridCipher initializes this folder.`,
            canContinue,
        };
    };
const buildMountTimeoutMessageValue = typeof betaUxUtils.buildMountTimeoutMessage === 'function'
    ? betaUxUtils.buildMountTimeoutMessage
    : ({ folderLabel = 'folder', folderPath = '', inBackground = false } = {}) => [
        inBackground
            ? `Mount for ${folderLabel} did not finish in the background.`
            : `Mount for ${folderLabel} did not finish.`,
        folderPath ? `Folder: ${folderPath}.` : '',
        'Review the embedded terminal output for the mount command, then retry if needed.',
        'Before retrying, check whether the folder is already mounted.'
    ].filter(Boolean).join(' ');
const autoMountUtils = window.HybridCipherAutoMountUtils || {};
const loadAutoMountPreferenceValue = typeof autoMountUtils.loadAutoMountPreference === 'function'
    ? autoMountUtils.loadAutoMountPreference
    : () => true;
const saveAutoMountPreferenceValue = typeof autoMountUtils.saveAutoMountPreference === 'function'
    ? autoMountUtils.saveAutoMountPreference
    : () => {};
const loadLastMountedRootIdValue = typeof autoMountUtils.loadLastMountedRootId === 'function'
    ? autoMountUtils.loadLastMountedRootId
    : () => null;
const saveLastMountedRootIdValue = typeof autoMountUtils.saveLastMountedRootId === 'function'
    ? autoMountUtils.saveLastMountedRootId
    : () => {};
const resolveAutoMountFolderValue = typeof autoMountUtils.resolveAutoMountFolder === 'function'
    ? autoMountUtils.resolveAutoMountFolder
    : () => null;
const legalUtils = window.HybridCipherLegalUtils || {};
const readStoredLegalAcceptanceValue = typeof legalUtils.readStoredLegalAcceptance === 'function'
    ? legalUtils.readStoredLegalAcceptance
    : () => null;
const hasAcceptedLegalVersionValue = typeof legalUtils.hasAcceptedLegalVersion === 'function'
    ? legalUtils.hasAcceptedLegalVersion
    : () => false;
const saveLegalAcceptanceValue = typeof legalUtils.saveLegalAcceptance === 'function'
    ? legalUtils.saveLegalAcceptance
    : (_storageLike, version, acceptedAt = new Date().toISOString()) => ({
        version: String(version || ''),
        acceptedAt,
    });
const releaseNotesUtils = window.HybridCipherReleaseNotesUtils || {};
const resolveReleaseNotesStartupValue = typeof releaseNotesUtils.resolveReleaseNotesStartup === 'function'
    ? releaseNotesUtils.resolveReleaseNotesStartup
    : () => ({
        shouldShow: false,
        reason: 'release-notes-utils-unavailable',
        currentVersion: null,
        previousVersion: null,
        modal: null,
    });
const finalizeReleaseNotesVersionValue = typeof releaseNotesUtils.finalizeReleaseNotesVersion === 'function'
    ? releaseNotesUtils.finalizeReleaseNotesVersion
    : () => null;

class HybridCipherApp {
    constructor() {
        this.currentUser = null;
        this.currentDeviceId = null;
        this.enrolledFolders = [];
        this.selectedFolder = null;
        this.currentMountPath = null;
        this.isLoggedIn = false;
        this.adminPanelVisible = false;
        this.appMode = 'individual';
        this.activeWorkspaceView = 'home';
        this.rememberMePreference = this.loadRememberPreference();
        this.autoMountLastFolderPreference = this.loadAutoMountLastFolderPreference();
        this.userFolderPreferences = this.loadFolderPreferences();
        this.mountProgressInterval = null;
        this.mountProgressValue = 0;
        this.mountProgressMountPath = null;
        this.mountProgressJobs = {};
        this.mountProgressModalRootId = null;
        this.mountProgressUiTimer = null;
        this.mountContinueEnableMs = 10 * 1000;
        this.mountCancelEnableMs = 120 * 1000;
        this.mountBackgroundTimeoutMs = 120 * 1000;
        this.isSidebarCollapsed = false;
        this.cliCommands = this.loadCliCommandConfig();
        this.commandPaletteOpen = false;
        this.commandPaletteResults = [];
        this.commandPaletteIndex = -1;
        this.commandPaletteRecentLimit = 6;
        this.commandPaletteSuggestionLimit = 8;
        this.commandPaletteStorageKey = 'hybridcipher_cli_recent';
        this.markersReminderDismissed = this.loadMarkersReminderDismissed();
        this.hasShownMarkersReminder = false;
        this.markersReminderEnabled = false;
        this.securityStatus = null;
        this.securityWarnings = [];
        this.homeStatusSnapshot = null;
        this.personalDevicesOverview = null;
        this.coverageCenterSnapshot = null;
        this.coverageCenterState = {
            loading: false,
            error: null,
            scanState: {
                state: 'idle',
                processed: 0,
                total: 0,
                rootProgress: {},
            },
        };
        this.mfaPromptTimer = null;
        this.pendingMfaPrompt = false;
        this.mfaEnrollData = null;
        this.availableUpdate = null;
        this.updatePreference = localStorage.getItem('hybridcipher_update_preference') || 'automatic';
        this.updateInstallInProgress = false;
        this.updateRestartCountdownTimer = null;
        this.updateRestartRemainingSecs = 15;
        this.terminalVisible = true; // Terminal visible by default
        this.isRegisterOverlay = false;
        this.registerOverlayPrevTerminalVisible = null;
        this.registerOverlaySessionId = null;
        this.registerOverlayCompletionHandled = false;
        this.registerSentinelBuffers = {};
        this.registerOverlayCommandEchoBySession = {};
        this.pendingRegistrationEmail = null;
        this.pendingRegistrationPassword = null;
        this.activeQueueDetails = null;
        this.operationsRefreshIntervalSecs = null;
        this.operationsRefreshTimer = null;
        this.operationsRefreshInFlight = false;
        this.sessionHealthTimer = null;
        this.sessionHealthCheckInFlight = false;
        this.sessionHealthIntervalMs = 60 * 1000;
        this.sessionExpiryGraceMs = 5 * 1000;
        this.lastHealthCheckTime = Date.now();
        this.pendingDevicesCache = [];
        this.pendingDevicesPage = 1;
        this.pendingDevicesPageSize = 6;
        this.unverifiedDevicesCache = [];
        this.unverifiedDevicesPage = 1;
        this.unverifiedDevicesPageSize = 6;
        this.staleDevicesCache = [];
        this.staleDevicesPage = 1;
        this.staleDevicesPageSize = 6;
        this.confirmationPollTimer = null;
        this.confirmationPollDeadline = null;
        this.confirmationCheckInFlight = false;
        this.confirmationVerified = false;
        this.lastConfirmationResendAt = 0;
        this.resendCooldownTimer = null;
        this.registerSubmitting = false;
        this.loggingMessageTimer = null;
        this.loggingLongWaitTimer = null;
        this.loggingMessageIndex = 0;
        this.terminalHistory = [];
        this.terminalHistoryIndex = -1;
        this.terminalCwd = null;
        this.switchGroupSelectedId = null;
        this.switchGroupCurrentId = null;
        this.switchGroupCloseSettings = false;
        this.groupSwitchRefreshTimers = [];
        // Platform information for native terminal styling
        this.platformInfo = null;
        this.preferredTerminalRenderer = getStoredTerminalRendererValue(window.localStorage);
        this.xtermDebugEnabled = isStoredTerminalDebugEnabledValue(window.localStorage);
        this.useXterm = this.preferredTerminalRenderer === TERMINAL_RENDERER_XTERM
            && typeof window.Terminal === 'function';
        this.xtermByTabId = {};
        this.xtermFitByTabId = {};
        this.xtermInputBufferByTab = {};
        this.xtermResizeObserverByTab = {};
        this.xtermDiagnosticsAttachedByTab = {};
        this.xtermDiagnosticLastEventAt = {};
        this.pendingTerminalDataByTab = {};
        this.startingTerminalSessionByTab = {};
        this.welcomeMessageShownByTab = {};
        // Terminal tab management
        this.terminalTabs = [{ id: 1, title: 'Welcome', history: [], historyIndex: -1, output: [], sessionId: null }];
        this.activeTabId = 1;
        this.nextTabId = 2;
        this.welcomeTabId = 1;
        // Terminal line buffers now track cursor position for proper editing
        // currentLine: full line content, cursorPos: position within line, lineEl: DOM element
        this.tabLineBuffers = { 1: { currentLine: '', cursorPos: 0, lineEl: null } };
        this.terminalRenderIntervalMs = 33;
        this.terminalRenderQueues = {};
        // Cache for CLI binary path
        this.cachedCliPath = null;
        // Track PTY sessions for each mount by root_id
        this.mountSessions = {}; // root_id -> sessionId
        // Active mounts keyed by root_id -> mountpoint
        this.activeMountsByRootId = {};
        this.activeMountDetailsByRootId = {};
        this.folderCoverageReviewsByRootId = {};
        this.latestPostQuantumModel = null;
        this.recoveryPromptFingerprintByRootId = {};
        this.conflictCenterState = {
            rootId: null,
            folder: null,
            records: [],
            selectedConflictId: null
        };
        this.activeConflictPreview = null;
        this.recoveryCenterState = {
            rootId: null,
            folder: null,
            records: [],
            selectedRecoveryPath: null
        };
        this.activeRecoveryPreview = null;
        this.mountStatusRefreshTimer = null;
        this.mountStatusPollTimer = null;
        this.mountStatusPollIntervalMs = 3000;
        this.quitFlowInProgress = false;
        this.promptResponders = {};
        this.promptEchoSuppress = {};
        this.actionProgressTimer = null;
        this.actionProgressIndex = 0;
        this.welcomeModalDismissedStorageKey = 'hybridcipher_welcome_modal_dismissed_v1';
        this.coverageCommandTrackers = {};
        this.coverageCommandPollIntervalMs = 2500;
        this.coverageCommandTimeoutMs = 10 * 60 * 1000;
        this.adminPinVerifyMembers = [];
        this.legalDocuments = null;
        this.legalDocumentsLoading = false;
        this.legalDocumentsError = null;
        this.legalDocumentOrder = [];
        this.legalActiveDocumentId = 'terms';
        this.legalModalRequiresAcceptance = false;
        this.releaseNotesModalModel = null;
        this.releaseNotesModalVersion = null;

        this.init();
    }

    async init() {
        console.log('Initializing HybridCipher app...');

        // Fetch platform info for terminal styling
        await this.fetchPlatformInfo();
        this.setupTerminalEvents();

        // Set up event listeners
        this.setupEventListeners();
        this.setupSidebarResizeHandle();
        this.updateTerminalTabControls();
        this.setupQueueRowState();

        // Load desktop runtime timing config (session health + mount modal behavior).
        await this.loadSessionHealthConfig();

        // Check session and restore if exists
        await this.checkSession();

        await this.initializeLegalDocuments();
        if (this.hasAcceptedCurrentLegalVersion()) {
            await this.runPostLegalStartupFlow();
        }

        // Check for updates after a short delay to avoid blocking startup
        setTimeout(() => this.checkForUpdates(), 5000);
    }

    setupQueueRowState() {
        document
            .querySelectorAll('#adminIssueWelcomeQueue, #adminStaleDevicesQueue, #adminUnverifiedDevicesQueue')
            .forEach(row => row.classList.add('queue-clickable'));
    }

    // ========================================================================
    // Layout Management
    // ========================================================================

    showWelcomeScreen() {
        document.getElementById('welcomeScreen').style.display = 'flex';
        const appContainer = document.getElementById('appContainer');
        if (appContainer) {
            appContainer.style.display = 'none';
            appContainer.classList.remove('register-overlay');
        }
        this.setAdminPanelVisible(false);
        this.isRegisterOverlay = false;
        this.registerOverlayPrevTerminalVisible = null;
        this.isLoggedIn = false;
        this.stopSessionHealthTimer();
        this.stopOperationsRefreshTimer();
        this.hasShownMarkersReminder = false;
        this.hideMarkersReminder();
        this.pendingMfaPrompt = false;
        if (this.mfaPromptTimer) {
            clearTimeout(this.mfaPromptTimer);
            this.mfaPromptTimer = null;
        }
        this.hideSecurityPanel();
        this.hidePostQuantumExplainer();
        this.hideMfaPromptModal();
        this.hideMfaSetupModal();
        if (this.mountStatusRefreshTimer) {
            clearTimeout(this.mountStatusRefreshTimer);
            this.mountStatusRefreshTimer = null;
        }
        this.stopMountStatusPolling();
        this.activeMountsByRootId = {};
        this.activeMountDetailsByRootId = {};
        this.folderCoverageReviewsByRootId = {};
        this.recoveryPromptFingerprintByRootId = {};
        this.resetConflictWorkflowState();
        this.quitFlowInProgress = false;
        this.updateMountButtons(false);
        this.updateSidebarMountSummary();
        this.stopMountProgress();
        this.activeWorkspaceView = 'home';
        this.homeStatusSnapshot = null;
        this.personalDevicesOverview = null;
        this.coverageCenterSnapshot = null;
        this.coverageCenterState = {
            loading: false,
            error: null,
            scanState: {
                state: 'idle',
                processed: 0,
                total: 0,
                rootProgress: {},
            },
        };
        this.latestPostQuantumModel = null;

    }

    showMainApp({ skipLoadEnrolledFolders = false } = {}) {
        document.getElementById('welcomeScreen').style.display = 'none';
        const appContainer = document.getElementById('appContainer');
        if (appContainer) {
            appContainer.style.display = 'flex';
            appContainer.classList.remove('register-overlay');
        }
        this.applyAppMode();
        this.setAdminPanelVisible(false);
        this.isRegisterOverlay = false;
        this.registerOverlayPrevTerminalVisible = null;
        this.isLoggedIn = true;
        this.updateMountButtons(false);
        this.updateSidebarMountSummary();
        this.startMountStatusPolling();
        this.startSessionHealthTimer();

        // Restore sidebar state
        const sidebarCollapsed = localStorage.getItem('hybridcipher_sidebar_collapsed') === 'true';
        if (sidebarCollapsed) {
            this.isSidebarCollapsed = true;
            document.getElementById('sidebar')?.classList.add('collapsed');
            document.getElementById('mainContent')?.classList.add('sidebar-collapsed');
        }

        if (!skipLoadEnrolledFolders) {
            this.loadEnrolledFolders();
        }

        // Keep terminal ready in the background, but land on Workspace Home.
        this.updateTerminalCwdDisplay();
        this.updateTerminalHeader();
        this.updateTerminalPromptSymbol();
        this.ensureTerminalWelcome();
        this.startTerminalSessionForTab(this.welcomeTabId);
        this.showWorkspaceHome();
    }

    setAdminPanelVisible(visible) {
        if (this.appMode === 'individual') {
            this.adminPanelVisible = false;
            const workspace = document.getElementById('workspace');
            const adminDashboard = document.getElementById('adminDashboard');
            const adminPanelBtn = document.getElementById('adminPanelBtn');
            if (workspace) {
                workspace.classList.remove('admin-panel-visible');
            }
            if (adminDashboard) {
                adminDashboard.style.display = 'none';
                adminDashboard.setAttribute('aria-hidden', 'true');
            }
            if (adminPanelBtn) {
                adminPanelBtn.classList.add('hidden');
                adminPanelBtn.setAttribute('aria-hidden', 'true');
                adminPanelBtn.tabIndex = -1;
                adminPanelBtn.setAttribute('aria-pressed', 'false');
            }
            if (visible) {
                this.showWorkspaceHome();
            }
            return;
        }

        this.adminPanelVisible = Boolean(visible);
        const workspace = document.getElementById('workspace');
        const adminDashboard = document.getElementById('adminDashboard');
        const terminalContainer = document.getElementById('terminalContainer');
        const fileBrowser = document.getElementById('fileBrowser');
        if (workspace) {
            workspace.classList.toggle('admin-panel-visible', this.adminPanelVisible);
        }
        if (this.adminPanelVisible) {
            if (adminDashboard) adminDashboard.style.display = 'flex';
            if (terminalContainer) terminalContainer.style.display = 'none';
            if (fileBrowser) fileBrowser.style.display = 'none';
        } else {
            if (adminDashboard) adminDashboard.style.display = '';
            if (terminalContainer) {
                terminalContainer.style.display = this.terminalVisible ? 'flex' : 'none';
            }
            if (fileBrowser) {
                fileBrowser.style.display = this.terminalVisible ? 'none' : 'flex';
            }
            if (this.terminalVisible && this.shouldUseXtermForTab(this.activeTabId)) {
                this.ensureXtermForTab(this.activeTabId);
                this.fitActiveXterm();
            }
        }
        const adminPanelBtn = document.getElementById('adminPanelBtn');
        if (adminPanelBtn) {
            const label = adminPanelBtn.querySelector('.btn-label');
            if (label) {
                label.textContent = this.adminPanelVisible ? 'Hide panel' : 'Admin panel';
            }
            adminPanelBtn.setAttribute('aria-pressed', this.adminPanelVisible ? 'true' : 'false');
        }
        if (this.adminPanelVisible) {
            this.refreshAdminDashboard();
        }
    }

    toggleAdminPanel() {
        if (this.appMode === 'individual') {
            this.showWorkspaceHome();
            return;
        }
        this.setAdminPanelVisible(!this.adminPanelVisible);
    }

    applyAppMode() {
        const appContainer = document.getElementById('appContainer');
        const adminPanelBtn = document.getElementById('adminPanelBtn');
        const sidebarSwitchGroupBtn = document.getElementById('sidebarSwitchGroupBtn');

        if (appContainer) {
            appContainer.setAttribute('data-app-mode', this.appMode);
        }
        if (this.appMode === 'individual') {
            adminPanelBtn?.classList.add('hidden');
            adminPanelBtn?.setAttribute('aria-hidden', 'true');
            if (adminPanelBtn) {
                adminPanelBtn.tabIndex = -1;
            }
            sidebarSwitchGroupBtn?.classList.add('hidden');
        }
    }

    setWorkspaceView(view) {
        const nextView = this.appMode === 'individual' && view === 'admin' ? 'home' : view;
        this.activeWorkspaceView = nextView;

        const workspaceHome = document.getElementById('workspaceHome');
        const folderDetail = document.getElementById('folderDetailView');
        const devicesCenter = document.getElementById('devicesCenterView');
        const coverageCenter = document.getElementById('coverageCenterView');
        const adminDashboard = document.getElementById('adminDashboard');
        const terminalContainer = document.getElementById('terminalContainer');
        const fileBrowser = document.getElementById('fileBrowser');
        const mainContent = document.getElementById('mainContent');

        if (workspaceHome) {
            workspaceHome.style.display = nextView === 'home' ? 'flex' : 'none';
        }
        if (folderDetail) {
            folderDetail.style.display = nextView === 'folder-detail' ? 'flex' : 'none';
        }
        if (devicesCenter) {
            devicesCenter.style.display = nextView === 'devices' ? 'flex' : 'none';
        }
        if (coverageCenter) {
            coverageCenter.style.display = nextView === 'coverage' ? 'flex' : 'none';
        }
        if (adminDashboard) {
            adminDashboard.style.display = nextView === 'admin' ? 'flex' : 'none';
            adminDashboard.setAttribute('aria-hidden', nextView === 'admin' ? 'false' : 'true');
        }
        if (terminalContainer) {
            terminalContainer.style.display = nextView === 'terminal' ? 'flex' : 'none';
        }
        if (fileBrowser) {
            fileBrowser.style.display = nextView === 'file-browser' ? 'flex' : 'none';
        }
        if (mainContent) {
            mainContent.classList.toggle('terminal-visible', nextView === 'terminal');
        }

        this.updateSidebarViewButtons();
    }

    showWorkspaceHome() {
        this.setWorkspaceView('home');
        this.updateWorkspaceHomeSummary();
        this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true });
    }

    showFolderDetail(folder = this.selectedFolder) {
        if (!folder) {
            this.showWorkspaceHome();
            return;
        }
        this.setWorkspaceView('folder-detail');
        this.renderFolderDetailView(folder);
    }

    async showDevicesView({ suppressErrorNotification = false } = {}) {
        this.setWorkspaceView('devices');
        this.renderDevicesCenterLoading();
        await this.refreshPersonalDevicesOverview({ suppressErrorNotification });
    }

    showTerminalView() {
        this.terminalVisible = true;
        this.setWorkspaceView('terminal');
        this.updateTerminalCwdDisplay();
        this.updateTerminalHeader();
        this.ensureTerminalWelcome();
        this.updateTerminalPromptSymbol();
        this.focusTerminalArea();
        this.startTerminalSessionForTab(this.activeTabId);
        if (this.shouldUseXtermForTab(this.activeTabId)) {
            this.ensureXtermForTab(this.activeTabId);
            this.fitActiveXterm();
        } else {
            this.applyCursorToActiveTab();
        }
    }

    showFileBrowserView() {
        this.terminalVisible = false;
        this.setWorkspaceView('file-browser');
    }

    updateSidebarViewButtons() {
        const homeBtn = document.getElementById('sidebarHomeBtn');
        const terminalBtn = document.getElementById('sidebarTerminalBtn');
        const isHome = this.activeWorkspaceView === 'home';
        const isTerminal = this.activeWorkspaceView === 'terminal';

        if (homeBtn) {
            homeBtn.classList.toggle('active', isHome);
            homeBtn.setAttribute('aria-pressed', isHome ? 'true' : 'false');
        }
        if (terminalBtn) {
            terminalBtn.classList.toggle('active', isTerminal);
            terminalBtn.setAttribute('aria-pressed', isTerminal ? 'true' : 'false');
        }
    }

    getCurrentPostQuantumModel() {
        const folders = Array.isArray(this.enrolledFolders) ? this.enrolledFolders : [];
        const snapshot = this.homeStatusSnapshot || {};
        return buildPostQuantumStatusModelValue({
            protectedCount: Number.isFinite(Number(snapshot.protected_count))
                ? Number(snapshot.protected_count)
                : folders.length,
            status: snapshot.post_quantum_status || null,
            primaryText: snapshot.post_quantum_primary_text || null,
            secondaryText: snapshot.post_quantum_secondary_text || null,
            explainerAvailable: snapshot.post_quantum_explainer_available !== false,
        });
    }

    renderPostQuantumBadge(postQuantum = this.getCurrentPostQuantumModel()) {
        const badge = document.getElementById('postQuantumBadge');
        const eyebrowEl = document.getElementById('postQuantumBadgeEyebrow');
        const labelEl = document.getElementById('postQuantumBadgeLabel');
        if (!badge || !eyebrowEl || !labelEl) return;

        const model = postQuantum || buildPostQuantumStatusModelValue();
        this.latestPostQuantumModel = model;

        const shouldShow = this.isLoggedIn && this.appMode === 'individual';
        badge.classList.toggle('hidden', !shouldShow);
        if (!shouldShow) {
            badge.setAttribute('aria-hidden', 'true');
            return;
        }

        badge.setAttribute('aria-hidden', 'false');
        badge.classList.remove('tone-safe', 'tone-warning', 'tone-idle');
        badge.classList.add(`tone-${model.tone || 'idle'}`);
        eyebrowEl.textContent = model.shellBadge?.eyebrow || 'Post-quantum protection';
        labelEl.textContent = model.shellBadge?.label || model.primaryText || 'Protection status unknown';
        badge.title = `${model.shellBadge?.eyebrow || 'Post-quantum protection'}\n${model.shellBadge?.detail || model.secondaryText || ''}`;
        badge.setAttribute(
            'aria-label',
            `${model.shellBadge?.eyebrow || 'Post-quantum protection'}: ${model.shellBadge?.label || model.primaryText || 'Protection status unknown'}`
        );
        badge.dataset.workspaceAction = model.shellBadge?.action || '';
    }

    showPostQuantumExplainer() {
        const modal = document.getElementById('postQuantumExplainerModal');
        const titleEl = document.getElementById('postQuantumExplainerTitle');
        const bodyEl = document.getElementById('postQuantumExplainerBody');
        if (!modal || !titleEl || !bodyEl) return;

        const model = this.latestPostQuantumModel || this.getCurrentPostQuantumModel();
        titleEl.textContent = model.explainer?.title || 'Why post-quantum protection matters';
        bodyEl.textContent = model.explainer?.body
            || 'Your protected files are secured with hybrid post-quantum encryption, designed to protect against today’s attackers and to remain secure even if stolen encrypted data is targeted by future quantum-capable systems.';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    }

    openPostQuantumAttention() {
        this.showWorkspaceHome();
        requestAnimationFrame(() => {
            const panel = document.getElementById('workspaceHomeAttentionPanel');
            panel?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    }

    hidePostQuantumExplainer() {
        const modal = document.getElementById('postQuantumExplainerModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    }

    updateWorkspaceHomeSummary() {
        const folders = Array.isArray(this.enrolledFolders) ? this.enrolledFolders : [];
        const mountedCount = folders.reduce((count, folder) => {
            if (folder?.root_id && this.isRootMounted(folder.root_id)) {
                return count + 1;
            }
            return count;
        }, 0);
        const folderAttention = Object.values(this.activeMountDetailsByRootId || {}).reduce((summary, detail) => {
            const syncStatus = detail?.syncStatus || {};
            summary.conflicts += Number(syncStatus.pending_conflict_count || 0);
            summary.recovery_copies += Number(syncStatus.recovered_pending_copy_count || 0);
            return summary;
        }, { conflicts: 0, recovery_copies: 0 });
        const snapshot = {
            ...(this.homeStatusSnapshot || {}),
            protected_count: folders.length,
            mounted_count: mountedCount,
            folder_attention: folderAttention,
            current_device: this.homeStatusSnapshot?.current_device
                || (this.currentDeviceId ? { device_id: this.currentDeviceId, is_verified: true } : null),
            device_counts: this.homeStatusSnapshot?.device_counts || {
                trusted: 0,
                pending: 0,
                stale: 0,
                unverified: 0,
            },
        };
        const model = buildWorkspaceHomeModelValue(snapshot, { nowMs: Date.now() });
        this.renderPostQuantumBadge(model.postQuantum);

        const leadEl = document.getElementById('workspaceHomeLead');
        const protectedCountEl = document.getElementById('workspaceHomeProtectedCount');
        const mountedCountEl = document.getElementById('workspaceHomeMountedCount');
        const statusLabelEl = document.getElementById('workspaceHomeStatusLabel');
        const summaryCard = document.getElementById('workspaceHomeSummaryCard');
        const cardGrid = document.getElementById('workspaceHomeCardGrid');
        const attentionList = document.getElementById('workspaceHomeAttentionList');
        const attentionPanel = document.getElementById('workspaceHomeAttentionPanel');

        if (leadEl) {
            if (folders.length === 0) {
                leadEl.textContent = 'Add a protected folder to start securing files on this account.';
            } else if (model.attentionItems.length > 0) {
                leadEl.textContent = `Your protected folders are secured now with post-quantum encryption, but ${model.attentionItems.length} protection check${model.attentionItems.length === 1 ? '' : 's'} need attention.`;
            } else {
                leadEl.textContent = 'Your protected folders are secured now with post-quantum encryption, and sign-in protection, backup status, and this device are all in a good state.';
            }
        }
        if (protectedCountEl) protectedCountEl.textContent = String(model.protectedCount);
        if (mountedCountEl) mountedCountEl.textContent = String(model.mountedCount);
        if (statusLabelEl) statusLabelEl.textContent = model.summaryLabel;
        if (summaryCard) {
            summaryCard.classList.toggle('is-danger', model.summaryTone === 'danger');
            summaryCard.classList.toggle('is-safe', model.summaryTone === 'safe');
        }
        if (cardGrid) {
            cardGrid.innerHTML = model.cards.map(card => `
                <article class="workspace-health-card tone-${this.escapeHtmlAttr(card.tone || 'idle')}">
                    <div class="workspace-health-card-label">${this.escapeHtml(card.title)}</div>
                    <div class="workspace-health-card-value">${this.escapeHtml(card.value || '—')}</div>
                    <p class="workspace-health-card-detail">${this.escapeHtml(card.detail || '')}</p>
                    ${card.ctaAction ? `
                        <button class="btn btn-secondary btn-small workspace-health-card-btn"
                            type="button"
                            data-workspace-action="${this.escapeHtmlAttr(card.ctaAction)}">
                            ${this.escapeHtml(card.ctaLabel || 'Open')}
                        </button>
                    ` : ''}
                </article>
            `).join('');
            cardGrid.querySelectorAll('[data-workspace-action]').forEach(button => {
                button.addEventListener('click', () => this.handleWorkspaceHomeAction(button.dataset.workspaceAction));
            });
        }
        if (attentionList && attentionPanel) {
            const items = model.attentionItems;
            attentionList.innerHTML = items.length > 0
                ? items.map(item => `
                    <div class="workspace-attention-item">
                        <div>
                            <div class="workspace-attention-title">${this.escapeHtml(item.title)}</div>
                            <div class="workspace-attention-detail">${this.escapeHtml(item.detail || '')}</div>
                        </div>
                        <button class="btn btn-secondary btn-small"
                            type="button"
                            data-workspace-action="${this.escapeHtmlAttr(item.action?.id || item.action || '')}">
                            ${this.escapeHtml(item.action?.label || 'Review')}
                        </button>
                    </div>
                `).join('')
                : '<div class="workspace-attention-empty">Nothing needs attention right now.</div>';
            attentionPanel.classList.toggle('is-clear', items.length === 0);
            attentionList.querySelectorAll('[data-workspace-action]').forEach(button => {
                button.addEventListener('click', () => this.handleWorkspaceHomeAction(button.dataset.workspaceAction));
            });
        }
    }

    async refreshWorkspaceHomeStatus({ suppressErrorNotification = false } = {}) {
        if (!this.isLoggedIn) return;
        try {
            const result = await invoke('get_individual_home_status');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Workspace status unavailable');
            }
            this.homeStatusSnapshot = result.data;
            this.updateWorkspaceHomeSummary();
        } catch (error) {
            console.error('Failed to refresh workspace home status:', error);
            if (!suppressErrorNotification) {
                this.showNotification('Failed to refresh workspace status.', 'warning');
            }
            this.updateWorkspaceHomeSummary();
        }
    }

    showCoverageView({ autoStartScan = false } = {}) {
        this.setWorkspaceView('coverage');
        this.renderCoverageCenter();
        this.refreshCoverageCenter({ suppressLoadingState: false }).then(() => {
            if (autoStartScan) {
                this.startCoverageScan({ rootPath: null });
            }
        });
    }

    async refreshCoverageCenter({ suppressLoadingState = false } = {}) {
        if (!this.isLoggedIn) return;
        if (!suppressLoadingState) {
            this.coverageCenterState.loading = true;
            this.coverageCenterState.error = null;
            this.renderCoverageCenter();
        }

        try {
            const result = await invoke('get_coverage_center_snapshot');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Coverage snapshot unavailable');
            }
            this.coverageCenterSnapshot = result.data;
            this.coverageCenterState.loading = false;
            this.coverageCenterState.error = null;
        } catch (error) {
            console.error('Failed to refresh coverage center:', error);
            this.coverageCenterState.loading = false;
            this.coverageCenterState.error = error?.message || 'Coverage snapshot unavailable';
        }

        this.renderCoverageCenter();
    }

    renderCoverageCenter() {
        const container = document.getElementById('coverageCenterContent');
        if (!container) return;

        if (this.coverageCenterState.loading && !this.coverageCenterSnapshot) {
            container.innerHTML = `
                <div class="workspace-empty-state">
                    <h3>Loading coverage</h3>
                    <p>Refreshing your protected-folder coverage state.</p>
                </div>
            `;
            return;
        }

        if (this.coverageCenterState.error && !this.coverageCenterSnapshot) {
            container.innerHTML = `
                <div class="workspace-empty-state">
                    <h3>Coverage unavailable</h3>
                    <p>${this.escapeHtml(this.coverageCenterState.error)}</p>
                    <button class="btn btn-secondary" id="coverageRetryBtn" type="button">Try again</button>
                </div>
            `;
            document.getElementById('coverageRetryBtn')?.addEventListener('click', () => {
                this.refreshCoverageCenter({ suppressLoadingState: false });
            });
            return;
        }

        const model = buildCoverageCenterModelValue(
            this.coverageCenterSnapshot || {},
            { scanState: this.coverageCenterState.scanState }
        );
        const scanTone = model.scanBanner.state === 'error'
            ? 'danger'
            : (model.scanBanner.state === 'success'
                ? 'safe'
                : (model.scanBanner.state === 'running' ? 'warning' : 'idle'));
        const scanMessage = model.scanBanner.state === 'running'
            ? `Scanning ${this.formatCount(model.scanBanner.processed)} of ${this.formatCount(model.scanBanner.total)} files across ${this.formatCount(model.scanBanner.rootCount || 1)} root${model.scanBanner.rootCount === 1 ? '' : 's'}.`
            : (model.scanBanner.state === 'success'
                ? 'Coverage scan completed. Review folders below if anything still needs attention.'
                : (model.scanBanner.state === 'error'
                    ? (this.coverageCenterState.error || 'Coverage scan failed.')
                    : 'Run a coverage scan to check which files in your protected folders are already tracked and which ones still need review or protection.'));

        container.innerHTML = `
            <div class="coverage-center-shell">
                <div class="coverage-center-hero">
                    <div class="coverage-center-copy">
                        <span class="workspace-home-eyebrow">Coverage center</span>
                        <h2 class="workspace-home-title">Protection coverage center</h2>
                        <p class="workspace-home-text">Review scan freshness, folder coverage, and the next fixes from one screen.</p>
                    </div>
                    <div class="workspace-home-summary-card coverage-center-summary-card">
                        <div>
                            <div class="workspace-home-summary-label">Coverage status</div>
                            <div class="coverage-center-summary-value">${this.escapeHtml(String(model.summary.overallCoveragePercent))}%</div>
                            <p class="workspace-health-card-detail">Across ${this.escapeHtml(this.formatCount(model.summary.folderCount))} protected folder${model.summary.folderCount === 1 ? '' : 's'}.</p>
                        </div>
                        <div class="workspace-home-summary-grid">
                            <div class="workspace-home-stat">
                                <span class="workspace-home-stat-value">${this.escapeHtml(this.formatCount(model.summary.trackedFiles))}</span>
                                <span class="workspace-home-stat-label">Tracked files</span>
                            </div>
                            <div class="workspace-home-stat">
                                <span class="workspace-home-stat-value">${this.escapeHtml(this.formatCount(model.summary.orphanedFiles + model.summary.unmanagedFiles))}</span>
                                <span class="workspace-home-stat-label">Need review</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="coverage-center-grid">
                    <div class="workspace-home-panel">
                        <div class="workspace-home-panel-header">
                            <h3>Scan status</h3>
                            <p>Last scan: ${this.escapeHtml(this.formatSettingsTimestamp(model.summary.lastScanAt))} • Desktop watcher: ${this.escapeHtml(model.summary.ipcState)}</p>
                        </div>
                        <div class="coverage-scan-banner tone-${this.escapeHtmlAttr(scanTone)}">
                            <div class="coverage-scan-banner-header">
                                <strong>${this.escapeHtml(model.summary.scanState === 'running' ? 'Scan in progress' : (model.summary.scanState === 'success' ? 'Scan finished' : (model.summary.scanState === 'error' ? 'Scan failed' : 'Ready to scan')))}</strong>
                                <span>${this.escapeHtml(model.scanBanner.state === 'running' ? `${model.scanBanner.percent}%` : model.summary.ipcState)}</span>
                            </div>
                            <p>${this.escapeHtml(scanMessage)}</p>
                            <div class="coverage-progress-track" aria-hidden="true">
                                <div class="coverage-progress-bar" style="width:${Math.max(0, Math.min(100, Number(model.scanBanner.percent || 0)))}%"></div>
                            </div>
                            <div class="coverage-center-actions">
                                <button class="btn btn-primary" type="button" data-coverage-action="scan-all"${model.summary.scanState === 'running' ? ' disabled' : ''}>Run coverage scan</button>
                                <button class="btn btn-secondary" type="button" data-coverage-action="refresh-center">Refresh status</button>
                            </div>
                        </div>
                    </div>

                    <div class="workspace-home-panel workspace-home-attention-panel ${model.attentionItems.length === 0 ? 'is-clear' : ''}" id="workspaceHomeAttentionPanel">
                        <div class="workspace-home-panel-header">
                            <h3>Needs attention</h3>
                            <p>Folders with uncovered files or cleanup work appear here first.</p>
                        </div>
                        <div class="workspace-home-attention-list">
                            ${model.attentionItems.length > 0
                                ? model.attentionItems.map(item => `
                                    <div class="workspace-attention-item">
                                        <div>
                                            <div class="workspace-attention-title">${this.escapeHtml(item.title)}</div>
                                            <div class="workspace-attention-detail">${this.escapeHtml(item.detail || '')}</div>
                                        </div>
                                        <button class="btn btn-secondary btn-small"
                                            type="button"
                                            data-workspace-action="${this.escapeHtmlAttr(item.action?.id || item.action || '')}">
                                            ${this.escapeHtml(item.action?.label || 'Review')}
                                        </button>
                                    </div>
                                `).join('')
                                : '<div class="workspace-attention-empty">Nothing needs attention right now.</div>'
                            }
                        </div>
                    </div>
                </div>

                <div class="workspace-home-panel">
                    <div class="workspace-home-panel-header">
                        <h3>Protected folders</h3>
                        <p>Open a folder review when something needs fixing, or rescan an individual root.</p>
                    </div>
                    ${model.isEmpty
                        ? `
                            <div class="workspace-empty-state compact">
                                <h3>${this.escapeHtml(model.emptyState.title)}</h3>
                                <p>${this.escapeHtml(model.emptyState.detail)}</p>
                                <button class="btn btn-primary" type="button" data-coverage-action="add-folder">Add protected folder</button>
                            </div>
                        `
                        : `
                            <div class="coverage-folder-list">
                                ${model.folderRows.map(folder => `
                                    <article class="coverage-folder-row ${folder.needsAttention ? 'needs-attention' : 'is-safe'}">
                                        <div class="coverage-folder-row-main">
                                            <div class="coverage-folder-row-title">${this.escapeHtml(folder.name)}</div>
                                            <div class="coverage-folder-row-path">${this.escapeHtml(folder.path)}</div>
                                            <div class="coverage-folder-row-meta">
                                                <span>${this.escapeHtml(folder.coverageLabel)}</span>
                                                <span>${this.escapeHtml(folder.attentionLabel)}</span>
                                                <span>Last scan ${this.escapeHtml(this.formatSettingsTimestamp(folder.lastScanAt))}</span>
                                            </div>
                                        </div>
                                        <div class="coverage-folder-row-side">
                                            <div class="coverage-folder-percent">${this.escapeHtml(String(folder.coveragePercent))}%</div>
                                            <div class="coverage-center-actions">
                                                <button class="btn btn-secondary btn-small" type="button" data-coverage-action="review-folder" data-folder-path="${this.escapeHtmlAttr(folder.path)}">Review</button>
                                                <button class="btn btn-secondary btn-small" type="button" data-coverage-action="scan-folder" data-folder-path="${this.escapeHtmlAttr(folder.path)}"${model.summary.scanState === 'running' ? ' disabled' : ''}>Scan again</button>
                                                ${folder.recommendedAction ? `
                                                    <button class="btn btn-secondary btn-small" type="button" data-coverage-action="review-folder" data-folder-path="${this.escapeHtmlAttr(folder.path)}">
                                                        ${this.escapeHtml(folder.recommendedAction.label)}
                                                    </button>
                                                ` : ''}
                                            </div>
                                        </div>
                                    </article>
                                `).join('')}
                            </div>
                        `
                    }
                </div>

                <div class="workspace-home-panel coverage-center-advanced">
                    <div class="workspace-home-panel-header">
                        <h3>Advanced coverage tools</h3>
                        <p>Proof audit, verify, and recovery commands still live in the embedded terminal for now.</p>
                    </div>
                    <div class="coverage-center-actions">
                        <button class="btn btn-secondary" type="button" data-coverage-action="open-terminal">Open terminal</button>
                    </div>
                </div>
            </div>
        `;

        container.querySelectorAll('[data-coverage-action]').forEach(button => {
            button.addEventListener('click', async () => {
                const action = button.dataset.coverageAction;
                const folderPath = button.dataset.folderPath || null;
                switch (action) {
                    case 'scan-all':
                        await this.startCoverageScan({ rootPath: null });
                        break;
                    case 'scan-folder':
                        await this.startCoverageScan({ rootPath: folderPath });
                        break;
                    case 'refresh-center':
                        await this.refreshCoverageCenter({ suppressLoadingState: false });
                        break;
                    case 'review-folder':
                        await this.handleCoverageFixAction(folderPath, 'review-folder-coverage');
                        break;
                    case 'open-terminal':
                        this.showTerminalView();
                        break;
                    case 'add-folder':
                        await this.addEnrolledFolder();
                        await this.refreshCoverageCenter({ suppressLoadingState: true });
                        break;
                    default:
                        break;
                }
            });
        });
    }

    handleCoverageScanProgress(payload = {}) {
        const rootPath = String(payload.root_path || '').trim();
        if (!rootPath) return;

        const rootProgress = {
            ...(this.coverageCenterState.scanState?.rootProgress || {}),
            [rootPath]: {
                processed: Number(payload.processed || 0),
                total: Number(payload.total || 0),
                rootId: payload.root_id || '',
            },
        };
        const aggregate = Object.values(rootProgress).reduce((summary, entry) => {
            summary.processed += Number(entry?.processed || 0);
            summary.total += Number(entry?.total || 0);
            return summary;
        }, { processed: 0, total: 0 });

        this.coverageCenterState.scanState = {
            state: 'running',
            processed: aggregate.processed,
            total: aggregate.total,
            rootProgress,
        };

        if (this.activeWorkspaceView === 'coverage') {
            this.renderCoverageCenter();
        }
    }

    async handleCoverageScanFinished(payload = {}) {
        const success = payload?.success !== false;
        this.coverageCenterState.scanState = {
            state: success ? 'success' : 'error',
            processed: this.coverageCenterState.scanState?.processed || 0,
            total: this.coverageCenterState.scanState?.total || 0,
            rootProgress: {},
        };
        this.coverageCenterState.error = success ? null : (payload?.error || 'Coverage scan failed.');
        await this.refreshCoverageDependentViews();
    }

    async startCoverageScan({ rootPath = null } = {}) {
        if (this.coverageCenterState.scanState?.state === 'running') {
            return;
        }

        this.coverageCenterState.scanState = {
            state: 'running',
            processed: 0,
            total: 0,
            rootProgress: {},
        };
        this.coverageCenterState.error = null;
        if (this.activeWorkspaceView === 'coverage') {
            this.renderCoverageCenter();
        }

        try {
            const result = await invoke('run_coverage_scan', {
                rootPath: rootPath || null,
            });
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Coverage scan failed.');
            }
        } catch (error) {
            console.error('Coverage scan failed:', error);
            this.coverageCenterState.scanState = {
                state: 'error',
                processed: 0,
                total: 0,
                rootProgress: {},
            };
            this.coverageCenterState.error = error?.message || 'Coverage scan failed.';
            if (this.activeWorkspaceView === 'coverage') {
                this.renderCoverageCenter();
            }
        }
    }

    async handleCoverageFixAction(folderPath, action) {
        const folder = this.enrolledFolders.find(entry => entry.path === folderPath);
        if (!folder) {
            this.showNotification('Protected folder no longer exists in the current list.', 'warning');
            await this.refreshCoverageDependentViews();
            return;
        }

        if (action === 'review-folder-coverage') {
            this.selectFolder(folder, { showDetail: true });
            await this.openFolderCoverageReview(folder, { forceRefresh: true });
            return;
        }
    }

    async refreshCoverageDependentViews() {
        await this.loadEnrolledFolders({ suppressErrorNotification: true });
        await Promise.all([
            this.refreshCoverageCenter({ suppressLoadingState: true }),
            this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true }),
            this.refreshSettingsStatus(),
            this.refreshAdminCoverageSummary(),
        ]);
        if (this.activeWorkspaceView === 'folder-detail' && this.selectedFolder) {
            this.renderFolderDetailView(this.selectedFolder);
        }
        if (this.activeWorkspaceView === 'coverage') {
            this.renderCoverageCenter();
        }
    }

    handleWorkspaceHomeAction(action) {
        switch (action) {
            case 'show-post-quantum-explainer':
                this.showPostQuantumExplainer();
                break;
            case 'open-post-quantum-attention':
                this.openPostQuantumAttention();
                break;
            case 'open-settings-mfa':
                this.openSettingsModal('settingsSecuritySection');
                break;
            case 'open-settings-recovery':
                this.openSettingsModal('settingsRecoverySection');
                break;
            case 'run-coverage-scan':
                this.showCoverageView({ autoStartScan: true });
                break;
            case 'add-protected-folder':
                this.addEnrolledFolder();
                break;
            case 'open-devices':
                this.showDevicesView({ suppressErrorNotification: false });
                break;
            case 'open-folder-issues': {
                const folder = this.enrolledFolders.find(entry =>
                    this.folderHasPendingConflicts(entry) || this.folderHasPendingRecoveryCopies(entry)
                );
                if (folder) {
                    this.selectFolder(folder, { showDetail: true });
                } else {
                    this.showNotification('No mounted folder currently needs review.', 'info');
                }
                break;
            }
            default:
                break;
        }
    }

    getFolderCoverageReviewState(rootId) {
        if (!rootId) return null;
        return this.folderCoverageReviewsByRootId?.[rootId] || null;
    }

    async openFolderCoverageReview(folder, { forceRefresh = false } = {}) {
        const rootId = folder?.root_id;
        const folderPath = folder?.path;
        if (!rootId || !folderPath) return;

        const existing = this.getFolderCoverageReviewState(rootId) || {};
        if (existing.loading) {
            return;
        }

        if (existing.data && !forceRefresh) {
            this.folderCoverageReviewsByRootId[rootId] = {
                ...existing,
                open: true,
                loading: false,
                error: null,
            };
            if (this.selectedFolder?.root_id === rootId) {
                this.renderFolderDetailView(this.selectedFolder);
            }
            return;
        }

        this.folderCoverageReviewsByRootId[rootId] = {
            ...existing,
            open: true,
            loading: true,
            error: null,
        };
        if (this.selectedFolder?.root_id === rootId) {
            this.renderFolderDetailView(this.selectedFolder);
        }

        try {
            const result = await invoke('get_folder_coverage_review', { folderPath });
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Coverage review unavailable');
            }

            this.folderCoverageReviewsByRootId[rootId] = {
                open: true,
                loading: false,
                error: null,
                data: result.data,
            };
        } catch (error) {
            console.error('Failed to load folder coverage review:', error);
            this.folderCoverageReviewsByRootId[rootId] = {
                ...existing,
                open: true,
                loading: false,
                error: error?.message || 'Coverage review unavailable',
                data: existing.data || null,
            };
        }

        if (this.selectedFolder?.root_id === rootId) {
            this.renderFolderDetailView(this.selectedFolder);
        }
    }

    closeFolderCoverageReview(rootId) {
        if (!rootId || !this.folderCoverageReviewsByRootId?.[rootId]) return;
        this.folderCoverageReviewsByRootId[rootId] = {
            ...this.folderCoverageReviewsByRootId[rootId],
            open: false,
        };
        if (this.selectedFolder?.root_id === rootId) {
            this.renderFolderDetailView(this.selectedFolder);
        }
    }

    buildCoverageActionPrompt(group, folder) {
        const folderLabel = folder?.name || this.basename(folder?.path || 'this folder');
        const itemCount = Number(group?.itemCount || 0);
        const itemLabel = `${this.formatCount(itemCount)} ${itemCount === 1 ? 'item' : 'items'}`;

        switch (group?.recommendedAction) {
            case 'adopt_missing_metadata':
                return {
                    title: 'Restore protection',
                    message: `Restore protection for ${itemLabel} in "${folderLabel}"?\n\nThis rebuilds missing protection records for files that still belong here.`,
                    progress: 'Restoring protection...',
                };
            case 'prune_missing_files':
                return {
                    title: 'Clean up missing items',
                    message: `Clean up ${itemLabel} in "${folderLabel}"?\n\nThis removes old tracking records for files that are gone from disk.`,
                    progress: 'Cleaning up missing items...',
                };
            case 'purge_outcasts':
                return {
                    title: 'Remove leftover protected data',
                    message: `Review cleanup for ${itemLabel} in "${folderLabel}"?\n\nThis removes leftover protected data that no longer belongs in this folder.`,
                    progress: 'Removing leftover protected data...',
                };
            case 'migrate_wrong_epoch':
                return {
                    title: 'Repair protection history',
                    message: `Repair protection for ${itemLabel} in "${folderLabel}"?\n\nThis refreshes protection history for items that are currently out of date.`,
                    progress: 'Repairing protection history...',
                };
            default:
                return {
                    title: group?.title || 'Review coverage',
                    message: `Review ${itemLabel} in "${folderLabel}"?`,
                    progress: 'Updating coverage...',
                };
        }
    }

    async executeFolderCoverageAction(folder, coverageAction, groupId) {
        const rootId = folder?.root_id;
        const reviewState = this.getFolderCoverageReviewState(rootId);
        const coverage = buildFolderCoverageModelValue({
            folder,
            review: reviewState?.data || null,
        });
        const group = coverage?.groups?.find(entry => entry?.id === groupId);
        if (!group) {
            this.showNotification('Coverage group is no longer available. Refresh and try again.', 'warning');
            return;
        }
        if (!group.canRunAction) {
            this.showNotification('Review these files manually. No automatic action is available for this group yet.', 'info');
            return;
        }

        const prompt = this.buildCoverageActionPrompt(group, folder);
        const confirmed = await this.showConfirmDialog(prompt.title, prompt.message);
        if (!confirmed) return;

        try {
            this.showActionProgressModal(prompt.progress);
            const result = await invoke('run_folder_coverage_action', {
                action: coverageAction,
                folderPath: folder.path,
            });
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Coverage action failed');
            }

            const processed = Number(result.data.items_processed || 0);
            const failed = Number(result.data.items_failed || 0);
            if (failed > 0) {
                this.showNotification(
                    `${group.title}: ${this.formatCount(processed)} updated, ${this.formatCount(failed)} still need manual review.`,
                    'warning'
                );
            } else {
                this.showNotification(
                    `${group.title}: updated ${this.formatCount(processed)} ${processed === 1 ? 'item' : 'items'}.`,
                    'success'
                );
            }
        } catch (error) {
            console.error('Coverage action failed:', error);
            this.showNotification(error?.message || 'Coverage action failed.', 'error');
        } finally {
            this.hideActionProgressModal();
        }

        await this.refreshCoverageDependentViews();
        const refreshedFolder = this.enrolledFolders.find(entry => entry.path === folder.path) || folder;
        if (refreshedFolder?.root_id) {
            await this.openFolderCoverageReview(refreshedFolder, { forceRefresh: true });
        } else if (this.activeWorkspaceView === 'folder-detail') {
            this.renderFolderDetailView(this.selectedFolder);
        }
    }

    renderFolderCoverageReviewPanel(folder, coverage, coverageState) {
        if (!coverageState?.open) return '';

        if (coverageState.loading) {
            return `
                <div class="folder-coverage-review-panel">
                    <div class="workspace-empty-state compact">
                        <h3>Loading coverage review</h3>
                        <p>Checking the exact files behind this coverage state.</p>
                    </div>
                </div>
            `;
        }

        if (coverageState.error) {
            return `
                <div class="folder-coverage-review-panel">
                    <div class="workspace-empty-state compact">
                        <h3>Coverage review unavailable</h3>
                        <p>${this.escapeHtml(coverageState.error)}</p>
                        <div class="folder-coverage-inline-actions">
                            <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="refresh-coverage-review">
                                Try again
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }

        if (!coverage.groups.length) {
            return `
                <div class="folder-coverage-review-panel">
                    <div class="workspace-empty-state compact">
                        <h3>No uncovered items right now</h3>
                        <p>This folder does not currently have any coverage issues to review.</p>
                    </div>
                </div>
            `;
        }

        return `
            <div class="folder-coverage-review-panel">
                ${coverage.groups.map(group => `
                    <article class="folder-coverage-group tone-${this.escapeHtmlAttr(group.severity || 'warning')}">
                        <div class="folder-coverage-group-header">
                            <div>
                                <div class="folder-coverage-group-title">${this.escapeHtml(group.title)}</div>
                                <div class="folder-coverage-group-meta">${this.escapeHtml(this.formatCount(group.itemCount))} ${group.itemCount === 1 ? 'item' : 'items'}</div>
                            </div>
                            ${group.canRunAction ? `
                                <button
                                    class="btn btn-secondary btn-small"
                                    type="button"
                                    data-folder-detail-action="run-coverage-group-action"
                                    data-coverage-action="${this.escapeHtmlAttr(group.recommendedAction || '')}"
                                    data-coverage-group-id="${this.escapeHtmlAttr(group.id || '')}">
                                    ${this.escapeHtml(group.primaryCtaLabel || 'Review')}
                                </button>
                            ` : ''}
                        </div>
                        <p class="folder-coverage-group-reason">${this.escapeHtml(group.reasonText || '')}</p>
                        ${group.files.length ? `
                            <div class="folder-coverage-file-list">
                                ${group.files.map(file => `
                                    <div class="folder-coverage-file-row">
                                        <div class="folder-coverage-file-path">${this.escapeHtml(file.relative_path || 'Unknown path')}</div>
                                        <div class="folder-coverage-file-meta">
                                            ${this.escapeHtml(file.reason || 'Needs review')}
                                            ${file.size !== null ? ` • ${this.escapeHtml(this.formatFileSize(file.size))}` : ''}
                                            ${file.last_seen ? ` • Last seen ${this.escapeHtml(this.formatSettingsTimestamp(file.last_seen))}` : ''}
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        ` : (
                            group.samplePaths.length ? `
                                <div class="folder-coverage-file-list">
                                    ${group.samplePaths.map(path => `
                                        <div class="folder-coverage-file-row">
                                            <div class="folder-coverage-file-path">${this.escapeHtml(path)}</div>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''
                        )}
                    </article>
                `).join('')}
            </div>
        `;
    }

    renderFolderDetailView(folder = this.selectedFolder) {
        const container = document.getElementById('folderDetailContent');
        if (!container) return;

        if (!folder) {
            container.innerHTML = `
                <div class="workspace-empty-state">
                    <h3>Select a protected folder</h3>
                    <p>Choose a folder from the sidebar to review its mount status, scan freshness, conflicts, and recovery copies.</p>
                </div>
            `;
            return;
        }

        const isMounted = this.isFolderMounted(folder);
        const mountInfo = folder?.root_id ? this.getMountDetailsForRootId(folder.root_id) : null;
        const coverageState = folder?.root_id ? this.getFolderCoverageReviewState(folder.root_id) : null;
        const model = buildFolderDetailModelValue({
            folder,
            mountInfo,
            isMounted,
            coverageReview: coverageState?.data || null,
        });
        const healthLabel = model.healthTone === 'warning'
            ? 'Needs attention'
            : (model.healthTone === 'safe' ? 'Healthy' : 'Not mounted');
        const coverage = model.coverage || buildFolderCoverageModelValue({ folder });
        const mountStatusLabel = model.backendLabel && model.attention?.mountStatusLabel === 'Mounted'
            ? `${model.attention.mountStatusLabel} (${model.backendLabel})`
            : (model.attention?.mountStatusLabel || 'Not mounted');

        container.innerHTML = `
            <div class="folder-detail-shell tone-${this.escapeHtmlAttr(model.healthTone || 'idle')}">
                <div class="folder-detail-header">
                    <div>
                        <span class="workspace-section-eyebrow">Protected folder</span>
                        <h2>${this.escapeHtml(model.displayName || this.basename(model.path || 'Protected folder'))}</h2>
                        <p class="folder-detail-path">${this.escapeHtml(model.path || 'Path unavailable')}</p>
                    </div>
                    <div class="folder-detail-health">
                        <span class="folder-detail-health-label">${this.escapeHtml(healthLabel)}</span>
                        ${model.mountpoint ? `<span class="folder-detail-health-meta">${this.escapeHtml(model.mountpoint)}</span>` : ''}
                    </div>
                </div>
                <div class="folder-detail-actions">
                    <button class="btn btn-primary" type="button" data-folder-detail-action="${this.escapeHtmlAttr(model.primaryAction.id)}">
                        ${this.escapeHtml(model.primaryAction.label)}
                    </button>
                    ${model.secondaryActions.map(action => `
                        <button class="btn btn-secondary" type="button" data-folder-detail-action="${this.escapeHtmlAttr(action.id)}">
                            ${this.escapeHtml(action.label)}
                        </button>
                    `).join('')}
                </div>
                <div class="folder-detail-stats">
                    <div class="folder-detail-stat">
                        <span class="folder-detail-stat-label">Mount status</span>
                        <span class="folder-detail-stat-value">${this.escapeHtml(mountStatusLabel)}</span>
                    </div>
                    <div class="folder-detail-stat">
                        <span class="folder-detail-stat-label">Last scan</span>
                        <span class="folder-detail-stat-value">${this.escapeHtml(this.formatSettingsTimestamp(model.lastScanAt))}</span>
                    </div>
                    <div class="folder-detail-stat">
                        <span class="folder-detail-stat-label">Tracked files</span>
                        <span class="folder-detail-stat-value">${this.escapeHtml(this.formatCount(model.trackedFiles))}</span>
                    </div>
                    ${model.attention.unmountSafetyLabel ? `
                        <div class="folder-detail-stat">
                            <span class="folder-detail-stat-label">Unmount safety</span>
                            <span class="folder-detail-stat-value">${this.escapeHtml(model.attention.unmountSafetyLabel)}</span>
                        </div>
                    ` : ''}
                </div>
                <section class="folder-protection-card tone-safe">
                    <div class="folder-protection-header">
                        <div>
                            <span class="folder-detail-attention-label">Protection</span>
                            <h3>${this.escapeHtml(model.protection?.primaryText || 'Protection status unknown')}</h3>
                        </div>
                        <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="show-post-quantum-explainer">
                            Why this matters
                        </button>
                    </div>
                    <p class="folder-protection-summary">${this.escapeHtml(model.protection?.secondaryText || 'The app cannot confirm post-quantum protection for this folder yet.')}</p>
                </section>
                <section class="folder-coverage-card tone-${this.escapeHtmlAttr(coverage.stateTone || 'warning')}">
                    <div class="folder-coverage-header">
                        <div>
                            <span class="folder-detail-attention-label">Protection coverage</span>
                            <h3>${this.escapeHtml(coverage.stateLabel || 'Needs attention')} <span class="folder-coverage-percent">${this.escapeHtml(coverage.percentLabel || '0%')}</span></h3>
                        </div>
                        <div class="folder-coverage-summary-pill">${this.escapeHtml(this.formatCount(coverage.trackedFiles || 0))} tracked</div>
                    </div>
                    <p class="folder-coverage-summary">${this.escapeHtml(coverage.summaryText || '')}</p>
                    <div class="folder-coverage-inline-actions">
                        <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="${this.escapeHtmlAttr(coverage.primaryCta?.id || 'run-coverage-scan')}">
                            ${this.escapeHtml(coverage.primaryCta?.label || 'Run scan again')}
                        </button>
                        ${coverageState?.open ? `
                            <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="hide-coverage-review">
                                Hide review
                            </button>
                        ` : ''}
                    </div>
                    ${this.renderFolderCoverageReviewPanel(folder, coverage, coverageState)}
                </section>
                <div class="folder-detail-attention-grid">
                    <article class="folder-detail-attention-card">
                        <span class="folder-detail-attention-label">Conflicts</span>
                        <strong>${this.escapeHtml(this.formatCount(model.attention.conflicts))}</strong>
                        <p>${model.attention.conflicts > 0 ? 'Review conflicting local edits before you trust this folder.' : 'No unresolved conflicts are blocking this folder.'}</p>
                        ${model.showResolveConflicts ? `
                            <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="resolve-conflicts">
                                Open conflict review
                            </button>
                        ` : ''}
                    </article>
                    <article class="folder-detail-attention-card">
                        <span class="folder-detail-attention-label">Recovery copies</span>
                        <strong>${this.escapeHtml(this.formatCount(model.attention.recoveryCopies))}</strong>
                        <p>${model.attention.recoveryCopies > 0 ? 'Recovered local copies need an explicit keep, merge, or discard decision.' : 'No recovery copies are waiting for review.'}</p>
                        ${model.showResolveRecoveryCopies ? `
                            <button class="btn btn-secondary btn-small" type="button" data-folder-detail-action="resolve-recovery">
                                Open recovery review
                            </button>
                        ` : ''}
                    </article>
                </div>
            </div>
        `;

        container.querySelectorAll('[data-folder-detail-action]').forEach(button => {
            button.addEventListener('click', () => this.handleFolderDetailAction(
                folder,
                button.dataset.folderDetailAction,
                button.dataset
            ));
        });
    }

    async handleFolderDetailAction(folder, action, dataset = {}) {
        if (!folder) return;

        try {
            switch (action) {
                case 'mount':
                    await this.mountFolderFromContext(folder);
                    break;
                case 'open-mounted': {
                    const mountpoint = this.getMountpointForRootId(folder.root_id);
                    if (!mountpoint) {
                        this.showNotification('This folder is not mounted right now.', 'warning');
                        return;
                    }
                    await this.openMountInExplorer(mountpoint);
                    break;
                }
                case 'reveal-protected':
                    await invoke('open_path_in_shell', { path: folder.path });
                    break;
                case 'unmount':
                    await this.executeUnmountCommand(folder);
                    break;
                case 'resolve-conflicts':
                    await this.openConflictCenterForFolder(folder);
                    break;
                case 'resolve-recovery':
                    await this.openRecoveryCenterForFolder(folder);
                    break;
                case 'review-uncovered-items':
                    await this.openFolderCoverageReview(folder);
                    break;
                case 'hide-coverage-review':
                    this.closeFolderCoverageReview(folder.root_id);
                    break;
                case 'refresh-coverage-review':
                    await this.openFolderCoverageReview(folder, { forceRefresh: true });
                    break;
                case 'run-coverage-scan':
                    await this.executeCoverageCommand('coverage-scan', folder);
                    break;
                case 'show-post-quantum-explainer':
                    this.showPostQuantumExplainer();
                    break;
                case 'run-coverage-group-action':
                    await this.executeFolderCoverageAction(
                        folder,
                        dataset.coverageAction,
                        dataset.coverageGroupId
                    );
                    break;
                default:
                    break;
            }
        } catch (error) {
            console.error('Folder detail action failed:', error);
            this.showNotification(error?.message || 'Folder action failed.', 'error');
        }
    }

    renderDevicesCenterLoading() {
        const container = document.getElementById('devicesCenterContent');
        if (!container) return;
        container.innerHTML = '<div class="workspace-empty-state"><h3>Loading devices</h3><p>Checking trusted, pending, and stale devices for this account.</p></div>';
    }

    async refreshPersonalDevicesOverview({ suppressErrorNotification = false } = {}) {
        if (!this.isLoggedIn) return;
        try {
            const result = await invoke('get_personal_devices_overview');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Devices overview unavailable');
            }
            this.personalDevicesOverview = result.data;
            this.renderDevicesCenter();
            this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true });
        } catch (error) {
            console.error('Failed to refresh personal devices overview:', error);
            if (!suppressErrorNotification) {
                this.showNotification('Failed to load device status.', 'warning');
            }
            const container = document.getElementById('devicesCenterContent');
            if (container) {
                container.innerHTML = '<div class="workspace-empty-state"><h3>Device status unavailable</h3><p>HybridCipher could not load trusted devices right now.</p></div>';
            }
        }
    }

    formatDeviceStatusLabel(status) {
        switch (status) {
            case 'pending':
                return 'Needs approval';
            case 'unverified':
                return 'Needs verification';
            case 'stale':
                return 'Needs review';
            default:
                return 'Trusted';
        }
    }

    renderDevicesCenter() {
        const container = document.getElementById('devicesCenterContent');
        if (!container) return;

        const snapshot = this.personalDevicesOverview || {};
        const devices = [
            ...(snapshot.current_device ? [snapshot.current_device] : []),
            ...(Array.isArray(snapshot.trusted_devices) ? snapshot.trusted_devices : []),
            ...(Array.isArray(snapshot.setup_devices) ? snapshot.setup_devices : []),
            ...(Array.isArray(snapshot.review_devices) ? snapshot.review_devices : []),
        ];
        const model = buildPersonalDevicesModelValue({
            currentDeviceId: this.currentDeviceId,
            devices,
        });

        const renderDeviceRow = (device, group) => `
            <article class="device-row">
                <div class="device-row-copy">
                    <div class="device-row-title">
                        <strong>${this.escapeHtml(device.device_name || this.formatShortId(device.device_id, 16))}</strong>
                        <span class="device-row-badge status-${this.escapeHtmlAttr(device.status || 'trusted')}">${this.escapeHtml(this.formatDeviceStatusLabel(device.status))}</span>
                        ${device.is_current_device ? '<span class="device-row-badge current">This device</span>' : ''}
                    </div>
                    <div class="device-row-meta">
                        <span>ID: ${this.escapeHtml(this.formatShortId(device.device_id, 18))}</span>
                        ${device.last_seen ? `<span>Last seen: ${this.escapeHtml(this.formatSettingsTimestamp(device.last_seen))}</span>` : ''}
                        ${device.added_at ? `<span>Added: ${this.escapeHtml(this.formatSettingsTimestamp(device.added_at))}</span>` : ''}
                    </div>
                </div>
                <div class="device-row-actions">
                    ${group === 'setup' && device.status === 'pending' ? `
                        <button class="btn btn-secondary btn-small" type="button" data-devices-action="approve" data-device-id="${this.escapeHtmlAttr(device.device_id)}">Approve</button>
                    ` : ''}
                    ${group === 'setup' && device.status === 'unverified' ? `
                        <button class="btn btn-secondary btn-small" type="button" data-devices-action="verify" data-device-id="${this.escapeHtmlAttr(device.device_id)}">Verify</button>
                    ` : ''}
                    ${device.is_current_device && device.is_verified === false ? `
                        <button class="btn btn-secondary btn-small" type="button" data-devices-action="complete-setup" data-device-id="${this.escapeHtmlAttr(device.device_id)}">Complete setup</button>
                    ` : ''}
                    ${!device.is_current_device && snapshot.revoke_supported ? `
                        <button class="btn btn-secondary btn-small" type="button" data-devices-action="revoke" data-device-id="${this.escapeHtmlAttr(device.device_id)}">Revoke</button>
                    ` : ''}
                    <button class="btn btn-secondary btn-small" type="button" data-devices-action="rename-disabled" data-device-id="${this.escapeHtmlAttr(device.device_id)}" ${snapshot.rename_supported ? '' : 'disabled'}>
                        Rename
                    </button>
                </div>
            </article>
        `;

        container.innerHTML = `
            <div class="devices-center-shell ${model.hasAttention ? 'has-attention' : 'is-clear'}">
                <section class="devices-current-card">
                    <span class="workspace-section-eyebrow">This device</span>
                    <h2>${this.escapeHtml(model.currentDevice?.device_name || 'Current device')}</h2>
                    <p>${model.currentDevice
                        ? this.escapeHtml(this.formatDeviceStatusLabel(model.currentDevice.status))
                        : 'Current device details are unavailable.'}</p>
                    ${model.currentDevice ? `
                        <div class="device-row-meta">
                            <span>ID: ${this.escapeHtml(this.formatShortId(model.currentDevice.device_id, 24))}</span>
                            ${model.currentDevice.last_seen ? `<span>Last seen: ${this.escapeHtml(this.formatSettingsTimestamp(model.currentDevice.last_seen))}</span>` : ''}
                        </div>
                    ` : ''}
                </section>

                <section class="devices-group">
                    <div class="devices-group-header">
                        <h3>Trusted devices</h3>
                        <p>Devices that already have access to this account.</p>
                    </div>
                    <div class="devices-group-list">
                        ${model.trustedDevices.length
                            ? model.trustedDevices.map(device => renderDeviceRow(device, 'trusted')).join('')
                            : '<div class="workspace-empty-state compact"><p>No additional trusted devices.</p></div>'}
                    </div>
                </section>

                <section class="devices-group">
                    <div class="devices-group-header">
                        <h3>Needs setup</h3>
                        <p>Devices waiting for approval or fingerprint verification.</p>
                    </div>
                    <div class="devices-group-list">
                        ${model.setupDevices.length
                            ? model.setupDevices.map(device => renderDeviceRow(device, 'setup')).join('')
                            : '<div class="workspace-empty-state compact"><p>No devices are waiting for setup.</p></div>'}
                    </div>
                </section>

                <section class="devices-group">
                    <div class="devices-group-header">
                        <h3>Needs review</h3>
                        <p>Devices that look stale or should be revoked.</p>
                    </div>
                    <div class="devices-group-list">
                        ${model.reviewDevices.length
                            ? model.reviewDevices.map(device => renderDeviceRow(device, 'review')).join('')
                            : '<div class="workspace-empty-state compact"><p>No stale devices need review.</p></div>'}
                    </div>
                </section>
            </div>
        `;

        container.querySelectorAll('[data-devices-action]').forEach(button => {
            const deviceId = button.dataset.deviceId;
            const device = devices.find(entry => entry?.device_id === deviceId);
            button.addEventListener('click', () => this.handleDevicesAction(button.dataset.devicesAction, device));
        });
    }

    async handleDevicesAction(action, device) {
        if (!device) return;

        switch (action) {
            case 'approve':
                await this.issueWelcomeForDevice(device.device_id);
                break;
            case 'verify':
                await this.verifyUnverifiedDevice(device);
                break;
            case 'complete-setup':
                await this.runSettingsCliCommand('hybridcipher process-welcome-messages', { closeSettingsModal: false });
                break;
            case 'revoke':
                await this.revokeDeviceRecord(device);
                break;
            case 'rename-disabled':
                if (!(this.personalDevicesOverview?.rename_supported)) {
                    this.showNotification('Device rename is not supported by the current server API.', 'info');
                }
                break;
            default:
                break;
        }
    }

    async revokeDeviceRecord(device) {
        const label = device.device_name || device.device_id;
        const confirmed = await this.showConfirmDialog(
            'Revoke device',
            `Revoke "${label}" and invalidate its sessions?`
        );
        if (!confirmed) return;

        try {
            const result = await invoke('revoke_device', { deviceId: device.device_id });
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Device revocation failed');
            }

            if (result.data.removed_current_device) {
                await this.handleStaleSession('This device was revoked. Please login again.');
                return;
            }

            this.showNotification(`Revoked device ${label}.`, 'success');
            await this.refreshPersonalDevicesOverview({ suppressErrorNotification: true });
        } catch (error) {
            console.error('Failed to revoke device:', error);
            this.showNotification(error?.message || 'Failed to revoke device.', 'error');
        }
    }

    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.getElementById('mainContent');

        this.isSidebarCollapsed = !this.isSidebarCollapsed;

        if (this.isSidebarCollapsed) {
            sidebar.classList.add('collapsed');
            mainContent.classList.add('sidebar-collapsed');
        } else {
            sidebar.classList.remove('collapsed');
            mainContent.classList.remove('sidebar-collapsed');
        }

        // Save preference
        localStorage.setItem('hybridcipher_sidebar_collapsed', this.isSidebarCollapsed);
    }

    setupSidebarResizeHandle() {
        const sidebar = document.getElementById('sidebar');
        const handle = document.getElementById('sidebarResizeHandle');
        if (!sidebar || !handle) return;

        const storedWidth = Number.parseInt(localStorage.getItem('hybridcipher_sidebar_width') || '', 10);
        if (Number.isFinite(storedWidth)) {
            this.setSidebarWidth(storedWidth);
        }

        let isResizing = false;

        const startResize = (event) => {
            if (this.isSidebarCollapsed) return;
            isResizing = true;
            event.preventDefault();
            document.body.classList.add('resizing-sidebar');
            window.addEventListener('mousemove', onResize);
            window.addEventListener('mouseup', stopResize, { once: true });
        };

        const onResize = (event) => {
            if (!isResizing) return;
            const rect = sidebar.getBoundingClientRect();
            const minWidth = Number.parseInt(getComputedStyle(sidebar).minWidth || '220', 10);
            const maxWidth = Number.parseInt(getComputedStyle(sidebar).maxWidth || '420', 10);
            const nextWidth = Math.min(Math.max(event.clientX - rect.left, minWidth), maxWidth);
            this.setSidebarWidth(nextWidth);
        };

        const stopResize = () => {
            if (!isResizing) return;
            isResizing = false;
            document.body.classList.remove('resizing-sidebar');
            window.removeEventListener('mousemove', onResize);
            localStorage.setItem('hybridcipher_sidebar_width', `${sidebar.offsetWidth}`);
        };

        handle.addEventListener('mousedown', startResize);
    }

    setSidebarWidth(width) {
        const sidebar = document.getElementById('sidebar');
        if (!sidebar) return;
        const minWidth = Number.parseInt(getComputedStyle(sidebar).minWidth || '220', 10);
        const maxWidth = Number.parseInt(getComputedStyle(sidebar).maxWidth || '420', 10);
        const clampedWidth = Math.min(Math.max(width, minWidth), maxWidth);
        sidebar.style.width = `${clampedWidth}px`;
        if (this.shouldUseXtermForTab(this.activeTabId)) {
            this.fitActiveXterm();
        }
    }

    // ========================================================================
    // Command Palette
    // ========================================================================

    loadCliCommandConfig() {
        const rawConfig = window.hybridcipherCliCommands;
        if (!Array.isArray(rawConfig)) {
            console.warn('CLI command palette config missing or invalid.');
            return [];
        }

        return rawConfig
            .filter(item => item && typeof item.command === 'string')
            .map(item => ({
                command: item.command,
                description: item.description || '',
                keywords: Array.isArray(item.keywords) ? item.keywords : []
            }));
    }

    handleGlobalSearch(event) {
        const query = event?.target?.value ?? '';
        this.openCommandPalette();
        this.renderCommandPalette(query);
    }

    handleCommandPaletteKeydown(event) {
        if (!event) return;

        if (!this.commandPaletteOpen && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
            event.preventDefault();
            this.openCommandPalette();
            this.renderCommandPalette(event.target?.value ?? '');
            return;
        }

        if (!this.commandPaletteOpen) return;

        if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (!this.commandPaletteResults.length) return;
            const nextIndex = (this.commandPaletteIndex + 1) % this.commandPaletteResults.length;
            this.setCommandPaletteIndex(nextIndex);
            return;
        }

        if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (!this.commandPaletteResults.length) return;
            const baseIndex = this.commandPaletteIndex >= 0 ? this.commandPaletteIndex : 0;
            const nextIndex =
                (baseIndex - 1 + this.commandPaletteResults.length) %
                this.commandPaletteResults.length;
            this.setCommandPaletteIndex(nextIndex);
            return;
        }

        if (event.key === 'Enter') {
            if (this.commandPaletteIndex >= 0) {
                event.preventDefault();
                this.activateCommandPaletteSelection(this.commandPaletteIndex);
            }
            return;
        }

        if (event.key === 'Escape') {
            event.preventDefault();
            this.closeCommandPalette();
        }
    }

    ensureCommandPaletteElement() {
        let palette = document.getElementById('commandPalette');
        if (palette) return palette;

        const container = document.querySelector('.global-search');
        if (!container) return null;

        palette = document.createElement('div');
        palette.className = 'command-palette';
        palette.id = 'commandPalette';
        palette.setAttribute('role', 'listbox');
        palette.setAttribute('aria-hidden', 'true');
        container.appendChild(palette);
        return palette;
    }

    openCommandPalette() {
        const palette = this.ensureCommandPaletteElement();
        if (!palette) return;
        this.commandPaletteOpen = true;
        palette.classList.add('open');
        palette.setAttribute('aria-hidden', 'false');
    }

    closeCommandPalette() {
        const palette = this.ensureCommandPaletteElement();
        if (!palette) return;
        this.commandPaletteOpen = false;
        this.commandPaletteResults = [];
        this.commandPaletteIndex = -1;
        palette.classList.remove('open');
        palette.setAttribute('aria-hidden', 'true');
        palette.innerHTML = '';
    }

    renderCommandPalette(rawQuery = '') {
        const palette = this.ensureCommandPaletteElement();
        if (!palette) return;

        if (!this.commandPaletteOpen) {
            this.openCommandPalette();
        }

        const query = this.normalizeCommandQuery(rawQuery);
        palette.innerHTML = '';

        let entries = [];
        let sectionTitle = '';

        if (!query) {
            entries = this.getRecentCommandEntries();
            sectionTitle = 'Recent';
        } else {
            entries = this.filterCliCommands(query);
            sectionTitle = 'Suggestions';
        }

        if (!entries.length) {
            const empty = document.createElement('div');
            empty.className = 'command-palette-empty';
            empty.textContent = query ? 'No matching commands.' : 'No recent commands yet.';
            palette.appendChild(empty);
            this.commandPaletteResults = [];
            this.commandPaletteIndex = -1;
            return;
        }

        const section = document.createElement('div');
        section.className = 'command-palette-section';
        section.textContent = sectionTitle;
        palette.appendChild(section);

        entries.forEach((entry, index) => {
            const item = document.createElement('div');
            item.className = 'command-palette-item';
            item.dataset.index = `${index}`;
            item.dataset.command = entry.command;
            const title = document.createElement('span');
            title.className = 'command-title';
            title.textContent = entry.command;

            const description = document.createElement('span');
            description.className = 'command-description';
            description.textContent = entry.description || 'HybridCipher command';

            item.appendChild(title);
            item.appendChild(description);
            item.addEventListener('mouseenter', () => this.setCommandPaletteIndex(index));
            item.addEventListener('click', () => this.activateCommandPaletteSelection(index));
            palette.appendChild(item);
        });

        this.commandPaletteResults = entries;
        this.commandPaletteIndex = query ? 0 : -1;
        this.applyCommandPaletteActiveState();
    }

    setCommandPaletteIndex(index) {
        this.commandPaletteIndex = index;
        this.applyCommandPaletteActiveState();
    }

    applyCommandPaletteActiveState() {
        const palette = this.ensureCommandPaletteElement();
        if (!palette) return;
        const items = palette.querySelectorAll('.command-palette-item');
        items.forEach((item, idx) => {
            item.classList.toggle('active', idx === this.commandPaletteIndex);
        });
        const activeItem = palette.querySelector('.command-palette-item.active');
        if (activeItem) {
            activeItem.scrollIntoView({ block: 'nearest' });
        }
    }

    async activateCommandPaletteSelection(index) {
        const entry = this.commandPaletteResults[index];
        if (!entry) return;
        await this.runCliHelpCommand(entry.command);
    }

    async runCliHelpCommand(command) {
        if (!command) return;
        this.recordRecentCommand(command);
        this.closeCommandPalette();
        if (this.adminPanelVisible) {
            this.setAdminPanelVisible(false);
        }

        const input = document.getElementById('globalSearch');
        if (input) {
            input.value = '';
        }

        await this.createTerminalTab();
        await this.executeCommandDirectly(`hybridcipher ${command} -h`);
    }

    getRecentCommandEntries() {
        const recent = this.getRecentCommands();
        return recent.slice(0, this.commandPaletteRecentLimit).map(command => {
            const known = this.findCliCommand(command);
            return known || { command, description: 'Recent command', keywords: [] };
        });
    }

    getRecentCommands() {
        const stored = localStorage.getItem(this.commandPaletteStorageKey);
        if (!stored) return [];
        try {
            const parsed = JSON.parse(stored);
            return Array.isArray(parsed) ? parsed : [];
        } catch (error) {
            console.warn('Failed to parse recent commands:', error);
            return [];
        }
    }

    saveRecentCommands(commands) {
        localStorage.setItem(this.commandPaletteStorageKey, JSON.stringify(commands));
    }

    recordRecentCommand(command) {
        const existing = this.getRecentCommands();
        const deduped = [command, ...existing.filter(item => item !== command)];
        this.saveRecentCommands(deduped.slice(0, this.commandPaletteRecentLimit));
    }

    findCliCommand(command) {
        return this.cliCommands.find(item => item.command === command) || null;
    }

    filterCliCommands(query) {
        const tokens = query.split(/\s+/).filter(Boolean);
        const scored = this.cliCommands
            .map(item => ({
                item,
                score: tokens.reduce((sum, token) => sum + this.scoreCommandToken(item, token), 0)
            }))
            .filter(entry => entry.score > 0)
            .sort((a, b) => {
                if (b.score !== a.score) return b.score - a.score;
                return a.item.command.localeCompare(b.item.command);
            })
            .slice(0, this.commandPaletteSuggestionLimit)
            .map(entry => entry.item);

        return scored;
    }

    scoreCommandToken(command, token) {
        const normalizedToken = this.normalizeCommandQuery(token);
        if (!normalizedToken) return 0;

        const tokenVariants = [normalizedToken];
        if (normalizedToken.endsWith('s')) {
            tokenVariants.push(normalizedToken.slice(0, -1));
        }

        const commandName = this.normalizeCommandQuery(command.command);
        const description = this.normalizeCommandQuery(command.description);
        const keywords = (command.keywords || []).map(keyword => this.normalizeCommandQuery(keyword));

        let best = 0;
        tokenVariants.forEach(variant => {
            if (!variant) return;
            if (commandName === variant) {
                best = Math.max(best, 8);
            } else if (commandName.startsWith(variant)) {
                best = Math.max(best, 6);
            } else if (commandName.includes(variant)) {
                best = Math.max(best, 4);
            } else if (keywords.some(keyword => keyword.includes(variant))) {
                best = Math.max(best, 3);
            } else if (description.includes(variant)) {
                best = Math.max(best, 2);
            }
        });

        return best;
    }

    normalizeCommandQuery(value) {
        if (!value) return '';
        return value.toLowerCase().trim();
    }

    // ========================================================================
    // User Status Management
    // ========================================================================

    updateUserStatus(email, isConnected = true) {
        const statusPill = document.getElementById('userStatusPill');
        if (statusPill) {
            const emailSpan = statusPill.querySelector('#headerUserEmail');
            const statusDot = statusPill.querySelector('.status-dot');

            if (emailSpan) emailSpan.textContent = email;
            if (statusDot) {
                statusDot.style.background = isConnected ? '#2EE6D6' : '#f87171';
            }
        }
    }

    // ========================================================================
    // Preferences Management
    // ========================================================================

    loadRememberPreference() {
        try {
            const stored = localStorage.getItem('hybridcipher_remember_me');
            if (stored === null) return true;
            return stored === 'true';
        } catch (error) {
            console.warn('Failed to read remember-me preference:', error);
            return true;
        }
    }

    loadAutoMountLastFolderPreference() {
        return loadAutoMountPreferenceValue(window.localStorage);
    }

    saveAutoMountLastFolderPreference(value) {
        this.autoMountLastFolderPreference = Boolean(value);
        saveAutoMountPreferenceValue(window.localStorage, this.autoMountLastFolderPreference);
    }

    loadLastMountedRootId() {
        return loadLastMountedRootIdValue(window.localStorage);
    }

    saveLastMountedRootId(rootId) {
        saveLastMountedRootIdValue(window.localStorage, rootId);
    }

    loadMarkersReminderDismissed() {
        try {
            return localStorage.getItem('hybridcipher_markers_reminder_dismissed') === 'true';
        } catch (error) {
            console.warn('Failed to read markers reminder preference:', error);
            return false;
        }
    }

    setMarkersReminderDismissed(value) {
        try {
            localStorage.setItem('hybridcipher_markers_reminder_dismissed', value ? 'true' : 'false');
        } catch (error) {
            console.warn('Failed to save markers reminder preference:', error);
        }
    }

    loadRememberedCredentials() {
        try {
            const raw = localStorage.getItem('hybridcipher_remembered_login');
            if (!raw) return { email: '', password: '' };
            const parsed = JSON.parse(raw);
            return {
                email: typeof parsed?.email === 'string' ? parsed.email : '',
                password: typeof parsed?.password === 'string' ? parsed.password : ''
            };
        } catch (error) {
            console.warn('Failed to read remembered credentials:', error);
            return { email: '', password: '' };
        }
    }

    saveRememberedCredentials(email, password) {
        try {
            localStorage.setItem('hybridcipher_remembered_login', JSON.stringify({ email, password }));
        } catch (error) {
            console.warn('Failed to save remembered credentials:', error);
        }
    }

    clearRememberedCredentials() {
        try {
            localStorage.removeItem('hybridcipher_remembered_login');
        } catch (error) {
            console.warn('Failed to clear remembered credentials:', error);
        }
    }

    loadFolderPreferences() {
        try {
            const raw = localStorage.getItem('hybridcipher_folder_prefs');
            return raw ? JSON.parse(raw) : {};
        } catch (error) {
            console.warn('Failed to load folder preferences:', error);
            return {};
        }
    }

    saveFolderPreferences() {
        try {
            localStorage.setItem('hybridcipher_folder_prefs', JSON.stringify(this.userFolderPreferences));
        } catch (error) {
            console.warn('Failed to save folder preferences:', error);
        }
    }

    resolveAutoMountFolder() {
        return resolveAutoMountFolderValue({
            storage: window.localStorage,
            enrolledFolders: this.enrolledFolders,
            activeMountsByRootId: this.activeMountsByRootId,
        });
    }

    syncAutoMountSettingsUi() {
        const checkbox = document.getElementById('settingsAutoMountLastFolder');
        if (checkbox) {
            checkbox.checked = Boolean(this.autoMountLastFolderPreference);
        }
    }

    async maybeAutoMountLastFolder() {
        const folder = this.resolveAutoMountFolder();
        if (!folder?.root_id) {
            return false;
        }

        return this.mountFolderFromContext(folder, { autoMountRestore: true });
    }

    saveAccordionState(sectionId, isExpanded) {
        try {
            const state = JSON.parse(localStorage.getItem('hybridcipher_accordion_state') || '{}');
            state[sectionId] = isExpanded;
            localStorage.setItem('hybridcipher_accordion_state', JSON.stringify(state));
        } catch (error) {
            console.warn('Failed to save accordion state:', error);
        }
    }

    restoreAccordionState() {
        try {
            const state = JSON.parse(localStorage.getItem('hybridcipher_accordion_state') || '{}');
            document.querySelectorAll('.accordion-section').forEach(section => {
                const sectionId = section.dataset.section;
                if (sectionId && sectionId in state) {
                    section.classList.toggle('expanded', state[sectionId]);
                }
            });
        } catch (error) {
            console.warn('Failed to restore accordion state:', error);
        }
    }

    isWelcomeOverlayDismissed() {
        try {
            return localStorage.getItem(this.welcomeModalDismissedStorageKey) === 'true';
        } catch (error) {
            return false;
        }
    }

    markWelcomeOverlayDismissed() {
        try {
            localStorage.setItem(this.welcomeModalDismissedStorageKey, 'true');
        } catch (error) {
            console.warn('Failed to persist first run welcome flag:', error);
        }
    }

    showWelcomeOverlay() {
        const modal = document.getElementById('firstRunWelcomeModal');
        if (!modal) return;
        modal.style.display = 'flex';
        setTimeout(() => {
            document.getElementById('firstRunCreateAccountBtn')?.focus();
        }, 0);
    }

    hideWelcomeOverlay({ dontShowAgain = false } = {}) {
        const modal = document.getElementById('firstRunWelcomeModal');
        if (modal) {
            modal.style.display = 'none';
        }
        if (dontShowAgain) {
            this.markWelcomeOverlayDismissed();
        }
    }

    maybeShowWelcomeOverlay() {
        if (this.isWelcomeOverlayDismissed()) return;
        this.showWelcomeOverlay();
    }

    async runPostLegalStartupFlow() {
        const showedReleaseNotes = await this.maybeShowReleaseNotesModal();
        if (!showedReleaseNotes) {
            this.maybeShowWelcomeOverlay();
        }
    }

    async maybeShowReleaseNotesModal() {
        try {
            const result = await invoke('get_release_notes_payload');
            if (!result?.success || !result?.data) {
                return false;
            }

            const startupState = resolveReleaseNotesStartupValue(window.localStorage, {
                currentVersion: result.data.current_version || result.data.currentVersion || '',
                releases: Array.isArray(result.data.releases) ? result.data.releases : [],
            });

            if (!startupState?.shouldShow || !startupState.modal) {
                return false;
            }

            this.showReleaseNotesModal(startupState);
            return true;
        } catch (error) {
            console.warn('Failed to prepare startup release notes:', error);
            return false;
        }
    }

    showReleaseNotesModal(startupState) {
        const modal = document.getElementById('releaseNotesModal');
        const titleEl = document.getElementById('releaseNotesTitle');
        const introEl = document.getElementById('releaseNotesIntro');
        const bodyEl = document.getElementById('releaseNotesBody');
        if (!modal || !titleEl || !introEl || !bodyEl) {
            return;
        }

        this.releaseNotesModalModel = startupState.modal;
        this.releaseNotesModalVersion = startupState.currentVersion;

        titleEl.textContent = startupState.modal.title || 'What’s new';
        introEl.textContent = startupState.modal.intro || 'Here are the most important changes in this release.';

        bodyEl.innerHTML = (startupState.modal.sections || []).map((section) => {
            const versionCount = new Set((section.items || []).map(item => item.version)).size;
            const itemsMarkup = (section.items || []).map((item) => {
                const versionPill = versionCount > 1 && item.version
                    ? `<span class="release-note-version-pill">v${this.escapeHtml(item.version)}</span>`
                    : '';
                return `<li>${versionPill}<span>${this.escapeHtml(item.text || '')}</span></li>`;
            }).join('');

            return `
                <section class="release-notes-section">
                    <h3>${this.escapeHtml(section.title || '')}</h3>
                    <ul class="release-notes-list">${itemsMarkup}</ul>
                </section>
            `;
        }).join('');

        modal.style.display = 'flex';
        modal.classList.remove('hidden');
        setTimeout(() => {
            document.getElementById('releaseNotesContinueBtn')?.focus();
        }, 0);
    }

    hideReleaseNotesModal() {
        const modal = document.getElementById('releaseNotesModal');
        if (modal) {
            modal.style.display = 'none';
            modal.classList.add('hidden');
        }

        if (this.releaseNotesModalVersion) {
            finalizeReleaseNotesVersionValue(window.localStorage, this.releaseNotesModalVersion);
        }

        this.releaseNotesModalModel = null;
        this.releaseNotesModalVersion = null;
        this.maybeShowWelcomeOverlay();
    }

    focusOperationsSection() {
        const section = document.querySelector('.accordion-section[data-section="operations"]');
        if (!section) return;
        if (!section.classList.contains('expanded')) {
            section.classList.add('expanded');
            this.saveAccordionState('operations', true);
        }
        const header = section.querySelector('.accordion-header') || section;
        header.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    getStoredLegalAcceptance() {
        return readStoredLegalAcceptanceValue(window.localStorage);
    }

    hasAcceptedCurrentLegalVersion() {
        return hasAcceptedLegalVersionValue(window.localStorage, this.legalDocuments?.version || '');
    }

    formatLegalTimestamp(value) {
        if (!value) return 'Not accepted yet';
        const timestamp = new Date(value);
        if (Number.isNaN(timestamp.getTime())) {
            return value;
        }
        return new Intl.DateTimeFormat(undefined, {
            dateStyle: 'medium',
            timeStyle: 'short'
        }).format(timestamp);
    }

    async initializeLegalDocuments() {
        try {
            await this.ensureLegalDocumentsLoaded();
        } catch (error) {
            console.error('Failed to initialize legal documents:', error);
        }

        this.refreshLegalStatusUi();

        if (!this.hasAcceptedCurrentLegalVersion()) {
            this.openLegalModal({ requireAcceptance: true, documentId: 'terms' });
        }
    }

    async ensureLegalDocumentsLoaded({ forceRefresh = false } = {}) {
        if (this.legalDocuments && !forceRefresh) {
            return this.legalDocuments;
        }

        this.legalDocumentsLoading = true;
        this.legalDocumentsError = null;
        this.renderLegalModal();
        this.refreshLegalStatusUi();

        try {
            const result = await invoke('get_legal_documents');
            if (!result?.success || !result?.data) {
                throw new Error(result?.error || 'Failed to load legal documents');
            }
            this.legalDocuments = result.data;
            this.legalDocumentOrder = Array.isArray(result.data.documents)
                ? result.data.documents.map((document) => document.id)
                : [];
            if (!this.legalDocumentOrder.includes(this.legalActiveDocumentId)) {
                this.legalActiveDocumentId = this.legalDocumentOrder[0] || 'terms';
            }
            return this.legalDocuments;
        } catch (error) {
            this.legalDocumentsError = error;
            throw error;
        } finally {
            this.legalDocumentsLoading = false;
            this.renderLegalModal();
            this.refreshLegalStatusUi();
        }
    }

    getActiveLegalDocument() {
        if (!this.legalDocuments?.documents?.length) {
            return null;
        }
        return this.legalDocuments.documents.find((document) => document.id === this.legalActiveDocumentId)
            || this.legalDocuments.documents[0];
    }

    refreshLegalStatusUi() {
        const acceptedRecord = this.getStoredLegalAcceptance();
        const acceptedAtLabel = this.hasAcceptedCurrentLegalVersion()
            ? this.formatLegalTimestamp(acceptedRecord?.acceptedAt)
            : 'Not accepted yet';
        const legalVersion = this.legalDocuments?.version || '—';
        let statusLabel = 'Loading legal documents…';

        if (this.legalDocumentsError) {
            statusLabel = 'Unable to load bundled legal documents';
        } else if (this.legalDocuments) {
            statusLabel = this.hasAcceptedCurrentLegalVersion()
                ? 'Accepted on this device'
                : 'Acceptance required before use';
        }

        const versionEl = document.getElementById('settingsLegalVersion');
        const acceptedAtEl = document.getElementById('settingsLegalAcceptedAt');
        const statusEl = document.getElementById('settingsLegalStatus');
        const termsBtn = document.getElementById('settingsReviewTermsBtn');
        const privacyBtn = document.getElementById('settingsReviewPrivacyBtn');

        if (versionEl) versionEl.textContent = legalVersion;
        if (acceptedAtEl) acceptedAtEl.textContent = acceptedAtLabel;
        if (statusEl) statusEl.textContent = statusLabel;
        if (termsBtn) termsBtn.disabled = this.legalDocumentsLoading;
        if (privacyBtn) privacyBtn.disabled = this.legalDocumentsLoading;
    }

    openLegalModal({ requireAcceptance = false, documentId = null } = {}) {
        if (documentId) {
            this.legalActiveDocumentId = documentId;
        }
        this.legalModalRequiresAcceptance = Boolean(requireAcceptance);
        const modal = document.getElementById('legalModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.renderLegalModal();

        if (!this.legalDocuments && !this.legalDocumentsLoading) {
            this.ensureLegalDocumentsLoaded().catch((error) => {
                console.error('Failed to load legal documents:', error);
            });
        }
    }

    closeLegalModal({ accepted = false } = {}) {
        if (this.legalModalRequiresAcceptance && !accepted) {
            return;
        }
        const modal = document.getElementById('legalModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.legalModalRequiresAcceptance = false;
    }

    selectLegalDocument(documentId) {
        if (!documentId) return;
        this.legalActiveDocumentId = documentId;
        this.renderLegalModal();
    }

    renderLegalModal() {
        const titleEl = document.getElementById('legalModalTitle');
        const subtitleEl = document.getElementById('legalModalSubtitle');
        const bannerEl = document.getElementById('legalStatusBanner');
        const listEl = document.getElementById('legalDocumentList');
        const headingEl = document.getElementById('legalDocumentHeading');
        const metaEl = document.getElementById('legalDocumentMeta');
        const contentEl = document.getElementById('legalDocumentContent');
        const retryBtn = document.getElementById('legalRetryBtn');
        const declineBtn = document.getElementById('legalDeclineBtn');
        const acceptBtn = document.getElementById('legalAcceptBtn');
        const closeBtn = document.getElementById('legalCloseBtn');
        const closeIconBtn = document.getElementById('closeLegalModalBtn');
        const acceptedRecord = this.getStoredLegalAcceptance();

        if (!titleEl || !subtitleEl || !bannerEl || !listEl || !headingEl || !metaEl || !contentEl) {
            return;
        }

        subtitleEl.textContent = this.legalModalRequiresAcceptance
            ? 'Review and accept the bundled terms before using this device.'
            : 'Bundled legal documents packaged with this release.';

        retryBtn?.classList.toggle('hidden', !this.legalDocumentsError);
        declineBtn?.classList.toggle('hidden', !this.legalModalRequiresAcceptance);
        acceptBtn?.classList.toggle('hidden', !this.legalModalRequiresAcceptance);
        closeBtn?.classList.toggle('hidden', this.legalModalRequiresAcceptance);
        if (closeIconBtn) {
            closeIconBtn.style.display = this.legalModalRequiresAcceptance ? 'none' : 'inline-flex';
        }

        if (acceptBtn) {
            acceptBtn.disabled = this.legalDocumentsLoading || !this.legalDocuments || Boolean(this.legalDocumentsError);
        }

        if (this.legalDocumentsLoading && !this.legalDocuments) {
            titleEl.textContent = 'Loading legal documents';
            bannerEl.textContent = 'Loading bundled legal documents for this release…';
            listEl.innerHTML = '';
            headingEl.textContent = 'Please wait';
            metaEl.textContent = 'Preparing bundled terms';
            contentEl.textContent = 'Loading…';
            return;
        }

        if (this.legalDocumentsError && !this.legalDocuments) {
            titleEl.textContent = 'Legal documents unavailable';
            bannerEl.textContent = 'The app could not load its bundled legal documents. Retry loading or quit the app.';
            listEl.innerHTML = '';
            headingEl.textContent = 'Load error';
            metaEl.textContent = 'Bundled legal content is unavailable';
            contentEl.textContent = String(this.legalDocumentsError?.message || this.legalDocumentsError || 'Unknown error');
            return;
        }

        const activeDocument = this.getActiveLegalDocument();
        titleEl.textContent = this.legalModalRequiresAcceptance
            ? 'Review terms before continuing'
            : 'Legal documents';
        bannerEl.textContent = this.hasAcceptedCurrentLegalVersion()
            ? `Accepted on this device: ${this.formatLegalTimestamp(acceptedRecord?.acceptedAt)}`
            : `Legal version ${this.legalDocuments?.version || '—'} must be accepted before you continue.`;

        listEl.innerHTML = '';
        (this.legalDocuments?.documents || []).forEach((legalDocument) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'btn btn-secondary legal-doc-btn';
            if (legalDocument.id === activeDocument?.id) {
                button.classList.add('active');
            }
            button.dataset.documentId = legalDocument.id;
            button.setAttribute('aria-pressed', legalDocument.id === activeDocument?.id ? 'true' : 'false');
            button.textContent = legalDocument.title;
            listEl.appendChild(button);
        });

        headingEl.textContent = activeDocument?.title || 'Legal document';
        metaEl.textContent = `Version ${this.legalDocuments?.version || '—'} • Updated ${this.legalDocuments?.updated_at || '—'}`;
        contentEl.textContent = activeDocument?.content || 'No legal document content is available.';
    }

    async handleLegalAcceptance() {
        if (!this.legalDocuments?.version) {
            this.showNotification('Unable to record acceptance because the legal version is unavailable.', 'error');
            return;
        }

        saveLegalAcceptanceValue(window.localStorage, this.legalDocuments.version);
        this.refreshLegalStatusUi();
        this.renderLegalModal();
        this.closeLegalModal({ accepted: true });
        await this.runPostLegalStartupFlow();
        this.showNotification('Terms accepted for this device.', 'success');
    }

    async retryLoadingLegalDocuments() {
        try {
            await this.ensureLegalDocumentsLoaded({ forceRefresh: true });
        } catch (error) {
            console.error('Retrying legal document load failed:', error);
        }
    }

    async declineLegalAgreement() {
        try {
            await invoke('exit_application');
        } catch (error) {
            console.error('Failed to exit after declining legal agreement:', error);
            this.showNotification('Unable to close the app automatically. Please quit the app manually.', 'error');
        }
    }

    // ========================================================================
    // Event Listeners
    // ========================================================================

    setupEventListeners() {
        // Welcome screen
        document.getElementById('loginBtn')?.addEventListener('click', () => this.openLoginModal());
        document.getElementById('registerBtn')?.addEventListener('click', () => this.openRegisterModal());
        document.getElementById('forgotPasswordBtn')?.addEventListener('click', () => this.handleForgotPassword());

        // First run welcome
        document.getElementById('firstRunCreateAccountBtn')?.addEventListener('click', () => {
            this.hideWelcomeOverlay();
            this.openRegisterModal();
        });
        document.getElementById('firstRunLoginBtn')?.addEventListener('click', () => {
            this.hideWelcomeOverlay();
            this.openLoginModal();
        });
        document.getElementById('firstRunSkipBtn')?.addEventListener('click', () => {
            this.hideWelcomeOverlay();
        });
        document.getElementById('closeFirstRunWelcomeBtn')?.addEventListener('click', () => {
            this.hideWelcomeOverlay();
        });
        document.getElementById('firstRunWelcomeBackdrop')?.addEventListener('click', () => {
            this.hideWelcomeOverlay();
        });
        document.getElementById('firstRunDontShowAgainBtn')?.addEventListener('click', () => {
            this.hideWelcomeOverlay({ dontShowAgain: true });
        });
        document.getElementById('releaseNotesContinueBtn')?.addEventListener('click', () => {
            this.hideReleaseNotesModal();
        });
        document.getElementById('releaseNotesBackdrop')?.addEventListener('click', () => {
            this.hideReleaseNotesModal();
        });
        document.getElementById('closeLegalModalBtn')?.addEventListener('click', () => this.closeLegalModal());
        document.getElementById('legalCloseBtn')?.addEventListener('click', () => this.closeLegalModal());
        document.getElementById('legalRetryBtn')?.addEventListener('click', async () => {
            await this.retryLoadingLegalDocuments();
        });
        document.getElementById('legalAcceptBtn')?.addEventListener('click', async () => {
            await this.handleLegalAcceptance();
        });
        document.getElementById('legalDeclineBtn')?.addEventListener('click', async () => {
            await this.declineLegalAgreement();
        });
        document.getElementById('legalModalBackdrop')?.addEventListener('click', () => {
            if (!this.legalModalRequiresAcceptance) {
                this.closeLegalModal();
            }
        });
        document.getElementById('legalDocumentList')?.addEventListener('click', (event) => {
            const button = event.target.closest('[data-document-id]');
            if (!button) return;
            this.selectLegalDocument(button.dataset.documentId);
        });

        // Header actions
        const globalSearch = document.getElementById('globalSearch');
        globalSearch?.addEventListener('input', (e) => this.handleGlobalSearch(e));
        globalSearch?.addEventListener('focus', () => this.renderCommandPalette(globalSearch.value));
        globalSearch?.addEventListener('click', (e) => {
            e.stopPropagation(); // Prevent document click handler from closing the palette
            this.renderCommandPalette(globalSearch.value);
        });
        globalSearch?.addEventListener('keydown', (e) => this.handleCommandPaletteKeydown(e));
        document.getElementById('settingsBtn')?.addEventListener('click', () => this.openSettingsModal());
        document.getElementById('adminPanelBtn')?.addEventListener('click', () => this.toggleAdminPanel());
        document.getElementById('feedbackBtn')?.addEventListener('click', () => this.openFeedbackModal());
        document.getElementById('postQuantumBadge')?.addEventListener('click', () => {
            const action = this.latestPostQuantumModel?.shellBadge?.action || 'show-post-quantum-explainer';
            this.handleWorkspaceHomeAction(action);
        });
        document.getElementById('unmountAllBtn')?.addEventListener('click', () => this.unmountAllFolders());
        document.getElementById('userStatusPill')?.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleSecurityPanel();
        });

        // Sidebar
        document.getElementById('refreshFoldersBtn')?.addEventListener('click', () => this.loadEnrolledFolders());
        document.getElementById('addFolderBtn')?.addEventListener('click', () => this.addEnrolledFolder());
        document.getElementById('sidebarCoverageCenterBtn')?.addEventListener('click', () => {
            this.showCoverageView({ autoStartScan: false });
        });
        document.getElementById('sidebarSwitchGroupBtn')?.addEventListener('click', () => {
            this.openSwitchGroupModal({ closeSettingsOnSubmit: false });
        });
        document.getElementById('sidebarHomeBtn')?.addEventListener('click', () => {
            this.showWorkspaceHome();
        });
        document.getElementById('sidebarTerminalBtn')?.addEventListener('click', () => {
            this.showTerminalView();
        });
        document.getElementById('homeAddFolderBtn')?.addEventListener('click', () => this.addEnrolledFolder());
        document.getElementById('homeOpenDevicesBtn')?.addEventListener('click', () => this.showDevicesView());
        document.getElementById('homeOpenTerminalBtn')?.addEventListener('click', () => this.showTerminalView());
        document.getElementById('homeRunCoverageScanBtn')?.addEventListener('click', () => {
            this.showCoverageView({ autoStartScan: true });
        });
        document.getElementById('closePostQuantumExplainerBtn')?.addEventListener('click', () => this.hidePostQuantumExplainer());
        document.getElementById('closePostQuantumExplainerFooterBtn')?.addEventListener('click', () => this.hidePostQuantumExplainer());
        document.getElementById('postQuantumExplainerBackdrop')?.addEventListener('click', () => this.hidePostQuantumExplainer());
        // Keep mount badges in sync after window hide/show lifecycle or app re-focus.
        // Delay the session check slightly on wake to let the network interface come up,
        // then restart the health timer so the next periodic check is a full interval away.
        const onWake = () => {
            const sleepGapMs = Date.now() - this.lastHealthCheckTime;
            const forceRefresh = sleepGapMs > 30 * 60 * 1000; // >30 min gap implies sleep
            setTimeout(() => {
                this.performSessionHealthCheck({ silent: true, forceRefresh }).then(() => {
                    this.startSessionHealthTimer();
                });
            }, 2000);
            this.scheduleMountStatusRefresh({
                delayMs: 80,
                renderFolderList: true,
                suppressErrorNotification: true
            });
        };
        window.addEventListener('focus', onWake);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                onWake();
            }
        });

        // File browser
        document.getElementById('unmountBtn')?.addEventListener('click', () => this.unmountFolder());
        document.getElementById('resolveConflictsBtn')?.addEventListener('click', () => this.openSelectedFolderConflicts());
        document.getElementById('resolveRecoveryCopiesBtn')?.addEventListener('click', () => this.openSelectedFolderRecoveryCopies());
        document.getElementById('mountContinueBackgroundBtn')?.addEventListener('click', () => this.continueMountInBackground());
        document.getElementById('mountCancelBtn')?.addEventListener('click', () => this.requestMountCancelFromModal());
        document.getElementById('closeConflictCenterBtn')?.addEventListener('click', () => this.closeConflictCenter());
        document.getElementById('closeConflictCenterFooterBtn')?.addEventListener('click', () => this.closeConflictCenter());
        document.getElementById('conflictCenterBackdrop')?.addEventListener('click', () => this.closeConflictCenter());
        document.getElementById('refreshConflictCenterBtn')?.addEventListener('click', () => {
            this.refreshConflictCenter().catch(error => {
                console.error('Failed to refresh conflict center:', error);
                this.showNotification('Failed to refresh conflicts.', 'error');
            });
        });
        document.getElementById('closeConflictReviewBtn')?.addEventListener('click', () => this.closeConflictReview());
        document.getElementById('closeConflictReviewFooterBtn')?.addEventListener('click', () => this.closeConflictReview());
        document.getElementById('conflictReviewBackdrop')?.addEventListener('click', () => this.closeConflictReview());
        document.getElementById('conflictReviewUseMountedSeedBtn')?.addEventListener('click', () => {
            const textarea = document.getElementById('conflictMergeEditor');
            if (textarea) {
                textarea.value = this.activeConflictPreview?.live_text || '';
            }
        });
        document.getElementById('conflictReviewUseConflictSeedBtn')?.addEventListener('click', () => {
            const textarea = document.getElementById('conflictMergeEditor');
            if (textarea) {
                textarea.value = this.activeConflictPreview?.conflict_text || '';
            }
        });
        document.getElementById('conflictReviewKeepMountedBtn')?.addEventListener('click', () => {
            this.resolveCurrentConflict('keep_mounted_file').catch(error => {
                console.error('Conflict keep-mounted failed:', error);
                this.showNotification(`Conflict resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('conflictReviewUseConflictBtn')?.addEventListener('click', () => {
            this.resolveCurrentConflict('use_conflict_copy').catch(error => {
                console.error('Conflict use-conflict failed:', error);
                this.showNotification(`Conflict resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('conflictReviewMergeBtn')?.addEventListener('click', () => {
            this.submitConflictMerge().catch(error => {
                console.error('Conflict merge failed:', error);
                this.showNotification(`Conflict resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('conflictReviewSaveAsNewBtn')?.addEventListener('click', () => {
            this.saveConflictAsNewFile().catch(error => {
                console.error('Conflict save-as-new failed:', error);
                this.showNotification(`Conflict resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('conflictReviewArchiveDismissBtn')?.addEventListener('click', () => {
            this.resolveCurrentConflict('archive_and_dismiss').catch(error => {
                console.error('Conflict archive-dismiss failed:', error);
                this.showNotification(`Conflict resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('closeRecoveryCenterBtn')?.addEventListener('click', () => this.closeRecoveryCenter());
        document.getElementById('closeRecoveryCenterFooterBtn')?.addEventListener('click', () => this.closeRecoveryCenter());
        document.getElementById('recoveryCenterBackdrop')?.addEventListener('click', () => this.closeRecoveryCenter());
        document.getElementById('refreshRecoveryCenterBtn')?.addEventListener('click', () => {
            this.refreshRecoveryCenter().catch(error => {
                console.error('Failed to refresh recovery center:', error);
                this.showNotification('Failed to refresh recovery copies.', 'error');
            });
        });
        document.getElementById('closeRecoveryReviewBtn')?.addEventListener('click', () => this.closeRecoveryReview());
        document.getElementById('recoveryReviewBackdrop')?.addEventListener('click', () => this.closeRecoveryReview());
        document.getElementById('recoveryReviewRevealMountedBtn')?.addEventListener('click', () => {
            this.revealRecoveryPath('live').catch(error => {
                console.error('Reveal mounted recovery path failed:', error);
                this.showNotification(`Failed to reveal mounted file: ${error}`, 'error');
            });
        });
        document.getElementById('recoveryReviewRevealRecoveryBtn')?.addEventListener('click', () => {
            this.revealRecoveryPath('recovery').catch(error => {
                console.error('Reveal recovery copy failed:', error);
                this.showNotification(`Failed to reveal recovery copy: ${error}`, 'error');
            });
        });
        document.getElementById('recoveryReviewReplaceMountedBtn')?.addEventListener('click', () => {
            this.resolveCurrentRecoveryCopy('replace_mounted_file').catch(error => {
                console.error('Recovery replace-mounted failed:', error);
                this.showNotification(`Recovery resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('recoveryReviewSaveAsNewBtn')?.addEventListener('click', () => {
            this.saveRecoveryAsNewFile().catch(error => {
                console.error('Recovery save-as-new failed:', error);
                this.showNotification(`Recovery resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('recoveryReviewArchiveDismissBtn')?.addEventListener('click', () => {
            this.resolveCurrentRecoveryCopy('archive_and_dismiss').catch(error => {
                console.error('Recovery archive-dismiss failed:', error);
                this.showNotification(`Recovery resolution failed: ${error}`, 'error');
            });
        });
        document.getElementById('conflictReviewRevealMountedBtn')?.addEventListener('click', () => {
            this.revealConflictPath('live').catch(error => {
                console.error('Failed to reveal mounted file:', error);
                this.showNotification('Failed to reveal mounted file.', 'error');
            });
        });
        document.getElementById('conflictReviewRevealConflictBtn')?.addEventListener('click', () => {
            this.revealConflictPath('conflict').catch(error => {
                console.error('Failed to reveal conflict copy:', error);
                this.showNotification('Failed to reveal conflict copy.', 'error');
            });
        });

        // Close context menu when clicking elsewhere
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.context-menu') && !e.target.closest('.folder-item')) {
                this.hideContextMenu();
            }
            // Close command palette if clicking outside both the search bar and the palette itself
            if (!e.target.closest('.global-search') && !e.target.closest('.command-palette')) {
                this.closeCommandPalette();
            }
            if (!e.target.closest('#userStatusWrapper')) {
                this.hideSecurityPanel();
            }
        });

        // Terminal key handling on body (no separate input bar)
        this.bindTerminalInputs();

        // Terminal tabs and resize
        document.getElementById('newTabBtn')?.addEventListener('click', () => this.createTerminalTab());
        document.getElementById('terminalTabs')?.addEventListener('click', (e) => this.handleTabClick(e));
        document.getElementById('terminalTabs')?.addEventListener('contextmenu', (e) => this.handleTerminalTabContextMenu(e));
        this.setupTerminalResize();

        // Forms
        document.getElementById('loginForm')?.addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('registerForm')?.addEventListener('submit', (e) => this.handleRegister(e));
        document.getElementById('registerEmail')?.addEventListener('input', () => this.updateRegisterValidation());
        document.getElementById('registerEmailConfirm')?.addEventListener('input', () => this.updateRegisterValidation());
        document.getElementById('registerPassword')?.addEventListener('input', () => this.updateRegisterValidation());
        document.getElementById('registerPasswordConfirm')?.addEventListener('input', () => this.updateRegisterValidation());
        document.getElementById('loginPasswordToggle')?.addEventListener('click', () => this.toggleLoginPasswordVisibility());
        document.getElementById('closeMfaPromptModalBtn')?.addEventListener('click', () => this.handleMfaPromptDecline());
        document.getElementById('mfaPromptEnableBtn')?.addEventListener('click', () => this.handleMfaPromptAccept());
        document.getElementById('mfaPromptLaterBtn')?.addEventListener('click', () => this.handleMfaPromptDecline());
        document.getElementById('closeMfaSetupModalBtn')?.addEventListener('click', () => this.hideMfaSetupModal());
        document.getElementById('mfaSetupCancelBtn')?.addEventListener('click', () => this.hideMfaSetupModal());
        document.getElementById('mfaVerifyBtn')?.addEventListener('click', () => this.verifyMfaEnrollment());
        document.getElementById('copyMfaBackupCodesBtn')?.addEventListener('click', () => this.copyMfaBackupCodes());
        document.getElementById('mfaSetupDoneBtn')?.addEventListener('click', () => this.finishMfaSetup());

        // Markers reminder
        document.getElementById('markersReminderRunBtn')?.addEventListener('click', () => this.runEnrollMarkersDiscovery());
        document.getElementById('markersReminderDismissBtn')?.addEventListener('click', () => this.dismissMarkersReminder(false));
        document.getElementById('markersReminderDontShowBtn')?.addEventListener('click', () => this.dismissMarkersReminder(true));

        // Settings action buttons (CLI-driven)
        document.querySelectorAll('.settings-action').forEach(button => {
            button.addEventListener('click', () => this.setAdminPanelVisible(false));
        });
        document.getElementById('settingsLogoutBtn')?.addEventListener('click', async () => {
            await this.runSettingsCliCommand('hybridcipher logout');
            await this.logout();
        });
        document.getElementById('settingsQuitAppBtn')?.addEventListener('click', async () => {
            this.closeSettingsModal();
            await this.handleQuitRequested();
        });
        document.getElementById('settingsMfaEnableBtn')?.addEventListener('click', () => {
            this.startMfaEnrollment();
        });
        document.getElementById('settingsAddMemberBtn')?.addEventListener('click', async () => {
            const member = await this.promptForText(
                'Enter member email or user ID to invite.',
                { title: 'Add member', placeholder: 'email or UUID', submitLabel: 'Invite' }
            );
            if (member === null) return;
            const command = `hybridcipher add-member ${this.quoteCliArg(member)}`;
            this.runSettingsCliCommand(command, { closeSettingsModal: false });
        });
        document.getElementById('settingsPendingDevicesBtn')?.addEventListener('click', () => {
            this.closeSettingsModal();
            this.showDevicesView();
        });
        document.getElementById('settingsIssueWelcomeBtn')?.addEventListener('click', async () => {
            const deviceId = await this.promptForText(
                'Enter the device ID you want to approve for this account.',
                { title: 'Approve device', placeholder: 'device_id', submitLabel: 'Approve' }
            );
            if (deviceId === null) return;
            const command = `hybridcipher issue-welcome --device ${this.quoteCliArg(deviceId)}`;
            this.runSettingsCliCommand(command, { closeSettingsModal: false });
        });
        document.getElementById('settingsCoverageScanBtn')?.addEventListener('click', () => {
            this.closeSettingsModal();
            this.showCoverageView({ autoStartScan: true });
        });
        document.getElementById('settingsCoverageStatusBtn')?.addEventListener('click', () => {
            this.closeSettingsModal();
            this.showCoverageView({ autoStartScan: false });
        });
        document.getElementById('settingsEnrollFolderBtn')?.addEventListener('click', async () => {
            await this.addEnrolledFolder();
        });
        document.getElementById('settingsUnenrollFoldersBtn')?.addEventListener('click', async () => {
            await this.openSettingsEnrollmentModal();
        });
        document.getElementById('settingsAuditSampleBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher coverage audit --verify-proofs');
        });
        document.getElementById('settingsAuditFullBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher coverage audit --verify-proofs --verify-all-proofs');
        });
        document.getElementById('settingsRecoverMarkersBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher coverage recover-markers --yes');
        });
        document.getElementById('settingsRecoveryUploadBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher recovery upload');
            this.scheduleSecurityStatusRefresh();
        });
        document.getElementById('settingsRecoveryFetchBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher recovery fetch');
        });
        document.getElementById('settingsProcessWelcomeBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher process-welcome-messages');
        });
        document.getElementById('settingsDevicesListBtn')?.addEventListener('click', () => {
            this.closeSettingsModal();
            this.showDevicesView();
        });
        document.getElementById('settingsAuditDevicesBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher audit-devices');
        });
        document.getElementById('settingsServerTrustShowBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher server-trust show');
        });
        document.getElementById('settingsServerTrustCheckpointBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher server-trust checkpoint');
        });
        document.getElementById('settingsPinListBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher pin list');
        });
        document.getElementById('settingsPinHelpBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher pin -h');
        });
        document.getElementById('settingsServerTrustHelpBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand('hybridcipher server-trust -h');
        });
        document.getElementById('settingsUnmountBtn')?.addEventListener('click', () => {
            this.runSettingsCliCommand(
                'hybridcipher unmount --all',
                {
                    confirmTitle: 'Unmount all',
                    confirmMessage:
                        'This will unmount all active mounts. Unsaved work inside mounted folders may be lost. Proceed?'
                }
            );
        });
        document.getElementById('settingsAutoMountLastFolder')?.addEventListener('change', (event) => {
            this.saveAutoMountLastFolderPreference(event.target.checked);
        });
        document.getElementById('settingsUpdatePreference')?.addEventListener('change', (e) => {
            this.updatePreference = e.target.value;
            localStorage.setItem('hybridcipher_update_preference', this.updatePreference);
        });
        document.getElementById('settingsCheckUpdateBtn')?.addEventListener('click', () => {
            this.checkForUpdatesManual();
        });
        document.getElementById('settingsReviewTermsBtn')?.addEventListener('click', () => {
            this.openLegalModal({ documentId: 'terms' });
        });
        document.getElementById('settingsReviewPrivacyBtn')?.addEventListener('click', () => {
            this.openLegalModal({ documentId: 'privacy' });
        });
        document.getElementById('updateRestartNowBtn')?.addEventListener('click', () => {
            this.triggerAppRestart();
        });
        document.getElementById('updateRestartLaterBtn')?.addEventListener('click', () => {
            this.hideUpdateRestartModal();
        });
        document.getElementById('settingsInstallGlobalCliBtn')?.addEventListener('click', async () => {
            await this.installOrRepairGlobalCli();
        });

        // Admin dashboard actions (CLI-driven)
        document.getElementById('adminRefreshStatusBtn')?.addEventListener('click', () => {
            this.refreshAdminDashboard();
        });
        document.getElementById('adminPendingActionsCard')?.addEventListener('click', (event) => {
            if (event.target.closest('button')) return;
            this.focusOperationsSection();
        });
        document.getElementById('adminPendingActionsRefreshBtn')?.addEventListener('click', () => {
            this.refreshAdminPendingActionsSummary();
        });
        document.getElementById('adminTeamMembersRefreshBtn')?.addEventListener('click', () => {
            this.refreshAdminTeamMembersSummary();
        });
        document.getElementById('adminCoverageRefreshBtn')?.addEventListener('click', () => {
            this.refreshAdminCoverageSummary();
        });
        document.getElementById('adminServerStatusRefreshBtn')?.addEventListener('click', () => {
            this.refreshAdminServerStatusSummary();
        });
        document.getElementById('adminAddMemberBtn')?.addEventListener('click', async () => {
            const member = await this.promptForText(
                'Enter member email or user ID to invite.',
                { title: 'Add member', placeholder: 'email or UUID', submitLabel: 'Invite' }
            );
            if (member === null) return;
            const command = `hybridcipher add-member ${this.quoteCliArg(member)}`;
            this.runDashboardCliCommand(command);
        });
        document.getElementById('adminRemoveMemberBtn')?.addEventListener('click', async () => {
            this.openRemoveMemberModal();
        });
        document.getElementById('adminListMembersBtn')?.addEventListener('click', async () => {
            this.openListMembersModal();
        });
        document.getElementById('adminVerifyMembershipBtn')?.addEventListener('click', async () => {
            const userId = await this.promptForText(
                'Optional: enter a user email or UUID to verify. Leave blank to verify your own membership.',
                { allowEmpty: true, title: 'Verify membership', placeholder: 'email or UUID (optional)' }
            );
            if (userId === null) return;
            const trimmedUser = userId.trim();
            let command = 'hybridcipher verify-membership';
            if (trimmedUser) {
                command += ` --user ${this.quoteCliArg(trimmedUser)}`;
            }
            this.runDashboardCliCommand(command);
        });
        document.getElementById('adminProcessWelcomesBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher process-welcome-messages');
        });
        document.getElementById('adminCoverageScanBtn')?.addEventListener('click', () => {
            this.showCoverageView({ autoStartScan: true });
        });
        document.getElementById('adminCoverageSampleAuditBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher coverage audit --verify-proofs');
        });
        document.getElementById('adminCoverageFullAuditBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher coverage audit --verify-proofs --verify-all-proofs');
        });
        document.getElementById('adminCoverageVerifyBtn')?.addEventListener('click', async () => {
            const fileId = await this.promptForText(
                'Enter the file ID to verify coverage proof.',
                { title: 'Coverage verify', placeholder: 'file ID', submitLabel: 'Verify' }
            );
            if (fileId === null) return;
            const trimmed = fileId.trim();
            if (!trimmed) {
                this.showNotification('File ID is required for coverage verification.', 'warning');
                return;
            }
            this.runDashboardCliCommand(`hybridcipher coverage verify ${this.quoteCliArg(trimmed)}`);
        });
        document.getElementById('adminCoverageEnrolledListBtn')?.addEventListener('click', () => {
            this.openAdminEnrolledListModal();
        });
        document.getElementById('adminEnrollFolderBtn')?.addEventListener('click', () => {
            this.addEnrolledFolder();
        });
        document.getElementById('adminPendingDevicesBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher pending-devices');
        });
        document.getElementById('adminIssueWelcomeQueue')?.addEventListener('click', () => {
            this.showIssueWelcomeQueue();
        });
        document.getElementById('adminStaleDevicesQueue')?.addEventListener('click', () => {
            this.showStaleDevicesQueue();
        });
        document.getElementById('adminUnverifiedDevicesQueue')?.addEventListener('click', () => {
            this.showUnverifiedDevicesQueue();
        });
        document.getElementById('adminQueueRefreshBtn')?.addEventListener('click', () => {
            this.refreshActiveQueueDetails();
        });
        document.getElementById('adminQueuePrevBtn')?.addEventListener('click', () => {
            this.changeQueuePage(-1);
        });
        document.getElementById('adminQueueNextBtn')?.addEventListener('click', () => {
            this.changeQueuePage(1);
        });
        document.getElementById('adminListGroupsBtn')?.addEventListener('click', () => {
            this.openListGroupsModal();
        });
        document.getElementById('adminCreateGroupBtn')?.addEventListener('click', () => {
            this.openCreateGroupModal();
        });
        document.getElementById('adminSwitchGroupBtn')?.addEventListener('click', () => {
            this.openSwitchGroupModal({ closeSettingsOnSubmit: false });
        });
        document.getElementById('adminRekeyStartBtn')?.addEventListener('click', async () => {
            await this.handleRekeyStartPrompt();
        });
        document.getElementById('adminRekeyMigrationBtn')?.addEventListener('click', async () => {
            const confirmed = await this.showActionPrompt(
                'Migrate coverage now?',
                'Migrate all enrolled files to the new key?',
                {
                    primaryLabel: 'Migrate',
                    secondaryLabel: 'Cancel'
                }
            );
            if (confirmed !== true) return;

            try {
                await this.getCliBinaryPath();
            } catch (error) {
                this.showNotification(
                    'Failed to locate hybridcipher CLI. Please build it with "cargo build --release --bin hybridcipher"',
                    'error'
                );
                return;
            }

            this.setAdminPanelVisible(false);
            await this.createTerminalTab();
            await this.executeCommandDirectly(
                'hybridcipher coverage migrate --all --yes',
                true,
                { returnSessionId: true }
            );
        });
        document.getElementById('adminRekeyCutoverBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand(
                'hybridcipher rekey cutover',
                {
                    confirmTitle: 'Cutover rekey',
                    confirmMessage:
                        'This will finalize the active rekey operation. Ensure coverage and device health checks are complete. Proceed?'
                }
            );
        });
        document.getElementById('adminRekeyFallbackBtn')?.addEventListener('click', async () => {
            const reason = await this.promptForText(
                'Optional: reason for fallback. Leave blank to skip.',
                { allowEmpty: true, title: 'Rekey fallback', placeholder: 'reason (optional)' }
            );
            if (reason === null) return;
            const trimmed = reason.trim();
            const command = trimmed
                ? `hybridcipher rekey fallback --yes --reason ${this.quoteCliArg(trimmed)}`
                : 'hybridcipher rekey fallback --yes';
            this.runDashboardCliCommand(
                command,
                {
                    confirmTitle: 'Rekey fallback',
                    confirmMessage:
                        'This will cancel the active rekey operation and restore the previous epoch. Proceed?'
                }
            );
        });
        document.getElementById('adminTrustVerifyBtn')?.addEventListener('click', async () => {
            this.openAdminPinVerifyModal();
        });
        document.getElementById('adminTrustCheckpointBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher server-trust checkpoint');
        });
        document.getElementById('adminPinListBtn')?.addEventListener('click', () => {
            this.runDashboardCliCommand('hybridcipher pin list');
        });

        // Admin panel accordion toggle
        document.querySelectorAll('.accordion-header').forEach(header => {
            header.addEventListener('click', () => {
                const section = header.closest('.accordion-section');
                if (!section) return;
                const sectionId = section.dataset.section;
                const isExpanded = section.classList.toggle('expanded');
                this.saveAccordionState(sectionId, isExpanded);
            });
        });
        this.restoreAccordionState();

        // Modal close buttons
        document.getElementById('closeLoginModalBtn')?.addEventListener('click', () => this.closeLoginModal());
        document.getElementById('closeRegisterModalBtn')?.addEventListener('click', () => this.closeRegisterModal());
        document.getElementById('closeSettingsModalBtn')?.addEventListener('click', () => this.closeSettingsModal());
        document.getElementById('closeSettingsEnrollmentModalBtn')?.addEventListener('click', () => this.closeSettingsEnrollmentModal());
        document.getElementById('cancelSettingsEnrollmentModalBtn')?.addEventListener('click', () => this.closeSettingsEnrollmentModal());
        document.getElementById('settingsEnrollmentModalBackdrop')?.addEventListener('click', () => this.closeSettingsEnrollmentModal());
        document.getElementById('closeFeedbackModalBtn')?.addEventListener('click', () => this.closeFeedbackModal());
        document.getElementById('cancelFeedbackBtn')?.addEventListener('click', () => this.closeFeedbackModal());
        document.getElementById('closeRecoveryCodeModalBtn')?.addEventListener('click', () => this.acknowledgeRecoveryCode());
        document.getElementById('ackRecoveryCodeBtn')?.addEventListener('click', () => this.acknowledgeRecoveryCode());
        document.getElementById('copyRecoveryCodeBtn')?.addEventListener('click', () => this.copyRecoveryCode());
        document.getElementById('closeCreateGroupModalBtn')?.addEventListener('click', () => this.closeCreateGroupModal());
        document.getElementById('cancelCreateGroupBtn')?.addEventListener('click', () => this.closeCreateGroupModal());
        document.getElementById('createGroupForm')?.addEventListener('submit', (e) => this.handleCreateGroupSubmit(e));
        document.getElementById('closeSwitchGroupModalBtn')?.addEventListener('click', () => this.closeSwitchGroupModal());
        document.getElementById('cancelSwitchGroupBtn')?.addEventListener('click', () => this.closeSwitchGroupModal());
        document.getElementById('closeRemoveMemberModalBtn')?.addEventListener('click', () => this.closeRemoveMemberModal());
        document.getElementById('cancelRemoveMemberBtn')?.addEventListener('click', () => this.closeRemoveMemberModal());
        document.getElementById('removeMemberBackdrop')?.addEventListener('click', () => this.closeRemoveMemberModal());
        document.getElementById('closeListGroupsModalBtn')?.addEventListener('click', () => this.closeListGroupsModal());
        document.getElementById('cancelListGroupsBtn')?.addEventListener('click', () => this.closeListGroupsModal());
        document.getElementById('listGroupsBackdrop')?.addEventListener('click', () => this.closeListGroupsModal());
        document.getElementById('closeListMembersModalBtn')?.addEventListener('click', () => this.closeListMembersModal());
        document.getElementById('cancelListMembersBtn')?.addEventListener('click', () => this.closeListMembersModal());
        document.getElementById('listMembersBackdrop')?.addEventListener('click', () => this.closeListMembersModal());
        document.getElementById('closeAdminPinVerifyModalBtn')?.addEventListener('click', () => this.closeAdminPinVerifyModal());
        document.getElementById('cancelAdminPinVerifyBtn')?.addEventListener('click', () => this.closeAdminPinVerifyModal());
        document.getElementById('adminPinVerifyBackdrop')?.addEventListener('click', () => this.closeAdminPinVerifyModal());
        document.getElementById('adminPinVerifyMemberSelect')?.addEventListener('change', () => this.handleAdminPinVerifyMemberChange());
        document.getElementById('adminPinVerifyDeviceSelect')?.addEventListener('change', () => this.updateAdminPinVerifySubmitState());
        document.getElementById('adminPinVerifyFingerprintInput')?.addEventListener('input', () => this.updateAdminPinVerifySubmitState());
        document.getElementById('adminPinVerifyForm')?.addEventListener('submit', (event) => this.handleAdminPinVerifySubmit(event));
        document.getElementById('closeAdminEnrolledListModalBtn')?.addEventListener('click', () => this.closeAdminEnrolledListModal());
        document.getElementById('cancelAdminEnrolledListBtn')?.addEventListener('click', () => this.closeAdminEnrolledListModal());
        document.getElementById('adminEnrolledListBackdrop')?.addEventListener('click', () => this.closeAdminEnrolledListModal());
        document.getElementById('submitSwitchGroupBtn')?.addEventListener('click', () => this.handleSwitchGroupSubmit());
        document.getElementById('switchGroupList')?.addEventListener('click', (event) => {
            const row = event.target.closest('.group-list-item');
            if (!row) return;
            const groupId = row.dataset.groupId;
            if (!groupId) return;
            if (event.target.closest('.group-switch-action')) {
                if (event.target.closest('button:disabled')) {
                    return;
                }
                this.submitSwitchGroupSelection(groupId);
                return;
            }
            if (row.dataset.current === 'true') return;
            this.setSwitchGroupSelection(groupId);
        });
        document.getElementById('feedbackForm')?.addEventListener('submit', (e) => this.handleFeedbackSubmit(e));
        document.getElementById('addAttachmentBtn')?.addEventListener('click', () => this.addFeedbackAttachment());
        document.getElementById('emailConfirmYesBtn')?.addEventListener('click', () => this.handleEmailConfirmYes());
        document.getElementById('emailConfirmLaterBtn')?.addEventListener('click', () => this.handleEmailConfirmLater());
        document.getElementById('emailConfirmResendBtn')?.addEventListener('click', () => this.handleResendConfirmationEmail());

        // Remember me checkbox
        document.getElementById('rememberMe')?.addEventListener('change', (e) => {
            this.rememberMePreference = e.target.checked;
            localStorage.setItem('hybridcipher_remember_me', e.target.checked);
            if (!this.rememberMePreference) {
                this.clearRememberedCredentials();
            }
        });

        // Set initial checkbox state
        const rememberCheckbox = document.getElementById('rememberMe');
        if (rememberCheckbox) {
            rememberCheckbox.checked = this.rememberMePreference;
        }
    }

    // ========================================================================
    // Authentication & Session
    // ========================================================================

    async loadSessionHealthConfig() {
        try {
            const result = await invoke('get_session_health_config');
            if (result?.success && result.data) {
                const {
                    check_interval_ms,
                    expiry_grace_ms,
                    mount_continue_enable_ms,
                    mount_cancel_enable_ms,
                    mount_background_timeout_ms
                } = result.data;
                if (Number.isFinite(check_interval_ms)) {
                    this.sessionHealthIntervalMs = check_interval_ms;
                }
                if (Number.isFinite(expiry_grace_ms)) {
                    this.sessionExpiryGraceMs = expiry_grace_ms;
                }
                if (Number.isFinite(mount_continue_enable_ms) && mount_continue_enable_ms >= 0) {
                    this.mountContinueEnableMs = mount_continue_enable_ms;
                }
                if (Number.isFinite(mount_cancel_enable_ms) && mount_cancel_enable_ms >= 0) {
                    this.mountCancelEnableMs = mount_cancel_enable_ms;
                }
                if (Number.isFinite(mount_background_timeout_ms) && mount_background_timeout_ms >= 0) {
                    this.mountBackgroundTimeoutMs = mount_background_timeout_ms;
                }
            }
        } catch (error) {
            console.warn('Falling back to default desktop runtime config:', error);
        }
    }

    async checkSession() {
        try {
            const sessionInfo = await this.ensureSessionReady({
                silent: true,
                verifyCli: true,
                staleMessage: 'Session expired. Please login again.'
            });

            if (sessionInfo) {
                this.currentUser = sessionInfo.email;
                this.currentDeviceId = sessionInfo.device_id || null;
                this.updateUserStatus(sessionInfo.email, true);
                this.showMainApp({ skipLoadEnrolledFolders: true });
                this.showNotification(`Welcome back, ${sessionInfo.email}!`, 'success');
                this.refreshSecurityStatus();
                await this.initializeOperationsRefresh();
                await this.loadEnrolledFolders({ suppressErrorNotification: true });
                this.maybeAutoMountLastFolder().catch(error => {
                    console.error('Auto-mount on restored session failed:', error);
                });
            } else {
                this.showWelcomeScreen();
            }
        } catch (error) {
            console.error('Session check failed:', error);
            this.showWelcomeScreen();
        }
    }

    startSessionHealthTimer() {
        this.stopSessionHealthTimer();
        if (!this.isLoggedIn) return;

        // Run an immediate check, then schedule periodic checks
        this.performSessionHealthCheck({ silent: true });
        const intervalMs = Number(this.sessionHealthIntervalMs);
        if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
            return;
        }
        this.sessionHealthTimer = setInterval(() => {
            this.performSessionHealthCheck({ silent: true });
        }, intervalMs);
    }

    stopSessionHealthTimer() {
        if (this.sessionHealthTimer) {
            clearInterval(this.sessionHealthTimer);
            this.sessionHealthTimer = null;
        }
        this.sessionHealthCheckInFlight = false;
    }

    async performSessionHealthCheck({ silent = false, forceRefresh = false } = {}) {
        if (!this.isLoggedIn) return;
        if (this.sessionHealthCheckInFlight) return;

        this.sessionHealthCheckInFlight = true;
        try {
            await this.ensureSessionReady({
                silent,
                verifyCli: true,
                forceRefresh,
                staleMessage: 'Session expired. Please login again.'
            });
            this.lastHealthCheckTime = Date.now();
        } catch (error) {
            console.warn('Background session check failed:', error);
            if (!silent) {
                this.showNotification('Session check failed. Please login again.', 'warning');
            }
        } finally {
            this.sessionHealthCheckInFlight = false;
        }
    }

    async verifyCliSession() {
        try {
            const output = await this.runCliStatusCommand('hybridcipher current-user --no-color');
            const cleaned = this.stripAnsi(output);
            if (/no active authenticated session|not authenticated|authentication token rejected|please login again/i.test(cleaned)) {
                return false;
            }
        } catch (error) {
            console.warn('CLI session verification skipped:', error);
        }
        return true;
    }

    async ensureSessionReady({
        silent = false,
        verifyCli = true,
        forceRefresh = false,
        staleMessage = 'Session expired. Please login again.'
    } = {}) {
        let sessionInfo = null;
        try {
            sessionInfo = await invoke('get_session_info', { forceRefresh });
        } catch (error) {
            console.warn('Session readiness check failed:', error);
            if (!silent) {
                this.showNotification('Session check failed. Please login again.', 'warning');
            }
            if (this.isLoggedIn) {
                await this.handleStaleSession(staleMessage);
            }
            return null;
        }

        if (!sessionInfo || sessionInfo.status !== 'active') {
            if (this.isLoggedIn) {
                await this.handleStaleSession(staleMessage);
            }
            return null;
        }

        if (verifyCli) {
            const cliSessionOk = await this.verifyCliSession();
            if (!cliSessionOk) {
                // CLI session rejected (likely server-side idle timeout).
                // Force-refresh to update server last_activity and retry once.
                try {
                    const retryInfo = await invoke('get_session_info', { forceRefresh: true });
                    if (retryInfo && retryInfo.status === 'active') {
                        const retryOk = await this.verifyCliSession();
                        if (retryOk) {
                            this.currentUser = retryInfo.email || this.currentUser;
                            this.currentDeviceId = retryInfo.device_id || this.currentDeviceId || null;
                            return retryInfo;
                        }
                    }
                } catch (retryErr) {
                    console.warn('Session recovery after CLI rejection failed:', retryErr);
                }
                if (this.isLoggedIn) {
                    await this.handleStaleSession(staleMessage);
                }
                return null;
            }
        }

        this.currentUser = sessionInfo.email || this.currentUser;
        this.currentDeviceId = sessionInfo.device_id || this.currentDeviceId || null;
        return sessionInfo;
    }

    async handleStaleSession(message) {
        try {
            await invoke('logout_user');
        } catch (error) {
            console.error('Logout error:', error);
        }
        this.currentUser = null;
        this.currentDeviceId = null;
        this.enrolledFolders = [];
        this.selectedFolder = null;
        this.showWelcomeScreen();
        if (message) {
            this.showNotification(message, 'warning');
        }
    }

    async submitLoginRequest({ email, password, mfaCode = null, backupCode = null }) {
        return invoke('login_user', {
            email,
            password,
            persistSession: this.rememberMePreference,
            mfaCode,
            backupCode
        });
    }

    async promptForLoginMfaProof({
        title = 'Multi-factor authentication',
        lead = 'Enter your authenticator code or backup code to continue sign-in.',
        submitLabel = 'Continue'
    } = {}) {
        const backupTemplate = 'XXXXX-XXXXX';
        const modal = document.getElementById('loginMfaModal');
        const backdrop = document.getElementById('loginMfaBackdrop');
        const form = document.getElementById('loginMfaForm');
        const titleEl = document.getElementById('loginMfaTitle');
        const leadEl = document.getElementById('loginMfaLead');
        const methodSelect = document.getElementById('loginMfaMethod');
        const labelEl = document.getElementById('loginMfaLabel');
        const hintEl = document.getElementById('loginMfaHint');
        const input = document.getElementById('loginMfaInput');
        const toggleBtn = document.getElementById('loginMfaToggle');
        const errorEl = document.getElementById('loginMfaError');
        const submitBtn = document.getElementById('submitLoginMfaBtn');
        const cancelBtn = document.getElementById('cancelLoginMfaBtn');
        const closeBtn = document.getElementById('closeLoginMfaModalBtn');

        if (!modal || !backdrop || !form || !methodSelect || !labelEl || !hintEl || !input || !toggleBtn || !errorEl || !submitBtn || !cancelBtn || !closeBtn) {
            // Fallback to the generic prompt flow if modal markup is unavailable.
            const mfaInput = await this.promptForText(
                'Enter the 6-digit authenticator code. Leave blank to use a backup code.',
                {
                    allowEmpty: true,
                    title,
                    placeholder: '123456',
                    submitLabel
                }
            );
            if (mfaInput === null) {
                return null;
            }
            const trimmedMfa = (mfaInput || '').trim();
            if (trimmedMfa) {
                if (!/^\d{6}$/.test(trimmedMfa)) {
                    this.showNotification('MFA code must be exactly 6 digits.', 'warning');
                    return null;
                }
                return { mfaCode: trimmedMfa, backupCode: null };
            }

            const backupInput = await this.promptForText(
                'Enter a backup code.',
                {
                    allowEmpty: false,
                    title: 'Backup code',
                    placeholder: backupTemplate,
                    submitLabel
                }
            );
            if (backupInput === null) {
                return null;
            }
            const trimmedBackup = backupInput.trim();
            if (!trimmedBackup) {
                this.showNotification('Backup code is required.', 'warning');
                return null;
            }
            return { mfaCode: null, backupCode: trimmedBackup.toUpperCase() };
        }

        const setMethodUi = () => {
            const usingBackup = methodSelect.value === 'backup';
            labelEl.textContent = usingBackup ? 'Backup code' : 'Authenticator code';
            hintEl.textContent = usingBackup
                ? 'Use one of your saved backup codes.'
                : 'Use the 6-digit code from your authenticator app.';
            input.placeholder = usingBackup ? backupTemplate : '123456';
            input.setAttribute('autocomplete', usingBackup ? 'off' : 'one-time-code');
            input.value = usingBackup ? backupTemplate : '';
            input.type = 'password';
            toggleBtn.setAttribute('data-visible', 'false');
            toggleBtn.setAttribute('aria-label', 'Show code');
            toggleBtn.setAttribute('aria-pressed', 'false');
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        };

        const showInlineError = (message) => {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
            input.focus();
        };

        if (titleEl) {
            titleEl.textContent = title;
        }
        if (leadEl) {
            leadEl.textContent = lead;
        }
        submitBtn.textContent = submitLabel;
        setMethodUi();
        modal.style.display = 'flex';
        setTimeout(() => input.focus(), 0);

        return new Promise((resolve) => {
            const cleanup = () => {
                form.removeEventListener('submit', onSubmit);
                methodSelect.removeEventListener('change', onMethodChange);
                toggleBtn.removeEventListener('click', onToggleVisibility);
                input.removeEventListener('focus', onInputFocus);
                cancelBtn.removeEventListener('click', onCancel);
                closeBtn.removeEventListener('click', onCancel);
                backdrop.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onKeyDown);
            };

            const close = (value) => {
                modal.style.display = 'none';
                cleanup();
                resolve(value);
            };

            const onMethodChange = () => {
                setMethodUi();
                input.focus();
                if (methodSelect.value === 'backup') {
                    input.select();
                }
            };

            const onToggleVisibility = () => {
                const isVisible = input.type === 'text';
                input.type = isVisible ? 'password' : 'text';
                toggleBtn.setAttribute('data-visible', isVisible ? 'false' : 'true');
                toggleBtn.setAttribute('aria-label', isVisible ? 'Show code' : 'Hide code');
                toggleBtn.setAttribute('aria-pressed', isVisible ? 'false' : 'true');
                input.focus();
            };

            const onInputFocus = () => {
                if (methodSelect.value === 'backup' && input.value === backupTemplate) {
                    input.select();
                }
            };

            const onSubmit = (event) => {
                event.preventDefault();
                const value = input.value.trim();
                const usingBackup = methodSelect.value === 'backup';
                if (!value) {
                    showInlineError('A value is required.');
                    return;
                }
                if (!usingBackup && !/^\d{6}$/.test(value)) {
                    showInlineError('Authenticator code must be exactly 6 digits.');
                    return;
                }

                if (usingBackup) {
                    const normalizedBackup = value.toUpperCase();
                    if (normalizedBackup === backupTemplate) {
                        showInlineError('Backup code is required.');
                        return;
                    }
                    close({ mfaCode: null, backupCode: normalizedBackup });
                    return;
                }

                close({ mfaCode: value, backupCode: null });
            };

            const onCancel = () => close(null);

            const onBackdropClick = (event) => {
                if (event.target === backdrop) {
                    close(null);
                }
            };

            const onKeyDown = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    close(null);
                }
            };

            form.addEventListener('submit', onSubmit);
            methodSelect.addEventListener('change', onMethodChange);
            toggleBtn.addEventListener('click', onToggleVisibility);
            input.addEventListener('focus', onInputFocus);
            cancelBtn.addEventListener('click', onCancel);
            closeBtn.addEventListener('click', onCancel);
            backdrop.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeyDown);
        });
    }

    async handleLogin(e) {
        e.preventDefault();

        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        let mfaCode = null;
        let backupCode = null;

        while (true) {
            this.showLoggingInModal();
            let result;
            try {
                result = await this.submitLoginRequest({
                    email,
                    password,
                    mfaCode,
                    backupCode
                });
            } catch (error) {
                console.error('Login error:', error);
                this.showNotification('Login failed: ' + error, 'error');
                return;
            } finally {
                this.hideLoggingInModal();
            }

            if (result?.success) {
                if (this.rememberMePreference) {
                    this.saveRememberedCredentials(email, password);
                } else {
                    this.clearRememberedCredentials();
                }
                this.currentUser = email;
                this.currentDeviceId = result?.data?.device_id || null;
                this.updateUserStatus(email, true);
                this.closeLoginModal();
                this.showMainApp({ skipLoadEnrolledFolders: true });
                this.showNotification('Successfully logged in!', 'success');
                await this.refreshSecurityStatus();
                await this.initializeOperationsRefresh();
                await this.loadEnrolledFolders({ suppressErrorNotification: true });
                this.maybeAutoMountLastFolder().catch(error => {
                    console.error('Auto-mount after login failed:', error);
                });
                if (result.data && result.data.recovery_code) {
                    this.showRecoveryCodeModal(result.data.recovery_code);
                }
                return;
            }

            const errorCode = result?.error_code || '';

            if (errorCode === 'MFA_REQUIRED') {
                if (result?.error) {
                    this.showNotification(result.error, 'warning');
                }
                const proof = await this.promptForLoginMfaProof();
                if (!proof) {
                    this.showNotification('Login cancelled.', 'info');
                    return;
                }
                mfaCode = proof.mfaCode;
                backupCode = proof.backupCode;
                continue;
            }

            if (errorCode === 'MFA_ENROLLMENT_REQUIRED') {
                this.showNotification(
                    'MFA enrollment is required before this device can sign in. Enroll MFA on an existing trusted device and retry.',
                    'warning'
                );
                return;
            }

            // Handle unverified email - offer to resend confirmation
            const errorMsg = result?.error || '';
            if (errorMsg.toLowerCase().includes('email confirmation') || errorMsg.toLowerCase().includes('account requires')) {
                this.closeLoginModal();
                this.openEmailConfirmModal(email, password);
                this.showNotification('Please verify your email before logging in.', 'warning');
                return;
            }

            this.showNotification(result?.error || 'Login failed', 'error');
            return;
        }
    }

    async handleRegister(e) {
        e.preventDefault();

        const values = this.getRegisterFormValues();
        const validation = this.validateRegisterForm(values);
        this.updateRegisterValidation();

        if (!validation.valid) {
            this.showNotification('Please fix the highlighted fields before registering.', 'warning');
            return;
        }

        this.setRegisterSubmitState(true);
        try {
            const result = await invoke('register_user', {
                request: {
                    email: values.email,
                    password: values.password
                }
            });

            if (result.success) {
                this.closeRegisterModal();
                this.openEmailConfirmModal(values.email, values.password);
            } else {
                const errorMessage = result.error || 'Registration failed';
                if (this.isEmailAlreadyRegisteredError(errorMessage)) {
                    const confirmed = await this.showConfirmDialog(
                        'Email already registered',
                        'Would you like to log in with this email instead?'
                    );
                    if (confirmed) {
                        this.closeRegisterModal();
                        this.openLoginModal(values.email);
                    }
                    this.setRegisterSubmitState(false);
                    return;
                }
                this.showNotification(errorMessage, 'error');
                this.setRegisterSubmitState(false);
            }
        } catch (error) {
            console.error('Registration error:', error);
            this.showNotification('Registration failed: ' + error, 'error');
            this.setRegisterSubmitState(false);
        }
    }

    getRegisterFormValues() {
        const email = document.getElementById('registerEmail')?.value?.trim() || '';
        const emailConfirm = document.getElementById('registerEmailConfirm')?.value?.trim() || '';
        const password = document.getElementById('registerPassword')?.value || '';
        const passwordConfirm = document.getElementById('registerPasswordConfirm')?.value || '';
        return { email, emailConfirm, password, passwordConfirm };
    }

    isValidEmail(email) {
        if (!email || email.length < 5 || email.length > 100) {
            return false;
        }
        const basicPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return basicPattern.test(email);
    }

    hasWeakPasswordPattern(password) {
        const lowered = password.toLowerCase();
        if (lowered.includes('password') || lowered.includes('123456')) {
            return true;
        }
        const chars = Array.from(password);
        for (let i = 0; i < chars.length - 2; i++) {
            const a = chars[i].charCodeAt(0);
            const b = chars[i + 1].charCodeAt(0);
            const c = chars[i + 2].charCodeAt(0);
            if (a + 1 === b && b + 1 === c) {
                return true;
            }
        }
        return false;
    }

    evaluatePasswordRules(password) {
        const length = password.length >= 12 && password.length <= 128;
        const uppercase = /[A-Z]/.test(password);
        const lowercase = /[a-z]/.test(password);
        const digit = /[0-9]/.test(password);
        const symbol = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);
        const patterns = !this.hasWeakPasswordPattern(password);
        return { length, uppercase, lowercase, digit, symbol, patterns };
    }

    validateRegisterForm(values) {
        const emailValid = this.isValidEmail(values.email);
        const emailMatch =
            values.email.length > 0 &&
            values.emailConfirm.length > 0 &&
            values.email === values.emailConfirm;
        const passwordRules = this.evaluatePasswordRules(values.password);
        const passwordValid = Object.values(passwordRules).every(Boolean);
        const passwordMatch =
            values.password.length > 0 &&
            values.passwordConfirm.length > 0 &&
            values.password === values.passwordConfirm;
        const valid = emailValid && emailMatch && passwordValid && passwordMatch;
        return {
            valid,
            emailValid,
            emailMatch,
            passwordMatch,
            passwordRules
        };
    }

    validatePasswordPair(password, confirmPassword) {
        const passwordRules = this.evaluatePasswordRules(password);
        const passwordValid = Object.values(passwordRules).every(Boolean);
        const passwordMatch =
            password.length > 0 &&
            confirmPassword.length > 0 &&
            password === confirmPassword;
        return {
            valid: passwordValid && passwordMatch,
            passwordMatch,
            passwordRules
        };
    }

    updateRegisterValidation() {
        const values = this.getRegisterFormValues();
        const validation = this.validateRegisterForm(values);

        const emailError = document.getElementById('registerEmailError');
        if (emailError) {
            if (values.email && !validation.emailValid) {
                emailError.textContent = 'Enter a valid email address.';
                emailError.style.display = 'block';
            } else {
                emailError.textContent = '';
                emailError.style.display = 'none';
            }
        }

        const emailMatchError = document.getElementById('registerEmailMatchError');
        if (emailMatchError) {
            if (values.emailConfirm && !validation.emailMatch) {
                emailMatchError.textContent = 'Emails do not match.';
                emailMatchError.style.display = 'block';
            } else {
                emailMatchError.textContent = '';
                emailMatchError.style.display = 'none';
            }
        }

        const passwordMatchError = document.getElementById('registerPasswordMatchError');
        if (passwordMatchError) {
            if (values.passwordConfirm && !validation.passwordMatch) {
                passwordMatchError.textContent = 'Passwords do not match.';
                passwordMatchError.style.display = 'block';
            } else {
                passwordMatchError.textContent = '';
                passwordMatchError.style.display = 'none';
            }
        }

        const hintItems = document.querySelectorAll('#registerPasswordHints li');
        hintItems.forEach((item) => {
            const rule = item.getAttribute('data-rule');
            if (rule && validation.passwordRules[rule]) {
                item.classList.add('is-met');
            } else {
                item.classList.remove('is-met');
            }
        });

        const strengthContainer = document.querySelector('#registerModal .password-strength');
        const strengthFill = document.getElementById('registerPasswordStrengthFill');
        const strengthLabel = document.getElementById('registerPasswordStrengthLabel');
        if (strengthContainer && strengthFill && strengthLabel) {
            const strengthMeta = this.getPasswordStrengthMeta(values.password, validation.passwordRules);
            strengthContainer.classList.remove('weak', 'medium', 'strong');
            if (strengthMeta.level) {
                strengthContainer.classList.add(strengthMeta.level);
            }
            strengthFill.style.width = `${strengthMeta.percent}%`;
            strengthLabel.textContent = strengthMeta.label;
        }

        const submitBtn = document.getElementById('registerSubmitBtn');
        if (submitBtn) {
            submitBtn.disabled = !validation.valid || this.registerSubmitting;
        }
    }

    setRegisterSubmitState(isSubmitting) {
        this.registerSubmitting = Boolean(isSubmitting);
        const submitBtn = document.getElementById('registerSubmitBtn');
        if (!submitBtn) return;
        submitBtn.disabled = this.registerSubmitting || submitBtn.disabled;
        submitBtn.textContent = this.registerSubmitting ? 'Registering...' : 'Register';
        if (!this.registerSubmitting) {
            this.updateRegisterValidation();
        }
    }

    resetRegisterModalState() {
        const form = document.getElementById('registerForm');
        if (form) {
            form.reset();
        }
        this.registerSubmitting = false;
        const submitBtn = document.getElementById('registerSubmitBtn');
        if (submitBtn) {
            submitBtn.textContent = 'Register';
            submitBtn.disabled = true;
        }
        const errorIds = ['registerEmailError', 'registerEmailMatchError', 'registerPasswordMatchError'];
        errorIds.forEach((id) => {
            const el = document.getElementById(id);
            if (el) {
                el.textContent = '';
                el.style.display = 'none';
            }
        });
        this.updateRegisterValidation();
    }

    getPasswordStrengthMeta(password, rules) {
        if (!password) {
            return { level: null, percent: 0, label: 'Strength: --' };
        }
        const baseRules = ['length', 'uppercase', 'lowercase', 'digit', 'symbol'];
        const satisfied = baseRules.filter((rule) => rules[rule]).length;
        let level = 'weak';
        let percent = Math.round((satisfied / baseRules.length) * 100);

        if (!rules.patterns || !rules.length) {
            level = 'weak';
            percent = Math.min(percent, 40);
        } else if (satisfied >= 5) {
            level = 'strong';
            percent = 100;
        } else if (satisfied >= 3) {
            level = 'medium';
            percent = 60;
        } else {
            level = 'weak';
            percent = 25;
        }

        const label = `Strength: ${level.charAt(0).toUpperCase()}${level.slice(1)}`;
        return { level, percent, label };
    }

    async promptForPasswordResetValues() {
        const modal = document.getElementById('passwordResetModal');
        const backdrop = document.getElementById('passwordResetBackdrop');
        const form = document.getElementById('passwordResetForm');
        const passwordInput = document.getElementById('passwordResetInput');
        const confirmInput = document.getElementById('passwordResetConfirmInput');
        const passwordToggle = document.getElementById('passwordResetToggle');
        const confirmToggle = document.getElementById('passwordResetConfirmToggle');
        const confirmError = document.getElementById('passwordResetConfirmError');
        const errorEl = document.getElementById('passwordResetError');
        const strengthContainer = document.getElementById('passwordResetStrength');
        const strengthFill = document.getElementById('passwordResetStrengthFill');
        const strengthLabel = document.getElementById('passwordResetStrengthLabel');
        const hints = document.querySelectorAll('#passwordResetHints li');
        const submitBtn = document.getElementById('submitPasswordResetBtn');
        const cancelBtn = document.getElementById('cancelPasswordResetBtn');
        const closeBtn = document.getElementById('closePasswordResetModalBtn');

        if (!modal || !backdrop || !form || !passwordInput || !confirmInput || !passwordToggle || !confirmToggle || !confirmError || !errorEl || !strengthContainer || !strengthFill || !strengthLabel || !submitBtn || !cancelBtn || !closeBtn) {
            const password = await this.promptForText(
                'Enter your new password.',
                {
                    allowEmpty: false,
                    title: 'Set a new password',
                    submitLabel: 'Continue'
                }
            );
            if (password === null) {
                return null;
            }
            const confirmPassword = await this.promptForText(
                'Confirm your new password.',
                {
                    allowEmpty: false,
                    title: 'Confirm password',
                    submitLabel: 'Reset password'
                }
            );
            if (confirmPassword === null) {
                return null;
            }
            return { password, confirmPassword };
        }

        const setToggleState = (input, button, visibleLabel, hiddenLabel) => {
            const isVisible = input.type === 'text';
            input.type = isVisible ? 'password' : 'text';
            button.setAttribute('data-visible', isVisible ? 'false' : 'true');
            button.setAttribute('aria-label', isVisible ? visibleLabel : hiddenLabel);
            button.setAttribute('aria-pressed', isVisible ? 'false' : 'true');
            input.focus();
        };

        const updateUi = () => {
            const validation = this.validatePasswordPair(passwordInput.value, confirmInput.value);
            hints.forEach((item) => {
                const rule = item.getAttribute('data-rule');
                if (rule && validation.passwordRules[rule]) {
                    item.classList.add('is-met');
                } else {
                    item.classList.remove('is-met');
                }
            });

            const strengthMeta = this.getPasswordStrengthMeta(passwordInput.value, validation.passwordRules);
            strengthContainer.classList.remove('weak', 'medium', 'strong');
            if (strengthMeta.level) {
                strengthContainer.classList.add(strengthMeta.level);
            }
            strengthFill.style.width = `${strengthMeta.percent}%`;
            strengthLabel.textContent = strengthMeta.label;

            if (confirmInput.value && !validation.passwordMatch) {
                confirmError.textContent = 'Passwords do not match.';
                confirmError.style.display = 'block';
            } else {
                confirmError.textContent = '';
                confirmError.style.display = 'none';
            }

            errorEl.textContent = '';
            errorEl.style.display = 'none';
            submitBtn.disabled = !validation.valid;
            return validation;
        };

        passwordInput.value = '';
        confirmInput.value = '';
        passwordInput.type = 'password';
        confirmInput.type = 'password';
        passwordToggle.setAttribute('data-visible', 'false');
        passwordToggle.setAttribute('aria-label', 'Show password');
        passwordToggle.setAttribute('aria-pressed', 'false');
        confirmToggle.setAttribute('data-visible', 'false');
        confirmToggle.setAttribute('aria-label', 'Show password confirmation');
        confirmToggle.setAttribute('aria-pressed', 'false');
        submitBtn.disabled = true;
        updateUi();

        modal.style.display = 'flex';
        setTimeout(() => passwordInput.focus(), 0);

        return new Promise((resolve) => {
            const cleanup = () => {
                form.removeEventListener('submit', onSubmit);
                passwordInput.removeEventListener('input', onInput);
                confirmInput.removeEventListener('input', onInput);
                passwordToggle.removeEventListener('click', onTogglePassword);
                confirmToggle.removeEventListener('click', onToggleConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                closeBtn.removeEventListener('click', onCancel);
                backdrop.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onKeyDown);
            };

            const close = (value) => {
                modal.style.display = 'none';
                cleanup();
                resolve(value);
            };

            const onInput = () => {
                updateUi();
            };

            const onTogglePassword = () => {
                setToggleState(passwordInput, passwordToggle, 'Show password', 'Hide password');
            };

            const onToggleConfirm = () => {
                setToggleState(confirmInput, confirmToggle, 'Show password confirmation', 'Hide password confirmation');
            };

            const onSubmit = (event) => {
                event.preventDefault();
                const password = passwordInput.value;
                const confirmPassword = confirmInput.value;
                const validation = this.validatePasswordPair(password, confirmPassword);
                if (!Object.values(validation.passwordRules).every(Boolean)) {
                    errorEl.textContent = 'Password does not meet the required strength rules.';
                    errorEl.style.display = 'block';
                    passwordInput.focus();
                    return;
                }
                if (!validation.passwordMatch) {
                    errorEl.textContent = 'Passwords do not match.';
                    errorEl.style.display = 'block';
                    confirmInput.focus();
                    return;
                }
                close({ password, confirmPassword });
            };

            const onCancel = () => close(null);

            const onBackdropClick = (event) => {
                if (event.target === backdrop) {
                    close(null);
                }
            };

            const onKeyDown = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    close(null);
                }
            };

            form.addEventListener('submit', onSubmit);
            passwordInput.addEventListener('input', onInput);
            confirmInput.addEventListener('input', onInput);
            passwordToggle.addEventListener('click', onTogglePassword);
            confirmToggle.addEventListener('click', onToggleConfirm);
            cancelBtn.addEventListener('click', onCancel);
            closeBtn.addEventListener('click', onCancel);
            backdrop.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeyDown);
        });
    }

    isEmailAlreadyRegisteredError(message) {
        const lowered = String(message || '').toLowerCase();
        return (
            lowered.includes('already registered') ||
            lowered.includes('already exists') ||
            lowered.includes('already in use') ||
            lowered.includes('email exists')
        );
    }

    openEmailConfirmModal(email, password) {
        const modal = document.getElementById('emailConfirmModal');
        const address = document.getElementById('emailConfirmAddress');
        if (address) {
            address.textContent = email;
        }
        if (modal) {
            modal.style.display = 'flex';
        }
        this.pendingRegistrationEmail = email;
        this.pendingRegistrationPassword = password;
        this.confirmationVerified = false;
        this.lastConfirmationResendAt = 0;
        this.updateEmailConfirmStatus('Waiting for confirmation...', 'pending');
        this.updateResendCooldownState(true);

        const yesBtn = document.getElementById('emailConfirmYesBtn');
        if (yesBtn) {
            yesBtn.textContent = 'Yes, I confirmed';
        }

        this.startEmailConfirmationPolling();
    }

    closeEmailConfirmModal() {
        const modal = document.getElementById('emailConfirmModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.stopEmailConfirmationPolling();
        this.pendingRegistrationEmail = null;
        this.pendingRegistrationPassword = null;
        this.confirmationVerified = false;
        this.lastConfirmationResendAt = 0;
        this.updateResendCooldownState(true);
    }

    startEmailConfirmationPolling() {
        this.stopEmailConfirmationPolling();
        this.confirmationPollDeadline = Date.now() + 90000;
        this.confirmationPollTimer = setInterval(() => {
            this.pollEmailConfirmationStatus();
        }, 6000);
        this.pollEmailConfirmationStatus();
    }

    stopEmailConfirmationPolling() {
        if (this.confirmationPollTimer) {
            clearInterval(this.confirmationPollTimer);
            this.confirmationPollTimer = null;
        }
        if (this.resendCooldownTimer) {
            clearInterval(this.resendCooldownTimer);
            this.resendCooldownTimer = null;
        }
    }

    async pollEmailConfirmationStatus() {
        if (this.confirmationCheckInFlight) {
            return;
        }
        if (!this.pendingRegistrationEmail || !this.pendingRegistrationPassword) {
            return;
        }
        if (Date.now() > this.confirmationPollDeadline) {
            this.stopEmailConfirmationPolling();
            this.updateEmailConfirmStatus('Still waiting for confirmation. You can resend the email.', 'pending');
            return;
        }

        this.confirmationCheckInFlight = true;
        try {
            const result = await invoke('check_email_confirmation', {
                email: this.pendingRegistrationEmail,
                password: this.pendingRegistrationPassword
            });
            if (result.success && result.data?.confirmed) {
                this.handleEmailConfirmed();
            } else if (result.success) {
                this.updateEmailConfirmStatus('Waiting for confirmation...', 'pending');
            } else if (result.error) {
                this.updateEmailConfirmStatus(result.error, 'error');
            }
        } catch (error) {
            console.error('Confirmation check failed:', error);
            this.updateEmailConfirmStatus('Unable to check confirmation right now.', 'error');
        } finally {
            this.confirmationCheckInFlight = false;
        }
    }

    handleEmailConfirmed() {
        this.confirmationVerified = true;
        this.stopEmailConfirmationPolling();
        this.updateEmailConfirmStatus('Email confirmed. You can log in now.', 'confirmed');
        const yesBtn = document.getElementById('emailConfirmYesBtn');
        if (yesBtn) {
            yesBtn.textContent = 'Continue to Login';
        }
    }

    updateEmailConfirmStatus(message, state) {
        const statusEl = document.getElementById('emailConfirmStatus');
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.classList.remove('confirmed', 'error');
        if (state === 'confirmed') {
            statusEl.classList.add('confirmed');
        } else if (state === 'error') {
            statusEl.classList.add('error');
        }
    }

    async handleEmailConfirmYes() {
        if (!this.pendingRegistrationEmail || !this.pendingRegistrationPassword) {
            return;
        }

        if (this.confirmationVerified) {
            const email = this.pendingRegistrationEmail;
            this.closeEmailConfirmModal();
            this.openLoginModal(email);
            return;
        }

        const confirmed = await this.checkEmailConfirmationOnce();
        if (confirmed) {
            const email = this.pendingRegistrationEmail;
            this.closeEmailConfirmModal();
            this.openLoginModal(email);
            return;
        }

        const resend = await this.showConfirmDialog(
            'Not confirmed yet',
            'We still do not see the confirmation. Would you like to resend the confirmation email?'
        );
        if (resend) {
            await this.handleResendConfirmationEmail();
        }
    }

    handleEmailConfirmLater() {
        this.closeEmailConfirmModal();
        this.showWelcomeScreen();
    }

    async checkEmailConfirmationOnce() {
        try {
            const result = await invoke('check_email_confirmation', {
                email: this.pendingRegistrationEmail,
                password: this.pendingRegistrationPassword
            });
            if (result.success && result.data?.confirmed) {
                this.handleEmailConfirmed();
                return true;
            }
            if (result.success) {
                this.updateEmailConfirmStatus('Confirmation not detected yet.', 'pending');
                return false;
            }
            if (result.error) {
                this.updateEmailConfirmStatus(result.error, 'error');
            }
        } catch (error) {
            console.error('Confirmation check failed:', error);
            this.updateEmailConfirmStatus('Unable to check confirmation right now.', 'error');
        }
        return false;
    }

    async handleResendConfirmationEmail() {
        if (!this.pendingRegistrationEmail) {
            return;
        }
        const now = Date.now();
        const elapsed = now - this.lastConfirmationResendAt;
        if (this.lastConfirmationResendAt && elapsed < 60000) {
            this.updateResendCooldownState();
            return;
        }

        try {
            const result = await invoke('resend_confirmation_email', {
                email: this.pendingRegistrationEmail
            });
            if (result.success) {
                this.lastConfirmationResendAt = Date.now();
                this.updateEmailConfirmStatus('Confirmation email resent.', 'pending');
                this.updateResendCooldownState();
            } else {
                this.updateEmailConfirmStatus(result.error || 'Failed to resend confirmation email.', 'error');
            }
        } catch (error) {
            console.error('Failed to resend confirmation email:', error);
            this.updateEmailConfirmStatus('Failed to resend confirmation email.', 'error');
        }
    }

    updateResendCooldownState(reset = false) {
        const resendBtn = document.getElementById('emailConfirmResendBtn');
        const hint = document.getElementById('emailConfirmCooldownHint');
        if (reset) {
            if (resendBtn) resendBtn.disabled = false;
            if (hint) hint.textContent = '';
            if (this.resendCooldownTimer) {
                clearInterval(this.resendCooldownTimer);
                this.resendCooldownTimer = null;
            }
            return;
        }

        const updateHint = () => {
            const remaining = Math.max(0, 60000 - (Date.now() - this.lastConfirmationResendAt));
            if (!remaining) {
                if (resendBtn) resendBtn.disabled = false;
                if (hint) hint.textContent = '';
                if (this.resendCooldownTimer) {
                    clearInterval(this.resendCooldownTimer);
                    this.resendCooldownTimer = null;
                }
                return;
            }
            if (resendBtn) resendBtn.disabled = true;
            if (hint) {
                hint.textContent = `Please wait ${Math.ceil(remaining / 1000)}s to resend.`;
            }
        };

        updateHint();
        if (!this.resendCooldownTimer) {
            this.resendCooldownTimer = setInterval(updateHint, 1000);
        }
    }

    async logout() {
        try {
            await invoke('logout_user');
            this.currentUser = null;
            this.currentDeviceId = null;
            this.enrolledFolders = [];
            this.selectedFolder = null;
            this.showWelcomeScreen();
            this.showNotification('Logged out successfully', 'info');
        } catch (error) {
            console.error('Logout error:', error);
            this.showNotification('Logout failed', 'error');
        }
    }

    async handleForgotPassword() {
        const loginEmail = document.getElementById('loginEmail')?.value?.trim() || '';
        const rememberedEmail = this.loadRememberedCredentials().email || '';
        const suggestedEmail = (loginEmail || rememberedEmail || '').trim();

        const emailInput = await this.promptForText(
            'Enter the email address for the account you want to reset.',
            {
                allowEmpty: false,
                title: 'Forgot Password',
                placeholder: 'your@email.com',
                submitLabel: 'Continue',
                initialValue: suggestedEmail
            }
        );
        if (emailInput === null) {
            this.showNotification('Password reset cancelled.', 'info');
            return;
        }
        const email = emailInput.trim();
        if (!this.isValidEmail(email)) {
            this.showNotification('Enter a valid email address to continue.', 'warning');
            return;
        }

        this.showActionProgressModal([
            'Checking account...',
            'Verifying that the email can use password reset...'
        ]);
        let accountCheck;
        try {
            accountCheck = await invoke('check_password_reset_account', { email });
        } catch (error) {
            console.error('Password reset account lookup failed:', error);
            this.showNotification('Failed to verify the account: ' + error, 'error');
            return;
        } finally {
            this.hideActionProgressModal();
        }
        if (!accountCheck?.success) {
            this.showNotification(accountCheck?.error || 'No account was found for that email address.', 'error');
            return;
        }

        const proof = await this.promptForLoginMfaProof({
            title: 'Verify MFA to Reset Password',
            lead: 'Enter your authenticator code or backup code to request a password reset token.',
            submitLabel: 'Send Reset Token'
        });
        if (!proof) {
            this.showNotification('Password reset request cancelled.', 'info');
            return;
        }

        const requestReset = async (acceptDataLoss = false) => invoke('request_password_reset', {
            email,
            mfaCode: proof.mfaCode,
            backupCode: proof.backupCode,
            acceptDataLoss
        });

        this.showActionProgressModal([
            'Verifying MFA proof...',
            'Requesting password reset token...',
            'Preparing password reset flow...'
        ]);

        let requestResult;
        try {
            requestResult = await requestReset(false);
        } catch (error) {
            console.error('Forgot password request failed:', error);
            this.showNotification('Failed to request password reset: ' + error, 'error');
            return;
        } finally {
            this.hideActionProgressModal();
        }

        if (!requestResult?.success && requestResult?.error_code === 'DATA_LOSS_CONFIRMATION_REQUIRED') {
            const confirmation = await this.promptForText(
                "Type 'accept_data_loss' to continue. Press cancel to stop.",
                {
                    allowEmpty: false,
                    title: 'Potential Local Data Loss',
                    placeholder: 'accept_data_loss',
                    submitLabel: 'Continue'
                }
            );
            if (confirmation !== 'accept_data_loss') {
                this.showNotification('Password reset cancelled.', 'info');
                return;
            }

            this.showActionProgressModal([
                'Acknowledging local data loss warning...',
                'Requesting password reset token...'
            ]);
            try {
                requestResult = await requestReset(true);
            } catch (error) {
                console.error('Forgot password request retry failed:', error);
                this.showNotification('Failed to request password reset: ' + error, 'error');
                return;
            } finally {
                this.hideActionProgressModal();
            }
        }

        if (!requestResult?.success) {
            this.showNotification(requestResult?.error || 'Failed to request password reset.', 'error');
            return;
        }

        this.showNotification(
            requestResult?.data || 'If an account exists for that email, a reset token has been sent.',
            'success'
        );

        const token = await this.promptForText(
            'Paste the password reset token from your email.',
            {
                allowEmpty: false,
                title: 'Enter Reset Token',
                placeholder: 'reset-token',
                submitLabel: 'Continue'
            }
        );
        if (!token) {
            this.showNotification('Password reset cancelled before token submission.', 'info');
            return;
        }

        let resetSession;
        try {
            const result = await invoke('start_password_reset', { token: token.trim() });
            if (!result?.success || !result?.data?.session_id) {
                this.showNotification(result?.error || 'Failed to start password reset.', 'error');
                return;
            }
            resetSession = result.data.session_id;
        } catch (error) {
            console.error('Failed to start password reset:', error);
            this.showNotification('Failed to start password reset: ' + error, 'error');
            return;
        }

        const passwordValues = await this.promptForPasswordResetValues();
        if (!passwordValues) {
            try {
                await invoke('cancel_password_reset', { sessionId: resetSession });
            } catch (error) {
                console.warn('Failed to cancel password reset session:', error);
            }
            this.showNotification('Password reset cancelled.', 'info');
            return;
        }

        this.showActionProgressModal([
            'Submitting new password...',
            'Waiting for HybridCipher CLI to complete password reset...'
        ]);

        try {
            const result = await invoke('complete_password_reset', {
                sessionId: resetSession,
                password: passwordValues.password,
                confirmPassword: passwordValues.confirmPassword
            });
            if (!result?.success) {
                this.showNotification(result?.error || 'Password reset failed.', 'error');
                return;
            }

            this.openLoginModal(email);
            this.showNotification(
                result?.data || 'Password reset successful. Sign in with your new password.',
                'success'
            );
        } catch (error) {
            console.error('Password reset completion failed:', error);
            this.showNotification('Password reset failed: ' + error, 'error');
        } finally {
            this.hideActionProgressModal();
        }
    }

    // ========================================================================
    // Folder Management
    // ========================================================================

    isSettingsEnrollmentModalOpen() {
        const modal = document.getElementById('settingsEnrollmentModal');
        return Boolean(modal && modal.style.display === 'flex');
    }

    setSettingsEnrollmentModalExpanded(expanded) {
        const toggleBtn = document.getElementById('settingsUnenrollFoldersBtn');
        if (toggleBtn) {
            toggleBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        }
    }

    async openSettingsEnrollmentModal() {
        const modal = document.getElementById('settingsEnrollmentModal');
        const list = document.getElementById('settingsEnrollmentModalList');
        if (!modal || !list) return;

        this.setSettingsEnrollmentModalExpanded(true);
        modal.style.display = 'flex';
        list.innerHTML = '<div class="member-list-empty">Loading protected folders...</div>';

        const loaded = await this.loadEnrolledFolders({ suppressErrorNotification: true });
        if (!loaded) {
            list.innerHTML = '<div class="member-list-empty">Failed to load protected folders.</div>';
            this.showNotification('Failed to load protected folders', 'error');
            return;
        }
        this.renderSettingsEnrollmentList();
    }

    closeSettingsEnrollmentModal() {
        const modal = document.getElementById('settingsEnrollmentModal');
        const list = document.getElementById('settingsEnrollmentModalList');
        if (modal) {
            modal.style.display = 'none';
        }
        if (list) {
            list.innerHTML = '<div class="member-list-empty">Loading protected folders...</div>';
        }
        this.setSettingsEnrollmentModalExpanded(false);
    }

    renderSettingsEnrollmentList() {
        const list = document.getElementById('settingsEnrollmentModalList');
        if (!list || !this.isSettingsEnrollmentModalOpen()) return;

        list.innerHTML = '';
        if (!Array.isArray(this.enrolledFolders) || this.enrolledFolders.length === 0) {
            list.innerHTML = '<div class="member-list-empty">No protected folders.</div>';
            return;
        }

        this.enrolledFolders.forEach(folder => {
            const row = document.createElement('div');
            row.className = 'member-list-item settings-enrollment-item';

            const meta = document.createElement('div');
            meta.className = 'member-list-meta';

            const folderName = document.createElement('div');
            folderName.className = 'member-list-email';
            const fallbackName = folder.path ? folder.path.split(/[/\\\\]/).filter(Boolean).pop() : '';
            folderName.textContent = folder.name || fallbackName || folder.path || 'Unknown folder';

            const folderPath = document.createElement('div');
            folderPath.className = 'member-list-details';
            folderPath.textContent = folder.path || 'Path unavailable';

            meta.appendChild(folderName);
            meta.appendChild(folderPath);

            const action = document.createElement('button');
            action.type = 'button';
            action.className = 'btn btn-secondary btn-small';
            action.textContent = 'Remove';
            action.addEventListener('click', async (event) => {
                event.stopPropagation();
                if (action.disabled) return;
                action.disabled = true;
                try {
                    await this.handleSettingsUnenrollFolder(folder);
                } finally {
                    action.disabled = false;
                }
            });

            row.appendChild(meta);
            row.appendChild(action);
            list.appendChild(row);
        });
    }

    async handleSettingsUnenrollFolder(folder) {
        if (!folder?.root_id) {
            this.showNotification('Protected folder id is missing.', 'error');
            return;
        }

        let isMounted = false;
        let mountpoint = null;
        if (folder?.root_id) {
            try {
                const mountStatus = await invoke('check_mount_status_by_root_id', {
                    rootId: folder.root_id
                });
                isMounted = Boolean(mountStatus?.success && mountStatus?.data);
                mountpoint = isMounted ? mountStatus.data.mountpoint : null;
            } catch (error) {
                console.warn('Failed to check mount status before removal:', error);
            }
        }

        if (isMounted) {
            const unmountFirst = await this.showConfirmDialog(
                'Folder is mounted',
                `This folder is currently mounted${mountpoint ? ` at:\n${mountpoint}\n` : '.\n'}\nUnmount first and continue?`
            );
            if (!unmountFirst) {
                return;
            }

            const unmounted = await this.executeUnmountCommand(folder, {
                suppressSuccessNotification: true,
                suppressFailureNotification: true
            });
            if (!unmounted) {
                this.showNotification('Unmount failed. Cannot proceed with removal.', 'error');
                return;
            }

            const proceedAfterUnmount = await this.showConfirmDialog(
                'Unmount completed',
                `Unmount succeeded for:\n"${folder.path}"\n\nProceed with removal and decryption?`
            );
            if (!proceedAfterUnmount) {
                return;
            }
        }

        if (!isMounted) {
            const confirmed = await this.showConfirmDialog(
                'Remove Protected Folder',
                `This will decrypt all files in this folder and stop protecting it:\n\n"${folder.path}"\n\nDo you want to proceed?`
            );
            if (!confirmed) {
                return;
            }
        }

        this.showActionProgressModal(`Removing protection from ${folder.path}...`);
        try {
            const response = await invoke('unenroll_folder_and_decrypt', {
                rootId: folder.root_id
            });
            if (!response?.success) {
                throw new Error(response?.error || 'Folder removal failed.');
            }
            this.hideActionProgressModal();
            await this.loadEnrolledFolders({ suppressErrorNotification: true });
            this.renderSettingsEnrollmentList();
            this.showNotification('Protected folder removed and decrypted.', 'success');
        } catch (error) {
            this.hideActionProgressModal();
            console.error('Failed to remove protected folder:', error);
            await this.showActionPrompt(
                'Remove protected folder failed',
                error?.message || String(error),
                {
                    primaryLabel: 'Close',
                    secondaryLabel: null
                }
            );
            return;
        }
    }

    async addEnrolledFolder() {
        try {
            // Use Tauri dialog to pick a folder
            const tauriGlobal = window.__TAURI__;
            if (!tauriGlobal?.dialog?.open) {
                this.showNotification('Folder picker not available', 'error');
                return;
            }

            const selected = await tauriGlobal.dialog.open({
                directory: true,
                multiple: false,
                title: 'Select folder to enroll'
            });

            if (!selected) {
                // User cancelled
                return;
            }

            // Show confirmation dialog first
            const confirmed = await this.showConfirmDialog(
                'Add Protected Folder',
                `This will add "${selected}" to your protected folders for coverage tracking and automatic encryption.\n\nProceed?`
            );
            if (!confirmed) {
                return;
            }

            this.showActionProgressModal(`Protecting ${selected}...`);
            const response = await invoke('enroll_folder_and_hydrate', {
                folderPath: selected
            });
            if (!response?.success) {
                throw new Error(response?.error || 'Folder enrollment failed.');
            }

            this.hideActionProgressModal();
            await this.loadEnrolledFolders({ suppressErrorNotification: true });
            this.showNotification('Folder protected now with post-quantum encryption.', 'success');
        } catch (error) {
            this.hideActionProgressModal();
            console.error('Failed to add folder:', error);
            await this.showActionPrompt(
                'Protect folder failed',
                error?.message || String(error),
                {
                    primaryLabel: 'Close',
                    secondaryLabel: null
                }
            );
        }
    }

    async loadEnrolledFolders({ suppressErrorNotification = false } = {}) {
        try {
            const response = await invoke('list_enrolled_folders');
            if (!response.success) {
                throw new Error(response.error || 'Failed to load folders');
            }
            this.enrolledFolders = response.data || [];
            await this.refreshActiveMounts({
                renderFolderList: false,
                suppressErrorNotification: true
            });
            this.renderFolderList();
            this.renderSettingsEnrollmentList();
            if (this.enrolledFolders.length > 0) {
                this.maybeShowMarkersReminder();
            } else {
                this.hideMarkersReminder();
            }

            // Auto-select previously selected folder if it exists
            if (this.selectedFolder && this.userFolderPreferences.lastSelectedFolder) {
                const folder = this.enrolledFolders.find(f => f.path === this.userFolderPreferences.lastSelectedFolder);
                if (folder) {
                    this.selectFolder(folder);
                }
            } else {
                this.syncSelectedFolderMountUi();
            }
            if (this.activeWorkspaceView === 'folder-detail') {
                this.renderFolderDetailView(this.selectedFolder);
            }
            this.updateSidebarMountSummary();
            return true;
        } catch (error) {
            console.error('Failed to load folders:', error);
            if (!suppressErrorNotification) {
                this.showNotification('Failed to load folders', 'error');
            }
            return false;
        }
    }

    async refreshActiveMounts({
        renderFolderList = false,
        suppressErrorNotification = true,
        suppressRecoveryPrompt = false
    } = {}) {
        if (!this.isLoggedIn) {
            this.activeMountsByRootId = {};
            this.activeMountDetailsByRootId = {};
            this.syncSelectedFolderMountUi();
            if (renderFolderList) {
                this.renderFolderList();
            }
            if (this.activeWorkspaceView === 'folder-detail') {
                this.renderFolderDetailView(this.selectedFolder);
            }
            this.updateSidebarMountSummary();
            return this.activeMountsByRootId;
        }

        try {
            const response = await invoke('list_active_mounts');
            if (!response?.success || !Array.isArray(response?.data)) {
                throw new Error(response?.error || 'Active mounts unavailable');
            }

            const mountsByRoot = {};
            const mountDetailsByRoot = {};
            response.data.forEach(entry => {
                const rootId = String(entry?.root_id || '').trim();
                const mountpoint = String(entry?.mountpoint || '').trim();
                if (rootId && mountpoint) {
                    mountsByRoot[rootId] = mountpoint;
                    mountDetailsByRoot[rootId] = {
                        mountpoint,
                        backend: String(entry?.backend || '').trim() || 'sync',
                        fallbackReason: entry?.fallback_reason || null,
                        syncStatus: entry?.sync_status || null
                    };
                }
            });

            this.activeMountsByRootId = mountsByRoot;
            this.activeMountDetailsByRootId = mountDetailsByRoot;
            if (!suppressRecoveryPrompt) {
                await this.maybeShowRecoveryPrompts(mountDetailsByRoot);
            }
            this.syncSelectedFolderMountUi();
            if (renderFolderList) {
                this.renderFolderList();
            }
            if (this.activeWorkspaceView === 'folder-detail') {
                this.renderFolderDetailView(this.selectedFolder);
            }
            this.updateSidebarMountSummary();
            return this.activeMountsByRootId;
        } catch (error) {
            console.warn('Failed to refresh active mounts:', error);
            if (!suppressErrorNotification) {
                this.showNotification('Failed to refresh mount status.', 'warning');
            }
            this.syncSelectedFolderMountUi();
            if (this.activeWorkspaceView === 'folder-detail') {
                this.renderFolderDetailView(this.selectedFolder);
            }
            this.updateSidebarMountSummary();
            return this.activeMountsByRootId;
        }
    }

    async maybeShowRecoveryPrompts(mountDetailsByRoot = this.activeMountDetailsByRootId) {
        if (!mountDetailsByRoot || typeof mountDetailsByRoot !== 'object') return;

        for (const [rootId, detail] of Object.entries(mountDetailsByRoot)) {
            const syncStatus = detail?.syncStatus;
            const count = Number(syncStatus?.recovered_pending_copy_count || 0);
            if (!count) {
                continue;
            }

            const samplePaths = Array.isArray(syncStatus?.recovered_pending_copy_paths)
                ? syncStatus.recovered_pending_copy_paths
                : [];
            const fingerprint = `${count}:${samplePaths.join('|')}`;
            if (this.recoveryPromptFingerprintByRootId[rootId] === fingerprint) {
                continue;
            }

            this.recoveryPromptFingerprintByRootId[rootId] = fingerprint;
            const folder = this.enrolledFolders.find(entry => String(entry?.root_id || '') === rootId);
            const label = folder?.name || this.basename(folder?.path || detail?.mountpoint || rootId);
            const detailText = [
                `HybridCipher recreated ${count} pending-work file(s) as local-only read-only recovery copies after an unclean restart.`,
                samplePaths.length > 0 ? `Example: ${samplePaths[0]}` : '',
                '',
                'These recovery copies are not synced back automatically.',
                'Review them, then explicitly merge or rename the content you want to keep.'
            ].filter(Boolean).join('\n');

            const choice = await this.showActionPrompt(
                'Recovered pending work',
                `${label} contains recovered local-only copies from the previous mount session.`,
                {
                    detail: detailText,
                    primaryLabel: 'Open recovery copies',
                    secondaryLabel: 'Later'
                }
            );
            if (choice && folder) {
                await this.openRecoveryCenterForFolder(folder);
            }
            return;
        }
    }

    startMountStatusPolling() {
        this.stopMountStatusPolling();
        if (!this.isLoggedIn) return;
        this.mountStatusPollTimer = setInterval(() => {
            if (!this.isLoggedIn) return;
            this.refreshActiveMounts({
                renderFolderList: true,
                suppressErrorNotification: true
            }).catch(error => {
                console.warn('Background mount status refresh failed:', error);
            });
        }, this.mountStatusPollIntervalMs);
    }

    stopMountStatusPolling() {
        if (this.mountStatusPollTimer) {
            clearInterval(this.mountStatusPollTimer);
            this.mountStatusPollTimer = null;
        }
    }

    scheduleMountStatusRefresh({ delayMs = 120, renderFolderList = true, suppressErrorNotification = true } = {}) {
        if (this.mountStatusRefreshTimer) {
            clearTimeout(this.mountStatusRefreshTimer);
        }
        this.mountStatusRefreshTimer = setTimeout(async () => {
            this.mountStatusRefreshTimer = null;
            if (!this.isLoggedIn) return;
            await this.refreshActiveMounts({ renderFolderList, suppressErrorNotification });
        }, Math.max(0, delayMs));
    }

    getMountpointForRootId(rootId) {
        const key = String(rootId || '').trim();
        if (!key) return null;
        return this.activeMountsByRootId[key] || null;
    }

    getMountDetailsForRootId(rootId) {
        const key = String(rootId || '').trim();
        if (!key) return null;
        return this.activeMountDetailsByRootId[key] || null;
    }

    findFolderByRootId(rootId) {
        const key = String(rootId || '').trim();
        if (!key) return null;
        return this.enrolledFolders.find(entry => String(entry?.root_id || '') === key) || null;
    }

    isRootMounted(rootId) {
        return Boolean(this.getMountpointForRootId(rootId));
    }

    isFolderMounted(folder) {
        if (!folder?.root_id) return false;
        return this.isRootMounted(folder.root_id);
    }

    syncSelectedFolderMountUi() {
        const mountpoint = this.selectedFolder?.root_id
            ? this.getMountpointForRootId(this.selectedFolder.root_id)
            : null;
        this.currentMountPath = mountpoint || null;
        this.updateMountButtons(Boolean(mountpoint));
    }

    hasMountSafetyAlert(syncStatus) {
        return Boolean(syncStatus && !syncStatus.safe_to_unmount);
    }

    hasPendingConflicts(syncStatus) {
        return Boolean(syncStatus && Number(syncStatus.pending_conflict_count || 0) > 0);
    }

    folderHasPendingConflicts(folder) {
        if (!folder?.root_id) return false;
        return this.hasPendingConflicts(this.getMountDetailsForRootId(folder.root_id)?.syncStatus);
    }

    hasPendingRecoveryCopies(syncStatus) {
        return Boolean(syncStatus && Number(syncStatus.recovered_pending_copy_count || 0) > 0);
    }

    folderHasPendingRecoveryCopies(folder) {
        if (!folder?.root_id) return false;
        return this.hasPendingRecoveryCopies(this.getMountDetailsForRootId(folder.root_id)?.syncStatus);
    }

    getMountUnsafeReasons(syncStatus) {
        if (!syncStatus) return [];

        if (Array.isArray(syncStatus.unsafe_reasons) && syncStatus.unsafe_reasons.length > 0) {
            return syncStatus.unsafe_reasons.map(reason => {
                if (reason?.kind !== 'pending_writeback') {
                    return reason;
                }
                return {
                    ...reason,
                    sample_paths: reason.sample_paths || (syncStatus.pending_writeback_paths || []).slice(0, 3),
                    last_error: reason.last_error || syncStatus.last_error || null
                };
            });
        }

        const reasons = [];
        if (syncStatus.pending_conflict_count > 0) {
            reasons.push({
                kind: 'conflict',
                count: syncStatus.pending_conflict_count,
                edited_count: syncStatus.edited_conflict_count || 0,
                sample_paths: [
                    ...(syncStatus.edited_conflict_paths || []),
                    ...(syncStatus.conflict_paths || [])
                ].filter(Boolean).slice(0, 3)
            });
        }
        if (syncStatus.pending_writeback_count > 0) {
            reasons.push({
                kind: 'pending_writeback',
                count: syncStatus.pending_writeback_count,
                oldest_age_ms: syncStatus.pending_writeback_oldest_age_ms || 0,
                sample_paths: (syncStatus.pending_writeback_paths || []).slice(0, 3),
                last_error: syncStatus.last_error || null
            });
        }
        if (syncStatus.pending_refresh_count > 0) {
            reasons.push({
                kind: 'pending_refresh',
                count: syncStatus.pending_refresh_count
            });
        }
        if (syncStatus.pending_open_unlinked_count > 0) {
            reasons.push({
                kind: 'deleted_open',
                count: syncStatus.pending_open_unlinked_count,
                sample_paths: (syncStatus.open_unlinked_paths || []).slice(0, 3)
            });
        }
        if (syncStatus.low_space_mode && syncStatus.low_space_mode !== 'healthy') {
            reasons.push({
                kind: 'low_space_degraded',
                mode: syncStatus.low_space_mode,
                count: syncStatus.pending_low_space_path_count || 0,
                sample_paths: (syncStatus.low_space_paths || []).slice(0, 3)
            });
        }
        if (syncStatus.recovered_pending_copy_count > 0) {
            reasons.push({
                kind: 'recovery_copies_present',
                count: syncStatus.recovered_pending_copy_count,
                sample_paths: (syncStatus.recovered_pending_copy_paths || []).slice(0, 3)
            });
        }
        return reasons;
    }

    isAutoDrainableMountReason(reason) {
        if (reason?.kind === 'pending_writeback') {
            const error = String(reason.last_error || '').toLowerCase();
            return !error || error.includes('unstable file') || error.includes('changed during read') || error.includes('mid-write');
        }
        return reason?.kind === 'pending_refresh';
    }

    statusHasOnlyAutoDrainableReasons(syncStatus) {
        const reasons = this.getMountUnsafeReasons(syncStatus);
        return reasons.length > 0 && reasons.every(reason => this.isAutoDrainableMountReason(reason));
    }

    formatMountSafetyReason(reason) {
        if (!reason || typeof reason !== 'object') {
            return '';
        }

        switch (reason.kind) {
            case 'pending_writeback':
                {
                    let message = `${reason.count || 0} pending encrypted commit(s) still need to finish before the newest local changes are protected. Oldest pending commit age: ${Math.floor((reason.oldest_age_ms || 0) / 1000)}s.`;
                    const examplePath = reason.sample_paths?.[0] || '';
                    if (examplePath) {
                        message += ` Example: ${examplePath}`;
                    }
                    if (reason.last_error) {
                        message += ` Last error: ${reason.last_error}`;
                    }
                    return message;
                }
            case 'pending_refresh':
                return `${reason.count || 0} pending plaintext refresh(es) are still rebuilding the local mount state.`;
            case 'conflict': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = `${reason.count || 0} unresolved conflict file(s) remain local-only until they are resolved or merged back.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                if ((reason.edited_count || 0) > 0) {
                    message += ` ${reason.edited_count} conflict file(s) were edited locally and are still not protected by encrypted sync.`;
                }
                return message;
            }
            case 'deleted_open': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = `${reason.count || 0} deleted-open path(s) are still active.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                return message;
            }
            case 'transactional_blocked': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = `${reason.count || 0} transactional path(s) are blocked because sync mount does not provide atomic-set guarantees for databases, packages, or bundle-style formats.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                return message;
            }
            case 'hard_link_blocked': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = `${reason.count || 0} hard-linked file(s) are blocked because sync mount does not preserve hard-link semantics.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                message += ' Break the hard link or replace it with an independent copy to resume protected sync.';
                return message;
            }
            case 'low_space_degraded': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = (reason.count || 0) > 0
                    ? `Low-space degraded mode (${reason.mode || 'unknown'}) is active for ${reason.count} path(s).`
                    : `Low-space degraded mode (${reason.mode || 'unknown'}) is active.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                return message;
            }
            case 'recovery_copies_present': {
                const examplePath = reason.sample_paths?.[0] || '';
                let message = `${reason.count || 0} recovered pending-work copy/copies are present as local-only read-only files after an unclean restart.`;
                if (examplePath) {
                    message += ` Example: ${examplePath}`;
                }
                return message;
            }
            default:
                return '';
        }
    }

    buildMountSafetyReasons(syncStatus) {
        if (!syncStatus) return [];
        const formattedReasons = this.getMountUnsafeReasons(syncStatus)
            .map(reason => this.formatMountSafetyReason(reason))
            .filter(Boolean);

        const extraWarnings = Array.isArray(syncStatus.preflight_warnings)
            ? syncStatus.preflight_warnings
            : [];

        return Array.from(new Set([...formattedReasons, ...extraWarnings.slice(0, 3)]));
    }

    buildMountSafetyDetail(syncStatus, fallbackDetail = '') {
        const reasons = this.buildMountSafetyReasons(syncStatus);
        const lines = [];

        if (reasons.length > 0) {
            lines.push('Resolve these conditions before unmounting:');
            reasons.forEach(reason => {
                lines.push(`- ${reason}`);
            });
        } else if (fallbackDetail) {
            lines.push(fallbackDetail);
        } else {
            lines.push('HybridCipher still reports background sync or recovery work that is unsafe to interrupt.');
        }

        if (fallbackDetail && reasons.length > 0 && !fallbackDetail.includes('not safe to unmount')) {
            lines.push('');
            lines.push(`Backend detail: ${fallbackDetail}`);
        }

        lines.push('');
        lines.push('It is not safe to unmount right now and may cause file loss.');
        lines.push('Use force unmount only if you accept the risk that the newest local changes may not be protected.');

        return lines.join('\n');
    }

    async showMountSafetyAlert(folder, fallbackDetail = '') {
        const syncStatus = folder?.root_id
            ? this.getMountDetailsForRootId(folder.root_id)?.syncStatus
            : null;
        const detail = this.buildMountSafetyDetail(syncStatus, fallbackDetail);

        await this.showActionPrompt(
            'Unmount safety warning',
            'This mount is not safe to unmount and may cause file loss.',
            {
                detail,
                primaryLabel: 'Close',
                secondaryLabel: ''
            }
        );
    }

    resetConflictWorkflowState() {
        this.conflictCenterState = {
            rootId: null,
            folder: null,
            records: [],
            selectedConflictId: null
        };
        this.activeConflictPreview = null;
        this.recoveryCenterState = {
            rootId: null,
            folder: null,
            records: [],
            selectedRecoveryPath: null
        };
        this.activeRecoveryPreview = null;
        const centerModal = document.getElementById('conflictCenterModal');
        const reviewModal = document.getElementById('conflictReviewModal');
        const recoveryCenterModal = document.getElementById('recoveryCenterModal');
        const recoveryReviewModal = document.getElementById('recoveryReviewModal');
        if (centerModal) {
            centerModal.style.display = 'none';
        }
        if (reviewModal) {
            reviewModal.style.display = 'none';
        }
        if (recoveryCenterModal) {
            recoveryCenterModal.style.display = 'none';
        }
        if (recoveryReviewModal) {
            recoveryReviewModal.style.display = 'none';
        }
    }

    getConflictCenterFolderLabel(folder, rootId = this.conflictCenterState.rootId) {
        const resolvedFolder = folder || this.findFolderByRootId(rootId);
        if (!resolvedFolder) {
            return rootId || 'Mounted folder';
        }
        return resolvedFolder.name || this.basename(resolvedFolder.path || resolvedFolder.root_id || 'Mounted folder');
    }

    formatConflictTimestamp(value) {
        if (!value) return 'Unknown';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return date.toLocaleString();
    }

    escapeHtml(value) {
        return escapeHtmlValue(value);
    }

    escapeHtmlAttr(value) {
        return escapeHtmlValue(value);
    }

    sanitizeSvg(svgString) {
        try {
            const doc = new DOMParser().parseFromString(svgString, 'image/svg+xml');
            if (doc.querySelector('parsererror')) return null;
            const svg = doc.querySelector('svg');
            if (!svg) return null;
            svg.querySelectorAll('script, foreignObject').forEach(el => el.remove());
            svg.querySelectorAll('*').forEach(el => {
                for (const attr of [...el.attributes]) {
                    if (attr.name.startsWith('on')) el.removeAttribute(attr.name);
                }
            });
            for (const attr of [...svg.attributes]) {
                if (attr.name.startsWith('on')) svg.removeAttribute(attr.name);
            }
            return svg;
        } catch {
            return null;
        }
    }

    buildConflictPaneHtml(text, referenceText, emptyLabel) {
        if (typeof text !== 'string' || text.length === 0) {
            return `<div class="conflict-pane-empty">${this.escapeHtml(emptyLabel)}</div>`;
        }

        const lines = text.split('\n');
        const referenceLines = typeof referenceText === 'string' ? referenceText.split('\n') : [];
        const canHighlight = lines.length + referenceLines.length <= 400;
        const maxLines = 800;
        const truncated = lines.length > maxLines;
        const visibleLines = truncated ? lines.slice(0, maxLines) : lines;
        const rows = visibleLines.map((line, index) => {
            const changed = canHighlight && referenceLines.length > 0 && line !== (referenceLines[index] ?? '');
            return `
                <div class="conflict-pane-line ${changed ? 'changed' : ''}">
                    <span class="conflict-pane-line-no">${index + 1}</span>
                    <span class="conflict-pane-line-text">${this.escapeHtml(line || ' ')}</span>
                </div>
            `;
        });

        if (truncated) {
            rows.push(`
                <div class="conflict-pane-line truncated">
                    <span class="conflict-pane-line-no">…</span>
                    <span class="conflict-pane-line-text">Preview truncated after ${maxLines} lines.</span>
                </div>
            `);
        }

        return rows.join('');
    }

    async openSelectedFolderConflicts() {
        if (!this.selectedFolder?.root_id) {
            this.showNotification('Select a mounted folder with unresolved conflicts first.', 'warning');
            return;
        }
        await this.openConflictCenterForFolder(this.selectedFolder);
    }

    async openConflictCenterForFolder(folder, { selectedConflictId = null } = {}) {
        if (!folder?.root_id) {
            this.showNotification('No mounted folder selected for conflict resolution.', 'warning');
            return false;
        }

        const rootId = String(folder.root_id);
        const mountpoint = this.getMountpointForRootId(rootId);
        if (!mountpoint) {
            this.showNotification('The selected folder is not mounted.', 'warning');
            return false;
        }

        this.conflictCenterState.rootId = rootId;
        this.conflictCenterState.folder = folder;
        this.conflictCenterState.selectedConflictId = selectedConflictId;

        const modal = document.getElementById('conflictCenterModal');
        if (modal) {
            modal.style.display = 'flex';
        }

        return this.refreshConflictCenter({
            selectedConflictId,
            suppressNotification: false
        });
    }

    async refreshConflictCenter({ selectedConflictId = null, suppressNotification = false } = {}) {
        const rootId = String(this.conflictCenterState.rootId || '').trim();
        if (!rootId) {
            return false;
        }

        const response = await invoke('list_mount_conflicts', { rootId });
        if (!response?.success || !Array.isArray(response?.data)) {
            const message = response?.error || 'Failed to load mount conflicts.';
            if (!suppressNotification) {
                this.showNotification(message, 'error');
            }
            throw new Error(message);
        }

        this.conflictCenterState.records = response.data;
        if (!this.conflictCenterState.folder) {
            this.conflictCenterState.folder = this.findFolderByRootId(rootId);
        }

        if (selectedConflictId) {
            this.conflictCenterState.selectedConflictId = selectedConflictId;
        } else if (this.conflictCenterState.selectedConflictId) {
            const stillExists = this.conflictCenterState.records.some(
                record => record.id === this.conflictCenterState.selectedConflictId
            );
            if (!stillExists) {
                this.conflictCenterState.selectedConflictId = null;
            }
        }

        this.renderConflictCenter();

        if (this.conflictCenterState.records.length === 0) {
            this.closeConflictReview();
            if (!suppressNotification) {
                this.showNotification('No unresolved conflicts remain for this mount.', 'success');
            }
            return true;
        }

        const targetConflictId = this.conflictCenterState.selectedConflictId;
        if (targetConflictId) {
            await this.openConflictReview(targetConflictId, { suppressNotification: true });
        }

        return true;
    }

    renderConflictCenter() {
        const modal = document.getElementById('conflictCenterModal');
        const titleEl = document.getElementById('conflictCenterTitle');
        const summaryEl = document.getElementById('conflictCenterSummary');
        const listEl = document.getElementById('conflictCenterList');
        if (!modal || !titleEl || !summaryEl || !listEl) {
            return;
        }

        const folderLabel = this.getConflictCenterFolderLabel(this.conflictCenterState.folder);
        const records = Array.isArray(this.conflictCenterState.records) ? this.conflictCenterState.records : [];
        titleEl.textContent = `Resolve conflicts: ${folderLabel}`;
        summaryEl.textContent = records.length > 0
            ? `${records.length} unresolved conflict file(s) remain LOCAL-ONLY and still block safe unmount until you resolve them.`
            : 'No unresolved conflicts remain for this mount.';

        if (records.length === 0) {
            listEl.innerHTML = `
                <div class="conflict-center-empty">
                    <p>All unresolved conflicts have been cleared.</p>
                    <p class="text-secondary">You can close this window and try unmounting again.</p>
                </div>
            `;
            return;
        }

        listEl.innerHTML = records.map(record => `
            <button type="button" class="conflict-record-card ${record.id === this.conflictCenterState.selectedConflictId ? 'selected' : ''}" data-conflict-review-id="${record.id}">
                <div class="conflict-record-card-header">
                    <span class="conflict-local-only-pill">LOCAL-ONLY</span>
                    <span class="conflict-kind-pill">${this.escapeHtml(String(record.kind || '').replace(/_/g, ' '))}</span>
                    ${record.edited ? '<span class="conflict-kind-pill warning">Edited</span>' : ''}
                </div>
                <div class="conflict-record-path">${this.escapeHtml(record.live_relative_path || '')}</div>
                <div class="conflict-record-meta">Conflict copy: ${this.escapeHtml(record.conflict_relative_path || '')}</div>
                <div class="conflict-record-meta">Created: ${this.escapeHtml(this.formatConflictTimestamp(record.created_at))}</div>
                <div class="conflict-record-meta">Live path ${record.live_exists ? 'exists' : 'is missing'} • ${record.text_merge_supported ? 'Text merge available' : 'Winner-pick only'}</div>
            </button>
        `).join('');

        listEl.querySelectorAll('[data-conflict-review-id]').forEach(button => {
            button.addEventListener('click', () => {
                const conflictId = button.getAttribute('data-conflict-review-id');
                this.openConflictReview(conflictId).catch(error => {
                    console.error('Failed to open conflict preview:', error);
                    this.showNotification('Failed to open conflict preview.', 'error');
                });
            });
        });
    }

    closeConflictCenter() {
        const modal = document.getElementById('conflictCenterModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.closeConflictReview();
        this.conflictCenterState.selectedConflictId = null;
    }

    async openConflictReview(conflictId, { suppressNotification = false } = {}) {
        const rootId = String(this.conflictCenterState.rootId || '').trim();
        if (!rootId || !conflictId) {
            return false;
        }

        const response = await invoke('get_mount_conflict_preview', {
            rootId,
            conflictId: String(conflictId)
        });
        if (!response?.success || !response?.data) {
            const message = response?.error || 'Failed to load conflict preview.';
            if (!suppressNotification) {
                this.showNotification(message, 'error');
            }
            throw new Error(message);
        }

        this.conflictCenterState.selectedConflictId = String(conflictId);
        this.activeConflictPreview = response.data;
        this.renderConflictCenter();
        this.renderConflictReview();

        const modal = document.getElementById('conflictReviewModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        return true;
    }

    closeConflictReview() {
        const modal = document.getElementById('conflictReviewModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.activeConflictPreview = null;
    }

    renderConflictReview() {
        const preview = this.activeConflictPreview;
        if (!preview?.record) {
            return;
        }

        const titleEl = document.getElementById('conflictReviewTitle');
        const subtitleEl = document.getElementById('conflictReviewSubtitle');
        const metaEl = document.getElementById('conflictReviewMeta');
        const livePane = document.getElementById('conflictReviewLivePane');
        const conflictPane = document.getElementById('conflictReviewConflictPane');
        const mergeGroup = document.getElementById('conflictMergeEditorGroup');
        const mergeTools = document.getElementById('conflictReviewMergeTools');
        const mergeBtn = document.getElementById('conflictReviewMergeBtn');
        const archiveBtn = document.getElementById('conflictReviewArchiveDismissBtn');
        const keepMountedBtn = document.getElementById('conflictReviewKeepMountedBtn');
        const revealMountedBtn = document.getElementById('conflictReviewRevealMountedBtn');
        const textarea = document.getElementById('conflictMergeEditor');
        if (!titleEl || !subtitleEl || !metaEl || !livePane || !conflictPane || !mergeGroup || !mergeTools || !mergeBtn || !archiveBtn || !keepMountedBtn || !revealMountedBtn || !textarea) {
            return;
        }

        const { record } = preview;
        const canTextMerge = Boolean(record.text_merge_supported && typeof preview.live_text === 'string' && typeof preview.conflict_text === 'string');
        const titlePath = record.live_relative_path || record.conflict_relative_path || record.id;
        titleEl.textContent = `Resolve conflict: ${titlePath}`;
        subtitleEl.textContent = record.live_exists
            ? 'The mounted file is the synced path. The conflict copy is LOCAL-ONLY until you explicitly resolve it.'
            : 'The live mounted path is missing. You can promote the conflict copy, save it as a new synced file, or archive it and keep the delete.';

        metaEl.innerHTML = `
            <div><strong>Live path:</strong> ${this.escapeHtml(preview.live_path || record.live_relative_path || '')}</div>
            <div><strong>Conflict copy:</strong> ${this.escapeHtml(preview.conflict_path || record.conflict_relative_path || '')}</div>
            <div><strong>Created:</strong> ${this.escapeHtml(this.formatConflictTimestamp(record.created_at))}</div>
            <div><strong>Status:</strong> LOCAL-ONLY • ${record.edited ? 'edited locally' : 'read-only until resolved'} • ${canTextMerge ? 'text merge available' : 'winner-pick or save-as-new only'}</div>
        `;

        livePane.innerHTML = this.buildConflictPaneHtml(
            preview.live_text,
            preview.conflict_text,
            record.live_exists ? 'Text preview unavailable for the mounted file.' : 'The mounted file no longer exists.'
        );
        conflictPane.innerHTML = this.buildConflictPaneHtml(
            preview.conflict_text,
            preview.live_text,
            'Text preview unavailable for the conflict copy.'
        );

        if (textarea.dataset.conflictId !== record.id) {
            textarea.value = typeof preview.live_text === 'string'
                ? preview.live_text
                : (preview.conflict_text || '');
            textarea.dataset.conflictId = record.id;
        }

        mergeGroup.style.display = canTextMerge ? 'block' : 'none';
        mergeTools.style.display = canTextMerge ? 'flex' : 'none';
        mergeBtn.style.display = canTextMerge ? 'inline-flex' : 'none';
        keepMountedBtn.style.display = record.live_exists ? 'inline-flex' : 'none';
        revealMountedBtn.style.display = record.live_exists ? 'inline-flex' : 'none';
        archiveBtn.style.display = record.live_exists ? 'none' : 'inline-flex';
    }

    async submitConflictMerge() {
        const textarea = document.getElementById('conflictMergeEditor');
        const mergedText = textarea?.value ?? '';
        await this.resolveCurrentConflict('merge_text', { mergedText });
    }

    async saveConflictAsNewFile() {
        const preview = this.activeConflictPreview;
        if (!preview?.record) {
            return;
        }

        const suggestedName = `${preview.record.live_relative_path || preview.record.conflict_relative_path || 'resolved-copy'}`;
        const destinationPath = await this.promptForText(
            'Enter a new mount-relative destination for the synced resolved file.',
            {
                title: 'Save conflict as new file',
                placeholder: 'folder/resolved-file.txt',
                submitLabel: 'Save as new',
                initialValue: suggestedName
            }
        );
        if (destinationPath === null) {
            return;
        }

        await this.resolveCurrentConflict('save_conflict_as_new', { destinationPath });
    }

    async revealConflictPath(target) {
        const preview = this.activeConflictPreview;
        if (!preview) {
            return;
        }

        const path = target === 'live'
            ? preview.live_path
            : preview.conflict_path;
        if (!path) {
            this.showNotification('The requested path is not available.', 'warning');
            return;
        }

        const result = await invoke('open_path_in_shell', { path });
        if (!result?.success) {
            throw new Error(result?.error || 'Failed to reveal path');
        }
    }

    async resolveCurrentConflict(action, { mergedText = null, destinationPath = null } = {}) {
        const preview = this.activeConflictPreview;
        const rootId = String(this.conflictCenterState.rootId || '').trim();
        const conflictId = String(preview?.record?.id || '').trim();
        if (!rootId || !conflictId) {
            throw new Error('No active conflict selected');
        }

        this.showActionProgressModal('Resolving conflict...');
        try {
            const response = await invoke('resolve_mount_conflict', {
                rootId,
                conflictId,
                action,
                mergedText,
                destinationPath
            });
            if (!response?.success || !response?.data) {
                throw new Error(response?.error || 'Conflict resolution failed');
            }

            await this.refreshActiveMounts({
                renderFolderList: true,
                suppressErrorNotification: true,
                suppressRecoveryPrompt: true
            });

            this.closeConflictReview();
            await this.refreshConflictCenter({ suppressNotification: true });
            this.showNotification(`Resolved conflict ${conflictId.slice(0, 8)}.`, 'success');
            return true;
        } finally {
            this.hideActionProgressModal();
        }
    }

    async openSelectedFolderRecoveryCopies() {
        if (!this.selectedFolder?.root_id) {
            this.showNotification('Select a mounted folder with recovery copies first.', 'warning');
            return;
        }
        await this.openRecoveryCenterForFolder(this.selectedFolder);
    }

    async openRecoveryCenterForFolder(folder, { selectedRecoveryPath = null } = {}) {
        if (!folder?.root_id) {
            this.showNotification('No mounted folder selected for recovery copy review.', 'warning');
            return false;
        }

        const rootId = String(folder.root_id);
        const mountpoint = this.getMountpointForRootId(rootId);
        if (!mountpoint) {
            this.showNotification('The selected folder is not mounted.', 'warning');
            return false;
        }

        this.recoveryCenterState.rootId = rootId;
        this.recoveryCenterState.folder = folder;
        this.recoveryCenterState.selectedRecoveryPath = selectedRecoveryPath;

        const modal = document.getElementById('recoveryCenterModal');
        if (modal) {
            modal.style.display = 'flex';
        }

        return this.refreshRecoveryCenter({
            selectedRecoveryPath,
            suppressNotification: false
        });
    }

    async refreshRecoveryCenter({ selectedRecoveryPath = null, suppressNotification = false } = {}) {
        const rootId = String(this.recoveryCenterState.rootId || '').trim();
        if (!rootId) {
            return false;
        }

        const response = await invoke('list_mount_recovery_copies', { rootId });
        if (!response?.success || !Array.isArray(response?.data)) {
            const message = response?.error || 'Failed to load recovery copies.';
            if (!suppressNotification) {
                this.showNotification(message, 'error');
            }
            throw new Error(message);
        }

        this.recoveryCenterState.records = response.data;
        if (!this.recoveryCenterState.folder) {
            this.recoveryCenterState.folder = this.findFolderByRootId(rootId);
        }

        if (selectedRecoveryPath) {
            this.recoveryCenterState.selectedRecoveryPath = selectedRecoveryPath;
        } else if (this.recoveryCenterState.selectedRecoveryPath) {
            const stillExists = this.recoveryCenterState.records.some(
                record => record.recovery_relative_path === this.recoveryCenterState.selectedRecoveryPath
            );
            if (!stillExists) {
                this.recoveryCenterState.selectedRecoveryPath = null;
            }
        }

        this.renderRecoveryCenter();

        if (this.recoveryCenterState.records.length === 0) {
            this.closeRecoveryReview();
            if (!suppressNotification) {
                this.showNotification('No unresolved recovery copies remain for this mount.', 'success');
            }
            return true;
        }

        const targetRecoveryPath = this.recoveryCenterState.selectedRecoveryPath;
        if (targetRecoveryPath) {
            await this.openRecoveryReview(targetRecoveryPath, { suppressNotification: true });
        }

        return true;
    }

    renderRecoveryCenter() {
        const modal = document.getElementById('recoveryCenterModal');
        const titleEl = document.getElementById('recoveryCenterTitle');
        const summaryEl = document.getElementById('recoveryCenterSummary');
        const listEl = document.getElementById('recoveryCenterList');
        if (!modal || !titleEl || !summaryEl || !listEl) {
            return;
        }

        const folderLabel = this.getConflictCenterFolderLabel(
            this.recoveryCenterState.folder,
            this.recoveryCenterState.rootId
        );
        const records = Array.isArray(this.recoveryCenterState.records) ? this.recoveryCenterState.records : [];
        titleEl.textContent = `Resolve recovery copies: ${folderLabel}`;
        summaryEl.textContent = records.length > 0
            ? `${records.length} recovery copy/copies remain LOCAL-ONLY and still block safe unmount until you resolve or dismiss them.`
            : 'No unresolved recovery copies remain for this mount.';

        if (records.length === 0) {
            listEl.innerHTML = `
                <div class="conflict-center-empty">
                    <p>All recovery copies have been cleared.</p>
                    <p class="text-secondary">You can close this window and try unmounting again.</p>
                </div>
            `;
            return;
        }

        listEl.innerHTML = records.map(record => `
            <button type="button" class="conflict-record-card ${record.recovery_relative_path === this.recoveryCenterState.selectedRecoveryPath ? 'selected' : ''}" data-recovery-review-path="${this.escapeHtml(record.recovery_relative_path || '')}">
                <div class="conflict-record-card-header">
                    <span class="conflict-local-only-pill">LOCAL-ONLY</span>
                    <span class="conflict-kind-pill">recovery copy</span>
                </div>
                <div class="conflict-record-path">${this.escapeHtml(record.live_relative_path || '')}</div>
                <div class="conflict-record-meta">Recovery copy: ${this.escapeHtml(record.recovery_relative_path || '')}</div>
                <div class="conflict-record-meta">Created: ${this.escapeHtml(this.formatConflictTimestamp(record.created_at))}</div>
                <div class="conflict-record-meta">Live path ${record.live_exists ? 'exists' : 'is missing'} • ${record.text_preview_supported ? 'Text preview available' : 'Binary/large-file preview only'}</div>
            </button>
        `).join('');

        listEl.querySelectorAll('[data-recovery-review-path]').forEach(button => {
            button.addEventListener('click', () => {
                const recoveryPath = button.getAttribute('data-recovery-review-path');
                this.openRecoveryReview(recoveryPath).catch(error => {
                    console.error('Failed to open recovery preview:', error);
                    this.showNotification('Failed to open recovery preview.', 'error');
                });
            });
        });
    }

    closeRecoveryCenter() {
        const modal = document.getElementById('recoveryCenterModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.closeRecoveryReview();
        this.recoveryCenterState.selectedRecoveryPath = null;
    }

    async openRecoveryReview(recoveryPath, { suppressNotification = false } = {}) {
        const rootId = String(this.recoveryCenterState.rootId || '').trim();
        if (!rootId || !recoveryPath) {
            return false;
        }

        const response = await invoke('get_mount_recovery_copy_preview', {
            rootId,
            recoveryPath: String(recoveryPath)
        });
        if (!response?.success || !response?.data) {
            const message = response?.error || 'Failed to load recovery preview.';
            if (!suppressNotification) {
                this.showNotification(message, 'error');
            }
            throw new Error(message);
        }

        this.recoveryCenterState.selectedRecoveryPath = String(recoveryPath);
        this.activeRecoveryPreview = response.data;
        this.renderRecoveryCenter();
        this.renderRecoveryReview();

        const modal = document.getElementById('recoveryReviewModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        return true;
    }

    closeRecoveryReview() {
        const modal = document.getElementById('recoveryReviewModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.activeRecoveryPreview = null;
    }

    renderRecoveryReview() {
        const preview = this.activeRecoveryPreview;
        if (!preview?.record) {
            return;
        }

        const titleEl = document.getElementById('recoveryReviewTitle');
        const subtitleEl = document.getElementById('recoveryReviewSubtitle');
        const metaEl = document.getElementById('recoveryReviewMeta');
        const livePane = document.getElementById('recoveryReviewLivePane');
        const recoveryPane = document.getElementById('recoveryReviewCopyPane');
        const replaceBtn = document.getElementById('recoveryReviewReplaceMountedBtn');
        const revealMountedBtn = document.getElementById('recoveryReviewRevealMountedBtn');
        if (!titleEl || !subtitleEl || !metaEl || !livePane || !recoveryPane || !replaceBtn || !revealMountedBtn) {
            return;
        }

        const { record } = preview;
        titleEl.textContent = `Resolve recovery copy: ${record.live_relative_path || record.recovery_relative_path}`;
        subtitleEl.textContent = record.live_exists
            ? 'The recovery copy contains local plaintext observed before the previous mount ended uncleanly. It remains LOCAL-ONLY until you explicitly resolve it.'
            : 'The original mounted path is missing. You can save the recovery copy as a new synced file or archive it if you no longer need it.';

        metaEl.innerHTML = `
            <div><strong>Live path:</strong> ${this.escapeHtml(preview.live_path || record.live_relative_path || '')}</div>
            <div><strong>Recovery copy:</strong> ${this.escapeHtml(preview.recovery_path || record.recovery_relative_path || '')}</div>
            <div><strong>Created:</strong> ${this.escapeHtml(this.formatConflictTimestamp(record.created_at))}</div>
            <div><strong>Status:</strong> LOCAL-ONLY • read-only until resolved • ${record.text_preview_supported ? 'text preview available' : 'winner-pick or save-as-new only'}</div>
        `;

        livePane.innerHTML = this.buildConflictPaneHtml(
            preview.live_text,
            preview.recovery_text,
            record.live_exists ? 'Text preview unavailable for the mounted file.' : 'The mounted file no longer exists.'
        );
        recoveryPane.innerHTML = this.buildConflictPaneHtml(
            preview.recovery_text,
            preview.live_text,
            'Text preview unavailable for the recovery copy.'
        );

        replaceBtn.style.display = record.live_exists ? 'inline-flex' : 'none';
        revealMountedBtn.style.display = record.live_exists ? 'inline-flex' : 'none';
    }

    async saveRecoveryAsNewFile() {
        const preview = this.activeRecoveryPreview;
        if (!preview?.record) {
            return;
        }

        const suggestedName = `${preview.record.live_relative_path || preview.record.recovery_relative_path || 'recovered-copy'}`;
        const destinationPath = await this.promptForText(
            'Enter a new mount-relative destination for the synced recovered file.',
            {
                title: 'Save recovery copy as new file',
                placeholder: 'folder/recovered-file.txt',
                submitLabel: 'Save as new',
                initialValue: suggestedName
            }
        );
        if (destinationPath === null) {
            return;
        }

        await this.resolveCurrentRecoveryCopy('save_as_new', { destinationPath });
    }

    async revealRecoveryPath(target) {
        const preview = this.activeRecoveryPreview;
        if (!preview) {
            return;
        }

        const path = target === 'live'
            ? preview.live_path
            : preview.recovery_path;
        if (!path) {
            this.showNotification('The requested path is not available.', 'warning');
            return;
        }

        const result = await invoke('open_path_in_shell', { path });
        if (!result?.success) {
            throw new Error(result?.error || 'Failed to reveal path');
        }
    }

    async resolveCurrentRecoveryCopy(action, { destinationPath = null } = {}) {
        const preview = this.activeRecoveryPreview;
        const rootId = String(this.recoveryCenterState.rootId || '').trim();
        const recoveryPath = String(preview?.record?.recovery_relative_path || '').trim();
        if (!rootId || !recoveryPath) {
            throw new Error('No active recovery copy selected');
        }

        this.showActionProgressModal('Resolving recovery copy...');
        try {
            const response = await invoke('resolve_mount_recovery_copy', {
                rootId,
                recoveryPath,
                action,
                destinationPath
            });
            if (!response?.success || !response?.data) {
                throw new Error(response?.error || 'Recovery copy resolution failed');
            }

            await this.refreshActiveMounts({
                renderFolderList: true,
                suppressErrorNotification: true,
                suppressRecoveryPrompt: true
            });

            this.closeRecoveryReview();
            await this.refreshRecoveryCenter({ suppressNotification: true });
            this.showNotification(`Resolved recovery copy ${recoveryPath}.`, 'success');
            return true;
        } finally {
            this.hideActionProgressModal();
        }
    }

    getActiveMountEntries(rootIds = null) {
        const targetRootIds = Array.isArray(rootIds)
            ? rootIds.map(value => String(value || '').trim()).filter(Boolean)
            : Object.keys(this.activeMountDetailsByRootId || {});

        return targetRootIds
            .map(rootId => {
                const detail = this.getMountDetailsForRootId(rootId);
                if (!detail) return null;
                const folder = this.enrolledFolders.find(entry => String(entry?.root_id || '') === rootId) || null;
                return {
                    rootId,
                    mountpoint: detail.mountpoint,
                    syncStatus: detail.syncStatus || null,
                    folder
                };
            })
            .filter(Boolean);
    }

    buildMountGroupSafetyDetail(mountEntries, fallbackDetail = '') {
        const unsafeEntries = (Array.isArray(mountEntries) ? mountEntries : [])
            .filter(entry => this.hasMountSafetyAlert(entry?.syncStatus));
        const lines = [];

        if (unsafeEntries.length > 0) {
            lines.push('Resolve these conditions before unmounting:');
            unsafeEntries.forEach(entry => {
                const label = entry.folder?.name
                    || this.basename(entry.folder?.path || entry.mountpoint || entry.rootId || 'Mounted folder');
                lines.push(`${label}:`);
                const reasons = this.buildMountSafetyReasons(entry.syncStatus);
                reasons.forEach(reason => {
                    lines.push(`- ${reason}`);
                });
            });
        } else if (fallbackDetail) {
            lines.push(fallbackDetail);
        } else {
            lines.push('HybridCipher still reports background sync or recovery work that is unsafe to interrupt.');
        }

        if (fallbackDetail && unsafeEntries.length > 0 && !fallbackDetail.includes('not safe to unmount')) {
            lines.push('');
            lines.push(`Backend detail: ${fallbackDetail}`);
        }

        lines.push('');
        lines.push('It is not safe to unmount right now and may cause file loss.');
        lines.push('Use force unmount only if you accept the risk that the newest local changes may not be protected.');

        return lines.join('\n');
    }

    async waitForSafeUnmountTargets({ rootIds = null, timeoutMs = 10000, pollMs = 500 } = {}) {
        await this.refreshActiveMounts({
            renderFolderList: false,
            suppressErrorNotification: true,
            suppressRecoveryPrompt: true
        });

        let activeEntries = this.getActiveMountEntries(rootIds);
        let unsafeEntries = activeEntries.filter(entry => this.hasMountSafetyAlert(entry.syncStatus));
        if (unsafeEntries.length === 0) {
            return {
                safe: true,
                timedOut: false,
                activeEntries,
                unsafeEntries
            };
        }

        const hasNonDrainable = unsafeEntries.some(entry => !this.statusHasOnlyAutoDrainableReasons(entry.syncStatus));
        if (hasNonDrainable) {
            return {
                safe: false,
                timedOut: false,
                activeEntries,
                unsafeEntries
            };
        }

        const deadline = Date.now() + timeoutMs;
        this.showActionProgressModal('Finishing encrypted commits...');
        try {
            while (Date.now() < deadline) {
                await new Promise(resolve => setTimeout(resolve, pollMs));
                await this.refreshActiveMounts({
                    renderFolderList: false,
                    suppressErrorNotification: true,
                    suppressRecoveryPrompt: true
                });

                activeEntries = this.getActiveMountEntries(rootIds);
                unsafeEntries = activeEntries.filter(entry => this.hasMountSafetyAlert(entry.syncStatus));
                if (unsafeEntries.length === 0) {
                    return {
                        safe: true,
                        timedOut: false,
                        activeEntries,
                        unsafeEntries
                    };
                }

                const stillOnlyDrainable = unsafeEntries.every(entry => this.statusHasOnlyAutoDrainableReasons(entry.syncStatus));
                if (!stillOnlyDrainable) {
                    return {
                        safe: false,
                        timedOut: false,
                        activeEntries,
                        unsafeEntries
                    };
                }
            }
        } finally {
            this.hideActionProgressModal();
        }

        await this.refreshActiveMounts({
            renderFolderList: false,
            suppressErrorNotification: true,
            suppressRecoveryPrompt: true
        });
        activeEntries = this.getActiveMountEntries(rootIds);
        unsafeEntries = activeEntries.filter(entry => this.hasMountSafetyAlert(entry.syncStatus));
        return {
            safe: unsafeEntries.length === 0,
            timedOut: unsafeEntries.length > 0,
            activeEntries,
            unsafeEntries
        };
    }

    async promptUnsafeUnmountDecision({
        rootIds = null,
        title,
        message,
        forceLabel
    }) {
        while (true) {
            const result = await this.waitForSafeUnmountTargets({ rootIds });
            if (result.safe) {
                return 'safe';
            }

            const detail = this.buildMountGroupSafetyDetail(result.unsafeEntries);
            const conflictEntry = result.unsafeEntries.find(entry => this.hasPendingConflicts(entry?.syncStatus));
            const recoveryEntry = result.unsafeEntries.find(entry => this.hasPendingRecoveryCopies(entry?.syncStatus));
            const primaryLabel = conflictEntry
                ? 'Resolve conflicts'
                : (recoveryEntry ? 'Resolve recovery copies' : 'Keep waiting');
            const choice = await this.showThreeWayActionPrompt(
                title,
                message,
                {
                    detail,
                    primaryLabel,
                    secondaryLabel: forceLabel,
                    tertiaryLabel: 'Cancel'
                }
            );

            if (choice === 'primary') {
                if (conflictEntry) {
                    const folder = conflictEntry.folder || this.findFolderByRootId(conflictEntry.rootId);
                    if (folder) {
                        await this.openConflictCenterForFolder(folder);
                    } else {
                        await this.showMountSafetyAlert({
                            root_id: conflictEntry.rootId
                        }, detail);
                    }
                    return 'cancel';
                }
                if (recoveryEntry) {
                    const folder = recoveryEntry.folder || this.findFolderByRootId(recoveryEntry.rootId);
                    if (folder) {
                        await this.openRecoveryCenterForFolder(folder);
                    } else {
                        await this.showMountSafetyAlert({
                            root_id: recoveryEntry.rootId
                        }, detail);
                    }
                    return 'cancel';
                }
                continue;
            }
            if (choice === 'secondary') {
                const confirmed = await this.confirmForceUnmount(result.unsafeEntries);
                return confirmed ? 'force' : 'cancel';
            }
            return 'cancel';
        }
    }

    async confirmForceUnmount(unsafeEntries = []) {
        const entries = Array.isArray(unsafeEntries) ? unsafeEntries.filter(Boolean) : [];
        const singleEntry = entries.length === 1 ? entries[0] : null;
        const folderLabel = singleEntry
            ? (singleEntry.folder?.name
                || this.basename(singleEntry.folder?.path || singleEntry.mountpoint || singleEntry.rootId || 'Mounted folder'))
            : 'all mounted folders';
        const folderPath = singleEntry?.folder?.path || '';
        const unsafeReasons = entries
            .flatMap(entry => this.buildMountSafetyReasons(entry?.syncStatus || null))
            .filter(Boolean)
            .slice(0, 3);
        const confirmation = buildForceUnmountConfirmationValue({
            folderLabel,
            folderPath,
            unsafeReasons,
        });
        const typedValue = await this.promptForText(
            confirmation.detail.replace(/\n+/g, ' '),
            {
                allowEmpty: false,
                title: confirmation.title,
                placeholder: confirmation.confirmationToken,
                submitLabel: 'Confirm force unmount',
            }
        );

        if (typedValue === null) {
            return false;
        }

        if (String(typedValue).trim().toUpperCase() !== confirmation.confirmationToken) {
            this.showNotification('Force unmount cancelled: confirmation text did not match.', 'warning');
            return false;
        }

        return true;
    }

    updateSidebarMountSummary() {
        const summary = document.getElementById('sidebarMountSummary');
        if (!summary) return;

        const folders = Array.isArray(this.enrolledFolders) ? this.enrolledFolders : [];
        const mountedCount = folders.reduce((count, folder) => {
            if (folder?.root_id && this.isRootMounted(folder.root_id)) {
                return count + 1;
            }
            return count;
        }, 0);
        const degradedCount = folders.reduce((count, folder) => {
            const syncStatus = folder?.root_id
                ? this.getMountDetailsForRootId(folder.root_id)?.syncStatus
                : null;
            if (syncStatus && syncStatus.low_space_mode && syncStatus.low_space_mode !== 'healthy') {
                return count + 1;
            }
            return count;
        }, 0);

        summary.textContent = degradedCount > 0
            ? `${folders.length} protected • ${mountedCount} mounted • ${degradedCount} degraded`
            : `${folders.length} protected • ${mountedCount} mounted`;

        this.updateWorkspaceHomeSummary();
        if (this.activeWorkspaceView === 'folder-detail') {
            this.renderFolderDetailView(this.selectedFolder);
        }
    }

    getFolderRowStatusState(options = {}) {
        return getFolderRowStatusStateValue(options);
    }

    renderFolderList() {
        const folderList = document.getElementById('folderList');
        if (!folderList) return;
        this.updateSidebarMountSummary();

        if (this.enrolledFolders.length === 0) {
            folderList.innerHTML = `
                <div class="empty-state">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" opacity="0.5">
                        <path stroke="currentColor" stroke-width="2" d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                    </svg>
                    <p>No protected folders</p>
                    <button class="btn btn-add-folder btn-small" id="emptyAddFolderBtn" type="button">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                            <path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M12 5v14M5 12h14" />
                        </svg>
                        Add Protected Folder
                    </button>
                </div>
            `;
            document.getElementById('emptyAddFolderBtn')?.addEventListener('click', () => this.addEnrolledFolder());
            return;
        }

        folderList.innerHTML = this.enrolledFolders.map(folder => {
            const isMounted = this.isFolderMounted(folder);
            const displayName = folder.name || this.basename(folder.path);
            const escapedDisplayName = this.escapeHtml(displayName);
            const escapedFolderPath = this.escapeHtmlAttr(folder.path || '');
            const escapedRootId = this.escapeHtmlAttr(folder.root_id || '');
            const syncStatus = folder?.root_id
                ? this.getMountDetailsForRootId(folder.root_id)?.syncStatus
                : null;
            const showSafetyAlert = isMounted && this.hasMountSafetyAlert(syncStatus);
            const hasConflicts = isMounted && this.hasPendingConflicts(syncStatus);
            const hasRecoveryCopies = isMounted && this.hasPendingRecoveryCopies(syncStatus);
            const alertTitle = hasConflicts
                ? 'Resolve conflicts'
                : (hasRecoveryCopies ? 'Resolve recovery copies' : 'Unmount safety warning');
            const alertLabel = hasConflicts
                ? 'Resolve conflicts'
                : (hasRecoveryCopies ? 'Resolve recovery copies' : 'Show mount safety warning');
            const rowStatus = this.getFolderRowStatusState({
                isMounted,
                syncStatus,
                showSafetyAlert,
            });
            return `
                <div class="folder-item ${folder === this.selectedFolder ? 'active' : ''} ${isMounted ? 'mounted' : ''}" 
                     data-folder-path="${escapedFolderPath}"
                     data-folder-root-id="${escapedRootId}">
                    <div class="folder-item-main">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                            <path stroke="currentColor" stroke-width="2" d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                        </svg>
                        ${rowStatus.showMountedBadge ? '<span class="mount-indicator mounted compact">Mounted</span>' : ''}
                    </div>
                    <span class="folder-name">${escapedDisplayName}</span>
                    ${(rowStatus.showAlertButton || rowStatus.healthDotTone) ? `
                        <div class="folder-item-status">
                            ${rowStatus.showAlertButton ? `<button type="button" class="mount-status-alert-btn" data-mount-alert-root-id="${escapedRootId}" title="${alertTitle}" aria-label="${alertLabel}">!</button>` : ''}
                            ${rowStatus.healthDotTone ? `<span class="mount-health-dot ${rowStatus.healthDotTone}" aria-hidden="true"></span>` : ''}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');

        // Add event listeners
        folderList.querySelectorAll('.folder-item').forEach(item => {
            const path = item.getAttribute('data-folder-path');
            const folder = this.enrolledFolders.find(f => f.path === path);

            // Single click to select and open the folder detail pane
            item.addEventListener('click', () => {
                this.selectFolder(path, { showDetail: true });
            });

            // Double click to mount
            item.addEventListener('dblclick', (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (folder) {
                    this.mountFolderFromContext(folder);
                }
            });

            // Right click for context menu
            item.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (folder) {
                    this.showContextMenu(e, folder);
                }
            });
        });

        folderList.querySelectorAll('.mount-status-alert-btn').forEach(button => {
            const rootId = button.getAttribute('data-mount-alert-root-id');
            const folder = this.enrolledFolders.find(entry => String(entry?.root_id || '') === rootId);

            button.addEventListener('click', async (event) => {
                event.preventDefault();
                event.stopPropagation();
                if (folder) {
                    if (this.folderHasPendingConflicts(folder)) {
                        await this.openConflictCenterForFolder(folder);
                    } else if (this.folderHasPendingRecoveryCopies(folder)) {
                        await this.openRecoveryCenterForFolder(folder);
                    } else {
                        await this.showMountSafetyAlert(folder);
                    }
                }
            });

            button.addEventListener('dblclick', event => {
                event.preventDefault();
                event.stopPropagation();
            });
        });
    }

    selectFolder(folderPath, { showDetail = false } = {}) {
        const folder = typeof folderPath === 'string'
            ? this.enrolledFolders.find(f => f.path === folderPath)
            : folderPath;

        if (!folder) return;

        this.selectedFolder = folder;
        this.userFolderPreferences.lastSelectedFolder = folder.path;
        this.saveFolderPreferences();

        // Update UI
        document.querySelectorAll('.folder-item').forEach(el => {
            el.classList.toggle('active', el.dataset.folderPath === folder.path);
        });

        this.updateBreadcrumb(folder.path);
        this.syncSelectedFolderMountUi();
        if (showDetail) {
            this.showFolderDetail(folder);
        }
    }

    // ========================================================================
    // Embedded Terminal
    // ========================================================================

    async fetchPlatformInfo() {
        try {
            const result = await invoke('get_platform_info');
            if (result.success && result.data) {
                this.platformInfo = result.data;
                console.log('Platform info:', this.platformInfo);
                // Apply platform-specific class to body for global styling
                document.body.setAttribute('data-platform', this.platformInfo.os_type);
                // Refresh prompt now that we know who the user is
                this.updateTerminalPromptSymbol();
            }
        } catch (error) {
            console.warn('Failed to fetch platform info:', error);
            // Default fallback
            this.platformInfo = {
                os_type: 'linux',
                os_name: 'Unknown',
                shell: 'bash',
                username: 'user',
                hostname: 'localhost',
                home_dir: '~'
            };
            document.body.setAttribute('data-platform', 'linux');
        }
    }

    bindTerminalInputs() {
        document.querySelectorAll('.terminal-body').forEach(body => this.bindTerminalBodyEvents(body));
    }

    isXtermAvailable() {
        return this.useXterm && typeof window.Terminal === 'function';
    }

    isWelcomeTab(tabId) {
        return Number.isFinite(tabId) && tabId === this.welcomeTabId;
    }

    parseTabIdFromBody(body) {
        if (!body || !body.id) return null;
        const match = body.id.match(/^terminalBody-(\d+)$/);
        if (!match) return null;
        const tabId = parseInt(match[1], 10);
        return Number.isFinite(tabId) ? tabId : null;
    }

    getXtermForTab(tabId) {
        return this.xtermByTabId?.[tabId] || null;
    }

    shouldUseXtermForTab(tabId) {
        return this.isXtermAvailable() && Number.isFinite(tabId);
    }

    getXtermHostForTab(tabId) {
        const output = document.getElementById(`terminalOutput-${tabId}`);
        return output?.querySelector('.terminal-xterm-host') || null;
    }

    attachXtermResizeObserver(tabId, host) {
        if (!host || this.xtermResizeObserverByTab[tabId] || typeof ResizeObserver !== 'function') {
            return;
        }

        const observer = new ResizeObserver(() => {
            this.fitXtermForTab(tabId);
            this.recordTerminalDiagnostic('resize-observer', tabId);
        });
        observer.observe(host);
        this.xtermResizeObserverByTab[tabId] = observer;
    }

    recordTerminalDiagnostic(eventName, tabId = this.activeTabId, { term = null, host = null, body = null, force = false } = {}) {
        if (!this.xtermDebugEnabled || !this.shouldUseXtermForTab(tabId)) {
            return;
        }

        const throttleKey = `${tabId}:${eventName}`;
        const now = Date.now();
        if (!force && now - (this.xtermDiagnosticLastEventAt[throttleKey] || 0) < 150) {
            return;
        }
        this.xtermDiagnosticLastEventAt[throttleKey] = now;

        const snapshot = createTerminalDiagnosticSnapshotValue({
            tabId,
            sessionId: this.getTabById(tabId)?.sessionId || null,
            event: eventName,
            term: term || this.getXtermForTab(tabId),
            host: host || this.getXtermHostForTab(tabId),
            body: body || document.getElementById(`terminalBody-${tabId}`),
        });

        const payload = {
            tab_id: snapshot.tabId ?? tabId,
            session_id: snapshot.sessionId,
            event: snapshot.event,
            textarea_is_active: Boolean(snapshot.textareaIsActive),
            xterm_has_focus_class: Boolean(snapshot.xtermHasFocusClass),
            rows: snapshot.rows ?? null,
            cols: snapshot.cols ?? null,
            host_visible: Boolean(snapshot.hostVisible),
            host_width: snapshot.hostWidth ?? null,
            host_height: snapshot.hostHeight ?? null,
            host_occluded: typeof snapshot.hostOccluded === 'boolean' ? snapshot.hostOccluded : null,
            occluding_element_tag: snapshot.occludingElementTag ?? null,
            occluding_element_id: snapshot.occludingElementId ?? null,
            selection_overlay_count: snapshot.selectionOverlayCount ?? 0,
            term_has_selection: Boolean(snapshot.termHasSelection),
            selection_text_length: snapshot.selectionTextLength ?? 0,
            active_element_tag: snapshot.activeElementTag ?? null,
            active_element_id: snapshot.activeElementId ?? null,
        };

        console.debug('[terminal:xterm]', payload);
        invoke('record_terminal_diagnostic', { payload }).catch((error) => {
            console.debug('terminal diagnostic logging failed:', error);
        });
    }

    attachXtermDiagnostics(tabId, term, body, host) {
        if (!this.xtermDebugEnabled || !this.shouldUseXtermForTab(tabId) || !term || !body || !host) {
            return;
        }
        if (typeof this.xtermDiagnosticsAttachedByTab[tabId] === 'function') {
            return;
        }

        const cleanups = [];
        const addDomListener = (target, eventName, handler, options) => {
            if (!target?.addEventListener) return;
            target.addEventListener(eventName, handler, options);
            cleanups.push(() => target.removeEventListener(eventName, handler, options));
        };
        const record = (diagnosticEvent, options = {}) => {
            this.recordTerminalDiagnostic(diagnosticEvent, tabId, { term, host, body, ...options });
        };

        addDomListener(document, 'selectionchange', () => record('selectionchange'));

        if (term.textarea) {
            addDomListener(term.textarea, 'focus', () => record('textarea-focus', { force: true }));
            addDomListener(term.textarea, 'blur', () => record('textarea-blur', { force: true }));
        }

        if (typeof term.onFocus === 'function') {
            const disposable = term.onFocus(() => record('xterm-focus', { force: true }));
            cleanups.push(() => disposable?.dispose?.());
        }

        if (typeof term.onBlur === 'function') {
            const disposable = term.onBlur(() => record('xterm-blur', { force: true }));
            cleanups.push(() => disposable?.dispose?.());
        }

        if (typeof term.onSelectionChange === 'function') {
            const disposable = term.onSelectionChange(() => record('xterm-selection-change'));
            cleanups.push(() => disposable?.dispose?.());
        }

        this.xtermDiagnosticsAttachedByTab[tabId] = () => {
            cleanups.forEach((cleanup) => {
                try {
                    cleanup();
                } catch (_) {
                    // no-op
                }
            });
        };

        this.recordTerminalDiagnostic('xterm-attached', tabId, { term, host, body, force: true });
    }

    queuePendingTerminalData(tabId, chunk) {
        if (!chunk) return;
        const pending = this.pendingTerminalDataByTab[tabId] || '';
        this.pendingTerminalDataByTab[tabId] = pending + chunk;
    }

    flushPendingTerminalData(tabId) {
        const pending = this.pendingTerminalDataByTab[tabId];
        if (!pending) return;
        const term = this.getXtermForTab(tabId);
        if (!term) return;
        delete this.pendingTerminalDataByTab[tabId];
        term.write(pending);
    }

    fitXtermForTab(tabId) {
        const fitAddon = this.xtermFitByTabId?.[tabId];
        if (!fitAddon || typeof fitAddon.fit !== 'function') return;
        const pane = document.querySelector(`.terminal-tab-pane[data-tab-id="${tabId}"]`);
        if (pane && !pane.classList.contains('active')) return;
        const body = document.getElementById(`terminalBody-${tabId}`);
        if (!body || body.offsetParent === null) return;
        try {
            fitAddon.fit();
        } catch (error) {
            console.debug('xterm fit skipped:', error);
        }
    }

    fitActiveXterm() {
        const tabId = this.activeTabId;
        if (!Number.isFinite(tabId)) return;
        requestAnimationFrame(() => this.fitXtermForTab(tabId));
    }

    isTerminalTabActive(tabId) {
        const pane = document.querySelector(`.terminal-tab-pane[data-tab-id="${tabId}"]`);
        return Boolean(pane?.classList.contains('active'));
    }

    isTerminalTabVisible(tabId) {
        const body = document.getElementById(`terminalBody-${tabId}`);
        return Boolean(body && body.offsetParent !== null && this.isTerminalTabActive(tabId));
    }

    ensureXtermForTab(tabId) {
        if (!this.shouldUseXtermForTab(tabId)) return null;
        const existing = this.getXtermForTab(tabId);
        const existingHost = this.getXtermHostForTab(tabId);
        if (existing && existing.element?.isConnected && existingHost?.contains(existing.element)) {
            return existing;
        }
        if (existing) {
            this.disposeXtermForTab(tabId);
        }

        if (this.isWelcomeTab(tabId)) {
            this.renderWelcomeTab();
        }

        const output = document.getElementById(`terminalOutput-${tabId}`);
        if (!output) return null;
        const body = document.getElementById(`terminalBody-${tabId}`);
        if (body) {
            body.classList.add('terminal-body-xterm');
            body.classList.toggle('terminal-body-xterm-welcome', this.isWelcomeTab(tabId));
        }

        output.classList.add('terminal-output-xterm');
        output.classList.toggle('terminal-output-welcome-xterm', this.isWelcomeTab(tabId));

        let host = this.getXtermHostForTab(tabId);
        if (!host) {
            if (this.isWelcomeTab(tabId)) {
                return null;
            }
            output.innerHTML = '';
            output.dataset.rendered = 'xterm';
            host = document.createElement('div');
            host.className = 'terminal-xterm-host';
            output.appendChild(host);
        }

        const term = new window.Terminal({
            cursorBlink: true,
            cursorStyle: 'block',
            cursorInactiveStyle: 'outline',
            convertEol: false,
            scrollback: 5000,
            allowTransparency: false,
            fontFamily: this.platformInfo?.os_type === 'windows'
                ? "'Cascadia Mono', 'Cascadia Code', 'Consolas', 'Courier New', monospace"
                : this.platformInfo?.os_type === 'linux'
                    ? "'Ubuntu Mono', 'DejaVu Sans Mono', 'Liberation Mono', monospace"
                    : "'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace",
            fontSize: 13,
            lineHeight: 1.2,
            theme: {
                background: '#0f1117',
                foreground: '#e6edf3',
                cursor: '#e6edf3',
                cursorAccent: '#0f1117',
                selectionBackground: 'rgba(46, 230, 214, 0.28)',
                selectionInactiveBackground: 'rgba(46, 230, 214, 0.16)'
            }
        });

        if (window.FitAddon?.FitAddon) {
            const fitAddon = new window.FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            this.xtermFitByTabId[tabId] = fitAddon;
        }

        term.open(host);
        this.xtermByTabId[tabId] = term;
        this.attachXtermResizeObserver(tabId, host);
        this.attachXtermDiagnostics(tabId, term, body, host);

        term.onData(async (data) => {
            if (await this.shouldBlockXtermCommandInput(tabId, data)) {
                return;
            }
            this.sendInputToTab(tabId, data);
        });

        // Keep default browser copy behavior when text is selected.
        term.attachCustomKeyEventHandler((event) => {
            if (!event) return true;
            if ((event.ctrlKey || event.metaKey) && event.key?.toLowerCase() === 'c') {
                const selection = term.getSelection();
                if (selection) {
                    return true;
                }
            }
            return true;
        });

        this.flushPendingTerminalData(tabId);
        this.fitXtermForTab(tabId);
        requestAnimationFrame(() => {
            this.fitXtermForTab(tabId);
            this.recordTerminalDiagnostic('xterm-open', tabId, { term, host, body, force: true });
        });
        return term;
    }

    disposeXtermForTab(tabId) {
        const diagnosticCleanup = this.xtermDiagnosticsAttachedByTab?.[tabId];
        if (typeof diagnosticCleanup === 'function') {
            try {
                diagnosticCleanup();
            } catch (_) {
                // no-op
            }
            delete this.xtermDiagnosticsAttachedByTab[tabId];
        }
        const resizeObserver = this.xtermResizeObserverByTab?.[tabId];
        if (resizeObserver) {
            try {
                resizeObserver.disconnect();
            } catch (_) {
                // no-op
            }
            delete this.xtermResizeObserverByTab[tabId];
        }
        const term = this.xtermByTabId?.[tabId];
        if (term) {
            try {
                term.dispose();
            } catch (_) {
                // no-op
            }
            delete this.xtermByTabId[tabId];
        }
        if (this.xtermFitByTabId?.[tabId]) {
            delete this.xtermFitByTabId[tabId];
        }
        if (this.pendingTerminalDataByTab?.[tabId]) {
            delete this.pendingTerminalDataByTab[tabId];
        }
        if (this.xtermInputBufferByTab?.[tabId]) {
            delete this.xtermInputBufferByTab[tabId];
        }
        const output = document.getElementById(`terminalOutput-${tabId}`);
        if (output && !this.isWelcomeTab(tabId)) {
            delete output.dataset.rendered;
        }
        output?.classList.remove('terminal-output-xterm', 'terminal-output-welcome-xterm');
        const body = document.getElementById(`terminalBody-${tabId}`);
        body?.classList.remove('terminal-body-xterm', 'terminal-body-xterm-welcome');
        Object.keys(this.xtermDiagnosticLastEventAt)
            .filter((key) => key.startsWith(`${tabId}:`))
            .forEach((key) => delete this.xtermDiagnosticLastEventAt[key]);
    }

    bindTerminalBodyEvents(body) {
        if (!body) return;
        const tabId = this.parseTabIdFromBody(body);
        const isXtermTab = this.shouldUseXtermForTab(tabId);
        if (isXtermTab) {
            if (this.isTerminalTabVisible(tabId)) {
                this.ensureXtermForTab(tabId);
            }
            body.addEventListener('mousedown', () => {
                if (!this.isTerminalTabVisible(tabId)) return;
                const term = this.ensureXtermForTab(tabId);
                this.recordTerminalDiagnostic('body-mousedown', tabId, { term, body });
            });
            body.addEventListener('click', () => this.focusTerminalArea(tabId));
        } else {
            body.addEventListener('keydown', (e) => this.handleTerminalKey(e));
            body.addEventListener('paste', (e) => this.handleTerminalPaste(e));
            body.addEventListener('copy', (e) => this.handleTerminalCopy(e));
            body.addEventListener('click', () => this.focusTerminalArea(tabId));
        }
        body.addEventListener('contextmenu', (e) => this.handleTerminalContextMenu(e));
    }

    async handleTerminalKey(event) {
        const input = event.target;
        const tab = this.getActiveTab();
        if (!tab) return;

        // Ensure session exists
        if (!tab.sessionId) {
            await this.startTerminalSessionForTab(tab.id);
        }

        // Send keys to PTY
        const send = (data) => this.sendInputToPty(data);

        // Check for text selection - if text is selected, handle copy/paste differently
        const selection = window.getSelection();
        const hasSelection = selection && selection.toString().length > 0;

        // Copy: Ctrl+C / Cmd+C (only if text is selected, otherwise send interrupt)
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c') {
            if (hasSelection) {
                // Let default copy behavior happen
                return;
            }
            // No selection - send interrupt signal
            event.preventDefault();
            send('\u0003');
            return;
        }

        // Paste: Ctrl+V / Cmd+V
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'v') {
            event.preventDefault();
            // Paste will be handled by paste event listener
            navigator.clipboard.readText().then(text => {
                this.sendInputToPty(text);
            }).catch(err => {
                console.error('Failed to read clipboard:', err);
            });
            return;
        }

        // Cut: Ctrl+X / Cmd+X (only if text is selected)
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'x') {
            if (hasSelection) {
                // Let default cut behavior happen
                return;
            }
            event.preventDefault();
            return;
        }

        // Control keys
        if (event.ctrlKey && event.key.toLowerCase() === 'd') {
            event.preventDefault();
            send('\u0004'); // EOF
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'l') {
            event.preventDefault();
            this.clearTerminalOutput(tab.id);
            send('\u000c'); // Form feed (clear screen)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'a') {
            event.preventDefault();
            send('\u0001'); // Beginning of line
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'e') {
            event.preventDefault();
            send('\u0005'); // End of line
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'u') {
            event.preventDefault();
            send('\u0015'); // Clear line (kill backward)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            send('\u000b'); // Kill line (kill forward)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'w') {
            event.preventDefault();
            send('\u0017'); // Delete word backward
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'z') {
            event.preventDefault();
            send('\u001a'); // Suspend (SIGTSTP)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'r') {
            event.preventDefault();
            send('\u0012'); // Reverse search history
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 's') {
            event.preventDefault();
            send('\u0013'); // Forward search history (may be disabled in some terminals)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'p') {
            event.preventDefault();
            send('\u001b[A'); // Previous command (same as up arrow)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'n') {
            event.preventDefault();
            send('\u001b[B'); // Next command (same as down arrow)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'b') {
            event.preventDefault();
            send('\u001b[D'); // Back one character (same as left arrow)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'f') {
            event.preventDefault();
            send('\u001b[C'); // Forward one character (same as right arrow)
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 't') {
            event.preventDefault();
            send('\u0014'); // Transpose characters
            return;
        }
        if (event.ctrlKey && event.key.toLowerCase() === 'y') {
            event.preventDefault();
            send('\u0019'); // Yank (paste from kill ring)
            return;
        }
        if (event.ctrlKey && event.key === '_') {
            event.preventDefault();
            send('\u001f'); // Undo
            return;
        }

        // Alt+Arrow for word-wise movement (macOS/Linux) or Ctrl+Arrow (Windows)
        if ((event.altKey || (event.ctrlKey && this.platformInfo?.os_type === 'windows')) && event.key === 'ArrowLeft') {
            event.preventDefault();
            send('\u001bb'); // ESC b - backward word
            return;
        }
        if ((event.altKey || (event.ctrlKey && this.platformInfo?.os_type === 'windows')) && event.key === 'ArrowRight') {
            event.preventDefault();
            send('\u001bf'); // ESC f - forward word
            return;
        }

        // Alt+Backspace for delete word backward (macOS)
        if (event.altKey && event.key === 'Backspace') {
            event.preventDefault();
            send('\u0017'); // Ctrl+W - delete word backward
            return;
        }

        // Alt+Delete for delete word forward
        if (event.altKey && event.key === 'Delete') {
            event.preventDefault();
            send('\u001bd'); // ESC d - delete word forward
            return;
        }

        // Prevent default for all arrow keys and other control keys
        switch (event.key) {
            case 'Enter':
                event.preventDefault();
                const activeLine = this.getActiveLineText(tab.id);
                if (await this.handleRestrictedIndividualCliCommand(activeLine, { tabId: tab.id })) {
                    return;
                }
                if (!this.commandBuffer) this.commandBuffer = {};
                this.commandBuffer[tab.id] = activeLine;
                this.maybeQueueTerminalSessionCheck(activeLine);
                send('\r'); // Send CR instead of LF for better shell compatibility
                return;
            case 'Tab':
                event.preventDefault();
                send('\t');
                return;
            case 'Backspace':
                event.preventDefault();
                send('\u007f');
                return;
            case 'Delete':
                event.preventDefault();
                send('\u001b[3~');
                return;
            case 'ArrowUp':
                event.preventDefault();
                send('\u001b[A');
                return;
            case 'ArrowDown':
                event.preventDefault();
                send('\u001b[B');
                return;
            case 'ArrowLeft':
                event.preventDefault();
                send('\u001b[D');
                return;
            case 'ArrowRight':
                event.preventDefault();
                send('\u001b[C');
                return;
            case 'Home':
                event.preventDefault();
                send('\u001b[H');
                return;
            case 'End':
                event.preventDefault();
                send('\u001b[F');
                return;
            case 'PageUp':
                event.preventDefault();
                send('\u001b[5~');
                return;
            case 'PageDown':
                event.preventDefault();
                send('\u001b[6~');
                return;
            case 'Insert':
                event.preventDefault();
                send('\u001b[2~');
                return;
            case 'Escape':
                event.preventDefault();
                send('\u001b');
                return;
            default:
                break;
        }

        // Printable characters (no meta, no ctrl except handled above)
        if (
            event.key &&
            event.key.length === 1 &&
            !event.metaKey &&
            !event.ctrlKey &&
            !event.altKey
        ) {
            event.preventDefault();
            send(event.key);
        }
    }

    handleTerminalContextMenu(event) {
        event.preventDefault();
        const selection = window.getSelection();
        const hasSelection = selection && selection.toString().length > 0;

        // Create context menu
        const menu = document.createElement('div');
        const backdrop = document.createElement('div');
        backdrop.style.position = 'fixed';
        backdrop.style.left = '0';
        backdrop.style.top = '0';
        backdrop.style.width = '100%';
        backdrop.style.height = '100%';
        backdrop.style.zIndex = '9999';
        backdrop.style.background = 'transparent';
        backdrop.style.pointerEvents = 'auto';
        menu.className = 'terminal-context-menu';
        menu.style.position = 'fixed';
        menu.style.left = `${event.clientX}px`;
        menu.style.top = `${event.clientY}px`;
        menu.style.background = 'var(--bg-elevated)';
        menu.style.border = '1px solid var(--border)';
        menu.style.borderRadius = 'var(--radius-md)';
        menu.style.padding = '4px';
        menu.style.zIndex = '10000';
        menu.style.boxShadow = 'var(--shadow-lg)';
        menu.style.minWidth = '150px';

        if (hasSelection) {
            const copyItem = document.createElement('div');
            copyItem.className = 'context-menu-item';
            copyItem.textContent = 'Copy';
            copyItem.style.padding = '8px 12px';
            copyItem.style.cursor = 'pointer';
            copyItem.style.color = 'var(--text-primary)';
            copyItem.style.borderRadius = 'var(--radius-sm)';
            copyItem.addEventListener('mouseenter', () => {
                copyItem.style.background = 'rgba(255, 255, 255, 0.1)';
            });
            copyItem.addEventListener('mouseleave', () => {
                copyItem.style.background = 'transparent';
            });
            copyItem.addEventListener('click', () => {
                document.execCommand('copy');
                menu.remove();
            });
            menu.appendChild(copyItem);
        }

        const pasteItem = document.createElement('div');
        pasteItem.className = 'context-menu-item';
        pasteItem.textContent = 'Paste';
        pasteItem.style.padding = '8px 12px';
        pasteItem.style.cursor = 'pointer';
        pasteItem.style.color = 'var(--text-primary)';
        pasteItem.style.borderRadius = 'var(--radius-sm)';
        pasteItem.addEventListener('mouseenter', () => {
            pasteItem.style.background = 'rgba(255, 255, 255, 0.1)';
        });
        pasteItem.addEventListener('mouseleave', () => {
            pasteItem.style.background = 'transparent';
        });
        pasteItem.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    this.sendInputToPty(text);
                }
            } catch (err) {
                console.error('Failed to read clipboard:', err);
            }
            menu.remove();
        });
        menu.appendChild(pasteItem);

        // Add select all option
        const selectAllItem = document.createElement('div');
        selectAllItem.className = 'context-menu-item';
        selectAllItem.textContent = 'Select All';
        selectAllItem.style.padding = '8px 12px';
        selectAllItem.style.cursor = 'pointer';
        selectAllItem.style.color = 'var(--text-primary)';
        selectAllItem.style.borderRadius = 'var(--radius-sm)';
        selectAllItem.addEventListener('mouseenter', () => {
            selectAllItem.style.background = 'rgba(255, 255, 255, 0.1)';
        });
        selectAllItem.addEventListener('mouseleave', () => {
            selectAllItem.style.background = 'transparent';
        });
        selectAllItem.addEventListener('click', () => {
            if (this.shouldUseXtermForTab(this.activeTabId)) {
                const term = this.getXtermForTab(this.activeTabId) || this.ensureXtermForTab(this.activeTabId);
                if (term && typeof term.selectAll === 'function') {
                    term.selectAll();
                }
            } else {
                const output = this.getActiveTerminalOutput();
                if (output) {
                    const range = document.createRange();
                    range.selectNodeContents(output);
                    const sel = window.getSelection();
                    sel.removeAllRanges();
                    sel.addRange(range);
                }
            }
            menu.remove();
        });
        menu.appendChild(selectAllItem);

        document.body.appendChild(menu);

        // Remove menu when clicking elsewhere
        const openedAt = performance.now();
        const ignoreTabClicksUntil = openedAt + 600;
        const removeMenu = (e) => {
            if (performance.now() - openedAt < 120) {
                return;
            }
            if (menu.contains(e.target)) {
                return;
            }
            if (e.target.closest('.terminal-tabs') && performance.now() < ignoreTabClicksUntil) {
                return;
            }
            if (e.button !== 0 || e.ctrlKey || e.metaKey) return;
            menu.remove();
            document.removeEventListener('click', removeMenu);
        };
        setTimeout(() => {
            document.addEventListener('click', removeMenu);
        }, 0);
    }

    handleTerminalPaste(event) {
        event.preventDefault();
        event.stopPropagation();
        const pastedText = (event.clipboardData || window.clipboardData).getData('text');
        if (pastedText) {
            this.sendInputToPty(pastedText);
        }
    }

    handleTerminalCopy(event) {
        // Allow default copy behavior when text is selected
        const selection = window.getSelection();
        if (selection && selection.toString().length > 0) {
            // Default behavior is fine
            return;
        }
        // Prevent copy if nothing is selected
        event.preventDefault();
    }

    getActiveLineText(tabId) {
        const buffer = this.getTabLineBuffer(tabId);
        if (!buffer) return '';
        return buffer.currentLine || '';
    }

    getIndividualEditionRestrictionMessage(commandName) {
        return `This build disables team and group administration commands. \`${commandName}\` is not available.`;
    }

    getRestrictedIndividualCliCommand(command) {
        if (this.appMode !== 'individual' || !command || typeof command !== 'string') {
            return null;
        }

        const normalized = this.sanitizeCommandForTitle(command).trim();
        if (!normalized) {
            return null;
        }

        const match = normalized.match(
            /(?:^|\s)(?:(?:\.\.\/|\.\/|\/)?[^\s]*hybridcipher(?:\.exe)?)\s+([^\s]+)(?:\s+([^\s]+))?/i
        );
        if (!match) {
            return null;
        }

        const subcommand = (match[1] || '').toLowerCase();
        const action = (match[2] || '').toLowerCase();

        switch (subcommand) {
            case 'create-group':
            case 'rename-group':
            case 'initialize-group':
            case 'switch-group':
            case 'current-group':
            case 'list-groups':
            case 'delete-group':
            case 'add-member':
            case 'remove-member':
            case 'list-members':
            case 'generate-welcome':
            case 'unverified-devices':
                return subcommand;
            case 'rekey':
                if (['start', 'status', 'cutover', 'fallback'].includes(action)) {
                    return `rekey ${action}`;
                }
                return null;
            default:
                return null;
        }
    }

    async handleRestrictedIndividualCliCommand(command, { tabId = this.activeTabId, clearInput = true } = {}) {
        const blockedCommand = this.getRestrictedIndividualCliCommand(command);
        if (!blockedCommand) {
            return false;
        }

        const message = this.getIndividualEditionRestrictionMessage(blockedCommand);
        this.showNotification(message, 'warning');

        if (clearInput) {
            await this.sendInputToTab(tabId, '\u0015\r');
        }

        if (this.shouldUseXtermForTab(tabId)) {
            const term = this.getXtermForTab(tabId) || this.ensureXtermForTab(tabId);
            term?.writeln(`\r\n[blocked] ${message}`);
        } else {
            this.appendTerminalLine(message, 'error');
        }

        return true;
    }

    async shouldBlockXtermCommandInput(tabId, data) {
        if (this.appMode !== 'individual' || !data) {
            return false;
        }

        let buffer = this.xtermInputBufferByTab[tabId] || '';
        for (const ch of data) {
            if (ch === '\r' || ch === '\n') {
                const blocked = await this.handleRestrictedIndividualCliCommand(buffer, { tabId });
                this.xtermInputBufferByTab[tabId] = '';
                if (blocked) {
                    return true;
                }
                continue;
            }

            if (ch === '\u0003' || ch === '\u0015') {
                buffer = '';
                continue;
            }

            if (ch === '\u007f') {
                buffer = buffer.slice(0, -1);
                continue;
            }

            if (ch.length === 1 && ch >= ' ' && ch !== '\u007f') {
                buffer += ch;
            }
        }

        this.xtermInputBufferByTab[tabId] = buffer;
        return false;
    }

    sanitizeCommandForTitle(line) {
        const trimmed = (line || '').trim();
        if (!trimmed) return '';
        const prompts = ['% ', '$ ', '# ', '> ', '❯ ', '» '];
        let cut = -1;
        prompts.forEach(p => {
            const idx = trimmed.lastIndexOf(p);
            if (idx !== -1 && idx + p.length < trimmed.length) {
                cut = Math.max(cut, idx + p.length);
            }
        });
        if (cut !== -1) {
            return trimmed.slice(cut).trim();
        }
        return trimmed;
    }

    isCliLogoutCommand(command) {
        if (!command) return false;
        const normalized = command.trim();
        if (!normalized) return false;
        return /(^|\s)(?:\.\/)?hybridcipher(?:\.exe)?\s+(?:auth\s+)?logout\b/i.test(normalized);
    }

    shouldPreflightSessionForCommand(command) {
        if (!command || typeof command !== 'string') return false;
        const normalized = command.trim();
        if (!normalized) return false;
        const isHybridCipherCommand = /(^|\s)(?:\.\/)?hybridcipher(?:\.exe)?\b/i.test(normalized);
        if (!isHybridCipherCommand) return false;
        if (/(^|\s)(?:\.\/)?hybridcipher(?:\.exe)?\s+(?:auth\s+)?(?:login|register)\b/i.test(normalized)) {
            return false;
        }
        if (this.isCliLogoutCommand(normalized)) {
            return false;
        }
        return true;
    }

    maybeQueueTerminalSessionCheck(line) {
        const command = this.sanitizeCommandForTitle(line);
        if (!this.isCliLogoutCommand(command)) return;
        this.queueTerminalSessionCheck();
    }

    queueTerminalSessionCheck() {
        if (this.terminalSessionCheckTimer) {
            clearTimeout(this.terminalSessionCheckTimer);
        }
        if (this.terminalSessionCheckFollowupTimer) {
            clearTimeout(this.terminalSessionCheckFollowupTimer);
        }
        this.terminalSessionCheckTimer = setTimeout(() => {
            this.refreshSessionAfterTerminalAction();
        }, 2000);
        this.terminalSessionCheckFollowupTimer = setTimeout(() => {
            this.refreshSessionAfterTerminalAction();
        }, 8000);
    }

    async refreshSessionAfterTerminalAction() {
        if (!this.isLoggedIn) return;
        const cliSessionOk = await this.verifyCliSession();
        if (!cliSessionOk) {
            await this.handleStaleSession('Session ended. Please login again.');
        }
    }

    async sendInputToTab(tabId, data) {
        const tab = this.getTabById(tabId);
        if (!tab) return;
        if (!tab.sessionId) {
            await this.startTerminalSessionForTab(tab.id);
        }
        if (!tab.sessionId) return;
        try {
            await invoke('write_terminal_stdin', { sessionId: tab.sessionId, data });
        } catch (error) {
            console.error('Terminal PTY write error:', error);
            if (this.shouldUseXtermForTab(tab.id)) {
                const term = this.getXtermForTab(tab.id);
                if (term) {
                    term.writeln(`\r\n[error] ${error}`);
                }
            } else {
                this.appendTerminalLine(`Error: ${error}`, 'error');
            }
        }
    }

    async sendInputToPty(data) {
        const tab = this.getActiveTab();
        if (!tab) return;
        await this.sendInputToTab(tab.id, data);
    }

    getActiveTerminalBody() {
        return document.getElementById(`terminalBody-${this.activeTabId}`);
    }

    getActiveTerminalOutput() {
        return document.getElementById(`terminalOutput-${this.activeTabId}`);
    }

    focusTerminalArea(tabId = this.activeTabId) {
        if (this.shouldUseXtermForTab(tabId)) {
            const term = this.getXtermForTab(tabId) || this.ensureXtermForTab(tabId);
            if (term && typeof term.focus === 'function') {
                this.recordTerminalDiagnostic('focus-request', tabId, { term, force: true });
                term.focus();
                requestAnimationFrame(() => {
                    this.recordTerminalDiagnostic('focus-after-request', tabId, { term, force: true });
                });
                return;
            }
        }
        const body = document.getElementById(`terminalBody-${tabId}`);
        if (body && typeof body.focus === 'function') {
            body.focus();
        }
    }

    ensureTerminalWelcome() {
        if (this.activeTabId === this.welcomeTabId) {
            this.renderWelcomeTab();
            return;
        }

        if (this.shouldUseXtermForTab(this.activeTabId)) {
            const tab = this.getActiveTab();
            if (!tab) return;
            const term = this.ensureXtermForTab(tab.id);
            if (!term) return;
            if (this.welcomeMessageShownByTab[tab.id]) {
                return;
            }
            const welcomeMsg = this.getTerminalWelcome();
            if (welcomeMsg) {
                term.writeln(welcomeMsg);
                this.welcomeMessageShownByTab[tab.id] = true;
            }
            return;
        }

        const output = this.getActiveTerminalOutput();
        if (!output) return;

        if (output.children.length === 0) {
            const welcomeMsg = this.getTerminalWelcome();
            if (welcomeMsg) {
                this.appendTerminalLine(welcomeMsg, 'status');
            }
        }
    }

    setupTerminalEvents() {
        const tauriEvent = window.__TAURI__?.event;
        if (!tauriEvent || !tauriEvent.listen) return;
        tauriEvent.listen('terminal_output', (event) => {
            const payload = event?.payload || {};
            if (!payload.session_id || typeof payload.chunk !== 'string') return;
            this.appendChunkToSession(payload.session_id, payload.chunk);
        });
        tauriEvent.listen('app_quit_requested', async () => {
            await this.handleQuitRequested();
        });
        tauriEvent.listen('open_settings_requested', (event) => {
            const sectionId = typeof event?.payload === 'string' ? event.payload : null;
            this.openSettingsModal(sectionId);
        });
        tauriEvent.listen('updater_progress', (event) => {
            this.handleUpdaterProgressEvent(event?.payload || {});
        });
        tauriEvent.listen('coverage_scan_progress', (event) => {
            this.handleCoverageScanProgress(event?.payload || {});
        });
        tauriEvent.listen('coverage_scan_finished', async (event) => {
            await this.handleCoverageScanFinished(event?.payload || {});
        });
    }

    getTabById(id) {
        return this.terminalTabs.find(t => t.id === id);
    }

    getActiveTab() {
        return this.getTabById(this.activeTabId);
    }

    async startTerminalSessionForTab(tabId) {
        const tab = this.getTabById(tabId);
        if (!tab || tab.sessionId) return;
        if (this.startingTerminalSessionByTab[tabId]) {
            await this.startingTerminalSessionByTab[tabId];
            return;
        }
        if (this.shouldUseXtermForTab(tabId) && this.isTerminalTabVisible(tabId)) {
            this.ensureXtermForTab(tabId);
        }
        this.startingTerminalSessionByTab[tabId] = (async () => {
            try {
                const cwd = this.getTerminalCwd();
                const result = await invoke('start_terminal_session', { cwd });
                if (result?.success && result.data?.session_id) {
                    tab.sessionId = result.data.session_id;
                    if (this.shouldUseXtermForTab(tabId) && this.isTerminalTabVisible(tabId)) {
                        this.fitXtermForTab(tabId);
                        this.focusTerminalArea(tabId);
                    }
                    this.recordTerminalDiagnostic('session-started', tabId, { force: true });
                }
            } catch (error) {
                console.error('Failed to start terminal session:', error);
                this.appendTerminalLine('Failed to start terminal session', 'error');
            } finally {
                delete this.startingTerminalSessionByTab[tabId];
            }
        })();
        await this.startingTerminalSessionByTab[tabId];
    }

    appendChunkToSession(sessionId, chunk) {
        const tab = this.terminalTabs.find(t => t.sessionId === sessionId);
        if (!tab) {
            this.handleMountSessionOutput(sessionId, chunk);
            return;
        }

        let filteredChunk = this.filterRegisterOverlayChunk(sessionId, chunk);
        if (!filteredChunk) {
            return;
        }
        filteredChunk = this.suppressPromptEchoFromChunk(sessionId, filteredChunk);
        if (!filteredChunk) {
            return;
        }

        if (this.shouldUseXtermForTab(tab.id)) {
            this.writeChunkToTabTerminal(tab.id, filteredChunk);
            this.handlePromptAutoResponses(sessionId, filteredChunk);
            this.handleCoverageCommandOutput(sessionId, filteredChunk);
            return;
        }

        this.queueTerminalChunk(sessionId, tab.id, filteredChunk);
    }

    writeChunkToTabTerminal(tabId, chunk) {
        if (!chunk) return;
        if (this.shouldUseXtermForTab(tabId)) {
            let term = this.getXtermForTab(tabId);
            if (!term) {
                term = this.ensureXtermForTab(tabId);
            }
            if (term) {
                term.write(chunk);
                return;
            }
        }

        this.queuePendingTerminalData(tabId, chunk);
    }

    queueTerminalChunk(sessionId, tabId, chunk) {
        if (!chunk) return;
        if (!this.terminalRenderQueues) {
            this.terminalRenderQueues = {};
        }
        const queue = this.terminalRenderQueues[sessionId] || {
            pending: '',
            tabId,
            scheduled: false,
            timer: null
        };

        queue.pending += chunk;
        queue.tabId = tabId;
        this.terminalRenderQueues[sessionId] = queue;

        if (queue.scheduled) return;
        queue.scheduled = true;
        queue.timer = setTimeout(() => {
            queue.timer = null;
            this.flushTerminalChunk(sessionId);
        }, this.terminalRenderIntervalMs);
    }

    flushTerminalChunk(sessionId) {
        const queue = this.terminalRenderQueues?.[sessionId];
        if (!queue) return;

        queue.scheduled = false;
        const pending = queue.pending;
        if (!pending) return;
        queue.pending = '';

        const tab = this.terminalTabs.find(t => t.id === queue.tabId && t.sessionId === sessionId);
        if (!tab) return;

        if (this.shouldUseXtermForTab(tab.id)) {
            this.writeChunkToTabTerminal(tab.id, pending);
            this.handlePromptAutoResponses(sessionId, pending);
            this.handleCoverageCommandOutput(sessionId, pending);
            return;
        }

        const output = document.getElementById(`terminalOutput-${tab.id}`);
        if (!output) return;

        const buffer = this.getTabLineBuffer(tab.id);
        // Remove existing cursors in this tab before applying updates
        this.clearCursorsForTab(tab.id);

        // Process the chunk with ANSI escape sequence handling
        this.processTerminalChunk(pending, buffer, output, tab, { deferRender: true });

        // Apply cursor to active tab only
        if (tab.id === this.activeTabId) {
            this.applyCursorToActiveTab(true);
        }

        // Update tab title from last submitted command buffer (if any)
        if (!this.commandBuffer) this.commandBuffer = {};
        const lastCmd = this.commandBuffer[tab.id];
        if (lastCmd) {
            this.updateActiveTabTitle(this.sanitizeCommandForTitle(lastCmd));
            this.commandBuffer[tab.id] = '';
        }

        this.scrollTerminalToBottom(tab.id);
        this.handlePromptAutoResponses(sessionId, pending);
        this.handleCoverageCommandOutput(sessionId, pending);
    }

    clearTerminalRenderQueue(sessionId) {
        if (!sessionId || !this.terminalRenderQueues) return;
        const queue = this.terminalRenderQueues[sessionId];
        if (!queue) return;
        if (queue.timer) {
            clearTimeout(queue.timer);
        }
        delete this.terminalRenderQueues[sessionId];
    }

    filterRegisterOverlayChunk(sessionId, chunk) {
        if (!this.registerOverlaySessionId || sessionId !== this.registerOverlaySessionId) {
            return chunk;
        }

        const echoFiltered = this.stripRegisterOverlayCommandEcho(sessionId, chunk);
        if (!echoFiltered) {
            return '';
        }

        const successToken = '__HC_REGISTER_SUCCESS__';
        const failToken = '__HC_REGISTER_FAILED__';
        const holdLen = Math.max(successToken.length, failToken.length) - 1;

        const existing = this.registerSentinelBuffers[sessionId] || '';
        let combined = existing + echoFiltered;
        let success = false;
        let fail = false;

        if (combined.includes(successToken)) {
            success = true;
            combined = combined.split(successToken).join('');
        }
        if (combined.includes(failToken)) {
            fail = true;
            combined = combined.split(failToken).join('');
        }

        let output = combined;
        let hold = '';
        if (combined.length > holdLen) {
            output = combined.slice(0, -holdLen);
            hold = combined.slice(-holdLen);
        } else {
            output = '';
            hold = combined;
        }

        if (success || fail) {
            output += hold;
            hold = '';
            this.registerSentinelBuffers[sessionId] = '';
            this.registerOverlaySessionId = null;
            this.handleRegisterOverlayCompletion(success);
        } else {
            this.registerSentinelBuffers[sessionId] = hold;
        }

        return output;
    }

    stripRegisterOverlayCommandEcho(sessionId, chunk) {
        // The 'clear' command in the bash script handles hiding the command echo,
        // so we just return the chunk as-is and clean up the state
        const echoState = this.registerOverlayCommandEchoBySession[sessionId];
        if (echoState) {
            delete this.registerOverlayCommandEchoBySession[sessionId];
        }
        return chunk;
    }

    /**
     * Process terminal output chunk with proper ANSI escape sequence handling.
     * This handles cursor movement, line editing, and proper terminal emulation.
     */
    processTerminalChunk(chunk, buffer, output, tab, options = {}) {
        // Normalize \r\n to \n (Windows-style line endings)
        // But keep standalone \r for line redraws
        const normalized = chunk.replace(/\r\n/g, '\n');
        const renderState = {
            deferRender: Boolean(options.deferRender),
            needsRender: false
        };
        let i = 0;

        while (i < normalized.length) {
            const ch = normalized[i];

            // Check for escape sequence start
            if (ch === '\u001b') {
                // Parse escape sequence
                const result = this.parseEscapeSequence(normalized, i);
                if (result.action) {
                    this.handleEscapeAction(result.action, buffer, output, renderState);
                }
                i = result.nextIndex;
                continue;
            }

            // Handle carriage return - move cursor to beginning of line
            if (ch === '\r') {
                buffer.cursorPos = 0;
                i++;
                continue;
            }

            // Handle newline - commit current line and start new one
            if (ch === '\n') {
                this.commitCurrentLine(buffer, output, tab, renderState);
                i++;
                continue;
            }

            // Handle backspace (0x08) - move cursor left
            if (ch === '\b') {
                if (buffer.cursorPos > 0) {
                    buffer.cursorPos--;
                }
                i++;
                continue;
            }

            // Handle DEL (0x7F) - delete character at cursor
            if (ch === '\u007f') {
                if (buffer.cursorPos > 0) {
                    buffer.cursorPos--;
                    buffer.currentLine =
                        buffer.currentLine.slice(0, buffer.cursorPos) +
                        buffer.currentLine.slice(buffer.cursorPos + 1);
                    this.updateLineDisplay(buffer, output, renderState);
                }
                i++;
                continue;
            }

            // Handle bell (0x07) - ignore
            if (ch === '\u0007') {
                i++;
                continue;
            }

            // Handle tab - expand to spaces
            if (ch === '\t') {
                const spaces = 8 - (buffer.cursorPos % 8);
                for (let s = 0; s < spaces; s++) {
                    this.insertCharAtCursor(buffer, output, ' ', renderState);
                }
                i++;
                continue;
            }

            // Regular printable character - insert at cursor position
            if (ch.charCodeAt(0) >= 32 || ch.charCodeAt(0) === 9) {
                this.insertCharAtCursor(buffer, output, ch, renderState);
            }

            i++;
        }

        this.flushLineDisplay(buffer, output, renderState);
    }

    /**
     * Parse ANSI escape sequence starting at position i in chunk.
     * Returns { action: object|null, nextIndex: number }
     */
    parseEscapeSequence(chunk, i) {
        // Skip the ESC character
        i++;
        if (i >= chunk.length) {
            return { action: null, nextIndex: i };
        }

        const next = chunk[i];

        // CSI sequence: ESC [
        if (next === '[') {
            i++;
            let params = '';

            // Collect parameter bytes (0x30-0x3F: digits, semicolon, etc.)
            while (i < chunk.length && chunk.charCodeAt(i) >= 0x30 && chunk.charCodeAt(i) <= 0x3F) {
                params += chunk[i];
                i++;
            }

            // Collect intermediate bytes (0x20-0x2F)
            while (i < chunk.length && chunk.charCodeAt(i) >= 0x20 && chunk.charCodeAt(i) <= 0x2F) {
                i++;
            }

            // Final byte (0x40-0x7E)
            if (i < chunk.length) {
                const finalByte = chunk[i];
                i++;

                return {
                    action: { type: 'csi', params, finalByte },
                    nextIndex: i
                };
            }

            return { action: null, nextIndex: i };
        }

        // OSC sequence: ESC ]
        if (next === ']') {
            i++;
            // Skip until BEL (0x07) or ST (ESC \)
            while (i < chunk.length) {
                if (chunk[i] === '\u0007') {
                    i++;
                    break;
                }
                if (chunk[i] === '\u001b' && i + 1 < chunk.length && chunk[i + 1] === '\\') {
                    i += 2;
                    break;
                }
                i++;
            }
            return { action: null, nextIndex: i };
        }

        // Simple escape sequences (ESC followed by single char)
        if (next >= '@' && next <= '_') {
            return { action: null, nextIndex: i + 1 };
        }

        // Unknown escape - just skip ESC
        return { action: null, nextIndex: i };
    }

    /**
     * Handle a parsed escape sequence action
     */
    handleEscapeAction(action, buffer, output, renderState) {
        if (action.type !== 'csi') return;

        const { params, finalByte } = action;
        const n = parseInt(params) || 1;

        switch (finalByte) {
            case 'A': // Cursor Up - not typically used in line editing
                break;

            case 'B': // Cursor Down - not typically used in line editing
                break;

            case 'C': // Cursor Forward (Right)
                buffer.cursorPos = Math.min(buffer.cursorPos + n, buffer.currentLine.length);
                break;

            case 'D': // Cursor Back (Left)
                buffer.cursorPos = Math.max(buffer.cursorPos - n, 0);
                break;

            case 'G': // Cursor Horizontal Absolute
                buffer.cursorPos = Math.max(0, Math.min(n - 1, buffer.currentLine.length));
                break;

            case 'H': // Cursor Position
            case 'f': // Horizontal and Vertical Position
                // For single-line terminal, just handle column
                const parts = params.split(';');
                if (parts.length >= 2) {
                    const col = parseInt(parts[1]) || 1;
                    buffer.cursorPos = Math.max(0, Math.min(col - 1, buffer.currentLine.length));
                }
                break;

            case 'J': // Erase in Display
                // 0 or no param: clear from cursor to end of screen
                // 1: clear from start of screen to cursor
                // 2: clear entire screen
                // 3: clear entire screen and scrollback
                const jMode = parseInt(params) || 0;
                if (jMode === 0) {
                    // Clear from cursor to end
                    buffer.currentLine = buffer.currentLine.slice(0, buffer.cursorPos);
                    this.updateLineDisplay(buffer, output, renderState);
                } else if (jMode === 2 || jMode === 3) {
                    // Clear entire screen - for our terminal, clear all output
                    output.innerHTML = '';
                    buffer.lineEl = null;
                    buffer.currentLine = '';
                    buffer.cursorPos = 0;
                    if (renderState) {
                        renderState.needsRender = false;
                    }
                }
                break;

            case 'K': // Erase in Line
                // 0 or no param: clear from cursor to end of line
                // 1: clear from start of line to cursor
                // 2: clear entire line
                const mode = parseInt(params) || 0;
                if (mode === 0) {
                    buffer.currentLine = buffer.currentLine.slice(0, buffer.cursorPos);
                } else if (mode === 1) {
                    buffer.currentLine = ' '.repeat(buffer.cursorPos) + buffer.currentLine.slice(buffer.cursorPos);
                } else if (mode === 2) {
                    buffer.currentLine = '';
                    buffer.cursorPos = 0;
                }
                this.updateLineDisplay(buffer, output, renderState);
                break;

            case 'P': // Delete Characters
                buffer.currentLine =
                    buffer.currentLine.slice(0, buffer.cursorPos) +
                    buffer.currentLine.slice(buffer.cursorPos + n);
                this.updateLineDisplay(buffer, output, renderState);
                break;

            case '@': // Insert Characters
                buffer.currentLine =
                    buffer.currentLine.slice(0, buffer.cursorPos) +
                    ' '.repeat(n) +
                    buffer.currentLine.slice(buffer.cursorPos);
                this.updateLineDisplay(buffer, output, renderState);
                break;

            case 'm': // SGR (Select Graphic Rendition) - color/style, ignore for now
                break;

            default:
                // Unknown CSI sequence - ignore
                break;
        }
    }

    /**
     * Insert a character at the current cursor position
     */
    insertCharAtCursor(buffer, output, ch, renderState) {
        // Ensure line element exists
        if (!buffer.lineEl) {
            buffer.lineEl = document.createElement('div');
            buffer.lineEl.className = 'terminal-line';
            output.appendChild(buffer.lineEl);
        }

        // Insert/overwrite at cursor position
        if (buffer.cursorPos >= buffer.currentLine.length) {
            // Append at end
            buffer.currentLine += ch;
        } else {
            // Overwrite mode (typical for terminal)
            buffer.currentLine =
                buffer.currentLine.slice(0, buffer.cursorPos) +
                ch +
                buffer.currentLine.slice(buffer.cursorPos + 1);
        }

        buffer.cursorPos++;
        this.updateLineDisplay(buffer, output, renderState);
    }

    /**
     * Update the DOM element displaying the current line
     */
    updateLineDisplay(buffer, output, renderState) {
        if (!buffer.lineEl) {
            buffer.lineEl = document.createElement('div');
            buffer.lineEl.className = 'terminal-line';
            output.appendChild(buffer.lineEl);
        }
        if (renderState?.deferRender) {
            renderState.needsRender = true;
            return;
        }
        buffer.lineEl.textContent = buffer.currentLine;
    }

    /**
     * Flush deferred line updates
     */
    flushLineDisplay(buffer, output, renderState) {
        if (!renderState?.deferRender || !renderState.needsRender) return;
        renderState.needsRender = false;
        if (!buffer.lineEl) return;
        buffer.lineEl.textContent = buffer.currentLine;
    }

    /**
     * Commit the current line (on newline) and prepare for next line
     */
    commitCurrentLine(buffer, output, tab, renderState) {
        // Don't commit empty lines that are just prompts
        const lineText = buffer.currentLine.trim();

        // Drop stray lone prompts
        if (buffer.lineEl && lineText.match(/^[%$#>❯»]\s*$/)) {
            buffer.lineEl.remove();
            buffer.lineEl = null;
            buffer.currentLine = '';
            buffer.cursorPos = 0;
            if (renderState) {
                renderState.needsRender = false;
            }
            return;
        }

        this.flushLineDisplay(buffer, output, renderState);

        // Reset for next line
        buffer.lineEl = null;
        buffer.currentLine = '';
        buffer.cursorPos = 0;
    }

    getTabLineBuffer(tabId) {
        if (!this.tabLineBuffers[tabId]) {
            this.tabLineBuffers[tabId] = { currentLine: '', cursorPos: 0, lineEl: null };
        }
        return this.tabLineBuffers[tabId];
    }

    clearCursorsForTab(tabId) {
        document.querySelectorAll(`#terminalOutput-${tabId} .terminal-cursor`).forEach(el => el.remove());
    }

    applyCursorToActiveTab(skipClear = false) {
        if (this.shouldUseXtermForTab(this.activeTabId)) return;
        const tabId = this.activeTabId;
        const buffer = this.getTabLineBuffer(tabId);
        if (!buffer.lineEl) return;
        if (!skipClear) {
            this.clearCursorsForTab(tabId);
        }

        // Create text nodes for content before and after cursor
        const beforeCursor = buffer.currentLine.slice(0, buffer.cursorPos);
        const charAtCursor = buffer.currentLine.charAt(buffer.cursorPos) || ' ';
        const afterCursor = buffer.currentLine.slice(buffer.cursorPos + 1);

        // Clear and rebuild line with cursor
        buffer.lineEl.textContent = '';

        if (beforeCursor) {
            buffer.lineEl.appendChild(document.createTextNode(beforeCursor));
        }

        const cursorEl = document.createElement('span');
        cursorEl.className = 'terminal-cursor';
        cursorEl.textContent = charAtCursor;
        buffer.lineEl.appendChild(cursorEl);

        if (afterCursor) {
            buffer.lineEl.appendChild(document.createTextNode(afterCursor));
        }
    }

    // sanitizeChunk is no longer needed - escape sequence handling is done in processTerminalChunk

    renderWelcomeTab() {
        const body = document.getElementById(`terminalBody-${this.welcomeTabId}`);
        const output = document.getElementById(`terminalOutput-${this.welcomeTabId}`);
        if (!output) return;

        const usingWelcomeXterm = this.shouldUseXtermForTab(this.welcomeTabId);
        if (usingWelcomeXterm) {
            if (output.dataset.rendered === 'welcome-xterm' && this.getXtermHostForTab(this.welcomeTabId)) {
                return;
            }
            body?.classList.add('terminal-body-xterm', 'terminal-body-xterm-welcome');
            output.classList.add('terminal-output-xterm', 'terminal-output-welcome-xterm');
        } else if (output.dataset.rendered === 'welcome') {
            return;
        } else {
            body?.classList.remove('terminal-body-xterm', 'terminal-body-xterm-welcome');
            output.classList.remove('terminal-output-xterm', 'terminal-output-welcome-xterm');
        }

        const username = this.platformInfo?.username || 'User';
        const hostname = this.platformInfo?.hostname || 'localhost';
        const shell = this.platformInfo?.shell || 'shell';
        const home = this.platformInfo?.home_dir || '~';

        output.dataset.rendered = usingWelcomeXterm ? 'welcome-xterm' : 'welcome';
        output.innerHTML = `
            <div class="terminal-welcome-shell">
                <div class="terminal-welcome">
                    <div class="welcome-header">
                        <div class="welcome-badge">Welcome to HybridCipher</div>
                        <div class="welcome-meta">
                            <span class="meta-item">${username}@${hostname}</span>
                            <span class="meta-separator">•</span>
                            <span class="meta-item">Shell: ${shell}</span>
                            <span class="meta-separator">•</span>
                            <span class="meta-item">Home: ${home}</span>
                        </div>
                    </div>
                    <div class="welcome-hero">
                        <div class="welcome-logo-card">
                            <img src="logo.png" alt="HybridCipher Logo">
                        </div>
                        <div class="welcome-copy">
                            <div class="welcome-eyebrow">Encrypted CLI workspace</div>
                            <div class="welcome-headline">Operate safely with HybridCipher</div>
                            <p class="welcome-text">
                                Run coverage and mount commands directly inside your secure terminal.
                                Each action opens a fresh tab, so logs stay organized and auditable.
                            </p>
                        </div>
                    </div>
                    <div class="welcome-grid">
                        <div class="welcome-card">
                            <div class="card-title">Quick start</div>
                            <ul class="welcome-steps">
                                <li><span class="step-badge">1</span>Right-click a folder → choose <strong>Mount</strong> or a coverage action.</li>
                                <li><span class="step-badge">2</span>Each CLI runs in its own tab for clarity.</li>
                                <li><span class="step-badge">3</span>Use the prompt below for custom commands.</li>
                            </ul>
                        </div>
                        <div class="welcome-card">
                            <div class="card-title">Shortcuts</div>
                            <div class="welcome-shortcuts">
                                <span class="shortcut"><kbd>↑</kbd><kbd>↓</kbd> history</span>
                                <span class="shortcut"><code>clear</code> reset view</span>
                                <span class="shortcut">Tabs isolate CLI logs</span>
                            </div>
                        </div>
                    </div>
                </div>
                ${usingWelcomeXterm ? `
                    <div class="welcome-card terminal-welcome-terminal-card">
                        <div class="card-title">Interactive terminal</div>
                        <p class="terminal-welcome-terminal-copy">
                            This welcome tab keeps a live xterm session attached so cursor handling, selection, and multiline redraws match every other terminal tab.
                        </p>
                        <div class="terminal-welcome-terminal">
                            <div class="terminal-xterm-host terminal-welcome-xterm-host"></div>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;

        this.scrollTerminalToBottom(this.welcomeTabId);
    }

    clearTerminalOutput(tabId = this.activeTabId) {
        if (this.shouldUseXtermForTab(tabId)) {
            const term = this.getXtermForTab(tabId);
            if (term) {
                term.clear();
            } else if (!this.isWelcomeTab(tabId)) {
                const output = document.getElementById(`terminalOutput-${tabId}`);
                if (output) {
                    output.innerHTML = '';
                }
            } else {
                this.renderWelcomeTab();
            }
            return;
        }

        const output = document.getElementById(`terminalOutput-${tabId}`);
        if (output) {
            output.innerHTML = '';
            delete output.dataset.rendered;
        }
        this.tabLineBuffers[tabId] = { currentLine: '', cursorPos: 0, lineEl: null };
        this.scrollTerminalToBottom(tabId);
    }

    getTerminalPrompt() {
        const cwd = this.getTerminalCwd();
        const displayCwd = cwd ? this.basename(cwd) : '~';

        if (!this.platformInfo) {
            return `${displayCwd} $ `;
        }

        const { os_type, username, hostname, shell } = this.platformInfo;

        switch (os_type) {
            case 'macos':
                // macOS zsh style: user@hostname ~ %
                return `${username}@${hostname} ${displayCwd} % `;
            case 'windows':
                // Windows PowerShell style: PS C:\Users\user>
                if (shell === 'powershell') {
                    const winPath = cwd ? cwd.replace(/\//g, '\\') : 'C:\\Users\\' + username;
                    return `PS ${winPath}> `;
                }
                // CMD style: C:\Users\user>
                return `${cwd || 'C:\\Users\\' + username}> `;
            case 'linux':
            default:
                // Linux bash style: user@hostname:~$
                return `${username}@${hostname}:${displayCwd}$ `;
        }
    }

    getTerminalTitle() {
        return getEmbeddedTerminalHeaderTitleValue();
    }

    // ========================================================================
    // Terminal Tab Management
    // ========================================================================

    updateTerminalTabControls() {
        const tabsContainer = document.getElementById('terminalTabs');
        if (!tabsContainer) return;

        const isSingleTab = this.terminalTabs.length <= 1;
        tabsContainer.classList.toggle('single-tab', isSingleTab);
    }

    async createTerminalTab() {
        const tabId = this.nextTabId++;
        const newTab = {
            id: tabId,
            title: 'Terminal',
            history: [],
            historyIndex: -1,
            output: [],
            sessionId: null
        };
        this.terminalTabs.push(newTab);
        this.tabLineBuffers[tabId] = { currentLine: '', cursorPos: 0, lineEl: null };

        // Create tab element
        const tabsContainer = document.getElementById('terminalTabs');
        const newTabBtn = document.getElementById('newTabBtn');
        const tabEl = document.createElement('div');
        tabEl.className = 'terminal-tab';
        tabEl.setAttribute('data-tab-id', tabId);
        tabEl.innerHTML = `
            <span class="tab-title">Terminal</span>
            <button class="tab-close" title="Close tab">×</button>
        `;
        tabsContainer.insertBefore(tabEl, newTabBtn);
        this.updateTerminalTabControls();

        // Create tab pane
        const tabContent = document.getElementById('terminalTabContent');
        const paneEl = document.createElement('div');
        paneEl.className = 'terminal-tab-pane';
        paneEl.setAttribute('data-tab-id', tabId);
        paneEl.innerHTML = `
            <div class="terminal-body" id="terminalBody-${tabId}" tabindex="0">
                <div class="terminal-output" id="terminalOutput-${tabId}"></div>
            </div>
        `;
        tabContent.appendChild(paneEl);

        // Wire up key handling for this tab body
        const newBody = paneEl.querySelector('.terminal-body');
        this.bindTerminalBodyEvents(newBody);

        // Switch to the new tab
        this.switchToTab(tabId);

        // Start PTY session after the tab is active and xterm is visible/focused.
        await this.startTerminalSessionForTab(tabId);

        // Welcome message is handled by ensureTerminalWelcome() for both xterm and fallback mode.
    }

    switchToTab(tabId) {
        this.activeTabId = tabId;

        // Update tab visual state
        document.querySelectorAll('.terminal-tab').forEach(tab => {
            tab.classList.toggle('active', parseInt(tab.dataset.tabId) === tabId);
        });

        // Update pane visibility
        document.querySelectorAll('.terminal-tab-pane').forEach(pane => {
            pane.classList.toggle('active', parseInt(pane.dataset.tabId) === tabId);
        });

        // Restore history state for this tab
        const tab = this.terminalTabs.find(t => t.id === tabId);
        if (tab) {
            this.terminalHistory = tab.history;
            this.terminalHistoryIndex = tab.historyIndex;
        }

        // Focus input
        this.updateTerminalPromptSymbol();
        if (this.shouldUseXtermForTab(tabId)) {
            this.ensureXtermForTab(tabId);
            this.fitActiveXterm();
            this.focusTerminalArea(tabId);
        } else {
            this.focusTerminalArea(tabId);
            this.applyCursorToActiveTab();
        }
        this.ensureTerminalWelcome();
        this.startTerminalSessionForTab(tabId);
    }

    closeTerminalTab(tabId) {
        if (this.terminalTabs.length <= 1) {
            this.updateTerminalTabControls();
            return;
        }

        const tabIndex = this.terminalTabs.findIndex(t => t.id === tabId);
        if (tabIndex === -1) return;

        // Remove from state
        const [removed] = this.terminalTabs.splice(tabIndex, 1);

        // Remove DOM elements
        document.querySelector(`.terminal-tab[data-tab-id="${tabId}"]`)?.remove();
        document.querySelector(`.terminal-tab-pane[data-tab-id="${tabId}"]`)?.remove();

        // Close PTY session
        if (removed?.sessionId) {
            invoke('close_terminal_session', { sessionId: removed.sessionId }).catch(() => { });
            this.clearTerminalRenderQueue(removed.sessionId);
        }

        // Drop buffer
        delete this.tabLineBuffers[tabId];
        this.disposeXtermForTab(tabId);
        delete this.xtermInputBufferByTab[tabId];
        delete this.startingTerminalSessionByTab[tabId];
        delete this.welcomeMessageShownByTab[tabId];

        // If we closed the active tab, switch to another
        if (this.activeTabId === tabId) {
            const newActiveTab = this.terminalTabs[Math.max(0, tabIndex - 1)];
            this.switchToTab(newActiveTab.id);
        }

        this.updateTerminalTabControls();
    }

    handleTabClick(e) {
        const tab = e.target.closest('.terminal-tab');
        const closeBtn = e.target.closest('.tab-close');

        if (closeBtn && tab) {
            e.stopPropagation();
            const tabId = parseInt(tab.dataset.tabId);
            this.closeTerminalTab(tabId);
        } else if (tab) {
            const tabId = parseInt(tab.dataset.tabId);
            this.switchToTab(tabId);
        }
    }

    handleTerminalTabContextMenu(event) {
        const tab = event.target.closest('.terminal-tab');
        if (!tab) return;
        event.preventDefault();
        event.stopPropagation();
        const tabId = parseInt(tab.dataset.tabId);
        if (!Number.isFinite(tabId)) return;
        this.showTerminalTabContextMenu(event, tabId);
    }

    showTerminalTabContextMenu(event, tabId) {
        document.querySelectorAll('.terminal-context-menu').forEach(menu => menu.remove());
        document.querySelectorAll('.terminal-tab-context-backdrop').forEach(backdrop => backdrop.remove());

        const menu = document.createElement('div');
        const backdrop = document.createElement('div');
        backdrop.className = 'terminal-tab-context-backdrop';
        backdrop.style.position = 'fixed';
        backdrop.style.left = '0';
        backdrop.style.top = '0';
        backdrop.style.width = '100%';
        backdrop.style.height = '100%';
        backdrop.style.zIndex = '9999';
        backdrop.style.background = 'transparent';
        backdrop.style.pointerEvents = 'none';
        menu.className = 'terminal-context-menu';
        menu.style.position = 'fixed';
        menu.style.left = `${event.clientX}px`;
        menu.style.top = `${event.clientY}px`;
        menu.style.background = 'var(--bg-elevated)';
        menu.style.border = '1px solid var(--border)';
        menu.style.borderRadius = 'var(--radius-md)';
        menu.style.padding = '4px';
        menu.style.zIndex = '10000';
        menu.style.boxShadow = 'var(--shadow-lg)';
        menu.style.minWidth = '160px';

        const canClose = this.terminalTabs.length > 1;
        const canCloseOthers = this.terminalTabs.length > 1;

        const onKeydown = (e) => {
            if (e.key === 'Escape') {
                cleanup();
            }
        };

        const onPointerDown = (e) => {
            if (menu.contains(e.target)) {
                return;
            }
            cleanup();
        };

        const cleanup = () => {
            menu.remove();
            backdrop.remove();
            document.removeEventListener('keydown', onKeydown);
            document.removeEventListener('pointerdown', onPointerDown, true);
        };

        const addItem = (label, onClick, disabled = false) => {
            const item = document.createElement('div');
            item.className = 'context-menu-item';
            item.textContent = label;
            item.style.padding = '8px 12px';
            item.style.borderRadius = 'var(--radius-sm)';
            if (disabled) {
                item.style.opacity = '0.5';
                item.style.cursor = 'not-allowed';
            } else {
                item.style.cursor = 'pointer';
                item.addEventListener('mouseenter', () => {
                    item.style.background = 'rgba(255, 255, 255, 0.1)';
                });
                item.addEventListener('mouseleave', () => {
                    item.style.background = 'transparent';
                });
                item.addEventListener('click', () => {
                    onClick();
                    cleanup();
                });
            }
            menu.appendChild(item);
        };

        addItem('Close', () => this.closeTerminalTab(tabId), !canClose);
        addItem('Close others', () => this.closeOtherTerminalTabs(tabId), !canCloseOthers);
        addItem('Close all', () => this.resetTerminalTabsToWelcome(), false);

        document.body.appendChild(backdrop);
        document.body.appendChild(menu);

        // Keep menu within viewport
        const menuRect = menu.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        let left = event.clientX;
        let top = event.clientY;
        if (left + menuRect.width > viewportWidth) {
            left = viewportWidth - menuRect.width - 10;
        }
        if (top + menuRect.height > viewportHeight) {
            top = viewportHeight - menuRect.height - 10;
        }
        menu.style.left = `${Math.max(10, left)}px`;
        menu.style.top = `${Math.max(10, top)}px`;

        document.addEventListener('keydown', onKeydown);
        document.addEventListener('pointerdown', onPointerDown, true);
    }

    closeOtherTerminalTabs(tabId) {
        const toClose = this.terminalTabs
            .filter(tab => tab.id !== tabId)
            .map(tab => tab.id);
        toClose.forEach(id => this.closeTerminalTab(id));
    }

    resetTerminalTabsToWelcome() {
        this.terminalTabs.forEach(tab => {
            if (tab.sessionId) {
                invoke('close_terminal_session', { sessionId: tab.sessionId }).catch(() => { });
                this.clearTerminalRenderQueue(tab.sessionId);
            }
            this.disposeXtermForTab(tab.id);
        });

        this.terminalTabs = [{
            id: 1,
            title: 'Welcome',
            history: [],
            historyIndex: -1,
            output: [],
            sessionId: null
        }];
        this.activeTabId = 1;
        this.welcomeTabId = 1;
        this.nextTabId = 2;
        this.terminalHistory = [];
        this.terminalHistoryIndex = -1;
        this.tabLineBuffers = { 1: { currentLine: '', cursorPos: 0, lineEl: null } };
        this.xtermByTabId = {};
        this.xtermFitByTabId = {};
        this.xtermResizeObserverByTab = {};
        this.xtermDiagnosticsAttachedByTab = {};
        this.xtermDiagnosticLastEventAt = {};
        this.pendingTerminalDataByTab = {};
        this.startingTerminalSessionByTab = {};
        this.welcomeMessageShownByTab = {};

        const tabsContainer = document.getElementById('terminalTabs');
        const newTabBtn = document.getElementById('newTabBtn');
        if (tabsContainer && newTabBtn) {
            tabsContainer.querySelectorAll('.terminal-tab').forEach(el => el.remove());
            const welcomeTab = document.createElement('div');
            welcomeTab.className = 'terminal-tab active';
            welcomeTab.setAttribute('data-tab-id', '1');
            welcomeTab.innerHTML = `
                <span class="tab-title">Welcome</span>
                <button class="tab-close" title="Close tab">×</button>
            `;
            tabsContainer.insertBefore(welcomeTab, newTabBtn);
        }

        const tabContent = document.getElementById('terminalTabContent');
        if (tabContent) {
            tabContent.innerHTML = '';
            const paneEl = document.createElement('div');
            paneEl.className = 'terminal-tab-pane active';
            paneEl.setAttribute('data-tab-id', '1');
            paneEl.innerHTML = `
                <div class="terminal-body" id="terminalBody-1" tabindex="0">
                    <div class="terminal-output" id="terminalOutput-1"></div>
                </div>
            `;
            tabContent.appendChild(paneEl);
            const newBody = paneEl.querySelector('.terminal-body');
            this.bindTerminalBodyEvents(newBody);
            if (this.shouldUseXtermForTab(1)) {
                this.ensureXtermForTab(1);
            }
        }

        this.updateTerminalTabControls();
        this.switchToTab(1);
    }

    updateActiveTabTitle(title) {
        if (this.activeTabId === this.welcomeTabId) {
            return;
        }
        const tab = this.terminalTabs.find(t => t.id === this.activeTabId);
        if (tab) {
            // Use last command or truncate if too long
            const displayTitle = title.length > 20 ? title.substring(0, 20) + '...' : title;
            tab.title = displayTitle;

            const tabEl = document.querySelector(`.terminal-tab[data-tab-id="${this.activeTabId}"] .tab-title`);
            if (tabEl) {
                tabEl.textContent = displayTitle;
            }
        }
    }

    // ========================================================================
    // Terminal Resize
    // ========================================================================

    setupTerminalResize() {
        const handle = document.getElementById('terminalResizeHandle');
        const container = document.getElementById('terminalContainer');

        if (!handle || !container) return;

        let startX = 0;
        let startWidth = 0;
        let isDragging = false;

        const onMouseDown = (e) => {
            isDragging = true;
            startX = e.clientX;
            startWidth = container.offsetWidth;
            handle.classList.add('dragging');
            document.body.style.cursor = 'ew-resize';
            document.body.style.userSelect = 'none';
            e.preventDefault();
        };

        const onMouseMove = (e) => {
            if (!isDragging) return;

            // Dragging left increases width, dragging right decreases
            const deltaX = startX - e.clientX;
            const mainContent = document.getElementById('mainContent');
            const mainContentWidth = mainContent ? mainContent.offsetWidth : window.innerWidth;
            const newWidth = Math.max(300, Math.min(mainContentWidth - 200, startWidth + deltaX));
            container.style.width = `${newWidth}px`;
            container.style.flex = `0 0 ${newWidth}px`;
            if (this.shouldUseXtermForTab(this.activeTabId)) {
                this.fitActiveXterm();
            }
        };

        const onMouseUp = () => {
            if (isDragging) {
                isDragging = false;
                handle.classList.remove('dragging');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
                if (this.shouldUseXtermForTab(this.activeTabId)) {
                    this.fitActiveXterm();
                }
            }
        };

        handle.addEventListener('mousedown', onMouseDown);
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
        window.addEventListener('resize', () => {
            if (this.shouldUseXtermForTab(this.activeTabId)) {
                this.fitActiveXterm();
            }
        });
    }

    toggleTerminal() {
        if (this.activeWorkspaceView === 'home') {
            this.showTerminalView();
            return;
        }

        this.terminalVisible = !this.terminalVisible;
        if (this.terminalVisible) {
            this.showTerminalView();
        } else {
            this.showFileBrowserView();
            if (this.isRegisterOverlay) {
                this.closeRegisterTerminalOverlay();
            }
        }
    }

    getTerminalWelcome() {
        if (!this.platformInfo) {
            return 'Terminal ready';
        }
        const { os_type, os_name, shell } = this.platformInfo;
        switch (os_type) {
            case 'macos':
                return '';
            case 'windows':
                return shell === 'powershell'
                    ? `Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nTry the new cross-platform PowerShell https://aka.ms/pscore6`
                    : `Microsoft Windows [Version 10.0]\n(c) Microsoft Corporation. All rights reserved.`;
            case 'linux':
            default:
                return `Welcome to ${os_name}\nType 'help' for available commands.`;
        }
    }

    updateTerminalHeader() {
        const titleSpan = document.getElementById('terminalHeaderTitle');
        if (titleSpan) {
            titleSpan.textContent = this.getTerminalTitle();
        }
    }

    updateTerminalPromptSymbol() {
        const prompt = this.getTerminalPrompt();
        document.querySelectorAll('.terminal-prompt').forEach(el => {
            el.textContent = prompt;
        });
    }

    updateTerminalCwdDisplay() {
        const cwd = this.getTerminalCwd();
        this.terminalCwd = cwd;
        const el = document.getElementById('terminalCwdDisplay');
        if (el) {
            // Update status bar with platform-aware path display
            if (this.platformInfo?.os_type === 'windows') {
                const winPath = (cwd || '~').replace(/\//g, '\\');
                el.textContent = winPath;
            } else {
                el.textContent = cwd || '~';
            }
        }
    }

    getTerminalCwd() {
        // Priority: mount path > selected folder > home directory
        if (this.currentMountPath) return this.currentMountPath;
        // Default to system home directory (do not override with selected folder)
        if (this.platformInfo?.home_dir) {
            return this.platformInfo.home_dir;
        }
        // Fallback to ~ if platform info not available
        return '~';
    }

    appendTerminalLine(text, variant = '') {
        if (this.shouldUseXtermForTab(this.activeTabId)) {
            const term = this.getXtermForTab(this.activeTabId) || this.ensureXtermForTab(this.activeTabId);
            if (term) {
                const prefix = variant === 'error' ? '[error] ' : '';
                term.writeln(`${prefix}${text}`);
                return;
            }
        }

        // Use the active tab's output container
        const output = this.getActiveTerminalOutput();
        if (!output) return;
        const line = document.createElement('div');
        line.className = `terminal-line${variant ? ` ${variant}` : ''}`;
        line.textContent = text;
        output.appendChild(line);
        this.scrollTerminalToBottom();
    }

    scrollTerminalToBottom(tabId = this.activeTabId) {
        const body = document.getElementById(`terminalBody-${tabId}`);
        if (body) {
            body.scrollTop = body.scrollHeight;
        }
    }

    handleTerminalHistory(event) {
        const input = event.target;
        if (!input) return;

        if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (this.terminalHistory.length === 0) return;
            if (this.terminalHistoryIndex < this.terminalHistory.length - 1) {
                this.terminalHistoryIndex += 1;
            }
            const cmd = this.terminalHistory[this.terminalHistory.length - 1 - this.terminalHistoryIndex];
            input.value = cmd || '';
        } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (this.terminalHistoryIndex > 0) {
                this.terminalHistoryIndex -= 1;
                const cmd = this.terminalHistory[this.terminalHistory.length - 1 - this.terminalHistoryIndex];
                input.value = cmd || '';
            } else {
                this.terminalHistoryIndex = -1;
                input.value = '';
            }
        }
    }

    async handleTerminalSubmit(event) {
        event.preventDefault();
        const input = event?.target?.closest('input') || this.getActiveTerminalInput();
        if (!input) return;

        // Keystrokes are streamed directly to PTY; Enter handling is in handleTerminalKey.
    }

    async runTerminalCommand(command, skipMount = false) {
        // Mount if we have a selected folder so cwd resolves to decrypted view
        // Skip mounting for coverage commands as they operate on original paths
        if (!skipMount && !this.currentMountPath && this.selectedFolder) {
            await this.mountFolderFromContext(this.selectedFolder);
        }

        // PTY handles command submission directly through keystream; nothing to do here.
    }

    // Execute command directly without populating input field or mounting
    async executeCommandDirectly(command, skipMount = true, options = {}) {
        // Show terminal if it is not the active workspace view
        if (this.activeWorkspaceView !== 'terminal') {
            this.showTerminalView();
        }

        if (await this.handleRestrictedIndividualCliCommand(command, { clearInput: false })) {
            return null;
        }

        // Wait a bit for terminal to render
        await new Promise(resolve => setTimeout(resolve, 100));

        const cwd = this.getTerminalCwd();
        this.updateTerminalCwdDisplay();

        if (command === 'clear' || command === 'reset') {
            this.clearTerminalOutput();
            this.updateActiveTabTitle(command);
            return;
        }

        if (this.shouldPreflightSessionForCommand(command)) {
            const sessionInfo = await this.ensureSessionReady({
                silent: false,
                verifyCli: true,
                staleMessage: 'Session expired. Please login again.'
            });
            if (!sessionInfo) {
                return null;
            }
        }

        // Update tab title with the command
        this.updateActiveTabTitle(command);

        // Ensure PTY session exists and send command to it
        let targetTab = this.getActiveTab();
        if (targetTab && this.isWelcomeTab(targetTab.id)) {
            await this.createTerminalTab();
            targetTab = this.getActiveTab();
        }

        if (!targetTab?.sessionId) {
            await this.startTerminalSessionForTab(targetTab?.id);
        }
        const sessionId = targetTab?.sessionId;
        if (sessionId) {
            try {
                await invoke('write_terminal_stdin', { sessionId, data: `${command}\r` });
            } catch (error) {
                console.error('Terminal PTY write error:', error);
                this.appendTerminalLine(`Error: ${error}`, 'error');
            }
        } else {
            this.appendTerminalLine('No terminal session available', 'error');
        }

        if (options.returnSessionId) {
            return sessionId;
        }
    }

    // ========================================================================
    // Coverage CLI Command Integration
    // ========================================================================

    async getCliBinaryPath() {
        if (this.cachedCliPath) {
            return this.cachedCliPath;
        }

        try {
            const result = await invoke('get_cli_binary_path');
            if (result.success && result.data) {
                this.cachedCliPath = result.data;
                return this.cachedCliPath;
            } else {
                throw new Error(result.error || 'Failed to get CLI path');
            }
        } catch (error) {
            console.error('Failed to get CLI binary path:', error);
            throw error;
        }
    }


    async showConfirmDialog(title, message) {
        const confirmed = await this.showActionPrompt(title, message, {
            primaryLabel: 'Proceed',
            secondaryLabel: 'Cancel'
        });
        return confirmed === true;
    }

    async executeCoverageCommand(action, folder, options = {}) {
        const { skipPreConfirm = false } = options;
        // Handle both object with .path property and string path
        const folderPath = typeof folder === 'string' ? folder : (folder?.path || null);
        if (!folderPath) {
            this.showNotification('No folder selected', 'error');
            return false;
        }
        try {
            await this.getCliBinaryPath();
        } catch (error) {
            this.showNotification('Failed to locate hybridcipher CLI. Please build it with "cargo build --release --bin hybridcipher"', 'error');
            return false;
        }

        let command;
        let needsConfirm = false;
        switch (action) {
            case 'enroll':
                command = `hybridcipher coverage enroll ${this.quoteCliArg(folderPath)} --yes`;
                break;
            case 'unenroll':
                // Show confirmation dialog first
                if (!skipPreConfirm) {
                    const confirmed = await this.showConfirmDialog(
                        'Remove Protected Folder',
                        `This will decrypt all files in this folder and stop protecting it:\n\n"${folderPath}"\n\nDo you want to proceed?`
                    );
                    if (!confirmed) {
                        return false;
                    }
                }
                command = `hybridcipher coverage unenroll ${this.quoteCliArg(folderPath)} --yes`;
                break;
            case 'coverage-scan':
                command = `hybridcipher coverage scan --root ${this.quoteCliArg(folderPath)}`;
                break;
            case 'coverage-status':
                command = `hybridcipher coverage status --root ${this.quoteCliArg(folderPath)}`;
                break;
            default:
                this.showNotification(`Unknown action: ${action}`, 'error');
                return false;
        }

        // Execute command directly (no input field population, no auto-mount)
        const sessionId = await this.executeCommandDirectly(command, true, { returnSessionId: true });
        if (action === 'enroll' || action === 'unenroll') {
            this.startCoverageCommandTracking({
                action,
                path: folderPath,
                sessionId
            });
        }

        return true;
    }

    startCoverageCommandTracking({ action, path, sessionId }) {
        if (!sessionId || !path) return;
        if (this.coverageCommandTrackers[sessionId]) {
            this.stopCoverageCommandTracking(sessionId, { finalRefresh: false });
        }

        const tracker = {
            action,
            path,
            sessionId,
            startedAt: Date.now(),
            buffer: '',
            recentLines: [],
            didShowFailure: false,
            pollTimer: null,
            pollInFlight: false
        };
        this.coverageCommandTrackers[sessionId] = tracker;
        this.pollCoverageCommandList(tracker);
    }

    async pollCoverageCommandList(tracker) {
        if (!tracker || this.coverageCommandTrackers[tracker.sessionId] !== tracker) return;
        if (tracker.pollInFlight) return;
        tracker.pollInFlight = true;
        try {
            await this.loadEnrolledFolders();
        } catch (error) {
            // Keep polling on transient errors.
        } finally {
            tracker.pollInFlight = false;
        }

        if (Date.now() - tracker.startedAt > this.coverageCommandTimeoutMs) {
            this.stopCoverageCommandTracking(tracker.sessionId);
            return;
        }

        tracker.pollTimer = setTimeout(() => {
            this.pollCoverageCommandList(tracker);
        }, this.coverageCommandPollIntervalMs);
    }

    stopCoverageCommandTracking(sessionId, { finalRefresh = true } = {}) {
        const tracker = this.coverageCommandTrackers[sessionId];
        if (!tracker) return;
        if (tracker.pollTimer) {
            clearTimeout(tracker.pollTimer);
        }
        delete this.coverageCommandTrackers[sessionId];
        if (finalRefresh) {
            this.loadEnrolledFolders();
        }
    }

    handleCoverageCommandOutput(sessionId, chunk) {
        const tracker = this.coverageCommandTrackers?.[sessionId];
        if (!tracker || !chunk) return;

        tracker.buffer = `${tracker.buffer}${chunk}`.slice(-4000);
        const cleaned = this.stripAnsi(tracker.buffer).replace(/\r/g, '');
        const lines = cleaned.split('\n').map(line => line.trim()).filter(Boolean);
        tracker.recentLines = lines.slice(-25);
        const lastLine = lines[lines.length - 1] || '';

        const completionPatterns = tracker.action === 'enroll'
            ? [
                /Enrollment hydration complete/i,
                /Coverage enrollment complete/i,
                /Enrollment complete/i,
                /Initial scan complete/i,
                /Operation cancelled/i
            ]
            : [
                /Successfully unenrolled/i,
                /Unenrolled\s.+\(.*id/i,
                /Path is already missing; removed enrollment/i,
                /Operation cancelled/i
            ];

        if (completionPatterns.some(pattern => lines.some(line => pattern.test(line)))) {
            const wasCancelled = lines.some(line => /Operation cancelled/i.test(line));
            if (!wasCancelled && tracker.action === 'enroll') {
                this.showNotification('Folder protected now with post-quantum encryption.', 'success');
            }
            this.stopCoverageCommandTracking(sessionId);
            return;
        }

        const errorLine = lines.find(line =>
            /(?:^|\b)(error|failed|denied|unauthorized|forbidden|cancelled)\b/i.test(line)
        );
        if (errorLine) {
            this.handleCoverageCommandFailure(tracker, lines);
            this.stopCoverageCommandTracking(sessionId);
            return;
        }

        if (this.isLikelyShellPromptLine(lastLine)) {
            this.handleCoverageCommandFailure(tracker, lines);
            this.stopCoverageCommandTracking(sessionId);
        }
    }

    handleCoverageCommandFailure(tracker, lines = tracker?.recentLines || []) {
        if (!tracker || tracker.didShowFailure) return;
        tracker.didShowFailure = true;

        if (tracker.action === 'enroll') {
            const failure = classifyEnrollmentFailureValue({
                folderPath: tracker.path,
                lines,
            });

            if (failure.kind === 'already-enrolled') {
                this.showNotification(`${failure.title}. ${failure.detail}`, 'info');
                this.loadEnrolledFolders({ suppressErrorNotification: true }).catch(() => { });
                return;
            }

            this.showNotification(`${failure.title}. ${failure.detail}`, 'error');
            this.showTerminalView();
            this.focusTerminalArea();
            return;
        }

        if (tracker.action === 'unenroll') {
            this.showNotification(
                'HybridCipher could not remove this protected folder. Review the terminal output and retry.',
                'error'
            );
            this.showTerminalView();
            this.focusTerminalArea();
        }
    }

    queuePromptResponses(sessionId, responses, { initialDelay = 600, interval = 700 } = {}) {
        if (!Array.isArray(responses) || responses.length === 0) return;
        responses.forEach((response, index) => {
            const delay = initialDelay + index * interval;
            setTimeout(() => {
                if (sessionId) {
                    const line = /\r|\n/.test(response) ? response : `${response}\r`;
                    this.sendInputToSession(sessionId, line);
                } else {
                    const line = /\r|\n/.test(response) ? response : `${response}\r`;
                    this.sendInputToPty(line);
                }
            }, delay);
        });
    }

    async sendInputToSession(sessionId, data) {
        if (!sessionId) return;
        try {
            await invoke('write_terminal_stdin', { sessionId, data });
        } catch (error) {
            console.error('Terminal PTY write error:', error);
            this.appendTerminalLine(`Error: ${error}`, 'error');
        }
    }

    suppressPromptEcho(sessionId, count = 1, { durationMs = 8000 } = {}) {
        if (!sessionId || count <= 0) return;
        const current = this.promptEchoSuppress[sessionId] || 0;
        this.promptEchoSuppress[sessionId] = current + count;
        setTimeout(() => {
            const remaining = this.promptEchoSuppress[sessionId];
            if (!remaining || remaining <= 0) {
                delete this.promptEchoSuppress[sessionId];
            }
        }, durationMs);
    }

    suppressPromptEchoFromChunk(sessionId, chunk) {
        let remaining = this.promptEchoSuppress?.[sessionId] || 0;
        if (remaining <= 0) {
            return chunk;
        }

        const lines = chunk.split('\n');
        const kept = [];
        let removed = 0;

        for (const line of lines) {
            const trimmed = line.replace(/\r/g, '').trim();
            if (remaining > 0 && trimmed.length === 1 && /[yn]/i.test(trimmed)) {
                remaining -= 1;
                removed += 1;
                continue;
            }
            if (remaining > 0 && /\s*y\s*$/i.test(line)) {
                const cleaned = line.replace(/\s*y\s*$/i, '');
                if (this.isLikelyShellPromptLine(cleaned)) {
                    remaining -= 1;
                    removed += 1;
                    if (cleaned.trim()) {
                        kept.push(cleaned);
                    }
                    continue;
                }
            }
            kept.push(line);
        }

        if (removed > 0) {
            if (remaining <= 0) {
                delete this.promptEchoSuppress[sessionId];
            } else {
                this.promptEchoSuppress[sessionId] = remaining;
            }
        }

        return kept.join('\n');
    }

    isLikelyShellPromptLine(line) {
        if (!line) return false;
        const raw = line.replace(/\r/g, '');
        if (!raw.trim()) return false;

        // Fast path: prompt typically ends with one of these glyphs plus optional trailing space.
        if (/[#$%>❯»]\s$/.test(raw)) {
            return true;
        }

        const trimmed = raw.trimEnd();
        if (!/[#$%>❯»]$/.test(trimmed)) {
            return false;
        }

        // Heuristics for common prompts: user@host, paths, or PowerShell.
        if (/^PS\s.+>$/.test(trimmed)) return true;
        if (/[A-Za-z0-9_.-]+@[^\\s]+/.test(trimmed)) return true;
        if (/[~\\/].*[$#%>❯»]$/.test(trimmed)) return true;
        if (/^[A-Za-z]:[\\/].*[$#%>❯»]$/.test(trimmed)) return true;

        return false;
    }

    registerRekeyPromptResponder(sessionId) {
        if (!sessionId) return;
        this.promptResponders[sessionId] = {
            type: 'rekey',
            stage: 'await_prompt1',
            answered: {
                impact: false,
                migrate: false
            },
            buffer: ''
        };
    }

    handlePromptAutoResponses(sessionId, chunk) {
        const responder = this.promptResponders?.[sessionId];
        if (!responder) return;

        responder.buffer = `${responder.buffer}${chunk}`.slice(-800);
        const buffer = this.stripAnsi(responder.buffer).replace(/\r/g, '');
        const lines = buffer.split('\n');
        const lastLineRaw = lines[lines.length - 1] || '';

        const failureLine = lines.find(line =>
            /(?:^|\b)(error|failed|denied|unauthorized|forbidden|cancelled)\b/i.test(line)
        );
        if (failureLine) {
            this.hideActionProgressModal();
            delete this.promptResponders[sessionId];
            return;
        }

        if (responder.stage !== 'prompt2_shown' && this.isLikelyShellPromptLine(lastLineRaw)) {
            this.hideActionProgressModal();
            delete this.promptResponders[sessionId];
            return;
        }

        const prompt1Line = lines.find(line =>
            /proceed with the migration to a new epoch key\?/i.test(line)
        );
        const prompt1Answered = prompt1Line ? /\b(yes|no)\b/i.test(prompt1Line) : false;

        if (responder.stage === 'await_prompt1' && prompt1Line && !prompt1Answered) {
            responder.answered.impact = true;
            this.suppressPromptEcho(sessionId, 1, { durationMs: 12000 });
            this.sendInputToSession(sessionId, 'y\r');
            responder.stage = 'await_prompt2';
            responder.buffer = '';
            return;
        }

        const prompt2Line = lines.find(line =>
            /run local coverage migration now\?/i.test(line)
        );
        const prompt2Answered = prompt2Line ? /\b(yes|no)\b/i.test(prompt2Line) : false;

        if (responder.stage === 'await_prompt2' && prompt2Line && !prompt2Answered) {
            responder.answered.migrate = true;
            responder.stage = 'prompt2_shown';
            responder.buffer = '';
            this.hideActionProgressModal();
            this.promptRekeyMigrationChoice(sessionId);
            return;
        }
    }

    async executeUnmountCommand(folder, options = {}) {
        const {
            force = false,
            suppressSuccessNotification = false,
            suppressFailureNotification = false
        } = options;
        if (!folder || !folder.root_id) {
            if (!suppressFailureNotification) {
                this.showNotification('No folder selected', 'error');
            }
            return false;
        }

        const rootId = folder.root_id;
        const sessionId = this.mountSessions[rootId];
        const syncStatus = this.getMountDetailsForRootId(rootId)?.syncStatus || null;

        // Unmount command must run as a separate process, not in the same PTY where mount is running
        // because the mount process blocks that PTY. Use the Tauri command to spawn it as a process.
        try {
            const result = await invoke('unmount_mount_by_root_id', {
                rootId: rootId,
                force
            });

            if (result.success) {
                // Poll for unmount completion - wait up to 35 seconds (unmount waits 30s for mount process)
                const maxWait = 35000; // 35 seconds
                const checkInterval = 1000; // Check every second
                let waited = 0;
                let unmounted = false;

                while (waited < maxWait) {
                    await new Promise(resolve => setTimeout(resolve, checkInterval));
                    waited += checkInterval;

                    const checkResult = await invoke('check_mount_status_by_root_id', {
                        rootId: rootId
                    });

                    if (!checkResult.success || !checkResult.data) {
                        // Mountpoint is gone, unmount succeeded
                        unmounted = true;
                        break;
                    }
                }

                if (unmounted) {
                    // Clean up session
                    if (sessionId) {
                        delete this.mountSessions[rootId];
                        await invoke('close_terminal_session', { sessionId }).catch(() => { });
                    }
                    // Reset mount-aware UI/terminal state now that the folder is gone
                    this.currentMountPath = null;
                    this.updateMountButtons(false);
                    await this.refreshActiveMounts({
                        renderFolderList: true,
                        suppressErrorNotification: true
                    });
                    this.updateTerminalCwdDisplay();
                    if (!suppressSuccessNotification) {
                        this.showNotification('Unmounted successfully', 'success');
                    }
                    return true;
                } else {
                    // Still mounted after timeout - might need manual cleanup
                    if (!suppressFailureNotification) {
                        this.showNotification('Unmount may still be in progress. Please check manually.', 'warning');
                    }
                    return false;
                }
            } else {
                if (!suppressFailureNotification) {
                    if (!force && this.hasPendingConflicts(syncStatus)) {
                        await this.openConflictCenterForFolder(folder);
                    } else if (!force && this.hasPendingRecoveryCopies(syncStatus)) {
                        await this.openRecoveryCenterForFolder(folder);
                    } else if (!force && (this.hasMountSafetyAlert(syncStatus) || /not safe to unmount|file loss/i.test(String(result.error || '')))) {
                        await this.showMountSafetyAlert(folder, result.error || '');
                    } else {
                        this.showNotification(result.error || 'Unmount failed', 'error');
                    }
                }
                return false;
            }
        } catch (error) {
            console.error('Unmount error:', error);
            if (!suppressFailureNotification) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (!force && this.hasPendingConflicts(syncStatus)) {
                    await this.openConflictCenterForFolder(folder);
                } else if (!force && this.hasPendingRecoveryCopies(syncStatus)) {
                    await this.openRecoveryCenterForFolder(folder);
                } else if (!force && this.hasMountSafetyAlert(syncStatus)) {
                    await this.showMountSafetyAlert(folder, errorMessage);
                } else {
                    this.showNotification('Unmount failed: ' + errorMessage, 'error');
                }
            }
            return false;
        }
    }

    async executeUnmountAllCommand(options = {}) {
        const {
            force = false,
            suppressSuccessNotification = false,
            suppressFailureNotification = false
        } = options;

        try {
            const result = await invoke('unmount_all_mounts', { force });
            if (!result?.success) {
                if (!suppressFailureNotification) {
                    this.showNotification(result?.error || 'Unmount all failed', 'error');
                }
                return false;
            }

            for (const sessionId of Object.values(this.mountSessions)) {
                await invoke('close_terminal_session', { sessionId }).catch(() => { });
            }
            this.mountSessions = {};
            this.currentMountPath = null;
            this.updateMountButtons(false);
            await this.refreshActiveMounts({
                renderFolderList: true,
                suppressErrorNotification: true,
                suppressRecoveryPrompt: true
            });
            this.updateTerminalCwdDisplay();
            if (!suppressSuccessNotification) {
                this.showNotification('All mounts unmounted', 'success');
            }
            return true;
        } catch (error) {
            console.error('Unmount all error:', error);
            if (!suppressFailureNotification) {
                this.showNotification('Unmount all failed: ' + error, 'error');
            }
            return false;
        }
    }

    async handleQuitRequested() {
        if (this.quitFlowInProgress) {
            return;
        }

        this.quitFlowInProgress = true;
        try {
            await this.refreshActiveMounts({
                renderFolderList: false,
                suppressErrorNotification: true,
                suppressRecoveryPrompt: true
            });
            const rootIds = Object.keys(this.activeMountDetailsByRootId || {});
            if (rootIds.length === 0) {
                await invoke('exit_application');
                return;
            }

            const decision = await this.promptUnsafeUnmountDecision({
                rootIds,
                title: 'Quit HybridCipher',
                message: 'HybridCipher will finish pending encrypted commits when possible before quitting.',
                forceLabel: 'Quit anyway'
            });
            if (decision === 'cancel') {
                return;
            }

            const force = decision === 'force';
            const unmounted = await this.executeUnmountAllCommand({
                force,
                suppressSuccessNotification: true,
                suppressFailureNotification: force
            });
            if (!unmounted && !force) {
                return;
            }

            await invoke('exit_application');
        } catch (error) {
            console.error('Quit flow failed:', error);
            this.showNotification('Quit failed: ' + error, 'error');
        } finally {
            this.quitFlowInProgress = false;
        }
    }

    basename(path) {
        if (!path) return '';
        const parts = path.split(/[/\\]/).filter(Boolean);
        return parts[parts.length - 1] || path;
    }

    // ========================================================================
    // Mount Operations
    // ========================================================================

    async mountFolder() {
        if (!this.selectedFolder) {
            this.showNotification('Please select a folder first', 'warning');
            return;
        }
        await this.mountFolderFromContext(this.selectedFolder);
    }

    createMountProgressJob(rootId, folder = null) {
        const job = {
            rootId,
            sessionId: null,
            startedAt: Date.now(),
            mode: 'foreground',
            backgroundDeadlineAt: null,
            cancelRequested: false,
            folderLabel: folder?.name || this.basename(folder?.path || rootId || 'Mounted folder'),
            folderPath: folder?.path || '',
            outputBuffer: '',
            commandError: null,
            outputClosed: false,
        };
        this.mountProgressJobs[rootId] = job;
        return job;
    }

    getMountProgressJob(rootId) {
        return this.mountProgressJobs[rootId] || null;
    }

    getMountProgressJobBySessionId(sessionId) {
        if (!sessionId) return null;
        return Object.values(this.mountProgressJobs || {})
            .find(job => job?.sessionId === sessionId) || null;
    }

    detectMountCommandError(output) {
        const cleaned = this.stripAnsi(output || '').replace(/\r/g, '').trim();
        if (!cleaned) return null;

        const lines = cleaned
            .split('\n')
            .map(line => line.trim())
            .filter(Boolean);
        const errorLine = lines.find(line =>
            !/Auto-select:.*Falling back to sync strategy/i.test(line) && (
                /not recognized as an internal or external command/i.test(line)
                || /\berror:/i.test(line)
                || /No active enrolled root/i.test(line)
                || /missing welcome/i.test(line)
            )
        );

        return errorLine || null;
    }

    handleMountSessionOutput(sessionId, chunk) {
        const job = this.getMountProgressJobBySessionId(sessionId);
        if (!job) return false;

        const text = this.stripAnsi(chunk || '');
        job.outputBuffer = `${job.outputBuffer || ''}${text}`.slice(-12000);
        if (text.includes('[session closed]')) {
            job.outputClosed = true;
        }
        job.commandError = job.commandError || this.detectMountCommandError(job.outputBuffer);
        return true;
    }

    clearMountProgressJob(rootId) {
        delete this.mountProgressJobs[rootId];
        if (this.mountProgressModalRootId === rootId) {
            this.hideMountProgressModal();
        }
    }

    startMountProgressUiTimer() {
        this.stopMountProgressUiTimer();
        this.mountProgressUiTimer = setInterval(() => {
            this.updateMountProgressModalState();
        }, 500);
    }

    stopMountProgressUiTimer() {
        if (this.mountProgressUiTimer) {
            clearInterval(this.mountProgressUiTimer);
            this.mountProgressUiTimer = null;
        }
    }

    updateMountProgressModalState() {
        if (!this.mountProgressModalRootId) return;

        const modal = document.getElementById('mountProgressModal');
        const title = document.getElementById('mountProgressModalTitle');
        const folderLabel = document.getElementById('mountProgressModalFolderLabel');
        const folderPath = document.getElementById('mountProgressModalFolderPath');
        const text = document.getElementById('mountProgressModalText');
        const hint = document.getElementById('mountProgressModalHint');
        const continueBtn = document.getElementById('mountContinueBackgroundBtn');
        const cancelBtn = document.getElementById('mountCancelBtn');
        if (!modal || !text || !hint || !continueBtn || !cancelBtn) return;

        const job = this.getMountProgressJob(this.mountProgressModalRootId);
        if (!job) return;

        const elapsedMs = Date.now() - job.startedAt;
        const canContinue = elapsedMs >= this.mountContinueEnableMs;
        const canCancel = job.mode === 'foreground' && elapsedMs >= this.mountCancelEnableMs;
        const model = buildMountProgressModelValue({
            folderLabel: job.folderLabel,
            folderPath: job.folderPath,
            elapsedMs,
            continueEnableMs: this.mountContinueEnableMs,
        });

        if (title) {
            title.textContent = model.title;
        }
        if (folderLabel) {
            folderLabel.textContent = model.folderLabel || 'Mounted folder';
        }
        if (folderPath) {
            folderPath.textContent = model.folderPath || '';
            folderPath.style.display = model.folderPath ? 'block' : 'none';
        }
        text.textContent = model.status;
        hint.textContent = model.hint;

        continueBtn.style.display = job.mode === 'foreground' ? 'inline-flex' : 'none';
        continueBtn.disabled = !canContinue;

        cancelBtn.style.display = canCancel ? 'inline-flex' : 'none';
        cancelBtn.disabled = !canCancel;
    }

    continueMountInBackground() {
        if (!this.mountProgressModalRootId) return;

        const job = this.getMountProgressJob(this.mountProgressModalRootId);
        if (!job || job.mode !== 'foreground') return;

        const elapsedMs = Date.now() - job.startedAt;
        if (elapsedMs < this.mountContinueEnableMs) return;

        job.mode = 'background';
        job.backgroundDeadlineAt = Date.now() + this.mountBackgroundTimeoutMs;
        this.hideMountProgressModal();
        this.showNotification(
            `Mount for ${job.folderLabel} continues in background. You will be notified if it succeeds or fails.`,
            'info'
        );
    }

    async requestMountCancelFromModal() {
        if (!this.mountProgressModalRootId) return;

        const job = this.getMountProgressJob(this.mountProgressModalRootId);
        if (!job || job.mode !== 'foreground') return;

        const elapsedMs = Date.now() - job.startedAt;
        if (elapsedMs < this.mountCancelEnableMs) return;

        const confirmed = await this.showConfirmDialog(
            'Cancel mount',
            'Mounting has not finished yet. Cancel this mount attempt?'
        );
        if (!confirmed) {
            return;
        }

        job.cancelRequested = true;
        await this.cleanupMountSession(job.rootId, job.sessionId);
        this.hideMountProgressModal();
        this.showNotification('Mount cancellation requested.', 'info');
    }

    async invokeWithTimeout(command, args, timeoutMs, timeoutMessage) {
        let timeoutHandle;
        try {
            return await Promise.race([
                invoke(command, args),
                new Promise((_, reject) => {
                    timeoutHandle = setTimeout(() => {
                        reject(new Error(timeoutMessage));
                    }, timeoutMs);
                })
            ]);
        } finally {
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
            }
        }
    }

    async cleanupMountSession(rootId, sessionId = null) {
        const targetSessionId = sessionId || this.mountSessions[rootId];
        if (this.mountSessions[rootId]) {
            delete this.mountSessions[rootId];
        }
        if (targetSessionId && targetSessionId !== 'native-mount') {
            await invoke('close_terminal_session', { sessionId: targetSessionId }).catch(() => { });
        }
    }

    async mountFolderFromContext(folder, { autoMountRestore = false } = {}) {
        if (!folder) {
            this.showNotification('No folder provided', 'warning');
            return false;
        }

        // Check if already mounted - if so, just open the folder
        try {
            const checkResult = await invoke('check_mount_status_by_root_id', {
                rootId: folder.root_id
            });

            if (checkResult.success && checkResult.data) {
                // Already mounted, just open it
                if (!autoMountRestore) {
                    await this.openMountInExplorer(checkResult.data.mountpoint);
                }
                return true;
            } else {
                // Not mounted - clean up any stale session entry
                if (this.mountSessions[folder.root_id]) {
                    const staleSessionId = this.mountSessions[folder.root_id];
                    delete this.mountSessions[folder.root_id];
                    // Try to close the session, but don't fail if it's already closed
                    await invoke('close_terminal_session', { sessionId: staleSessionId }).catch(() => { });
                }
            }
        } catch (error) {
            // Continue with mount process if check fails
            console.log('Mount check failed, proceeding with mount:', error);
            // Clean up stale session entry on error too
            if (this.mountSessions[folder.root_id]) {
                const staleSessionId = this.mountSessions[folder.root_id];
                delete this.mountSessions[folder.root_id];
                await invoke('close_terminal_session', { sessionId: staleSessionId }).catch(() => { });
            }
        }

        // Check if there's already a mount session for this root_id
        // Only check this if mount status check passed (meaning we're sure it's not mounted)
        if (this.mountSessions[folder.root_id]) {
            if (!autoMountRestore) {
                this.showNotification('Mount already in progress for this folder', 'info');
            }
            return false;
        }

        const mountJob = this.createMountProgressJob(folder.root_id, folder);
        this.showMountProgressModal(folder.root_id);

        try {
            this.mountSessions[folder.root_id] = 'native-mount';
            const mountResult = await this.invokeWithTimeout(
                'mount_enrolled_folder',
                { rootId: folder.root_id },
                330000,
                'Mount did not complete within timeout period'
            );
            const pollResult = mountResult?.success && mountResult.data
                ? {
                    status: 'mounted',
                    mountpoint: mountResult.data.mountpoint,
                    backend: mountResult.data.backend || 'sync',
                    fallbackReason: mountResult.data.fallback_reason || null
                }
                : {
                    status: 'failed',
                    error: mountResult?.error || 'Mount did not complete within timeout period'
                };
            const currentJob = this.getMountProgressJob(folder.root_id);
            const completedInBackground = currentJob?.mode === 'background';
            this.clearMountProgressJob(folder.root_id);
            delete this.mountSessions[folder.root_id];

            if (pollResult.status === 'mounted') {
                this.currentMountPath = pollResult.mountpoint;
                this.saveLastMountedRootId(folder.root_id);
                this.updateMountButtons(true);

                // Select the folder if not already selected
                if (!this.selectedFolder || this.selectedFolder.root_id !== folder.root_id) {
                    this.selectFolder(folder.path);
                }
                await this.refreshActiveMounts({
                    renderFolderList: true,
                    suppressErrorNotification: true
                });

                if (
                    (this.platformInfo?.os_type === 'windows' || this.platformInfo?.os_type === 'macos') &&
                    pollResult.backend === 'sync' &&
                    pollResult.fallbackReason
                ) {
                    this.showNotification(
                        `${mountJob.folderLabel} mounted with sync fallback. ${pollResult.fallbackReason}`,
                        'warning'
                    );
                }

                if (completedInBackground) {
                    this.showNotification(`${mountJob.folderLabel} mounted successfully in background.`, 'success');
                } else {
                    // Open system file explorer
                    if (!autoMountRestore) {
                        await this.openMountInExplorer(pollResult.mountpoint);
                    }
                    this.showNotification(`${mountJob.folderLabel} mounted successfully.`, 'success');
                }
                return true;
            } else if (pollResult.status === 'cancelled') {
                await this.cleanupMountSession(folder.root_id);
                this.showNotification('Mount cancelled', 'info');
                return false;
            } else if (pollResult.status === 'background_timeout') {
                await this.cleanupMountSession(folder.root_id);
                this.showNotification(buildMountTimeoutMessageValue({
                    folderLabel: mountJob.folderLabel,
                    folderPath: mountJob.folderPath,
                    inBackground: true,
                }), autoMountRestore ? 'warning' : 'error');
                return false;
            } else {
                await this.cleanupMountSession(folder.root_id);
                const fallbackError =
                    pollResult.error || 'Mount did not complete within timeout period';
                if (completedInBackground) {
                    const failureMessage = buildMountTimeoutMessageValue({
                        folderLabel: mountJob.folderLabel,
                        folderPath: mountJob.folderPath,
                        inBackground: true,
                    });
                    this.showNotification(
                        `${failureMessage} Error detail: ${fallbackError}`,
                        autoMountRestore ? 'warning' : 'error'
                    );
                } else {
                    if (autoMountRestore) {
                        this.hideMountProgressModal();
                        this.showNotification(`Auto-mount failed for ${mountJob.folderLabel}: ${fallbackError}`, 'warning');
                    } else {
                        this.showMountProgressError(fallbackError, {
                            folderLabel: mountJob.folderLabel,
                            folderPath: mountJob.folderPath,
                        });
                    }
                }
                return false;
            }
        } catch (error) {
            const currentJob = this.getMountProgressJob(folder.root_id);
            const failedInBackground = currentJob?.mode === 'background';
            const failureFolderLabel = currentJob?.folderLabel || mountJob.folderLabel;
            const failureFolderPath = currentJob?.folderPath || mountJob.folderPath;
            this.clearMountProgressJob(folder.root_id);
            console.error('Mount error:', error);
            // Clean up session on error
            if (this.mountSessions[folder.root_id]) {
                const sessionId = this.mountSessions[folder.root_id];
                await this.cleanupMountSession(folder.root_id, sessionId);
            }
            if (failedInBackground) {
                const failureMessage = buildMountTimeoutMessageValue({
                    folderLabel: failureFolderLabel,
                    folderPath: failureFolderPath,
                    inBackground: true,
                });
                this.showNotification(
                    `${failureMessage} Error detail: ${error}`,
                    autoMountRestore ? 'warning' : 'error'
                );
            } else {
                if (autoMountRestore) {
                    this.hideMountProgressModal();
                    this.showNotification(`Auto-mount failed for ${failureFolderLabel}: ${error}`, 'warning');
                } else {
                    this.showMountProgressError(`Mount failed: ${error}`, {
                        folderLabel: failureFolderLabel,
                        folderPath: failureFolderPath,
                    });
                }
            }
            return false;
        }
    }

    async pollMountState(rootId) {
        const checkInterval = 500; // Check every 500ms
        while (true) {
            const job = this.getMountProgressJob(rootId);
            if (!job) {
                return {
                    status: 'failed',
                    error: 'Mount tracking state was lost'
                };
            }

            if (job.cancelRequested) {
                return { status: 'cancelled' };
            }

            if (job.commandError) {
                return {
                    status: 'failed',
                    error: job.commandError
                };
            }

            if (job.outputClosed) {
                const { message, detail } = this.extractCliErrorMessage(
                    job.outputBuffer,
                    'Mount command exited before the folder became available.'
                );
                return {
                    status: 'failed',
                    error: detail ? `${message}\n${detail}` : message
                };
            }

            if (
                job.mode === 'background' &&
                job.backgroundDeadlineAt &&
                Date.now() >= job.backgroundDeadlineAt
            ) {
                return { status: 'background_timeout' };
            }

            try {
                const result = await this.invokeWithTimeout(
                    'check_mount_status_by_root_id',
                    { rootId },
                    8000,
                    'Mount status check timed out'
                );

                if (result.success && result.data) {
                    return {
                        status: 'mounted',
                        mountpoint: result.data.mountpoint,
                        backend: result.data.backend || 'sync',
                        fallbackReason: result.data.fallback_reason || null
                    };
                }
            } catch (error) {
                // Continue polling
            }

            await new Promise(resolve => setTimeout(resolve, checkInterval));
        }
    }

    async openMountInExplorer(mountPath) {
        try {
            await invoke('open_path_in_shell', { path: mountPath });
        } catch (error) {
            console.error('Failed to open folder in explorer:', error);
            this.showNotification('Failed to open folder: ' + error, 'error');
        }
    }

    showMountProgressModal(rootId) {
        const modal = document.getElementById('mountProgressModal');
        const title = document.getElementById('mountProgressModalTitle');
        const folderLabel = document.getElementById('mountProgressModalFolderLabel');
        const folderPath = document.getElementById('mountProgressModalFolderPath');
        const text = document.getElementById('mountProgressModalText');
        const hint = document.getElementById('mountProgressModalHint');
        const continueBtn = document.getElementById('mountContinueBackgroundBtn');
        const cancelBtn = document.getElementById('mountCancelBtn');
        const job = this.getMountProgressJob(rootId);
        if (modal) {
            this.mountProgressModalRootId = rootId;
            modal.style.display = 'flex';
            const model = buildMountProgressModelValue({
                folderLabel: job?.folderLabel || 'Mounted folder',
                folderPath: job?.folderPath || '',
                elapsedMs: 0,
                continueEnableMs: this.mountContinueEnableMs,
            });
            if (title) {
                title.textContent = model.title;
            }
            if (folderLabel) {
                folderLabel.textContent = model.folderLabel || 'Mounted folder';
            }
            if (folderPath) {
                folderPath.textContent = model.folderPath || '';
                folderPath.style.display = model.folderPath ? 'block' : 'none';
            }
            if (text) {
                text.style.color = '';
                text.textContent = model.status;
            }
            if (hint) {
                hint.textContent = model.hint;
            }
            if (continueBtn) {
                continueBtn.style.display = 'inline-flex';
                continueBtn.disabled = true;
            }
            if (cancelBtn) {
                cancelBtn.style.display = 'none';
                cancelBtn.disabled = true;
            }

            const header = modal.querySelector('.modal-header');
            if (header) {
                header.querySelectorAll('.modal-close').forEach(btn => btn.remove());
            }
        }
        this.startMountProgressUiTimer();
    }

    hideMountProgressModal() {
        const modal = document.getElementById('mountProgressModal');
        this.mountProgressModalRootId = null;
        this.stopMountProgressUiTimer();
        if (modal) {
            modal.style.display = 'none';
        }
    }

    showMountProgressError(errorMessage, { folderLabel = 'Mounted folder', folderPath = '' } = {}) {
        const modal = document.getElementById('mountProgressModal');
        const title = document.getElementById('mountProgressModalTitle');
        const folderLabelEl = document.getElementById('mountProgressModalFolderLabel');
        const folderPathEl = document.getElementById('mountProgressModalFolderPath');
        const text = document.getElementById('mountProgressModalText');
        const hint = document.getElementById('mountProgressModalHint');
        const continueBtn = document.getElementById('mountContinueBackgroundBtn');
        const cancelBtn = document.getElementById('mountCancelBtn');

        this.mountProgressModalRootId = null;
        this.stopMountProgressUiTimer();
        if (modal && text) {
            modal.style.display = 'flex';
            if (title) {
                title.textContent = `Could not mount ${folderLabel}`;
            }
            if (folderLabelEl) {
                folderLabelEl.textContent = folderLabel;
            }
            if (folderPathEl) {
                folderPathEl.textContent = folderPath || '';
                folderPathEl.style.display = folderPath ? 'block' : 'none';
            }
            text.textContent = `Could not mount ${folderLabel}`;
            text.style.color = 'var(--error-color, #e74c3c)';
            if (hint) {
                const timeoutMessage = buildMountTimeoutMessageValue({
                    folderLabel,
                    folderPath,
                    inBackground: false,
                });
                hint.textContent = errorMessage
                    ? `${timeoutMessage} Error detail: ${errorMessage}`
                    : timeoutMessage;
            }
            if (continueBtn) {
                continueBtn.style.display = 'none';
            }
            if (cancelBtn) {
                cancelBtn.style.display = 'none';
            }

            // Add close button if not present
            const header = modal.querySelector('.modal-header');
            if (header && !header.querySelector('.modal-close')) {
                const closeBtn = document.createElement('button');
                closeBtn.className = 'modal-close';
                closeBtn.innerHTML = '&times;';
                closeBtn.onclick = () => this.hideMountProgressModal();
                header.appendChild(closeBtn);
            }
        } else {
            this.showNotification(errorMessage, 'error');
        }
    }

    async unmountFolder() {
        if (!this.currentMountPath) return;

        // Try to unmount the selected folder by root_id if available
        if (this.selectedFolder && this.selectedFolder.root_id) {
            const decision = await this.promptUnsafeUnmountDecision({
                rootIds: [this.selectedFolder.root_id],
                title: 'Unmount safety warning',
                message: 'HybridCipher will wait briefly for pending encrypted commits before unmounting this folder.',
                forceLabel: 'Force unmount'
            });
            if (decision === 'cancel') {
                return;
            }
            await this.executeUnmountCommand(this.selectedFolder, {
                force: decision === 'force'
            });
        } else {
            // Fallback to unmount all if we don't have root_id
            const decision = await this.promptUnsafeUnmountDecision({
                rootIds: null,
                title: 'Unmount safety warning',
                message: 'HybridCipher will wait briefly for pending encrypted commits before unmounting active folders.',
                forceLabel: 'Force unmount'
            });
            if (decision === 'cancel') {
                return;
            }
            await this.executeUnmountAllCommand({ force: decision === 'force' });
        }
    }

    async unmountAllFolders() {
        const decision = await this.promptUnsafeUnmountDecision({
            rootIds: null,
            title: 'Unmount all folders',
            message: 'HybridCipher will wait briefly for pending encrypted commits before unmounting all folders.',
            forceLabel: 'Force unmount'
        });
        if (decision === 'cancel') {
            return;
        }
        await this.executeUnmountAllCommand({ force: decision === 'force' });
    }

    startMountProgress() {
        const progressBar = document.getElementById('mountProgress');
        const progressFill = document.getElementById('mountProgressFill');
        const progressText = document.getElementById('mountProgressText');

        if (progressBar) {
            progressBar.style.display = 'block';
            this.mountProgressValue = 0;

            this.mountProgressInterval = setInterval(() => {
                this.mountProgressValue = Math.min(this.mountProgressValue + 5, 95);
                if (progressFill) {
                    progressFill.style.width = `${this.mountProgressValue}%`;
                }
                if (progressText) {
                    progressText.textContent = `Mounting... ${this.mountProgressValue}%`;
                }
            }, 100);
        }
    }

    stopMountProgress() {
        if (this.mountProgressInterval) {
            clearInterval(this.mountProgressInterval);
            this.mountProgressInterval = null;
        }

        const progressBar = document.getElementById('mountProgress');
        const progressFill = document.getElementById('mountProgressFill');

        if (progressBar) {
            setTimeout(() => {
                progressBar.style.display = 'none';
                if (progressFill) {
                    progressFill.style.width = '0%';
                }
                this.mountProgressValue = 0;
            }, 500);
        }
    }

    updateMountButtons(isMounted) {
        const unmountBtn = document.getElementById('unmountBtn');
        const resolveConflictBtn = document.getElementById('resolveConflictsBtn');
        const resolveRecoveryBtn = document.getElementById('resolveRecoveryCopiesBtn');
        const showResolveConflict = Boolean(isMounted && this.selectedFolder && this.folderHasPendingConflicts(this.selectedFolder));
        const showResolveRecovery = Boolean(isMounted && this.selectedFolder && this.folderHasPendingRecoveryCopies(this.selectedFolder));

        if (unmountBtn) {
            if (isMounted) {
                unmountBtn.style.display = 'flex';
            } else {
                unmountBtn.style.display = 'none';
            }
        }
        if (resolveConflictBtn) {
            resolveConflictBtn.style.display = showResolveConflict ? 'flex' : 'none';
        }
        if (resolveRecoveryBtn) {
            resolveRecoveryBtn.style.display = showResolveRecovery ? 'flex' : 'none';
        }
    }

    // ========================================================================
    // Context Menu
    // ========================================================================

    showContextMenu(event, folder) {
        const contextMenu = document.getElementById('contextMenu');
        if (!contextMenu) return;

        // Position the context menu, ensuring it stays within viewport
        contextMenu.style.display = 'block';

        // Get menu dimensions
        const menuRect = contextMenu.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        let left = event.clientX;
        let top = event.clientY;

        // Adjust if menu would go off-screen horizontally
        if (left + menuRect.width > viewportWidth) {
            left = viewportWidth - menuRect.width - 10;
        }

        // Adjust if menu would go off-screen vertically
        if (top + menuRect.height > viewportHeight) {
            top = viewportHeight - menuRect.height - 10;
        }

        contextMenu.style.left = `${Math.max(10, left)}px`;
        contextMenu.style.top = `${Math.max(10, top)}px`;

        // Store the folder for context menu actions
        contextMenu.dataset.folderRootId = folder.root_id;
        contextMenu.dataset.folderPath = folder.path;

        const isMounted = this.isFolderMounted(folder);
        const mountItem = contextMenu.querySelector('[data-action="mount"]');
        const openMountedItem = contextMenu.querySelector('[data-action="open-mounted"]');
        const resolveConflictsItem = contextMenu.querySelector('[data-action="resolve-conflicts"]');
        const resolveRecoveryItem = contextMenu.querySelector('[data-action="resolve-recovery"]');
        const unmountItem = contextMenu.querySelector('[data-action="unmount-cli"]');
        const hasConflicts = this.folderHasPendingConflicts(folder);
        const hasRecoveryCopies = this.folderHasPendingRecoveryCopies(folder);
        if (mountItem) {
            mountItem.style.display = isMounted ? 'none' : 'flex';
        }
        if (openMountedItem) {
            openMountedItem.style.display = isMounted ? 'flex' : 'none';
        }
        if (resolveConflictsItem) {
            resolveConflictsItem.style.display = isMounted && hasConflicts ? 'flex' : 'none';
        }
        if (resolveRecoveryItem) {
            resolveRecoveryItem.style.display = isMounted && hasRecoveryCopies ? 'flex' : 'none';
        }
        if (unmountItem) {
            unmountItem.style.display = isMounted ? 'flex' : 'none';
        }

        // Add event listeners to context menu items
        contextMenu.querySelectorAll('.context-menu-item').forEach(item => {
            item.onclick = (e) => {
                e.stopPropagation();
                const action = item.dataset.action;
                this.handleContextMenuAction(action, folder);
                this.hideContextMenu();
            };
        });
    }

    hideContextMenu() {
        const contextMenu = document.getElementById('contextMenu');
        if (contextMenu) {
            contextMenu.style.display = 'none';
            // Clear event listeners
            contextMenu.querySelectorAll('.context-menu-item').forEach(item => {
                item.onclick = null;
            });
        }
    }

    async handleContextMenuAction(action, folder) {
        const cliActions = ['unmount-cli'];
        if (cliActions.includes(action)) {
            if (this.adminPanelVisible) {
                this.setAdminPanelVisible(false);
            }
            await this.createTerminalTab();
        }

        switch (action) {
            case 'mount':
                this.mountFolderFromContext(folder);
                break;
            case 'open-mounted': {
                const mountpoint = this.getMountpointForRootId(folder?.root_id);
                if (!mountpoint) {
                    this.showNotification('Folder is not mounted.', 'warning');
                    break;
                }
                await this.openMountInExplorer(mountpoint);
                break;
            }
            case 'resolve-conflicts':
                await this.openConflictCenterForFolder(folder);
                break;
            case 'resolve-recovery':
                await this.openRecoveryCenterForFolder(folder);
                break;
            case 'unmount-cli':
                await this.executeUnmountCommand(folder);
                break;
            default:
                console.warn('Unknown context menu action:', action);
        }
    }

    // ========================================================================
    // UI Helpers
    // ========================================================================

    showMarkersReminder() {
        const reminder = document.getElementById('markersReminder');
        if (!reminder) return;
        reminder.classList.add('visible');
        reminder.setAttribute('aria-hidden', 'false');
    }

    hideMarkersReminder() {
        const reminder = document.getElementById('markersReminder');
        if (!reminder) return;
        reminder.classList.remove('visible');
        reminder.setAttribute('aria-hidden', 'true');
    }

    dismissMarkersReminder(persistDismissal) {
        this.hideMarkersReminder();
        this.hasShownMarkersReminder = true;
        if (persistDismissal) {
            this.markersReminderDismissed = true;
            this.setMarkersReminderDismissed(true);
        }
    }

    maybeShowMarkersReminder() {
        if (!this.markersReminderEnabled) return;
        if (!this.isLoggedIn) return;
        if (this.markersReminderDismissed) return;
        if (this.hasShownMarkersReminder) return;
        if (this.enrolledFolders.length === 0) return;
        this.hasShownMarkersReminder = true;
        this.showMarkersReminder();
    }

    async runEnrollMarkersDiscovery() {
        this.dismissMarkersReminder(false);
        await this.runSettingsCliCommand(
            'hybridcipher coverage recover-markers --yes',
            { closeSettingsModal: false }
        );
    }

    async refreshSecurityStatus() {
        if (!this.isLoggedIn) return;
        try {
            const result = await invoke('get_security_status');
            if (!result?.success || !result.data) {
                return;
            }
            this.securityStatus = result.data;
            this.updateSecurityBanner();
        } catch (error) {
            console.error('Failed to refresh security status:', error);
        }
    }

    scheduleSecurityStatusRefresh(delayMs = 8000) {
        if (!this.isLoggedIn) return;
        setTimeout(() => {
            this.refreshSecurityStatus();
        }, delayMs);
    }

    updateSecurityBanner() {
        const pill = document.getElementById('userStatusPill');
        const alertEl = document.getElementById('userStatusAlert');
        if (!pill || !alertEl) return;

        const mfaEnabled = Boolean(this.securityStatus?.mfa_enabled);
        const recoveryOk = Boolean(this.securityStatus?.recovery_auto_backup_ok);
        const recoveryState = String(this.securityStatus?.recovery_auto_backup_state || '').trim().toLowerCase();
        this.securityWarnings = [];

        if (!mfaEnabled) {
            this.securityWarnings.push({
                title: 'MFA not enabled',
                text: 'Enable MFA in Settings > MFA or run <code>hybridcipher mfa enroll</code>.'
            });
        }

        if (!recoveryOk) {
            let title = 'Automatic recovery backup unavailable';
            let text = 'Unlock your OS keychain/keyring and re-run <code>hybridcipher recovery upload</code> to re-enable silent backups.';

            if (recoveryState === 'missing_writer_blob') {
                if (this.securityStatus?.recovery_backup_ok) {
                    title = 'Automatic recovery backup not enabled on this device';
                    text = 'Run <code>hybridcipher recovery upload</code> once on this device to seed silent backups for future updates.';
                } else {
                    title = 'Recovery backup not set up';
                    text = 'Run <code>hybridcipher recovery upload</code> to create your recovery backup and enable silent backups on this device.';
                }
            } else if (recoveryState === 'missing_writer_key') {
                title = 'Recovery secure storage entry missing';
                text = 'Re-run <code>hybridcipher recovery upload</code> on this device to restore the secure writer key used for silent backups.';
            }

            this.securityWarnings.push({ title, text });
        }

        const hasWarnings = this.securityWarnings.length > 0;
        pill.classList.toggle('warning', hasWarnings);
        alertEl.style.display = hasWarnings ? 'inline-flex' : 'none';
        pill.setAttribute('aria-expanded', 'false');

        this.renderSecurityWarnings();
        if (!hasWarnings) {
            this.hideSecurityPanel();
        }
        this.updateMfaSettingsButton();
    }

    updateMfaSettingsButton() {
        const button = document.getElementById('settingsMfaEnableBtn');
        if (!button) return;
        const enabled = Boolean(this.securityStatus?.mfa_enabled);
        if (enabled) {
            button.textContent = 'MFA already enabled';
            button.disabled = true;
            button.classList.add('enabled');
            button.setAttribute('aria-disabled', 'true');
        } else {
            button.textContent = 'Enable MFA';
            button.disabled = false;
            button.classList.remove('enabled');
            button.removeAttribute('aria-disabled');
        }
    }

    renderSecurityWarnings() {
        const list = document.getElementById('statusWarningList');
        if (!list) return;
        list.innerHTML = '';

        if (!this.securityWarnings.length) {
            const empty = document.createElement('div');
            empty.className = 'status-warning-empty';
            empty.textContent = 'All security checks look good.';
            list.appendChild(empty);
            return;
        }

        this.securityWarnings.forEach((warning) => {
            const item = document.createElement('div');
            item.className = 'status-warning-item';
            item.innerHTML = `
                <div class="status-warning-title">${warning.title}</div>
                <div class="status-warning-text">${warning.text}</div>
            `;
            list.appendChild(item);
        });
    }

    toggleSecurityPanel() {
        if (!this.securityWarnings.length) return;
        const panel = document.getElementById('statusWarningPanel');
        const pill = document.getElementById('userStatusPill');
        if (!panel || !pill) return;
        const shouldOpen = !panel.classList.contains('open');
        panel.classList.toggle('open', shouldOpen);
        panel.setAttribute('aria-hidden', shouldOpen ? 'false' : 'true');
        pill.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
        if (shouldOpen) {
            this.refreshSecurityStatus();
        }
    }

    hideSecurityPanel() {
        const panel = document.getElementById('statusWarningPanel');
        const pill = document.getElementById('userStatusPill');
        if (panel) {
            panel.classList.remove('open');
            panel.setAttribute('aria-hidden', 'true');
        }
        if (pill) {
            pill.setAttribute('aria-expanded', 'false');
        }
    }

    scheduleMfaPrompt() {
        if (!this.pendingMfaPrompt) return;
        if (this.mfaPromptTimer) {
            clearTimeout(this.mfaPromptTimer);
        }
        this.mfaPromptTimer = setTimeout(async () => {
            await this.maybeShowMfaPrompt();
        }, 900);
    }

    async maybeShowMfaPrompt() {
        this.pendingMfaPrompt = false;
        if (!this.isLoggedIn) return;
        await this.refreshSecurityStatus();
        if (this.securityStatus?.mfa_enabled) return;
        this.showMfaPromptModal();
    }

    showMfaPromptModal() {
        const modal = document.getElementById('mfaPromptModal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideMfaPromptModal() {
        const modal = document.getElementById('mfaPromptModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    handleMfaPromptAccept() {
        this.hideMfaPromptModal();
        this.startMfaEnrollment();
    }

    handleMfaPromptDecline() {
        this.hideMfaPromptModal();
        this.showNotification(
            'MFA is not enabled. Without it, sign-ins are easier to compromise. Enable it later in Settings > MFA or run "hybridcipher mfa enroll".',
            'warning'
        );
    }

    async startMfaEnrollment() {
        if (!this.isLoggedIn) {
            this.showNotification('Please login before enabling MFA.', 'warning');
            return;
        }
        try {
            const result = await invoke('mfa_enroll_start');
            if (!result?.success || !result.data) {
                this.showNotification(result?.error || 'Failed to start MFA enrollment', 'error');
                return;
            }
            this.mfaEnrollData = result.data;
            this.showMfaSetupModal(result.data);
        } catch (error) {
            console.error('Failed to start MFA enrollment:', error);
            this.showNotification('Failed to start MFA enrollment', 'error');
        }
    }

    showMfaSetupModal(data) {
        const modal = document.getElementById('mfaSetupModal');
        const qrContainer = document.getElementById('mfaQrContainer');
        const secretEl = document.getElementById('mfaSecretValue');
        const verifyInput = document.getElementById('mfaVerifyCodeInput');
        const enrollStep = document.getElementById('mfaSetupStepEnroll');
        const backupStep = document.getElementById('mfaSetupStepBackup');
        if (qrContainer) {
            if (data?.qr_svg) {
                const sanitized = this.sanitizeSvg(data.qr_svg);
                qrContainer.innerHTML = '';
                if (sanitized) {
                    qrContainer.appendChild(sanitized);
                } else {
                    qrContainer.innerHTML = '<span class="mfa-qr-placeholder">QR code unavailable</span>';
                }
            } else {
                qrContainer.innerHTML = '<span class="mfa-qr-placeholder">QR code unavailable</span>';
            }
        }
        if (secretEl) {
            secretEl.textContent = data?.secret || '----';
        }
        if (verifyInput) {
            verifyInput.value = '';
        }
        if (enrollStep) enrollStep.style.display = 'block';
        if (backupStep) backupStep.style.display = 'none';
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideMfaSetupModal() {
        const modal = document.getElementById('mfaSetupModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async verifyMfaEnrollment() {
        const input = document.getElementById('mfaVerifyCodeInput');
        const code = input?.value?.trim() || '';
        if (!code) {
            this.showNotification('Enter the 6-digit authenticator code.', 'warning');
            return;
        }
        try {
            const result = await invoke('mfa_enroll_verify', { code });
            if (!result?.success || !result.data) {
                this.showNotification(result?.error || 'Failed to verify MFA', 'error');
                return;
            }
            this.showMfaBackupCodes(result.data.backup_codes || []);
            await this.refreshSecurityStatus();
        } catch (error) {
            console.error('Failed to verify MFA enrollment:', error);
            this.showNotification('Failed to verify MFA enrollment', 'error');
        }
    }

    showMfaBackupCodes(codes) {
        const enrollStep = document.getElementById('mfaSetupStepEnroll');
        const backupStep = document.getElementById('mfaSetupStepBackup');
        const list = document.getElementById('mfaBackupCodesList');
        if (list) {
            list.innerHTML = '';
            codes.forEach((code) => {
                const item = document.createElement('div');
                item.className = 'mfa-backup-code';
                item.textContent = code;
                list.appendChild(item);
            });
        }
        if (enrollStep) enrollStep.style.display = 'none';
        if (backupStep) backupStep.style.display = 'block';
        this.mfaEnrollData = { ...(this.mfaEnrollData || {}), backup_codes: codes };
    }

    copyMfaBackupCodes() {
        const codes = this.mfaEnrollData?.backup_codes || [];
        if (!codes.length) {
            this.showNotification('No backup codes available to copy.', 'warning');
            return;
        }
        const text = codes.join('\n');
        navigator.clipboard.writeText(text).then(() => {
            this.showNotification('Backup codes copied to clipboard.', 'success');
        }).catch((error) => {
            console.error('Failed to copy backup codes:', error);
            this.showNotification('Failed to copy backup codes', 'error');
        });
    }

    finishMfaSetup() {
        this.hideMfaSetupModal();
        this.showNotification('MFA enabled successfully.', 'success');
    }

    updateBreadcrumb(path) {
        const breadcrumb = document.getElementById('breadcrumb');
        if (breadcrumb) {
            const parts = path.split('/').filter(p => p);
            breadcrumb.innerHTML = parts.map((part, index) =>
                `<span class="breadcrumb-item">${this.escapeHtml(part)}</span>`
            ).join(' <span class="breadcrumb-separator">/</span> ');
        }
    }

    formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '-';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    // ========================================================================
    // Modal Management
    // ========================================================================

    openLoginModal(prefillEmail = null) {
        document.getElementById('loginModal').style.display = 'flex';
        const passwordInput = document.getElementById('loginPassword');
        if (passwordInput) {
            passwordInput.type = 'password';
        }
        const toggleBtn = document.getElementById('loginPasswordToggle');
        if (toggleBtn) {
            toggleBtn.setAttribute('data-visible', 'false');
            toggleBtn.setAttribute('aria-label', 'Show password');
            toggleBtn.setAttribute('aria-pressed', 'false');
        }
        const rememberCheckbox = document.getElementById('rememberMe');
        if (rememberCheckbox) {
            rememberCheckbox.checked = this.rememberMePreference;
        }

        const emailInput = document.getElementById('loginEmail');
        if (!prefillEmail && this.rememberMePreference && emailInput && passwordInput) {
            const { email, password } = this.loadRememberedCredentials();
            emailInput.value = email;
            passwordInput.value = password;
            if (password) {
                passwordInput.focus();
                return;
            }
        } else if (emailInput && passwordInput) {
            emailInput.value = '';
            passwordInput.value = '';
        }
        if (prefillEmail && emailInput && passwordInput) {
            emailInput.value = prefillEmail;
            passwordInput.value = '';
            passwordInput.focus();
            return;
        }
        emailInput?.focus();
    }

    closeLoginModal() {
        document.getElementById('loginModal').style.display = 'none';
        document.getElementById('loginForm').reset();
    }

    showLoggingInModal() {
        const modal = document.getElementById('loggingInModal');
        const messageEl = document.getElementById('loggingInMessage');
        const standardMessages = [
            'Contacting server...',
            'Verifying credentials...',
            'Setting up local encrypted session...',
            'Finalizing login...'
        ];
        const longWaitMessages = [
            'Please be patient. First-time login can take longer.',
            'Setting up local encrypted state for this account...',
            'Checking and initializing your default group context...',
            'Preparing initial epoch and recovery data...'
        ];
        if (modal) {
            modal.style.display = 'flex';
        }
        if (messageEl) {
            this.loggingMessageIndex = 0;
            messageEl.textContent = standardMessages[this.loggingMessageIndex];
        }
        if (this.loggingMessageTimer) {
            clearInterval(this.loggingMessageTimer);
        }
        if (this.loggingLongWaitTimer) {
            clearTimeout(this.loggingLongWaitTimer);
            this.loggingLongWaitTimer = null;
        }
        this.loggingMessageTimer = setInterval(() => {
            if (!messageEl) return;
            this.loggingMessageIndex = (this.loggingMessageIndex + 1) % standardMessages.length;
            messageEl.textContent = standardMessages[this.loggingMessageIndex];
        }, 1400);
        this.loggingLongWaitTimer = setTimeout(() => {
            if (!messageEl) return;
            this.loggingMessageIndex = 0;
            messageEl.textContent = longWaitMessages[this.loggingMessageIndex];
            if (this.loggingMessageTimer) {
                clearInterval(this.loggingMessageTimer);
            }
            this.loggingMessageTimer = setInterval(() => {
                this.loggingMessageIndex = (this.loggingMessageIndex + 1) % longWaitMessages.length;
                messageEl.textContent = longWaitMessages[this.loggingMessageIndex];
            }, 2400);
        }, 6500);
    }

    hideLoggingInModal() {
        const modal = document.getElementById('loggingInModal');
        const messageEl = document.getElementById('loggingInMessage');
        if (modal) {
            modal.style.display = 'none';
        }
        if (this.loggingMessageTimer) {
            clearInterval(this.loggingMessageTimer);
            this.loggingMessageTimer = null;
        }
        if (this.loggingLongWaitTimer) {
            clearTimeout(this.loggingLongWaitTimer);
            this.loggingLongWaitTimer = null;
        }
        if (messageEl) {
            messageEl.textContent = 'Logging in...';
        }
    }

    showActionProgressModal(message = 'Working...') {
        const modal = document.getElementById('actionProgressModal');
        const messageEl = document.getElementById('actionProgressMessage');
        const messages = Array.isArray(message) ? message.filter(Boolean) : [message];
        if (messageEl) {
            this.actionProgressIndex = 0;
            messageEl.textContent = messages[0] || 'Working...';
        }
        if (this.actionProgressTimer) {
            clearInterval(this.actionProgressTimer);
            this.actionProgressTimer = null;
        }
        if (messages.length > 1 && messageEl) {
            this.actionProgressTimer = setInterval(() => {
                this.actionProgressIndex = (this.actionProgressIndex + 1) % messages.length;
                messageEl.textContent = messages[this.actionProgressIndex];
            }, 3000);
        }
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideActionProgressModal() {
        const modal = document.getElementById('actionProgressModal');
        if (modal) {
            modal.style.display = 'none';
        }
        if (this.actionProgressTimer) {
            clearInterval(this.actionProgressTimer);
            this.actionProgressTimer = null;
        }
    }

    toggleLoginPasswordVisibility() {
        const passwordInput = document.getElementById('loginPassword');
        const toggleBtn = document.getElementById('loginPasswordToggle');
        if (!passwordInput || !toggleBtn) return;

        const isVisible = passwordInput.type === 'text';
        passwordInput.type = isVisible ? 'password' : 'text';
        toggleBtn.setAttribute('data-visible', isVisible ? 'false' : 'true');
        toggleBtn.setAttribute('aria-label', isVisible ? 'Show password' : 'Hide password');
        toggleBtn.setAttribute('aria-pressed', isVisible ? 'false' : 'true');
        passwordInput.focus();
    }

    openRegisterModal() {
        this.resetRegisterModalState();
        document.getElementById('registerModal').style.display = 'flex';
        document.getElementById('registerEmail').focus();
        this.updateRegisterValidation();
    }

    closeRegisterModal() {
        document.getElementById('registerModal').style.display = 'none';
        this.resetRegisterModalState();
    }

    async openRegisterTerminalOverlay() {
        const appContainer = document.getElementById('appContainer');
        const mainContent = document.getElementById('mainContent');
        const fileBrowser = document.getElementById('fileBrowser');
        const terminalContainer = document.getElementById('terminalContainer');
        if (!appContainer || !terminalContainer) {
            return;
        }

        if (this.isRegisterOverlay) {
            this.focusTerminalArea();
            return;
        }

        this.registerOverlayPrevTerminalVisible = this.terminalVisible;
        this.isRegisterOverlay = true;
        appContainer.style.display = 'flex';
        appContainer.classList.add('register-overlay');

        // Force terminal visibility for the overlay
        this.terminalVisible = true;
        terminalContainer.style.display = 'flex';
        if (fileBrowser) fileBrowser.style.display = 'none';
        mainContent?.classList.add('terminal-visible');
        this.updateTerminalCwdDisplay();
        this.updateTerminalHeader();
        this.ensureTerminalWelcome();
        this.updateTerminalPromptSymbol();
        this.focusTerminalArea();
        await this.startTerminalSessionForTab(this.activeTabId);
        this.applyCursorToActiveTab();

        await this.createTerminalTab();
        const activeTab = this.getActiveTab();
        if (activeTab?.sessionId) {
            this.registerOverlaySessionId = activeTab.sessionId;
            this.registerOverlayCompletionHandled = false;
            this.registerSentinelBuffers[activeTab.sessionId] = '';
        }
        await this.executeRegisterCommand();
    }

    closeRegisterTerminalOverlay() {
        const appContainer = document.getElementById('appContainer');
        const mainContent = document.getElementById('mainContent');
        const fileBrowser = document.getElementById('fileBrowser');
        const terminalContainer = document.getElementById('terminalContainer');
        if (appContainer) {
            appContainer.style.display = 'none';
            appContainer.classList.remove('register-overlay');
        }

        this.isRegisterOverlay = false;

        if (this.registerOverlayPrevTerminalVisible === false) {
            this.terminalVisible = false;
            if (terminalContainer) terminalContainer.style.display = 'none';
            if (fileBrowser) fileBrowser.style.display = 'flex';
            mainContent?.classList.remove('terminal-visible');
        } else {
            this.terminalVisible = true;
            if (terminalContainer) terminalContainer.style.display = 'flex';
            if (fileBrowser) fileBrowser.style.display = 'none';
            mainContent?.classList.add('terminal-visible');
        }

        this.registerOverlayPrevTerminalVisible = null;
    }

    buildRegisterCommand(cliPath) {
        const osType = this.platformInfo?.os_type;
        if (osType === 'windows') {
            const escapedCliPath = cliPath.replace(/'/g, "''");
            return `powershell -NoProfile -Command "$email = Read-Host 'Please enter your email address'; & '${escapedCliPath}' register $email; if ($LASTEXITCODE -eq 0) { echo __HC_REGISTER_SUCCESS__ } else { echo __HC_REGISTER_FAILED__ }"`;
        }

        const escapedCliPath = cliPath.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `bash -lc 'clear; read -r -p "Please enter your email address: " email; echo; "${escapedCliPath}" register "$email"; status=$?; if [ $status -eq 0 ]; then printf "__HC_REGISTER_SUCCESS__\\n"; else printf "__HC_REGISTER_FAILED__\\n"; fi'`;
    }

    async executeRegisterCommand() {
        let cliPath;
        try {
            cliPath = await this.getCliBinaryPath();
        } catch (error) {
            this.showNotification('Failed to locate hybridcipher CLI. Please build it with "cargo build --release --bin hybridcipher"', 'error');
            return;
        }

        const command = this.buildRegisterCommand(cliPath);
        if (this.registerOverlaySessionId) {
            this.registerOverlayCommandEchoBySession[this.registerOverlaySessionId] = {
                remaining: `${command}\r\n`
            };
        }
        await this.executeCommandDirectly(command, true);
        this.updateActiveTabTitle('Register');
    }

    async handleRegisterOverlayCompletion(success) {
        if (this.registerOverlayCompletionHandled) {
            return;
        }
        this.registerOverlayCompletionHandled = true;

        if (!success) {
            this.showNotification('Registration failed. Please try again.', 'error');
            return;
        }

        try {
            const sessionInfo = await invoke('get_session_info');
            if (sessionInfo && sessionInfo.status === 'active') {
                this.currentUser = sessionInfo.email || null;
                this.showMainApp();
                this.showNotification('Registration complete. You are now logged in.', 'success');
            } else {
                this.showNotification('Registration complete. Please log in.', 'info');
            }
        } catch (error) {
            console.error('Post-register session check failed:', error);
            this.showNotification('Registration complete. Please log in.', 'info');
        }
    }

    openSettingsModal(sectionId = null) {
        this.refreshSettingsStatus();
        this.refreshLegalStatusUi();
        this.updateMfaSettingsButton();
        this.syncAutoMountSettingsUi();
        this.closeSettingsEnrollmentModal();
        // Populate update settings
        const prefSelect = document.getElementById('settingsUpdatePreference');
        if (prefSelect) prefSelect.value = this.updatePreference;
        const versionEl = document.getElementById('settingsCurrentVersion');
        if (versionEl) {
            invoke('get_app_version').then(r => {
                const value = r?.success ? `v${r.data}` : '—';
                versionEl.textContent = value;
                const aboutVersionEl = document.getElementById('settingsAboutVersion');
                if (aboutVersionEl) {
                    aboutVersionEl.textContent = value;
                }
            }).catch(() => {});
        }
        this.renderSettingsUpdateStatus();
        this.refreshGlobalCliInstallStatus();
        document.getElementById('settingsModal').style.display = 'flex';
        if (sectionId) {
            requestAnimationFrame(() => {
                document.getElementById(sectionId)?.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            });
        }
    }

    closeSettingsModal() {
        this.closeSettingsEnrollmentModal();
        document.getElementById('settingsModal').style.display = 'none';
    }

    showRecoveryCodeModal(code) {
        this.recoveryCodeValue = code;
        this.pendingMfaPrompt = true;
        const modal = document.getElementById('recoveryCodeModal');
        const codeEl = document.getElementById('recoveryCodeValue');
        if (codeEl) {
            codeEl.textContent = code;
        }
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    hideRecoveryCodeModal() {
        const modal = document.getElementById('recoveryCodeModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    acknowledgeRecoveryCode() {
        this.hideRecoveryCodeModal();
        this.scheduleMfaPrompt();
    }

    openCreateGroupModal() {
        const modal = document.getElementById('createGroupModal');
        const input = document.getElementById('createGroupName');
        const descriptionInput = document.getElementById('createGroupDescription');
        if (input) {
            input.value = '';
            setTimeout(() => input.focus(), 0);
        }
        if (descriptionInput) {
            descriptionInput.value = '';
        }
        if (modal) {
            modal.style.display = 'flex';
        }
    }

    closeCreateGroupModal() {
        const modal = document.getElementById('createGroupModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    handleCreateGroupSubmit(e) {
        e.preventDefault();
        const nameInput = document.getElementById('createGroupName');
        const descriptionInput = document.getElementById('createGroupDescription');
        const name = nameInput?.value?.trim() || '';
        const description = descriptionInput?.value?.trim() || '';
        if (!name) {
            this.showNotification('Group name is required.', 'warning');
            return;
        }

        this.closeCreateGroupModal();
        const descriptionArg = description ? ` --description ${this.quoteCliArg(description)}` : '';
        const command = `hybridcipher create-group ${this.quoteCliArg(name)}${descriptionArg} && hybridcipher initialize-group`;
        this.runDashboardCliCommand(command);
    }

    openSwitchGroupModal({ closeSettingsOnSubmit = false } = {}) {
        this.switchGroupCloseSettings = Boolean(closeSettingsOnSubmit);
        this.switchGroupSelectedId = null;
        this.switchGroupCurrentId = null;
        const list = document.getElementById('switchGroupList');
        const manualInput = document.getElementById('switchGroupManualId');
        if (manualInput) {
            manualInput.value = '';
        }
        if (list) {
            list.innerHTML = '<div class="group-list-empty">Loading groups...</div>';
        }
        const modal = document.getElementById('switchGroupModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.loadSwitchGroupList();
    }

    closeSwitchGroupModal() {
        const modal = document.getElementById('switchGroupModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async loadSwitchGroupList() {
        const list = document.getElementById('switchGroupList');
        if (!list) return;
        try {
            const [groups, context] = await Promise.all([
                this.fetchGroupList(),
                this.getActiveGroupContext()
            ]);
            this.switchGroupCurrentId = context.groupId;
            this.renderSwitchGroupList(groups, this.switchGroupCurrentId);
        } catch (error) {
            console.error('Failed to load group list:', error);
            list.innerHTML = '<div class="group-list-empty">Failed to load groups.</div>';
        }
    }

    async fetchGroupListFromCli() {
        let cliPath;
        try {
            cliPath = await this.getCliBinaryPath();
        } catch (error) {
            throw new Error('CLI binary not available');
        }

        const rawCommand = 'hybridcipher list-groups --format json --no-color';
        const command = this.resolveCliCommand(rawCommand, cliPath);
        const result = await invoke('run_shell_command', { command, cwd: null });
        if (!result?.success || !result?.data) {
            throw new Error(result?.error || 'Group list command failed');
        }

        const stdout = result.data.stdout || '';
        const stderr = result.data.stderr || '';
        let groups = this.parseGroupListOutput(stdout);
        if (!groups.length && stderr) {
            groups = this.parseGroupListOutput(stderr);
        }
        return groups;
    }

    async fetchGroupList() {
        try {
            const result = await invoke('get_group_summaries');
            if (result?.success && Array.isArray(result.data)) {
                return result.data
                    .map(group => this.normalizeGroupListEntry(group))
                    .filter(Boolean);
            }
            if (result?.error) {
                console.warn('Group summary command failed, falling back to CLI:', result.error);
            }
        } catch (error) {
            console.warn('Failed to fetch group summaries from desktop backend:', error);
        }
        return this.fetchGroupListFromCli();
    }

    parseGroupListOutput(output) {
        if (!output) return [];
        const trimmed = output.trim();
        let parsedPayload = null;

        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                parsedPayload = JSON.parse(trimmed);
            } catch (error) {
                console.warn('Failed to parse JSON group list:', error);
            }
        }

        if (!parsedPayload) {
            const jsonStart = output.indexOf('[');
            const jsonEnd = output.lastIndexOf(']');
            if (jsonStart !== -1 && jsonEnd > jsonStart) {
                try {
                    parsedPayload = JSON.parse(output.slice(jsonStart, jsonEnd + 1));
                } catch (error) {
                    console.warn('Failed to parse bracketed JSON group list:', error);
                }
            }
        }

        const parsedGroups = Array.isArray(parsedPayload)
            ? parsedPayload
            : Array.isArray(parsedPayload?.groups)
                ? parsedPayload.groups
                : [];
        if (parsedGroups.length) {
            return parsedGroups
                .map(group => this.normalizeGroupListEntry(group))
                .filter(Boolean);
        }

        const lines = output.split(/\r?\n/);
        const groups = [];
        for (const line of lines) {
            const match = line.match(/(\d+)\.\s+(.+?)\s+\(ID:\s*([^)]+)\)/);
            if (!match) continue;
            const name = match[2]?.trim() || 'Untitled group';
            const id = match[3]?.trim() || '';
            if (!id) continue;
            groups.push(this.normalizeGroupListEntry({ id, name }));
        }
        return groups.filter(Boolean);
    }

    normalizeGroupListEntry(group) {
        const id = String(group?.id || group?.group_id || '').trim();
        if (!id) return null;

        const descriptionValue =
            typeof group?.description === 'string' && group.description.trim()
                ? group.description.trim()
                : null;

        const createdAtValue = group?.created_at || group?.createdAt || null;
        const currentEpochRaw =
            group?.current_epoch_id ??
            group?.current_epoch ??
            group?.epoch_id ??
            group?.epoch ??
            null;
        const currentEpochId =
            currentEpochRaw === null || currentEpochRaw === undefined || currentEpochRaw === ''
                ? null
                : String(currentEpochRaw);

        return {
            id,
            name: group?.name || 'Untitled group',
            description: descriptionValue,
            created_at: createdAtValue,
            member_count: this.parseOptionalNumber(
                group?.member_count ?? group?.members_count ?? group?.members
            ),
            device_count: this.parseOptionalNumber(
                group?.device_count ??
                group?.devices_count ??
                group?.devices_total ??
                group?.total_devices ??
                group?.devices
            ),
            current_epoch_id: currentEpochId
        };
    }

    parseOptionalNumber(value) {
        if (Array.isArray(value)) {
            return value.length;
        }
        if (typeof value === 'number' && Number.isFinite(value)) {
            return value;
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) return null;
            const parsed = Number(trimmed);
            if (Number.isFinite(parsed)) {
                return parsed;
            }
        }
        return null;
    }

    normalizeGroupId(groupId) {
        if (!groupId) return '';
        return String(groupId).trim().toLowerCase();
    }

    isCurrentGroupId(groupId, currentGroupId = null) {
        const targetId = this.normalizeGroupId(groupId);
        const currentId = this.normalizeGroupId(
            currentGroupId === null ? this.switchGroupCurrentId : currentGroupId
        );
        return Boolean(targetId && currentId && targetId === currentId);
    }

    parseCurrentGroupContext(output) {
        const cleaned = this.stripAnsi(output || '');
        const activeMatch = cleaned.match(/Active group:\s*([^\n]+)/i);
        if (!activeMatch) {
            return { groupId: null, groupName: null };
        }

        const details = activeMatch[1].trim();
        if (!details) {
            return { groupId: null, groupName: null };
        }

        const withId = details.match(/^(.*)\(([^)]+)\)\s*$/);
        const nameRaw = withId ? withId[1].trim() : details;
        const groupIdRaw = withId ? withId[2].trim() : '';

        const normalizedNameMatch = nameRaw.match(/'s\s+(.+)$/);
        const groupName = (normalizedNameMatch ? normalizedNameMatch[1].trim() : nameRaw) || null;
        const groupId = groupIdRaw.replace(/^ID:\s*/i, '').trim() || null;

        return { groupId, groupName };
    }

    async getActiveGroupContext() {
        try {
            const context = await invoke('get_active_group_context');
            if (context?.success && context.data) {
                const groupId = context.data.group_id ? String(context.data.group_id).trim() : '';
                const groupName = context.data.group_name ? String(context.data.group_name).trim() : '';
                return {
                    groupId: groupId || null,
                    groupName: groupName || null
                };
            }
        } catch (error) {
            console.warn('Failed to load cached group context:', error);
        }

        try {
            const output = await this.runCliStatusCommand('hybridcipher current-group --no-color');
            return this.parseCurrentGroupContext(output);
        } catch (error) {
            console.warn('Failed to resolve active group from CLI:', error);
        }

        return { groupId: null, groupName: null };
    }

    renderSwitchGroupList(groups, currentGroupId = null) {
        const list = document.getElementById('switchGroupList');
        if (!list) return;
        list.innerHTML = '';
        if (!groups.length) {
            list.innerHTML = '<div class="group-list-empty">No groups found.</div>';
            return;
        }

        groups.forEach(group => {
            const row = document.createElement('div');
            row.className = 'group-list-item';
            row.dataset.groupId = group.id;
            const isCurrentGroup = this.isCurrentGroupId(group.id, currentGroupId);
            if (isCurrentGroup) {
                row.classList.add('current');
                row.dataset.current = 'true';
            }

            const meta = document.createElement('div');
            meta.className = 'group-list-meta';

            const title = document.createElement('div');
            title.className = 'group-list-title';

            const name = document.createElement('div');
            name.className = 'group-list-name';
            name.textContent = group.name || 'Untitled group';
            title.appendChild(name);

            if (isCurrentGroup) {
                const badge = document.createElement('span');
                badge.className = 'group-list-badge';
                badge.textContent = 'Current';
                title.appendChild(badge);
            }

            const details = document.createElement('div');
            details.className = 'group-list-details';
            const memberCount =
                typeof group.member_count === 'number'
                    ? `${this.formatCount(group.member_count)} members`
                    : 'members —';
            const epoch = group.current_epoch_id ? `epoch ${group.current_epoch_id}` : 'epoch —';
            details.textContent = `${group.id} | ${memberCount} | ${epoch}`;

            meta.appendChild(title);
            meta.appendChild(details);

            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'btn btn-secondary btn-small group-switch-action';
            button.textContent = isCurrentGroup ? 'Current' : 'Switch';
            button.disabled = isCurrentGroup;
            if (isCurrentGroup) {
                button.title = 'Already the active group.';
            }

            row.appendChild(meta);
            row.appendChild(button);
            list.appendChild(row);
        });
    }

    setSwitchGroupSelection(groupId) {
        if (this.isCurrentGroupId(groupId)) {
            this.switchGroupSelectedId = null;
            groupId = null;
        } else {
            this.switchGroupSelectedId = groupId;
        }
        document.querySelectorAll('#switchGroupList .group-list-item').forEach(item => {
            const selected = Boolean(
                groupId && item.dataset.groupId === groupId && item.dataset.current !== 'true'
            );
            item.classList.toggle('selected', selected);
        });
    }

    handleSwitchGroupSubmit() {
        const manualInput = document.getElementById('switchGroupManualId');
        const manualId = manualInput?.value?.trim() || '';
        const targetId = manualId || this.switchGroupSelectedId;
        if (!targetId) {
            this.showNotification('Select or enter a group ID to switch.', 'warning');
            return;
        }
        if (this.isCurrentGroupId(targetId)) {
            this.showNotification('You are already on this group.', 'warning');
            return;
        }
        this.submitSwitchGroupSelection(targetId);
    }

    submitSwitchGroupSelection(groupId) {
        if (!groupId) return;
        if (this.isCurrentGroupId(groupId)) {
            this.showNotification('You are already on this group.', 'warning');
            return;
        }
        this.closeSwitchGroupModal();
        this.setAdminPanelVisible(false);
        const command = `hybridcipher switch-group ${this.quoteCliArg(groupId)}`;
        if (this.switchGroupCloseSettings) {
            this.runSettingsCliCommand(command);
        } else {
            this.runDashboardCliCommand(command);
        }
        this.scheduleGroupSwitchRefresh();
    }

    clearFolderSelectionForGroupSwitch() {
        this.selectedFolder = null;
        this.activeMountsByRootId = {};
        this.activeMountDetailsByRootId = {};
        if (this.userFolderPreferences?.lastSelectedFolder) {
            this.userFolderPreferences.lastSelectedFolder = null;
            this.saveFolderPreferences();
        }
        this.renderFolderList();
        this.updateBreadcrumb('');
        this.updateMountButtons(false);
        this.updateSidebarMountSummary();
    }

    scheduleGroupSwitchRefresh() {
        this.clearFolderSelectionForGroupSwitch();

        if (Array.isArray(this.groupSwitchRefreshTimers)) {
            this.groupSwitchRefreshTimers.forEach(timerId => clearTimeout(timerId));
        }

        const refresh = async () => {
            try {
                await invoke('refresh_local_client');
            } catch (error) {
                console.warn('Failed to refresh local client after group switch:', error);
            }
            await this.loadEnrolledFolders();
            this.refreshAdminGroupStatus();
            this.refreshAdminCoverageSummary();
            this.refreshOperationsQueues();
        };

        this.groupSwitchRefreshTimers = [
            setTimeout(refresh, 1500),
            setTimeout(refresh, 6000)
        ];
    }

    openListGroupsModal() {
        const list = document.getElementById('listGroupsList');
        if (list) {
            list.innerHTML = '<div class="group-list-empty">Loading groups...</div>';
        }
        const modal = document.getElementById('listGroupsModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.loadListGroups();
    }

    closeListGroupsModal() {
        const modal = document.getElementById('listGroupsModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async loadListGroups() {
        const list = document.getElementById('listGroupsList');
        if (!list) return;
        try {
            const [groups, context] = await Promise.all([
                this.fetchGroupList(),
                this.getActiveGroupContext()
            ]);
            this.renderListGroups(groups, context.groupId);
        } catch (error) {
            console.error('Failed to load groups list modal:', error);
            list.innerHTML = '<div class="group-list-empty">Failed to load groups.</div>';
        }
    }

    renderListGroups(groups, currentGroupId = null) {
        const list = document.getElementById('listGroupsList');
        if (!list) return;
        list.innerHTML = '';
        if (!groups.length) {
            list.innerHTML = '<div class="group-list-empty">No groups found.</div>';
            return;
        }

        groups.forEach(group => {
            const item = document.createElement('div');
            item.className = 'group-details-item';
            const isCurrentGroup = this.isCurrentGroupId(group.id, currentGroupId);
            if (isCurrentGroup) {
                item.classList.add('current');
            }

            const header = document.createElement('div');
            header.className = 'group-details-header';

            const title = document.createElement('div');
            title.className = 'group-details-title';

            const name = document.createElement('div');
            name.className = 'group-details-name';
            name.textContent = group.name || 'Untitled group';

            const uuid = document.createElement('div');
            uuid.className = 'group-details-uuid';
            uuid.textContent = group.id || '—';

            title.appendChild(name);
            title.appendChild(uuid);
            header.appendChild(title);

            if (isCurrentGroup) {
                const badge = document.createElement('span');
                badge.className = 'group-list-badge';
                badge.textContent = 'Current';
                header.appendChild(badge);
            }

            const description = document.createElement('div');
            description.className = 'group-details-description';
            description.textContent = `Description: ${group.description || '—'}`;

            const stats = document.createElement('div');
            stats.className = 'group-details-meta';

            const createdAt = document.createElement('span');
            createdAt.textContent = `Created: ${this.formatSettingsTimestamp(group.created_at)}`;

            const memberCount = document.createElement('span');
            memberCount.textContent =
                `Members: ${typeof group.member_count === 'number' ? this.formatCount(group.member_count) : '—'}`;

            const deviceCount = document.createElement('span');
            deviceCount.textContent =
                `Devices: ${typeof group.device_count === 'number' ? this.formatCount(group.device_count) : '—'}`;

            const epoch = document.createElement('span');
            epoch.textContent = `Current epoch ID: ${group.current_epoch_id || '—'}`;

            stats.appendChild(createdAt);
            stats.appendChild(memberCount);
            stats.appendChild(deviceCount);
            stats.appendChild(epoch);

            item.appendChild(header);
            item.appendChild(description);
            item.appendChild(stats);
            list.appendChild(item);
        });
    }

    openRemoveMemberModal() {
        const list = document.getElementById('removeMemberList');
        if (list) {
            list.innerHTML = '<div class="member-list-empty">Loading members...</div>';
        }
        const modal = document.getElementById('removeMemberModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.loadRemoveMemberList();
    }

    closeRemoveMemberModal() {
        const modal = document.getElementById('removeMemberModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    openListMembersModal() {
        const list = document.getElementById('listMembersList');
        if (list) {
            list.innerHTML = '<div class="member-list-empty">Loading members...</div>';
        }
        const modal = document.getElementById('listMembersModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.loadListMembers();
    }

    closeListMembersModal() {
        const modal = document.getElementById('listMembersModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    openAdminPinVerifyModal() {
        const modal = document.getElementById('adminPinVerifyModal');
        if (!modal) return;
        this.resetAdminPinVerifyModal();
        modal.style.display = 'flex';
        this.loadAdminPinVerifyMembers();
    }

    closeAdminPinVerifyModal() {
        const modal = document.getElementById('adminPinVerifyModal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.resetAdminPinVerifyModal();
    }

    resetAdminPinVerifyModal() {
        const memberSelect = document.getElementById('adminPinVerifyMemberSelect');
        const deviceSelect = document.getElementById('adminPinVerifyDeviceSelect');
        const fingerprintInput = document.getElementById('adminPinVerifyFingerprintInput');
        const submitBtn = document.getElementById('submitAdminPinVerifyBtn');

        this.adminPinVerifyMembers = [];
        this.setAdminPinVerifyError('');

        if (memberSelect) {
            memberSelect.innerHTML = '<option value="">Loading members...</option>';
            memberSelect.disabled = true;
            memberSelect.value = '';
        }
        if (deviceSelect) {
            deviceSelect.innerHTML = '<option value="">Select a member first</option>';
            deviceSelect.disabled = true;
            deviceSelect.value = '';
        }
        if (fingerprintInput) {
            fingerprintInput.value = '';
        }
        if (submitBtn) {
            submitBtn.disabled = true;
        }
    }

    setAdminPinVerifyError(message) {
        const errorEl = document.getElementById('adminPinVerifyError');
        if (!errorEl) return;
        const text = (message || '').trim();
        if (!text) {
            errorEl.style.display = 'none';
            errorEl.textContent = '';
            return;
        }
        errorEl.textContent = text;
        errorEl.style.display = 'block';
    }

    isCurrentUserMemberForPinVerify(member) {
        const memberEmail = String(member?.email || '').trim().toLowerCase();
        const currentEmail = String(this.currentUser || '').trim().toLowerCase();
        if (memberEmail && currentEmail && memberEmail === currentEmail) {
            return true;
        }

        if (this.currentDeviceId) {
            const devices = Array.isArray(member?.devices) ? member.devices : [];
            if (devices.some(device => String(device?.device_id || '') === this.currentDeviceId)) {
                return true;
            }
        }
        return false;
    }

    async loadAdminPinVerifyMembers() {
        const memberSelect = document.getElementById('adminPinVerifyMemberSelect');
        if (!memberSelect) return;

        try {
            const result = await invoke('get_group_member_details');
            if (!result?.success) {
                throw new Error(result?.error || 'Member list unavailable');
            }

            const allMembers = Array.isArray(result.data) ? result.data : [];
            this.adminPinVerifyMembers = allMembers.filter(member => !this.isCurrentUserMemberForPinVerify(member));
            this.renderAdminPinVerifyMemberOptions();
            this.handleAdminPinVerifyMemberChange();
        } catch (error) {
            console.error('Failed to load members for trust verification:', error);
            this.adminPinVerifyMembers = [];
            memberSelect.innerHTML = '<option value="">Failed to load members</option>';
            memberSelect.disabled = true;
            this.handleAdminPinVerifyMemberChange();
            this.setAdminPinVerifyError('Failed to load member/device list for verification.');
        }
    }

    renderAdminPinVerifyMemberOptions() {
        const memberSelect = document.getElementById('adminPinVerifyMemberSelect');
        if (!memberSelect) return;

        memberSelect.innerHTML = '';
        if (!Array.isArray(this.adminPinVerifyMembers) || this.adminPinVerifyMembers.length === 0) {
            memberSelect.innerHTML = '<option value="">No other members in current group</option>';
            memberSelect.disabled = true;
            return;
        }

        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = 'Select a member';
        memberSelect.appendChild(placeholder);

        this.adminPinVerifyMembers.forEach(member => {
            const option = document.createElement('option');
            option.value = member.user_id || member.email || '';
            option.textContent = `${member.email || 'Unknown user'} (${member.user_id || '—'})`;
            memberSelect.appendChild(option);
        });
        memberSelect.disabled = false;
        memberSelect.value = '';
    }

    getSelectedAdminPinVerifyMember() {
        const memberSelect = document.getElementById('adminPinVerifyMemberSelect');
        const memberKey = memberSelect?.value || '';
        if (!memberKey || !Array.isArray(this.adminPinVerifyMembers)) {
            return null;
        }
        return this.adminPinVerifyMembers.find(member => (member.user_id || member.email || '') === memberKey) || null;
    }

    handleAdminPinVerifyMemberChange() {
        const deviceSelect = document.getElementById('adminPinVerifyDeviceSelect');
        if (!deviceSelect) return;

        this.setAdminPinVerifyError('');
        const selectedMember = this.getSelectedAdminPinVerifyMember();
        deviceSelect.innerHTML = '';

        if (!selectedMember) {
            deviceSelect.innerHTML = '<option value="">Select a member first</option>';
            deviceSelect.disabled = true;
            this.updateAdminPinVerifySubmitState();
            return;
        }

        const devices = Array.isArray(selectedMember.devices) ? selectedMember.devices : [];
        if (devices.length === 0) {
            deviceSelect.innerHTML = '<option value="">No devices for selected member</option>';
            deviceSelect.disabled = true;
            this.updateAdminPinVerifySubmitState();
            return;
        }

        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = 'Select a device';
        deviceSelect.appendChild(placeholder);

        devices.forEach(device => {
            const option = document.createElement('option');
            option.value = device.device_id || '';
            const addedAt = device.added_at || device.created_at || device.last_seen || null;
            option.textContent = `${device.device_id || 'Unknown device'} • Added: ${this.formatSettingsTimestamp(addedAt)}`;
            deviceSelect.appendChild(option);
        });

        deviceSelect.disabled = false;
        deviceSelect.value = '';
        this.updateAdminPinVerifySubmitState();
    }

    updateAdminPinVerifySubmitState() {
        const memberSelect = document.getElementById('adminPinVerifyMemberSelect');
        const deviceSelect = document.getElementById('adminPinVerifyDeviceSelect');
        const fingerprintInput = document.getElementById('adminPinVerifyFingerprintInput');
        const submitBtn = document.getElementById('submitAdminPinVerifyBtn');
        if (!submitBtn) return;

        const hasMember = Boolean(memberSelect?.value);
        const hasDevice = Boolean(deviceSelect?.value);
        const fingerprint = String(fingerprintInput?.value || '').trim();
        const hasFingerprint = fingerprint.length > 0;
        submitBtn.disabled = !(hasMember && hasDevice && hasFingerprint);
    }

    async handleAdminPinVerifySubmit(event) {
        if (event?.preventDefault) {
            event.preventDefault();
        }

        const selectedMember = this.getSelectedAdminPinVerifyMember();
        const deviceSelect = document.getElementById('adminPinVerifyDeviceSelect');
        const fingerprintInput = document.getElementById('adminPinVerifyFingerprintInput');

        const deviceId = String(deviceSelect?.value || '').trim();
        const fingerprint = String(fingerprintInput?.value || '').trim();
        if (!selectedMember) {
            this.setAdminPinVerifyError('Select a member to verify.');
            return;
        }
        if (!deviceId) {
            this.setAdminPinVerifyError('Select a device to verify.');
            return;
        }
        if (!fingerprint) {
            this.setAdminPinVerifyError('Fingerprint is required.');
            return;
        }

        const targetDeviceId = String(deviceId).trim();
        const currentDeviceId = String(this.currentDeviceId || '').trim();
        if (currentDeviceId && targetDeviceId === currentDeviceId) {
            this.setAdminPinVerifyError('Cannot verify the current device from itself.');
            await this.showActionPrompt(
                'Cannot verify from this device',
                'This target device is your current device.',
                {
                    detail: 'Use an already trusted device in the group to verify this device fingerprint.',
                    primaryLabel: 'Close',
                    secondaryLabel: ''
                }
            );
            return;
        }

        this.setAdminPinVerifyError('');
        const userIdOrEmail = selectedMember.user_id || selectedMember.email;
        if (!userIdOrEmail) {
            this.setAdminPinVerifyError('Selected member is missing a user identifier.');
            return;
        }

        const command =
            `hybridcipher pin verify ${this.quoteCliArg(userIdOrEmail)} ${this.quoteCliArg(deviceId)} --fingerprint ${this.quoteCliArg(fingerprint)}`;
        this.closeAdminPinVerifyModal();
        this.runDashboardCliCommand(command);
    }

    openAdminEnrolledListModal() {
        const list = document.getElementById('adminEnrolledList');
        if (list) {
            list.innerHTML = '<div class="member-list-empty">Loading enrolled folders...</div>';
        }
        const summary = document.getElementById('adminEnrolledListSummary');
        if (summary) {
            summary.textContent = 'Loading summary...';
        }
        const modal = document.getElementById('adminEnrolledListModal');
        if (modal) {
            modal.style.display = 'flex';
        }
        this.loadAdminEnrolledList();
    }

    closeAdminEnrolledListModal() {
        const modal = document.getElementById('adminEnrolledListModal');
        if (modal) {
            modal.style.display = 'none';
        }
        const list = document.getElementById('adminEnrolledList');
        if (list) {
            list.innerHTML = '<div class="member-list-empty">Loading enrolled folders...</div>';
        }
        const summary = document.getElementById('adminEnrolledListSummary');
        if (summary) {
            summary.textContent = 'Loading summary...';
        }
    }

    async loadAdminEnrolledList() {
        const list = document.getElementById('adminEnrolledList');
        if (!list) return;
        const summary = document.getElementById('adminEnrolledListSummary');

        try {
            const result = await invoke('list_enrolled_folders');
            if (!result?.success) {
                throw new Error(result?.error || 'Enrolled folders unavailable');
            }

            const folders = Array.isArray(result.data) ? result.data : [];
            const activeFolders = folders
                .filter(folder => String(folder?.state || '').toLowerCase() === 'active')
                .sort((left, right) => {
                    const leftTs = Date.parse(left?.enrolled_at || '');
                    const rightTs = Date.parse(right?.enrolled_at || '');
                    if (Number.isFinite(leftTs) && Number.isFinite(rightTs) && leftTs !== rightTs) {
                        return rightTs - leftTs;
                    }
                    return String(left?.path || '').localeCompare(String(right?.path || ''));
                });

            this.renderAdminEnrolledList(activeFolders);
        } catch (error) {
            console.error('Failed to load admin enrolled folders:', error);
            list.innerHTML = '<div class="member-list-empty">Failed to load enrolled folders.</div>';
            if (summary) {
                summary.textContent = 'Summary unavailable';
            }
        }
    }

    renderAdminEnrolledList(folders) {
        const list = document.getElementById('adminEnrolledList');
        if (!list) return;

        this.renderAdminEnrolledListSummary(folders);
        list.innerHTML = '';
        if (!Array.isArray(folders) || folders.length === 0) {
            list.innerHTML = '<div class="member-list-empty">No enrolled folders in the current group.</div>';
            return;
        }

        folders.forEach(folder => {
            const row = document.createElement('div');
            row.className = 'member-list-item admin-enrolled-list-item';

            const meta = document.createElement('div');
            meta.className = 'member-list-meta';

            const folderName = document.createElement('div');
            folderName.className = 'member-list-email';
            const fallbackName = folder.path ? folder.path.split(/[/\\\\]/).filter(Boolean).pop() : '';
            folderName.textContent = folder.name || fallbackName || folder.path || 'Unknown folder';

            const folderPath = document.createElement('div');
            folderPath.className = 'member-list-details admin-enrolled-list-path';
            folderPath.textContent = folder.path || 'Path unavailable';

            const enrolledAt = this.formatSettingsTimestamp(folder.enrolled_at);
            const trackedBytes = Number(folder.tracked_bytes);
            const trackedSize =
                Number.isFinite(trackedBytes) && trackedBytes > 0 ? this.formatFileSize(trackedBytes) : '0 B';
            const trackedFiles = this.formatCount(folder.tracked_files || 0);
            const stats = document.createElement('div');
            stats.className = 'member-list-details admin-enrolled-list-stats';
            stats.textContent = `Enrolled: ${enrolledAt} • Size: ${trackedSize} • Files: ${trackedFiles}`;

            meta.appendChild(folderName);
            meta.appendChild(folderPath);
            meta.appendChild(stats);
            row.appendChild(meta);
            list.appendChild(row);
        });
    }

    renderAdminEnrolledListSummary(folders) {
        const summary = document.getElementById('adminEnrolledListSummary');
        if (!summary) return;

        const items = Array.isArray(folders) ? folders : [];
        const folderCount = items.length;
        const totalFiles = items.reduce((sum, folder) => sum + (Number(folder?.tracked_files) || 0), 0);
        const totalBytes = items.reduce((sum, folder) => sum + (Number(folder?.tracked_bytes) || 0), 0);
        const sizeLabel = totalBytes > 0 ? this.formatFileSize(totalBytes) : '0 B';
        const folderLabel = folderCount === 1 ? 'folder' : 'folders';

        summary.textContent =
            `${this.formatCount(folderCount)} ${folderLabel} • ${this.formatCount(totalFiles)} files • ${sizeLabel}`;
    }

    async loadListMembers() {
        const list = document.getElementById('listMembersList');
        if (!list) return;
        try {
            const result = await invoke('get_group_member_details');
            if (!result?.success) {
                throw new Error(result?.error || 'Member list unavailable');
            }
            const members = Array.isArray(result.data) ? result.data : [];
            this.renderListMembers(members);
        } catch (error) {
            console.error('Failed to load members list:', error);
            list.innerHTML = '<div class="member-list-empty">Failed to load members.</div>';
        }
    }

    renderListMembers(members) {
        const list = document.getElementById('listMembersList');
        if (!list) return;
        list.innerHTML = '';
        if (!members.length) {
            list.innerHTML = '<div class="member-list-empty">No members found.</div>';
            return;
        }

        members.forEach(member => {
            const item = document.createElement('div');
            item.className = 'member-details-item';

            const header = document.createElement('div');
            header.className = 'member-details-header';

            const email = document.createElement('div');
            email.className = 'member-details-email';
            email.textContent = member.email || 'Unknown user';

            const uuid = document.createElement('div');
            uuid.className = 'member-details-uuid';
            uuid.textContent = member.user_id || '—';

            header.appendChild(email);
            header.appendChild(uuid);

            const meta = document.createElement('div');
            meta.className = 'member-details-meta';
            const joinedAt = this.formatSettingsTimestamp(member.joined_at);
            const lastSeen = this.formatSettingsTimestamp(member.last_seen);
            meta.textContent = `Joined: ${joinedAt} • Last seen: ${lastSeen}`;

            const devicesBlock = document.createElement('div');
            devicesBlock.className = 'member-details-devices';
            const devices = Array.isArray(member.devices) ? member.devices : [];
            if (!devices.length) {
                devicesBlock.textContent = 'Devices: —';
            } else {
                const label = document.createElement('div');
                label.textContent = 'Devices:';
                devicesBlock.appendChild(label);
                devices.forEach(device => {
                    const chip = document.createElement('div');
                    chip.className = 'member-device-chip';
                    const name = device.device_name ? `${device.device_name}` : device.device_id;
                    const seen = this.formatSettingsTimestamp(device.last_seen);
                    chip.textContent = `${name} • ${seen}`;
                    devicesBlock.appendChild(chip);
                });
            }

            item.appendChild(header);
            item.appendChild(meta);
            item.appendChild(devicesBlock);
            list.appendChild(item);
        });
    }

    async loadRemoveMemberList() {
        const list = document.getElementById('removeMemberList');
        if (!list) return;
        try {
            const result = await invoke('get_group_members');
            if (!result?.success) {
                throw new Error(result?.error || 'Members unavailable');
            }
            const members = Array.isArray(result.data) ? result.data : [];
            this.renderRemoveMemberList(members);
        } catch (error) {
            console.error('Failed to load group members:', error);
            list.innerHTML = '<div class="member-list-empty">Failed to load members.</div>';
        }
    }

    renderRemoveMemberList(members) {
        const list = document.getElementById('removeMemberList');
        if (!list) return;
        list.innerHTML = '';
        if (!members.length) {
            list.innerHTML = '<div class="member-list-empty">No members found.</div>';
            return;
        }

        members.forEach(member => {
            const row = document.createElement('div');
            row.className = 'member-list-item';

            const meta = document.createElement('div');
            meta.className = 'member-list-meta';

            const email = document.createElement('div');
            email.className = 'member-list-email';
            email.textContent = member.email || 'Unknown user';

            meta.appendChild(email);

            if (member.user_id) {
                const details = document.createElement('div');
                details.className = 'member-list-details';
                details.textContent = member.user_id;
                meta.appendChild(details);
            }

            const action = document.createElement('button');
            action.type = 'button';
            action.className = 'btn btn-secondary btn-small';
            action.textContent = member.is_owner ? 'Owner' : 'Remove';
            action.disabled = Boolean(member.is_owner);
            if (member.is_owner) {
                action.title = 'Group owner cannot be removed.';
            } else {
                action.addEventListener('click', (event) => {
                    event.stopPropagation();
                    this.confirmMemberRemoval(member);
                });
            }

            row.appendChild(meta);
            row.appendChild(action);
            list.appendChild(row);
        });
    }

    async confirmMemberRemoval(member) {
        const targetLabel = member.email || member.user_id || 'this member';
        const response = await this.promptForText(
            `Type REMOVE to remove ${targetLabel}.`,
            { title: 'Confirm removal', placeholder: 'REMOVE', submitLabel: 'Remove' }
        );
        if (response === null) {
            return;
        }
        if (response.trim() !== 'REMOVE') {
            this.showNotification('Removal cancelled. Type REMOVE to confirm.', 'warning');
            return;
        }

        const targetId = member.user_id || member.email;
        if (!targetId) {
            this.showNotification('Member identifier missing.', 'error');
            return;
        }

        this.showActionProgressModal(`Removing ${targetLabel}...`);
        try {
            const cliResult = await this.runCliCommandRaw(
                `hybridcipher remove-member ${this.quoteCliArg(targetId)} --yes`
            );
            const output = this.stripAnsi(`${cliResult.stdout || ''}\n${cliResult.stderr || ''}`.trim());
            if (typeof cliResult.status === 'number' && cliResult.status !== 0) {
                this.hideActionProgressModal();
                const { message, detail } = this.extractCliErrorMessage(output, 'Member removal failed.');
                await this.showActionPrompt(
                    'Remove member failed',
                    message,
                    {
                        detail,
                        primaryLabel: 'Close',
                        secondaryLabel: null
                    }
                );
                return;
            }

            this.hideActionProgressModal();
            await this.loadRemoveMemberList();
            this.refreshAdminGroupStatus();

            this.closeRemoveMemberModal();
            await this.beginRekeyFlow({
                title: 'Member removed',
                message: `Removed ${targetLabel}. Start rekey now?`
            });
        } catch (error) {
            console.error('Remove member failed:', error);
            this.hideActionProgressModal();
            const { message, detail } = this.extractCliErrorMessage(
                error?.message || '',
                'Member removal failed.'
            );
            await this.showActionPrompt(
                'Remove member failed',
                message,
                {
                    detail,
                    primaryLabel: 'Close',
                    secondaryLabel: null
                }
            );
        } finally {
            this.hideActionProgressModal();
        }
    }

    async beginRekeyFlow({ title, message, progressMessage = 'Preparing rekey...' }) {
        const startRekey = await this.showActionPrompt(
            title,
            message,
            {
                primaryLabel: 'Start rekey',
                secondaryLabel: 'Not now'
            }
        );
        if (startRekey !== true) {
            return;
        }

        this.setAdminPanelVisible(false);
        await this.createTerminalTab();
        const command = 'hybridcipher rekey start --activation-delay immediate --local-migration defer';
        await this.executeCommandDirectly(command, true, { returnSessionId: true });
        const progressMessages = Array.isArray(progressMessage)
            ? progressMessage
            : [
                'Preparing rekey...',
                'Verifying device security...',
                'Auditing active devices...',
                'Scanning coverage state...',
                'Generating Welcome payloads...',
                'Publishing new epoch descriptor...'
            ];
        this.showActionProgressModal(progressMessages);
    }

    async promptRekeyMigrationChoice(sessionId) {
        const startMigration = await this.showActionPrompt(
            'Start migration now?',
            'Run local coverage migration now?',
            {
                primaryLabel: 'Start now',
                secondaryLabel: 'Not now'
            }
        );

        const shouldMigrate = startMigration === true;
        this.suppressPromptEcho(sessionId, 1, { durationMs: 12000 });
        this.sendInputToSession(sessionId, shouldMigrate ? 'y\r' : 'n\r');
        delete this.promptResponders[sessionId];

        if (!shouldMigrate) {
            await this.showMigrationDeferredPrompt();
        }
    }

    async showMigrationDeferredPrompt() {
        await this.showActionPrompt(
            'Migration deferred',
            'When ready, run: hybridcipher coverage migration',
            {
                primaryLabel: 'OK',
                secondaryLabel: null
            }
        );
    }

    async handleRekeyStartPrompt() {
        await this.beginRekeyFlow({
            title: 'Start rekey',
            message: 'Start a new rekey operation for the active group?'
        });
    }

    async copyRecoveryCode() {
        if (!this.recoveryCodeValue) {
            return;
        }
        try {
            await navigator.clipboard.writeText(this.recoveryCodeValue);
            this.showNotification('Recovery code copied to clipboard', 'success');
        } catch (err) {
            console.error('Failed to copy recovery code:', err);
            this.showNotification('Failed to copy recovery code', 'error');
        }
    }

    // ========================================================================
    // Feedback Modal
    // ========================================================================

    openFeedbackModal() {
        // Reset form
        document.getElementById('feedbackForm')?.reset();
        document.getElementById('attachmentList').innerHTML = '';
        this.feedbackAttachments = [];

        // Pre-fill email if logged in
        const emailInput = document.getElementById('feedbackEmail');
        if (emailInput && this.currentUser) {
            emailInput.value = this.currentUser;
        }

        document.getElementById('feedbackModal').style.display = 'flex';
    }

    closeFeedbackModal() {
        document.getElementById('feedbackModal').style.display = 'none';
    }

    async addFeedbackAttachment() {
        try {
            const tauriGlobal = window.__TAURI__;
            if (!tauriGlobal?.dialog?.open) {
                this.showNotification('File picker not available', 'error');
                return;
            }

            const selected = await tauriGlobal.dialog.open({
                multiple: true,
                title: 'Select files to attach',
                filters: [
                    { name: 'All Files', extensions: ['*'] },
                    { name: 'Images', extensions: ['png', 'jpg', 'jpeg', 'gif', 'webp'] },
                    { name: 'Logs', extensions: ['log', 'txt'] },
                ]
            });

            if (!selected) return;

            // Handle both single and multiple selection
            const paths = Array.isArray(selected) ? selected : [selected];

            if (!this.feedbackAttachments) {
                this.feedbackAttachments = [];
            }

            for (const path of paths) {
                // Avoid duplicates
                if (this.feedbackAttachments.includes(path)) continue;

                this.feedbackAttachments.push(path);
                this.renderAttachmentChip(path);
            }
        } catch (error) {
            console.error('Failed to add attachment:', error);
            this.showNotification('Failed to add attachment', 'error');
        }
    }

    renderAttachmentChip(path) {
        const list = document.getElementById('attachmentList');
        const filename = path.split('/').pop() || path.split('\\').pop() || 'file';

        const chip = document.createElement('div');
        chip.className = 'attachment-chip';
        chip.dataset.path = path;
        chip.innerHTML = `
            <span class="filename" title="${this.escapeHtmlAttr(path)}">${this.escapeHtml(filename)}</span>
            <button type="button" class="remove-attachment" title="Remove">&times;</button>
        `;

        chip.querySelector('.remove-attachment').addEventListener('click', () => {
            this.feedbackAttachments = this.feedbackAttachments.filter(p => p !== path);
            chip.remove();
        });

        list.appendChild(chip);
    }

    async handleFeedbackSubmit(e) {
        e.preventDefault();

        const title = document.getElementById('feedbackTitle')?.value?.trim();
        const description = document.getElementById('feedbackDescription')?.value?.trim();
        const email = document.getElementById('feedbackEmail')?.value?.trim();
        const attachmentPaths = this.feedbackAttachments || [];

        if (!title || !description || !email) {
            this.showNotification('Please fill in title, description, and email', 'error');
            return;
        }

        const submitBtn = document.getElementById('submitFeedbackBtn');
        submitBtn?.classList.add('loading');

        try {
            const result = await invoke('submit_feedback', {
                title,
                description,
                userEmail: email,
                attachmentPaths,
            });

            if (result.success) {
                this.showNotification('Feedback sent successfully. Thank you!', 'success');
                this.closeFeedbackModal();
            } else {
                this.showNotification(result.message || 'Failed to send feedback', 'error');
            }
        } catch (error) {
            console.error('Failed to submit feedback:', error);
            this.showNotification('Failed to send feedback: ' + error, 'error');
        } finally {
            submitBtn?.classList.remove('loading');
        }
    }

    formatSettingsTimestamp(value) {
        if (!value) return '—';
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) {
            return value;
        }
        const pad = num => String(num).padStart(2, '0');
        const year = parsed.getFullYear();
        const month = pad(parsed.getMonth() + 1);
        const day = pad(parsed.getDate());
        const hours = pad(parsed.getHours());
        const minutes = pad(parsed.getMinutes());
        const seconds = pad(parsed.getSeconds());
        const offsetMinutes = -parsed.getTimezoneOffset();
        const sign = offsetMinutes >= 0 ? '+' : '-';
        const absOffset = Math.abs(offsetMinutes);
        const offsetHours = pad(Math.floor(absOffset / 60));
        const offsetMins = pad(absOffset % 60);
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC${sign}${offsetHours}:${offsetMins}`;
    }

    formatShortId(value, maxLength = 8) {
        if (!value) return '—';
        if (value.length <= maxLength) return value;
        return `${value.slice(0, maxLength)}…`;
    }

    formatCount(value) {
        const number = Number(value);
        if (!Number.isFinite(number)) return '0';
        return new Intl.NumberFormat().format(number);
    }

    stripAnsi(value) {
        if (!value) return '';
        return value.replace(/\x1b\[[0-9;]*m/g, '');
    }

    extractCliErrorMessage(output, fallback = 'Command failed.') {
        const cleaned = this.stripAnsi(output || '').trim();
        if (!cleaned) {
            return { message: fallback, detail: '' };
        }
        const lines = cleaned.split('\n').map(line => line.trim()).filter(Boolean);
        if (lines.length === 0) {
            return { message: fallback, detail: '' };
        }
        const errorLine = lines.find(line => /failed|error|denied|unauthorized|forbidden|cancelled/i.test(line));
        const message = errorLine || lines[lines.length - 1] || fallback;
        const detailLines = lines.filter(line => line !== message);
        const detail = detailLines.slice(-3).join('\n');
        return { message, detail };
    }

    updateAdminIdentityLabels() {
        const deviceEl = document.getElementById('adminDeviceLabel');

        if (deviceEl) {
            deviceEl.textContent = this.currentDeviceId
                ? `Device ID: ${this.currentDeviceId}`
                : 'Device ID: —';
        }
    }

    refreshAdminDashboard() {
        this.updateAdminIdentityLabels();

        const pendingValueEl = document.getElementById('adminPendingActionsValue');
        const pendingMetaEl = document.getElementById('adminPendingActionsMeta');
        const membersValueEl = document.getElementById('adminTeamMembersValue');
        const membersMetaEl = document.getElementById('adminTeamMembersMeta');
        const coverageStatusEl = document.getElementById('adminCoverageStatus');
        const coverageMetaEl = document.getElementById('adminCoverageMeta');
        const serverValueEl = document.getElementById('adminServerStatusValue');
        const serverMetaEl = document.getElementById('adminServerStatusMeta');

        if (pendingValueEl) pendingValueEl.textContent = 'Loading pending actions...';
        if (pendingMetaEl) pendingMetaEl.textContent = '—';
        if (membersValueEl) membersValueEl.textContent = 'Loading members...';
        if (membersMetaEl) membersMetaEl.textContent = '—';
        if (coverageStatusEl) coverageStatusEl.textContent = 'Loading coverage...';
        if (coverageMetaEl) coverageMetaEl.textContent = '—';
        if (serverValueEl) serverValueEl.textContent = 'Loading status...';
        if (serverMetaEl) serverMetaEl.textContent = 'Last: —';

        this.refreshSettingsStatus();
        this.refreshAdminPendingActionsSummary();
        this.refreshAdminTeamMembersSummary();
        this.refreshAdminCoverageSummary();
        this.refreshAdminServerStatusSummary();
    }

    async initializeOperationsRefresh() {
        const intervalSecs = await this.fetchOperationsRefreshIntervalSecs();
        this.operationsRefreshIntervalSecs = intervalSecs;
        await this.refreshOperationsQueues();
        this.startOperationsRefreshTimer(intervalSecs);
    }

    async fetchOperationsRefreshIntervalSecs() {
        try {
            const result = await invoke('get_operations_refresh_interval_secs');
            const rawValue = result?.success ? result.data : null;
            const parsed = Number(rawValue);
            if (Number.isFinite(parsed) && parsed >= 0) {
                return Math.floor(parsed);
            }
        } catch (error) {
            console.warn('Failed to load operations refresh interval:', error);
        }
        return 300;
    }

    startOperationsRefreshTimer(intervalSecs) {
        if (this.operationsRefreshTimer) {
            clearInterval(this.operationsRefreshTimer);
            this.operationsRefreshTimer = null;
        }

        if (!Number.isFinite(intervalSecs) || intervalSecs <= 0) {
            return;
        }

        this.operationsRefreshTimer = setInterval(() => {
            if (!this.isLoggedIn) {
                return;
            }
            this.refreshOperationsQueues();
        }, intervalSecs * 1000);
    }

    stopOperationsRefreshTimer() {
        if (this.operationsRefreshTimer) {
            clearInterval(this.operationsRefreshTimer);
            this.operationsRefreshTimer = null;
        }
    }

    async refreshOperationsQueues() {
        if (this.operationsRefreshInFlight) {
            return;
        }
        this.operationsRefreshInFlight = true;
        try {
            const refreshIssue = this.activeQueueDetails === 'issue';
            const refreshStale = this.activeQueueDetails === 'stale';
            const refreshUnverified = this.activeQueueDetails === 'unverified';
            await Promise.all([
                this.loadPendingDevicesQueue({ suppressDetails: !refreshIssue }),
                this.loadStaleDevicesQueue({ suppressDetails: !refreshStale }),
                this.loadUnverifiedDevicesQueue({ suppressDetails: !refreshUnverified })
            ]);
            this.updateAdminPendingActionsCard();
        } finally {
            this.operationsRefreshInFlight = false;
        }
    }

    async refreshAdminPendingActionsSummary() {
        const valueEl = document.getElementById('adminPendingActionsValue');
        const metaEl = document.getElementById('adminPendingActionsMeta');
        if (valueEl) valueEl.textContent = 'Loading pending actions...';
        if (metaEl) metaEl.textContent = '—';
        await this.refreshOperationsQueues();
        this.updateAdminPendingActionsCard();
    }

    updateAdminPendingActionsCard() {
        const valueEl = document.getElementById('adminPendingActionsValue');
        const metaEl = document.getElementById('adminPendingActionsMeta');
        if (!valueEl || !metaEl) return;

        const getCount = (cache, queueRowId) => {
            if (Array.isArray(cache)) {
                return cache.length;
            }
            const queueRow = document.getElementById(queueRowId);
            const raw = queueRow?.querySelector('.queue-count')?.textContent?.trim() || '';
            const parsed = Number(raw);
            return Number.isFinite(parsed) ? parsed : null;
        };

        const pending = getCount(this.pendingDevicesCache, 'adminIssueWelcomeQueue');
        const stale = getCount(this.staleDevicesCache, 'adminStaleDevicesQueue');
        const unverified = getCount(this.unverifiedDevicesCache, 'adminUnverifiedDevicesQueue');

        const counts = [pending, stale, unverified];
        if (counts.some(count => count === null)) {
            valueEl.textContent = 'Pending actions: —';
            metaEl.textContent = 'Need attention';
            return;
        }

        const total = (pending || 0) + (stale || 0) + (unverified || 0);
        const label = `Pending actions: ${this.formatCount(total)}`;

        if (total > 0) {
            valueEl.innerHTML = `${label} <span class="status-dot danger" aria-hidden="true"></span>`;
            metaEl.textContent = 'Need attention';
        } else {
            valueEl.innerHTML = `${label} <span class="status-dot ok" aria-hidden="true"></span>`;
            metaEl.textContent = 'All clear';
        }
    }

    async refreshAdminTeamMembersSummary() {
        const valueEl = document.getElementById('adminTeamMembersValue');
        const metaEl = document.getElementById('adminTeamMembersMeta');
        if (!valueEl || !metaEl) return;

        valueEl.textContent = 'Loading members...';
        metaEl.textContent = '—';

        try {
            const [membersResp, staleResp] = await Promise.all([
                invoke('get_group_member_details'),
                invoke('get_stale_devices')
            ]);

            if (!membersResp?.success) {
                throw new Error(membersResp?.error || 'Members unavailable');
            }

            const members = Array.isArray(membersResp.data) ? membersResp.data : [];
            const staleDevices = staleResp?.success && Array.isArray(staleResp.data) ? staleResp.data : [];
            const staleIds = new Set(staleDevices.map(device => device?.device_id).filter(Boolean));

            const allDeviceIds = new Set();
            let activeUsers = 0;

            members.forEach(member => {
                const devices = Array.isArray(member?.devices) ? member.devices : [];
                let hasNonStaleDevice = false;
                devices.forEach(device => {
                    const deviceId = typeof device === 'string' ? device : device?.device_id;
                    if (!deviceId) return;
                    allDeviceIds.add(deviceId);
                    if (!staleIds.has(deviceId)) {
                        hasNonStaleDevice = true;
                    }
                });
                if (hasNonStaleDevice) {
                    activeUsers += 1;
                }
            });

            let nonStaleDevices = 0;
            allDeviceIds.forEach(deviceId => {
                if (!staleIds.has(deviceId)) {
                    nonStaleDevices += 1;
                }
            });

            const userLabel = activeUsers === 1 ? 'active user' : 'active users';
            const deviceLabel = nonStaleDevices === 1 ? 'device' : 'devices';
            valueEl.textContent = `${this.formatCount(activeUsers)} ${userLabel}`;
            metaEl.textContent = `${this.formatCount(nonStaleDevices)} ${deviceLabel} (non-stale)`;
        } catch (error) {
            console.warn('Failed to load team members summary:', error);
            valueEl.textContent = 'Members unavailable';
            metaEl.textContent = '—';
        }
    }

    formatRelativeAge(msAgo) {
        const seconds = Math.floor(Number(msAgo) / 1000);
        if (!Number.isFinite(seconds) || seconds < 0) {
            return '—';
        }
        if (seconds < 10) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 48) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        return `${days}d ago`;
    }

    summarizeServerTrustStatus(statusLabel) {
        if (!statusLabel) return '';
        if (/^Verified/i.test(statusLabel)) return 'Verified';
        if (/^Pinned/i.test(statusLabel)) return 'Pinned - verify safety number';
        if (/^First contact/i.test(statusLabel)) return 'First contact - verify safety number';
        return statusLabel;
    }

    async refreshAdminServerStatusSummary() {
        const valueEl = document.getElementById('adminServerStatusValue');
        const metaEl = document.getElementById('adminServerStatusMeta');
        if (!valueEl || !metaEl) return;

        const lastUpdatedAt = this.adminServerStatusLastUpdatedAt;
        metaEl.textContent = lastUpdatedAt ? `Last: ${this.formatRelativeAge(Date.now() - lastUpdatedAt)}` : 'Last: —';

        try {
            const output = await this.runCliStatusCommand('hybridcipher server-trust show --no-color');
            const status = this.parseServerTrustStatus(output);
            const summary = this.summarizeServerTrustStatus(status) || 'Status unavailable';
            if (summary === 'Verified') {
                valueEl.innerHTML = `${summary} <span class="status-dot ok" aria-hidden="true"></span>`;
            } else if (/verify safety number/i.test(summary) || /^First contact/i.test(summary)) {
                valueEl.innerHTML = `${summary} <span class="status-dot danger" aria-hidden="true"></span>`;
            } else {
                valueEl.textContent = summary;
            }
            this.adminServerStatusLastUpdatedAt = Date.now();
            metaEl.textContent = 'Last: just now';
        } catch (error) {
            console.warn('Failed to load server status:', error);
            const message = error?.message || '';
            if (/not authenticated|login/i.test(message)) {
                valueEl.textContent = 'Sign in to check status';
            } else if (/cli binary not available/i.test(message)) {
                valueEl.textContent = 'CLI unavailable';
            } else {
                valueEl.textContent = 'Unable to load status';
            }
            const last = this.adminServerStatusLastUpdatedAt;
            metaEl.textContent = last ? `Last: ${this.formatRelativeAge(Date.now() - last)}` : 'Last: —';
        }
    }

    async refreshAdminGroupStatus() {
        const groupStatusEl = document.getElementById('adminCurrentGroupStatus');
        if (!groupStatusEl) return;

        const context = await this.getActiveGroupContext();
        if (context.groupName || context.groupId) {
            groupStatusEl.textContent = context.groupName || context.groupId;
            return;
        }

        try {
            const output = await this.runCliStatusCommand('hybridcipher current-group --no-color');
            const status = this.parseCurrentGroupStatus(output);
            groupStatusEl.textContent = status || 'Active group unavailable';
        } catch (error) {
            console.warn('Failed to load current group status:', error);
            groupStatusEl.textContent = 'Active group unavailable';
        }
    }

    async refreshAdminTrustStatus() {
        return this.refreshAdminServerStatusSummary();
    }

    async refreshAdminCoverageSummary() {
        const statusEl = document.getElementById('adminCoverageStatus');
        const metaEl = document.getElementById('adminCoverageMeta');
        if (!statusEl || !metaEl) return;

        try {
            const response = await invoke('list_enrolled_folders');
            if (!response?.success) {
                throw new Error(response?.error || 'Coverage data unavailable');
            }

            const folders = response.data || [];
            const activeRoots = folders.filter(folder => folder?.state === 'active');

            if (activeRoots.length === 0) {
                statusEl.textContent = '0% covered';
                metaEl.textContent = '0 enrolled folders • 0 files';
                return;
            }

            const trackedFiles = activeRoots.reduce((sum, folder) => sum + (folder.tracked_files || 0), 0);
            const orphanedFiles = activeRoots.reduce((sum, folder) => sum + (folder.orphaned_files || 0), 0);
            const unmanagedFiles = activeRoots.reduce((sum, folder) => sum + (folder.unmanaged_files || 0), 0);
            const totalKnown = trackedFiles + orphanedFiles + unmanagedFiles;
            const folderCount = activeRoots.filter(folder => folder.kind === 'folder').length || activeRoots.length;
            const percentTracked = totalKnown > 0 ? Math.round((trackedFiles / totalKnown) * 100) : 0;

            statusEl.textContent = `${percentTracked}% covered`;
            metaEl.textContent = `${this.formatCount(folderCount)} enrolled folders • ${this.formatCount(totalKnown)} files`;
        } catch (error) {
            console.warn('Failed to load coverage summary:', error);
            statusEl.textContent = 'Coverage unavailable';
            metaEl.textContent = '—';
        }
    }

    async runCliStatusCommand(rawCommand) {
        let cliPath;
        try {
            cliPath = await this.getCliBinaryPath();
        } catch (error) {
            throw new Error('CLI binary not available');
        }

        const command = this.resolveCliCommand(rawCommand, cliPath);
        const result = await invoke('run_shell_command', { command, cwd: null });
        if (!result?.success || !result?.data) {
            throw new Error(result?.error || 'CLI command failed');
        }

        const stdout = result.data.stdout || '';
        const stderr = result.data.stderr || '';
        return `${stdout}\n${stderr}`.trim();
    }

    async runCliCommandRaw(rawCommand) {
        let cliPath;
        try {
            cliPath = await this.getCliBinaryPath();
        } catch (error) {
            throw new Error('CLI binary not available');
        }

        const command = this.resolveCliCommand(rawCommand, cliPath);
        const result = await invoke('run_shell_command', { command, cwd: null });
        if (!result?.success || !result.data) {
            throw new Error(result?.error || 'CLI command failed');
        }
        return result.data;
    }

    escapeShellInput(value) {
        if (!value) return '';
        return value
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"')
            .replace(/\$/g, '\\$')
            .replace(/`/g, '\\`');
    }

    async runCliCommandWithInput(rawCommand, inputLines = []) {
        let cliPath;
        try {
            cliPath = await this.getCliBinaryPath();
        } catch (error) {
            throw new Error('CLI binary not available');
        }

        const command = this.resolveCliCommand(rawCommand, cliPath);
        const joined = Array.isArray(inputLines) ? inputLines.join('\n') + '\n' : `${inputLines}\n`;
        const result = await invoke('run_shell_command', { command, cwd: null, input: joined });
        if (!result?.success || !result.data) {
            throw new Error(result?.error || 'CLI command failed');
        }
        return result.data;
    }

    showIssueWelcomeQueue() {
        this.setQueueDetailsHeader(
            'Issue welcome',
            'Pending devices waiting for a Welcome message.'
        );
        this.activeQueueDetails = 'issue';
        this.setQueueDetailsPagination({ visible: false });
        this.loadPendingDevicesQueue();
    }

    showStaleDevicesQueue() {
        this.setQueueDetailsHeader(
            'Stale devices',
            'Devices in the active group that need review.'
        );
        this.activeQueueDetails = 'stale';
        this.loadStaleDevicesQueue();
    }

    showUnverifiedDevicesQueue() {
        this.setQueueDetailsHeader(
            'Unverified devices',
            'Devices pending verification in the active group.'
        );
        this.activeQueueDetails = 'unverified';
        this.loadUnverifiedDevicesQueue();
    }

    setQueueDetailsHeader(title, subtitle) {
        const titleEl = document.getElementById('adminQueueDetailsTitle');
        const subtitleEl = document.getElementById('adminQueueDetailsSubtitle');
        if (titleEl) titleEl.textContent = title;
        if (subtitleEl) subtitleEl.textContent = subtitle;
    }

    setQueueDetailsMessage(className, message) {
        const body = document.getElementById('adminQueueDetailsBody');
        if (!body) return;
        body.innerHTML = `<div class="${className}">${message}</div>`;
    }

    setQueueDetailsPagination({ visible, page = 1, totalPages = 1 } = {}) {
        const footer = document.getElementById('adminQueueDetailsFooter');
        const info = document.getElementById('adminQueuePageInfo');
        const prevBtn = document.getElementById('adminQueuePrevBtn');
        const nextBtn = document.getElementById('adminQueueNextBtn');
        if (!footer || !info || !prevBtn || !nextBtn) return;

        if (!visible) {
            footer.hidden = true;
            return;
        }

        footer.hidden = false;
        info.textContent = `Page ${page} of ${totalPages}`;
        prevBtn.disabled = page <= 1;
        nextBtn.disabled = page >= totalPages;
    }

    refreshActiveQueueDetails() {
        if (this.activeQueueDetails === 'issue') {
            this.loadPendingDevicesQueue();
        } else if (this.activeQueueDetails === 'unverified') {
            this.loadUnverifiedDevicesQueue();
        } else if (this.activeQueueDetails === 'stale') {
            this.loadStaleDevicesQueue();
        } else {
            this.setQueueDetailsMessage('queue-details-empty', 'Select a queue to view its list.');
            this.setQueueDetailsPagination({ visible: false });
        }
    }

    async loadPendingDevicesQueue(options = {}) {
        const { suppressDetails = false } = options;
        const queue = document.getElementById('adminIssueWelcomeQueue');
        if (!suppressDetails) {
            this.setQueueDetailsMessage('queue-details-loading', 'Loading pending devices...');
        }
        try {
            const result = await invoke('get_pending_devices');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Pending devices unavailable');
            }
            const devices = result.data;
            this.updateQueueCount(queue, devices.length);
            this.pendingDevicesCache = devices;
            this.updateAdminPendingActionsCard();
            if (!suppressDetails) {
                this.pendingDevicesPage = 1;
                this.renderPendingDevicesPage();
            }
        } catch (error) {
            console.error('Pending devices load failed:', error);
            if (!suppressDetails) {
                this.setQueueDetailsMessage('queue-details-error', 'Failed to load pending devices.');
                this.setQueueDetailsPagination({ visible: false });
            }
        }
    }

    async loadStaleDevicesQueue(options = {}) {
        const { suppressDetails = false } = options;
        const queue = document.getElementById('adminStaleDevicesQueue');
        if (!suppressDetails) {
            this.setQueueDetailsMessage('queue-details-loading', 'Loading stale devices...');
        }
        try {
            const result = await invoke('get_stale_devices');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Stale devices unavailable');
            }
            const devices = result.data;
            this.updateQueueCount(queue, devices.length);
            this.staleDevicesCache = devices;
            this.updateAdminPendingActionsCard();
            if (!suppressDetails) {
                this.staleDevicesPage = 1;
                this.renderStaleDevicesPage();
            }
        } catch (error) {
            console.error('Stale devices load failed:', error);
            if (!suppressDetails) {
                this.setQueueDetailsMessage('queue-details-error', 'Failed to load stale devices.');
                this.setQueueDetailsPagination({ visible: false });
            }
        }
    }

    async loadUnverifiedDevicesQueue(options = {}) {
        const { suppressDetails = false } = options;
        const queue = document.getElementById('adminUnverifiedDevicesQueue');
        if (!suppressDetails) {
            this.setQueueDetailsMessage('queue-details-loading', 'Loading unverified devices...');
        }
        try {
            const result = await invoke('get_unverified_devices');
            if (!result?.success || !result.data) {
                throw new Error(result?.error || 'Unverified devices unavailable');
            }
            const devices = result.data;
            this.updateQueueCount(queue, devices.length);
            this.unverifiedDevicesCache = devices;
            this.updateAdminPendingActionsCard();
            if (!suppressDetails) {
                this.unverifiedDevicesPage = 1;
                this.renderUnverifiedDevicesPage();
            }
        } catch (error) {
            console.error('Unverified devices load failed:', error);
            if (!suppressDetails) {
                this.setQueueDetailsMessage('queue-details-error', 'Failed to load unverified devices.');
                this.setQueueDetailsPagination({ visible: false });
            }
        }
    }

    updateQueueCount(queue, count) {
        if (!queue) return;
        const countEl = queue.querySelector('.queue-count');
        if (countEl) {
            countEl.textContent = Number.isFinite(count) ? String(count) : '—';
        }
        const hasAlert = Number.isFinite(count) && count > 0;
        queue.classList.toggle('has-alert', hasAlert);
    }

    renderPendingDevices(devices) {
        const body = document.getElementById('adminQueueDetailsBody');
        if (!body) return;
        body.innerHTML = '';

        if (!devices.length) {
            body.innerHTML = '<div class="queue-details-empty">No pending devices.</div>';
            return;
        }

        devices.forEach(device => {
            const row = document.createElement('div');
            row.className = 'queue-device-row';
            row.innerHTML = `
                <div class="queue-device-info">
                    <div class="queue-device-user">${this.escapeHtml(device.device_id)}</div>
                    <div class="queue-device-id">${this.escapeHtml(device.email || 'Unknown user')}</div>
                </div>
            `;
            const action = document.createElement('button');
            action.className = 'btn btn-secondary btn-small';
            action.type = 'button';
            action.textContent = 'Issue';
            action.addEventListener('click', () => this.issueWelcomeForDevice(device.device_id));
            row.appendChild(action);
            body.appendChild(row);
        });
    }

    changeQueuePage(delta) {
        if (this.activeQueueDetails === 'issue') {
            const totalPages = Math.max(1, Math.ceil(this.pendingDevicesCache.length / this.pendingDevicesPageSize));
            const nextPage = Math.min(totalPages, Math.max(1, this.pendingDevicesPage + delta));
            if (nextPage === this.pendingDevicesPage) return;
            this.pendingDevicesPage = nextPage;
            this.renderPendingDevicesPage();
            return;
        }
        if (this.activeQueueDetails === 'unverified') {
            const totalPages = Math.max(1, Math.ceil(this.unverifiedDevicesCache.length / this.unverifiedDevicesPageSize));
            const nextPage = Math.min(totalPages, Math.max(1, this.unverifiedDevicesPage + delta));
            if (nextPage === this.unverifiedDevicesPage) return;
            this.unverifiedDevicesPage = nextPage;
            this.renderUnverifiedDevicesPage();
            return;
        }
        if (this.activeQueueDetails === 'stale') {
            const totalPages = Math.max(1, Math.ceil(this.staleDevicesCache.length / this.staleDevicesPageSize));
            const nextPage = Math.min(totalPages, Math.max(1, this.staleDevicesPage + delta));
            if (nextPage === this.staleDevicesPage) return;
            this.staleDevicesPage = nextPage;
            this.renderStaleDevicesPage();
        }
    }

    renderPendingDevicesPage() {
        const totalItems = this.pendingDevicesCache.length;
        if (!totalItems) {
            this.renderPendingDevices([]);
            this.setQueueDetailsPagination({ visible: false });
            return;
        }

        const totalPages = Math.max(1, Math.ceil(totalItems / this.pendingDevicesPageSize));
        const start = (this.pendingDevicesPage - 1) * this.pendingDevicesPageSize;
        const end = start + this.pendingDevicesPageSize;
        const devices = this.pendingDevicesCache.slice(start, end);
        this.renderPendingDevices(devices);
        this.setQueueDetailsPagination({
            visible: totalPages > 1,
            page: this.pendingDevicesPage,
            totalPages
        });
    }

    renderUnverifiedDevicesPage() {
        const totalItems = this.unverifiedDevicesCache.length;
        if (!totalItems) {
            this.renderUnverifiedDevices([]);
            this.setQueueDetailsPagination({ visible: false });
            return;
        }

        const totalPages = Math.max(1, Math.ceil(totalItems / this.unverifiedDevicesPageSize));
        const start = (this.unverifiedDevicesPage - 1) * this.unverifiedDevicesPageSize;
        const end = start + this.unverifiedDevicesPageSize;
        const devices = this.unverifiedDevicesCache.slice(start, end);
        this.renderUnverifiedDevices(devices);
        this.setQueueDetailsPagination({
            visible: totalPages > 1,
            page: this.unverifiedDevicesPage,
            totalPages
        });
    }

    renderUnverifiedDevices(devices) {
        const body = document.getElementById('adminQueueDetailsBody');
        if (!body) return;
        body.innerHTML = '';

        if (!devices.length) {
            body.innerHTML = '<div class="queue-details-empty">No unverified devices found.</div>';
            return;
        }

        devices.forEach(device => {
            const row = document.createElement('div');
            row.className = 'queue-device-row';
            row.innerHTML = `
                <div class="queue-device-info">
                    <div class="queue-device-user">${this.escapeHtml(device.device_id)}</div>
                    <div class="queue-device-id">${this.escapeHtml(device.email || 'Unknown user')}</div>
                </div>
            `;
            const action = document.createElement('button');
            action.className = 'btn btn-secondary btn-small';
            action.type = 'button';
            action.textContent = 'Verify';
            action.addEventListener('click', () => this.verifyUnverifiedDevice(device));
            row.appendChild(action);
            body.appendChild(row);
        });
    }

    renderStaleDevicesPage() {
        const body = document.getElementById('adminQueueDetailsBody');
        if (!body) return;
        body.innerHTML = '';

        const totalItems = this.staleDevicesCache.length;
        if (!totalItems) {
            body.innerHTML = '<div class="queue-details-empty">No stale devices found.</div>';
            this.setQueueDetailsPagination({ visible: false });
            return;
        }

        const totalPages = Math.max(1, Math.ceil(totalItems / this.staleDevicesPageSize));
        const start = (this.staleDevicesPage - 1) * this.staleDevicesPageSize;
        const end = start + this.staleDevicesPageSize;
        const devices = this.staleDevicesCache.slice(start, end);

        devices.forEach(device => {
            const row = document.createElement('div');
            row.className = 'queue-device-row';
            row.innerHTML = `
                <div class="queue-device-info">
                    <div class="queue-device-user">${this.escapeHtml(device.device_id)}</div>
                    <div class="queue-device-id">${this.escapeHtml(device.email || 'Unknown user')}</div>
                </div>
            `;
            body.appendChild(row);
        });

        this.setQueueDetailsPagination({
            visible: totalPages > 1,
            page: this.staleDevicesPage,
            totalPages
        });
    }

    renderStaleDevices(devices) {
        const body = document.getElementById('adminQueueDetailsBody');
        if (!body) return;
        body.innerHTML = '';

        if (!devices.length) {
            body.innerHTML = '<div class="queue-details-empty">No stale devices found.</div>';
            return;
        }

        devices.forEach(device => {
            const row = document.createElement('div');
            row.className = 'queue-device-row';
            row.innerHTML = `
                <div class="queue-device-info">
                    <div class="queue-device-user">${this.escapeHtml(device.device_id)}</div>
                    <div class="queue-device-id">${this.escapeHtml(device.email || 'Unknown user')}</div>
                </div>
            `;
            body.appendChild(row);
        });
    }

    async issueWelcomeForDevice(deviceId) {
        if (!deviceId) {
            this.showNotification('Device ID is required.', 'warning');
            return;
        }
        const targetDeviceId = String(deviceId).trim();
        const currentDeviceId = String(this.currentDeviceId || '').trim();
        if (currentDeviceId && targetDeviceId === currentDeviceId) {
            await this.showActionPrompt(
                'Cannot issue welcome to this device',
                'This is your current device. Use an existing trusted device to issue the welcome.',
                {
                    primaryLabel: 'OK',
                    secondaryLabel: ''
                }
            );
            return;
        }
        try {
            const result = await this.runCliCommandRaw(
                `hybridcipher issue-welcome --device ${this.quoteCliArg(targetDeviceId)}`
            );
            if (typeof result.status === 'number' && result.status !== 0) {
                const message = (result.stderr || result.stdout || '').trim() || 'Issue welcome failed.';
                this.showNotification(message, 'error');
                return;
            }
            this.showNotification('Welcome issued successfully.', 'success');
            this.loadPendingDevicesQueue();
            this.refreshPersonalDevicesOverview({ suppressErrorNotification: true });
            this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true });
        } catch (error) {
            console.error('Issue welcome failed:', error);
            this.showNotification('Issue welcome failed.', 'error');
        }
    }

    async verifyUnverifiedDevice(device) {
        const deviceId = device?.device_id;
        const userId = device?.email;
        if (!deviceId) {
            this.showNotification('Device ID is required.', 'warning');
            return;
        }
        if (!userId) {
            this.showNotification('User identifier is required to verify this device.', 'warning');
            return;
        }
        const targetDeviceId = String(deviceId).trim();
        const currentDeviceId = String(this.currentDeviceId || '').trim();
        if (currentDeviceId && targetDeviceId === currentDeviceId) {
            await this.showActionPrompt(
                'Cannot verify from this device',
                'This unverified device is your current device.',
                {
                    detail: 'Use an already trusted device in the group to verify this device fingerprint.',
                    primaryLabel: 'Close',
                    secondaryLabel: ''
                }
            );
            return;
        }

        const fingerprint = await this.promptForText(
            'Enter the fingerprint for this device.',
            {
                title: 'Verify device',
                placeholder: 'xxxx xxxx xxxx xxxx',
                submitLabel: 'Verify'
            }
        );
        if (fingerprint === null) return;

        this.showActionProgressModal('Verifying...');
        try {
            const result = await this.runCliCommandRaw(
                `hybridcipher pin verify ${this.quoteCliArg(userId)} ${this.quoteCliArg(deviceId)} --fingerprint ${this.quoteCliArg(fingerprint)}`
            );
            if (typeof result.status === 'number' && result.status !== 0) {
                const message = (result.stderr || result.stdout || '').trim() || 'Device verification failed.';
                await this.showActionPrompt(
                    'Device verification failed',
                    'HybridCipher could not verify this device.',
                    {
                        detail: message,
                        primaryLabel: 'Close',
                        secondaryLabel: ''
                    }
                );
                return;
            }
            this.showNotification('Device verified successfully.', 'success');
            this.loadUnverifiedDevicesQueue();
            this.refreshPersonalDevicesOverview({ suppressErrorNotification: true });
            this.refreshWorkspaceHomeStatus({ suppressErrorNotification: true });
        } catch (error) {
            console.error('Device verification failed:', error);
            await this.showActionPrompt(
                'Device verification failed',
                'HybridCipher could not verify this device.',
                {
                    detail: error?.message || 'An unexpected error occurred while verifying this device.',
                    primaryLabel: 'Close',
                    secondaryLabel: ''
                }
            );
        } finally {
            this.hideActionProgressModal();
        }
    }

    parseCurrentGroupStatus(output) {
        const cleaned = this.stripAnsi(output);
        const context = this.parseCurrentGroupContext(cleaned);
        if (context.groupName) return context.groupName;
        if (context.groupId) return context.groupId;

        if (/no active group/i.test(cleaned)) {
            return 'No active group selected';
        }
        if (/not authenticated|login/i.test(cleaned)) {
            return 'Sign in to view group';
        }
        return '';
    }

    parseServerTrustStatus(output) {
        const cleaned = this.stripAnsi(output);
        if (/verified via transparency log/i.test(cleaned)) {
            return 'Verified (transparency log)';
        }
        if (/user-verified|user verified/i.test(cleaned)) {
            return 'Verified (user confirmed)';
        }
        if (/matches pinned fingerprint/i.test(cleaned)) {
            return 'Pinned (TOFU) - verify safety number';
        }
        if (/first contact/i.test(cleaned)) {
            return 'First contact - verify safety number';
        }
        if (/no pinned server identity/i.test(cleaned)) {
            return 'No pinned server identity - login first';
        }
        if (/unknown trust level/i.test(cleaned)) {
            return 'Unknown trust level - run `hybridcipher server-trust verify`';
        }
        if (/not authenticated|login/i.test(cleaned)) {
            return 'Sign in to check trust status';
        }
        return '';
    }

    async refreshSettingsStatus() {
        const coverageScanEl = document.getElementById('settingsCoverageLastScan');
        const ipcStatusEl = document.getElementById('settingsCoverageIpcStatus');
        const registryUploadEl = document.getElementById('settingsRegistryLastUpload');

        try {
            const result = await invoke('get_settings_status');
            if (!result.success || !result.data) {
                throw new Error(result.error || 'Settings status unavailable');
            }

            const status = result.data;
            if (coverageScanEl) {
                coverageScanEl.textContent = this.formatSettingsTimestamp(status.coverage_last_scan);
            }

            if (ipcStatusEl) {
                let ipcLabel = 'Inactive';
                let ipcState = 'inactive';
                if (!status.coverage_ipc_supported) {
                    ipcLabel = 'Unsupported';
                    ipcState = 'unsupported';
                } else if (status.coverage_ipc_active) {
                    ipcLabel = 'Active';
                    ipcState = 'active';
                }
                ipcStatusEl.textContent = ipcLabel;
                ipcStatusEl.setAttribute('data-state', ipcState);
            }

            if (registryUploadEl) {
                registryUploadEl.textContent = this.formatSettingsTimestamp(status.registry_last_upload);
            }
        } catch (error) {
            console.error('Failed to refresh settings status:', error);
            if (coverageScanEl) coverageScanEl.textContent = '—';
            if (ipcStatusEl) {
                ipcStatusEl.textContent = 'Unavailable';
                ipcStatusEl.setAttribute('data-state', 'unsupported');
            }
            if (registryUploadEl) registryUploadEl.textContent = '—';
        }
    }

    async refreshGlobalCliInstallStatus() {
        const statusEl = document.getElementById('settingsGlobalCliStatus');
        const globalPathEl = document.getElementById('settingsGlobalCliPath');
        if (!statusEl) return;

        statusEl.textContent = 'Checking...';
        try {
            const result = await invoke('get_global_cli_install_status');
            if (!result?.success || !result?.data) {
                statusEl.textContent = result?.error || 'Unavailable';
                return;
            }

            const status = result.data;
            if (globalPathEl && status.global_path) {
                globalPathEl.textContent = status.global_path;
            }

            if (!status.supported) {
                statusEl.textContent = status.detail || 'Unsupported on this platform';
                return;
            }

            if (status.points_to_bundle) {
                statusEl.textContent = 'Installed (auto-tracks app updates)';
                return;
            }

            if (!status.installed) {
                statusEl.textContent = 'Not installed';
                return;
            }

            if (status.is_symlink) {
                statusEl.textContent = 'Installed (points to different target)';
                return;
            }

            statusEl.textContent = 'Installed as standalone binary';
        } catch (error) {
            console.error('Failed to refresh global CLI install status:', error);
            statusEl.textContent = 'Unavailable';
        }
    }

    async installOrRepairGlobalCli() {
        const button = document.getElementById('settingsInstallGlobalCliBtn');
        if (button) {
            button.disabled = true;
            button.textContent = 'Installing...';
        }

        try {
            const result = await invoke('install_global_cli_symlink');
            if (!result?.success) {
                this.showNotification(result?.error || 'Failed to install terminal command.', 'error');
                return;
            }

            this.showNotification('Terminal command installed. It will track app updates automatically.', 'success');
            await this.refreshGlobalCliInstallStatus();
        } catch (error) {
            console.error('Failed to install global CLI symlink:', error);
            this.showNotification('Failed to install terminal command.', 'error');
        } finally {
            if (button) {
                button.disabled = false;
                button.textContent = 'Install terminal command';
            }
        }
    }

    resolveCliCommand(command, cliPath) {
        if (this.platformInfo?.os_type === 'windows') {
            const text = String(cliPath ?? '');
            const lastSlash = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'));
            const cliDir = lastSlash >= 0 ? text.slice(0, lastSlash) : '';
            if (cliDir) {
                return `set "PATH=${cliDir};%PATH%" && ${command}`;
            }
        }

        return command.replace(/^hybridcipher\b/, this.quoteTerminalArg(cliPath));
    }

    quoteTerminalArg(value) {
        const text = String(value ?? '');
        if (this.platformInfo?.os_type === 'windows') {
            if (text.length === 0) {
                return '""';
            }

            // The embedded terminal uses cmd.exe on Windows, so POSIX single-quote
            // escaping breaks paths with spaces. Wrap with cmd-compatible quotes.
            return `"${text.replace(/"/g, '""')}"`;
        }

        return quoteShellArgValue(text);
    }

    async runSettingsCliCommand(command, options = {}) {
        const { confirmTitle, confirmMessage, closeSettingsModal = true } = options;
        if (this.adminPanelVisible) {
            this.setAdminPanelVisible(false);
        }
        if (confirmTitle && confirmMessage) {
            const confirmed = await this.showConfirmDialog(confirmTitle, confirmMessage);
            if (!confirmed) return;
        }

        try {
            await this.getCliBinaryPath();
        } catch (error) {
            this.showNotification(
                'Failed to locate hybridcipher CLI. Please build it with "cargo build --release --bin hybridcipher"',
                'error'
            );
            return;
        }

        await this.createTerminalTab();
        await this.executeCommandDirectly(command, true);
        if (closeSettingsModal) {
            this.closeSettingsModal();
        }
    }

    runDashboardCliCommand(command, options = {}) {
        this.setAdminPanelVisible(false);
        return this.runSettingsCliCommand(command, { ...options, closeSettingsModal: false });
    }

    async promptForText(
        message,
        {
            allowEmpty = false,
            title = 'Enter details',
            placeholder = '',
            submitLabel = 'Continue',
            initialValue = ''
        } = {}
    ) {
        const modal = document.getElementById('textPromptModal');
        if (!modal) {
            const value = window.prompt(message);
            if (value === null) return null;
            const trimmed = value.trim();
            if (!trimmed && !allowEmpty) return null;
            return trimmed;
        }

        const titleEl = document.getElementById('textPromptTitle');
        const labelEl = document.getElementById('textPromptLabel');
        const input = document.getElementById('textPromptInput');
        const errorEl = document.getElementById('textPromptError');
        const form = document.getElementById('textPromptForm');
        const cancelBtn = document.getElementById('cancelTextPromptBtn');
        const closeBtn = document.getElementById('closeTextPromptBtn');
        const submitBtn = document.getElementById('submitTextPromptBtn');
        const backdrop = document.getElementById('textPromptBackdrop');

        if (!input || !form || !cancelBtn || !closeBtn || !submitBtn || !backdrop) {
            const value = window.prompt(message);
            if (value === null) return null;
            const trimmed = value.trim();
            if (!trimmed && !allowEmpty) return null;
            return trimmed;
        }

        if (titleEl) titleEl.textContent = title;
        if (labelEl) labelEl.textContent = message;
        if (submitBtn) submitBtn.textContent = submitLabel;
        input.value = initialValue || '';
        input.placeholder = placeholder || '';
        if (errorEl) {
            errorEl.textContent = '';
            errorEl.style.display = 'none';
        }

        modal.style.display = 'flex';
        setTimeout(() => input.focus(), 0);

        return new Promise(resolve => {
            const cleanup = () => {
                form.removeEventListener('submit', onSubmit);
                cancelBtn.removeEventListener('click', onCancel);
                closeBtn.removeEventListener('click', onCancel);
                backdrop.removeEventListener('click', onBackdrop);
                document.removeEventListener('keydown', onKeydown);
            };

            const close = (value) => {
                modal.style.display = 'none';
                cleanup();
                resolve(value);
            };

            const onSubmit = (event) => {
                event.preventDefault();
                const trimmed = input.value.trim();
                if (!trimmed && !allowEmpty) {
                    if (errorEl) {
                        errorEl.textContent = 'A value is required.';
                        errorEl.style.display = 'block';
                    }
                    input.focus();
                    return;
                }
                close(trimmed);
            };

            const onCancel = () => {
                close(null);
            };

            const onBackdrop = (event) => {
                if (event.target === backdrop) {
                    close(null);
                }
            };

            const onKeydown = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    close(null);
                }
            };

            form.addEventListener('submit', onSubmit);
            cancelBtn.addEventListener('click', onCancel);
            closeBtn.addEventListener('click', onCancel);
            backdrop.addEventListener('click', onBackdrop);
            document.addEventListener('keydown', onKeydown);
        });
    }

    closeActionPrompt() {
        const modal = document.getElementById('actionPromptModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async showActionPrompt(
        title,
        message,
        {
            detail = '',
            primaryLabel = 'Continue',
            secondaryLabel = 'Cancel',
            keepOpen = false
        } = {}
    ) {
        const modal = document.getElementById('actionPromptModal');
        const titleEl = document.getElementById('actionPromptTitle');
        const messageEl = document.getElementById('actionPromptMessage');
        const detailEl = document.getElementById('actionPromptDetail');
        const primaryBtn = document.getElementById('actionPromptPrimaryBtn');
        const secondaryBtn = document.getElementById('actionPromptSecondaryBtn');
        const tertiaryBtn = document.getElementById('actionPromptTertiaryBtn');
        const closeBtn = document.getElementById('closeActionPromptBtn');
        const backdrop = document.getElementById('actionPromptBackdrop');

        if (!modal || !titleEl || !messageEl || !primaryBtn || !secondaryBtn || !closeBtn || !backdrop) {
            const fullMessage = detail ? `${message}\n\n${detail}` : message;
            if (secondaryLabel) {
                return window.confirm(`${title}\n\n${fullMessage}`);
            }
            window.alert(`${title}\n\n${fullMessage}`);
            return true;
        }

        titleEl.textContent = title;
        messageEl.textContent = message;
        if (detailEl) {
            if (detail) {
                detailEl.textContent = detail;
                detailEl.style.display = 'block';
            } else {
                detailEl.textContent = '';
                detailEl.style.display = 'none';
            }
        }

        primaryBtn.textContent = primaryLabel;
        if (secondaryLabel) {
            secondaryBtn.textContent = secondaryLabel;
            secondaryBtn.style.display = 'inline-flex';
        } else {
            secondaryBtn.textContent = '';
            secondaryBtn.style.display = 'none';
        }
        if (tertiaryBtn) {
            tertiaryBtn.textContent = '';
            tertiaryBtn.style.display = 'none';
        }

        modal.style.display = 'flex';
        setTimeout(() => primaryBtn.focus(), 0);

        return new Promise(resolve => {
            const cleanup = () => {
                primaryBtn.removeEventListener('click', onPrimary);
                secondaryBtn.removeEventListener('click', onSecondary);
                closeBtn.removeEventListener('click', onCancel);
                backdrop.removeEventListener('click', onCancel);
                document.removeEventListener('keydown', onKeydown);
            };

            const close = (value, forceClose = false) => {
                if (forceClose || !keepOpen) {
                    modal.style.display = 'none';
                }
                cleanup();
                resolve(value);
            };

            const onPrimary = () => close(true);
            const onSecondary = () => close(false);
            const onCancel = () => close(null, true);
            const onKeydown = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    close(null, true);
                }
            };

            primaryBtn.addEventListener('click', onPrimary);
            secondaryBtn.addEventListener('click', onSecondary);
            closeBtn.addEventListener('click', onCancel);
            backdrop.addEventListener('click', onCancel);
            document.addEventListener('keydown', onKeydown);
        });
    }

    async showThreeWayActionPrompt(
        title,
        message,
        {
            detail = '',
            primaryLabel = 'Continue',
            secondaryLabel = 'Later',
            tertiaryLabel = 'Cancel'
        } = {}
    ) {
        const modal = document.getElementById('actionPromptModal');
        const titleEl = document.getElementById('actionPromptTitle');
        const messageEl = document.getElementById('actionPromptMessage');
        const detailEl = document.getElementById('actionPromptDetail');
        const primaryBtn = document.getElementById('actionPromptPrimaryBtn');
        const secondaryBtn = document.getElementById('actionPromptSecondaryBtn');
        const tertiaryBtn = document.getElementById('actionPromptTertiaryBtn');
        const closeBtn = document.getElementById('closeActionPromptBtn');
        const backdrop = document.getElementById('actionPromptBackdrop');

        if (!modal || !titleEl || !messageEl || !detailEl || !primaryBtn || !secondaryBtn || !tertiaryBtn || !closeBtn || !backdrop) {
            const fullMessage = detail ? `${message}\n\n${detail}` : message;
            const choice = window.prompt(
                `${title}\n\n${fullMessage}\n\nType 1 to ${primaryLabel}, 2 to ${secondaryLabel}, or anything else to ${tertiaryLabel}.`,
                ''
            );
            if (choice === '1') return 'primary';
            if (choice === '2') return 'secondary';
            return 'tertiary';
        }

        titleEl.textContent = title;
        messageEl.textContent = message;
        if (detail) {
            detailEl.textContent = detail;
            detailEl.style.display = 'block';
        } else {
            detailEl.textContent = '';
            detailEl.style.display = 'none';
        }

        primaryBtn.textContent = primaryLabel;
        secondaryBtn.textContent = secondaryLabel;
        secondaryBtn.style.display = 'inline-flex';
        tertiaryBtn.textContent = tertiaryLabel;
        tertiaryBtn.style.display = 'inline-flex';

        modal.style.display = 'flex';
        setTimeout(() => primaryBtn.focus(), 0);

        return new Promise(resolve => {
            const cleanup = () => {
                primaryBtn.removeEventListener('click', onPrimary);
                secondaryBtn.removeEventListener('click', onSecondary);
                tertiaryBtn.removeEventListener('click', onTertiary);
                closeBtn.removeEventListener('click', onCancel);
                backdrop.removeEventListener('click', onCancel);
                document.removeEventListener('keydown', onKeydown);
            };

            const close = (value) => {
                modal.style.display = 'none';
                tertiaryBtn.style.display = 'none';
                cleanup();
                resolve(value);
            };

            const onPrimary = () => close('primary');
            const onSecondary = () => close('secondary');
            const onTertiary = () => close('tertiary');
            const onCancel = () => close('tertiary');
            const onKeydown = (event) => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    close('tertiary');
                }
            };

            primaryBtn.addEventListener('click', onPrimary);
            secondaryBtn.addEventListener('click', onSecondary);
            tertiaryBtn.addEventListener('click', onTertiary);
            closeBtn.addEventListener('click', onCancel);
            backdrop.addEventListener('click', onCancel);
            document.addEventListener('keydown', onKeydown);
        });
    }

    quoteCliArg(value) {
        return this.quoteTerminalArg(value);
    }

    // ========================================================================
    // Notifications
    // ========================================================================

    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer');
        if (!container) return;

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                ${type === 'success' ? '<path stroke="currentColor" stroke-width="2" d="M5 13l4 4L19 7"/>' :
                type === 'error' ? '<path stroke="currentColor" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>' :
                    type === 'warning' ? '<path stroke="currentColor" stroke-width="2" d="M12 9v4m0 4h.01M5.07 19h13.86L12 4.99 5.07 19z"/>' :
                        '<path stroke="currentColor" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'}
            </svg>
            <span>${this.escapeHtml(message)}</span>
        `;

        container.appendChild(notification);

        // Auto remove after 4 seconds
        setTimeout(() => {
            notification.remove();
        }, 4000);
    }

    // ========================================================================
    // File Operations
    // ========================================================================

    async encryptSelectedFile() {
        this.showNotification(
            'Desktop file encryption is not available in this build. Use the bundled hybridcipher CLI.',
            'info'
        );
    }

    async decryptSelectedFile() {
        this.showNotification(
            'Desktop file decryption is not available in this build. Use the bundled hybridcipher CLI.',
            'info'
        );
    }
}

Object.assign(HybridCipherApp.prototype, window.HybridCipherAppUpdateMethods || {});

// Initialize app
const app = new HybridCipherApp();

// Export for global access
window.app = app;
