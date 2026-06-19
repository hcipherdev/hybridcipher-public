(function (global) {
    function toCount(value) {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    function parseTimestampMs(value) {
        if (!value) return null;
        const parsed = Date.parse(value);
        return Number.isFinite(parsed) ? parsed : null;
    }

    function pluralize(count, singular, plural) {
        return count === 1 ? singular : plural;
    }

    function getMountBackendLabel(backend) {
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
    }

    function buildPostQuantumStatusModel({
        protectedCount = null,
        isProtectedFolder = false,
        status = null,
        primaryText = null,
        secondaryText = null,
        explainerAvailable = true,
    } = {}) {
        const normalizedProtectedCount = Number.isFinite(Number(protectedCount))
            ? Number(protectedCount)
            : null;

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
                title: 'Post-quantum protection',
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
    }

    function buildWorkspaceHomeModel(snapshot = {}, { nowMs = Date.now() } = {}) {
        const protectedCount = toCount(snapshot.protected_count);
        const mountedCount = toCount(snapshot.mounted_count);
        const lastScanMs = parseTimestampMs(snapshot.last_scan_at);
        const lastBackupMs = parseTimestampMs(snapshot.last_backup_upload_at);
        const deviceCounts = snapshot.device_counts || {};
        const folderAttention = snapshot.folder_attention || {};
        const pendingDevices = toCount(deviceCounts.pending);
        const staleDevices = toCount(deviceCounts.stale);
        const unverifiedDevices = toCount(deviceCounts.unverified);
        const currentDevice = snapshot.current_device || null;
        const scanAgeMs = lastScanMs === null ? null : Math.max(0, nowMs - lastScanMs);
        const scanIsFresh = scanAgeMs !== null && scanAgeMs <= 36 * 60 * 60 * 1000;
        const backupHealthy = Boolean(snapshot.recovery_backup_ok) && Boolean(snapshot.recovery_auto_backup_ok);
        const deviceTrusted = Boolean(currentDevice && currentDevice.is_verified);
        const folderIssues = toCount(folderAttention.conflicts) + toCount(folderAttention.recovery_copies);
        const postQuantum = buildPostQuantumStatusModel({
            protectedCount,
            status: snapshot.post_quantum_status || null,
            primaryText: snapshot.post_quantum_primary_text || null,
            secondaryText: snapshot.post_quantum_secondary_text || null,
            explainerAvailable: snapshot.post_quantum_explainer_available !== false,
        });

        const cards = [
            postQuantum.homeCard,
            {
                id: 'mfa',
                title: 'Sign-in protection',
                tone: snapshot.mfa_enabled ? 'safe' : 'danger',
                value: snapshot.mfa_enabled ? 'On' : 'Off',
                detail: snapshot.mfa_enabled
                    ? 'Authenticator protection is enabled.'
                    : 'Turn on MFA to protect new sign-ins and recovery.',
                ctaAction: snapshot.mfa_enabled ? null : 'open-settings-mfa',
            },
            {
                id: 'scan',
                title: 'Scan freshness',
                tone: scanIsFresh ? 'safe' : 'warning',
                value: lastScanMs === null ? 'Not scanned yet' : (scanIsFresh ? 'Up to date' : 'Scan again'),
                detail: lastScanMs === null
                    ? 'Run a scan to verify your protected folders are covered.'
                    : `Last scan ${new Date(lastScanMs).toISOString()}`,
                ctaAction: 'run-coverage-scan',
            },
            {
                id: 'device',
                title: 'This device',
                tone: deviceTrusted ? 'safe' : 'danger',
                value: deviceTrusted ? 'Trusted' : 'Needs verification',
                detail: currentDevice?.device_id
                    ? `Device ID: ${currentDevice.device_id}`
                    : 'Current device information is unavailable.',
                ctaAction: 'open-devices',
            },
        ];

        const attentionItems = [];
        if (!snapshot.mfa_enabled) {
            attentionItems.push({
                id: 'mfa',
                title: 'Multi-factor authentication is off',
                detail: 'Enable MFA before relying on this device for everyday protection.',
                action: {
                    id: 'open-settings-mfa',
                    label: 'Set up MFA',
                },
            });
        }
        if (!backupHealthy) {
            attentionItems.push({
                id: 'backup',
                title: 'Recovery backup needs attention',
                detail: 'Upload or re-enable your recovery backup so you can recover on another device.',
                action: {
                    id: 'open-settings-recovery',
                    label: 'Review backup',
                },
            });
        }
        if (!scanIsFresh) {
            attentionItems.push({
                id: 'scan',
                title: protectedCount === 0
                    ? 'No protected folders yet'
                    : 'Folder safety scan is out of date',
                detail: protectedCount === 0
                    ? 'Click Add Protected Folder on the left to start protecting folders before running a coverage scan.'
                    : (lastScanMs === null
                        ? 'Run your first scan to check protected-folder coverage.'
                        : 'Run another scan to confirm your protected folders are still covered.'),
                action: protectedCount === 0
                    ? {
                        id: 'add-protected-folder',
                        label: 'Add Protected Folder',
                    }
                    : {
                        id: 'run-coverage-scan',
                        label: 'Run scan',
                    },
            });
        }
        if (!deviceTrusted) {
            attentionItems.push({
                id: 'device-trust',
                title: 'This device is not fully trusted',
                detail: 'Finish trust setup on this device before depending on it for recovery or approvals.',
                action: {
                    id: 'open-devices',
                    label: 'Review devices',
                },
            });
        }
        if (pendingDevices > 0 || staleDevices > 0 || unverifiedDevices > 0) {
            attentionItems.push({
                id: 'device-setup',
                title: 'Device review is needed',
                detail: `${pendingDevices} pending, ${unverifiedDevices} unverified, ${staleDevices} stale`,
                action: {
                    id: 'open-devices',
                    label: 'Review devices',
                },
            });
        }
        if (folderIssues > 0) {
            attentionItems.push({
                id: 'folder-issues',
                title: 'Protected folders need review',
                detail: `${toCount(folderAttention.conflicts)} conflicts and ${toCount(folderAttention.recovery_copies)} recovery copies need attention.`,
                action: {
                    id: 'open-folder-issues',
                    label: 'Review folders',
                },
            });
        }

        return {
            protectedCount,
            mountedCount,
            postQuantum,
            summaryTone: attentionItems.length > 0 ? 'danger' : 'safe',
            summaryLabel: attentionItems.length > 0 ? 'Needs attention' : 'Protected',
            cards,
            attentionItems,
        };
    }

    function buildFolderCoverageModel({ folder = {}, review = null } = {}) {
        const coveragePercent = Math.max(
            0,
            Math.min(
                100,
                Math.round(Number(review?.coverage_percent ?? (Number(folder.coverage_ratio || 0) * 100)))
            )
        );
        const trackedFiles = toCount(review?.tracked_files ?? folder.tracked_files);
        const unresolvedItemCount = toCount(
            review?.unresolved_item_count
            ?? (toCount(folder.orphaned_files) + toCount(folder.unmanaged_files))
        );
        const groups = Array.isArray(review?.groups)
            ? review.groups.map(group => ({
                id: group?.id || '',
                title: group?.title || '',
                reasonText: group?.reason_text || '',
                itemCount: toCount(group?.item_count),
                samplePaths: Array.isArray(group?.sample_paths) ? group.sample_paths.slice() : [],
                files: Array.isArray(group?.files)
                    ? group.files.map(file => ({
                        relative_path: file?.relative_path || '',
                        last_seen: file?.last_seen || null,
                        size: Number.isFinite(Number(file?.size)) ? Number(file.size) : null,
                        reason: file?.reason || '',
                    }))
                    : [],
                recommendedAction: group?.recommended_action || '',
                primaryCtaLabel: group?.primary_cta_label || '',
                severity: group?.severity || 'warning',
                canRunAction: Boolean(group?.can_run_action),
            }))
            : [];

        let stateLabel = review?.state_label || '';
        let summaryText = review?.summary_text || '';

        if (!stateLabel) {
            if (trackedFiles === 0 && unresolvedItemCount === 0) {
                stateLabel = 'No protected items indexed yet';
                summaryText = 'Run a scan to confirm what in this folder should be protected.';
            } else if (coveragePercent === 100 && unresolvedItemCount === 0) {
                stateLabel = 'Fully protected';
                summaryText = 'Everything in this folder is currently covered.';
            } else if (coveragePercent >= 99) {
                stateLabel = 'Almost fully protected';
                summaryText = `${unresolvedItemCount} ${pluralize(unresolvedItemCount, 'item', 'items')} need review to restore full protection.`;
            } else {
                stateLabel = 'Needs attention';
                summaryText = `${unresolvedItemCount} ${pluralize(unresolvedItemCount, 'item', 'items')} in this folder are outside protection and need review.`;
            }
        }

        const primaryCta = unresolvedItemCount > 0
            ? {
                id: 'review-uncovered-items',
                label: groups.length === 1 && groups[0].id === 'clean_up_missing'
                    ? 'Review missing items'
                    : 'Review uncovered items',
            }
            : {
                id: 'run-coverage-scan',
                label: 'Run scan again',
            };

        return {
            coveragePercent,
            percentLabel: `${coveragePercent}%`,
            trackedFiles,
            unresolvedItemCount,
            stateLabel,
            summaryText,
            stateTone: stateLabel === 'Fully protected' ? 'safe' : (stateLabel === 'Almost fully protected' ? 'warning' : 'danger'),
            groups,
            primaryCta,
        };
    }

    function buildFolderDetailModel({ folder = {}, mountInfo = null, isMounted = false, coverageReview = null } = {}) {
        const syncStatus = mountInfo?.syncStatus || mountInfo?.sync_status || {};
        const backend = mountInfo?.backend || null;
        const conflicts = toCount(syncStatus.pending_conflict_count);
        const recoveryCopies = toCount(syncStatus.recovered_pending_copy_count);
        const hasUnmountSafetyValue = Object.prototype.hasOwnProperty.call(syncStatus, 'safe_to_unmount');
        const safeToUnmount = isMounted && hasUnmountSafetyValue ? Boolean(syncStatus.safe_to_unmount) : null;
        const protection = buildPostQuantumStatusModel({ isProtectedFolder: Boolean(folder && (folder.root_id || folder.path)) }).folderDetail;
        const healthTone = conflicts > 0 || recoveryCopies > 0 || safeToUnmount === false
            ? 'warning'
            : (isMounted ? 'safe' : 'idle');

        const secondaryActions = [
            { id: 'reveal-protected', label: 'Reveal on disk' },
        ];
        if (isMounted) {
            secondaryActions.push(
                { id: 'unmount', label: 'Unmount' },
            );
        }

        return {
            rootId: folder.root_id || '',
            displayName: folder.name || '',
            path: folder.path || '',
            isMounted: Boolean(isMounted),
            mountpoint: mountInfo?.mountpoint || null,
            backend,
            backendLabel: getMountBackendLabel(backend),
            lastScanAt: folder.last_scan || null,
            trackedFiles: toCount(folder.tracked_files),
            coveragePercent: Math.round(Number(folder.coverage_ratio || 0) * 100),
            protection,
            coverage: buildFolderCoverageModel({ folder, review: coverageReview }),
            healthTone,
            primaryAction: isMounted
                ? { id: 'open-mounted', label: 'Open mounted folder' }
                : { id: 'mount', label: 'Mount folder' },
            secondaryActions,
            attention: {
                conflicts,
                recoveryCopies,
                mountStatusLabel: isMounted ? 'Mounted' : 'Not mounted',
                unmountSafetyLabel: !isMounted
                    ? null
                    : (safeToUnmount === null
                        ? 'Checking...'
                        : (safeToUnmount ? 'Safe' : 'Not safe yet')),
                safeToUnmount,
            },
            showResolveConflicts: conflicts > 0,
            showResolveRecoveryCopies: recoveryCopies > 0,
        };
    }

    function buildCoverageCenterModel(snapshot = {}, runtime = {}) {
        const folders = Array.isArray(snapshot.folders)
            ? snapshot.folders.map(folder => {
                const path = folder?.path || '';
                const recommendedActionId = folder?.recommended_action_id || null;
                const recommendedActionLabel = folder?.recommended_action_label || null;
                return {
                    rootId: folder?.root_id || '',
                    path,
                    name: path.split(/[\\/]/).filter(Boolean).pop() || path || 'Protected folder',
                    kind: folder?.kind || 'folder',
                    state: folder?.state || 'active',
                    lastScanAt: folder?.last_scan || null,
                    trackedFiles: toCount(folder?.tracked_files),
                    orphanedFiles: toCount(folder?.orphaned_files),
                    unmanagedFiles: toCount(folder?.unmanaged_files),
                    coveragePercent: Math.max(0, Math.min(100, Math.round(Number(folder?.coverage_percent || 0)))),
                    coverageLabel: folder?.coverage_label || 'Needs attention',
                    attentionLabel: folder?.attention_label || '',
                    needsAttention: Boolean(folder?.needs_attention),
                    reviewAction: {
                        id: 'review-folder-coverage',
                        label: 'Review',
                    },
                    scanAction: {
                        id: 'scan-folder-coverage',
                        label: 'Scan again',
                    },
                    recommendedAction: recommendedActionId
                        ? {
                            id: recommendedActionId,
                            label: recommendedActionLabel || 'Review fixes',
                        }
                        : null,
                };
            })
            : [];

        const attentionItems = Array.isArray(snapshot.attention_items)
            ? snapshot.attention_items.map(item => ({
                id: item?.id || '',
                title: item?.title || '',
                detail: item?.detail || '',
                rootId: item?.root_id || '',
                folderPath: item?.folder_path || '',
                action: item?.action_id
                    ? {
                        id: item.action_id,
                        label: item?.action_label || 'Review',
                    }
                    : null,
            }))
            : [];

        const scanState = runtime?.scanState || {};
        const rootProgress = scanState?.rootProgress || {};
        const processed = toCount(scanState?.processed);
        const total = toCount(scanState?.total);
        const scanPercent = total > 0
            ? Math.max(0, Math.min(100, Math.round((processed / total) * 100)))
            : 0;
        const currentScanState = scanState?.state || 'idle';

        const summary = {
            overallCoveragePercent: Math.max(0, Math.min(100, Math.round(Number(snapshot.overall_coverage_percent || 0)))),
            trackedFiles: toCount(snapshot.tracked_files),
            orphanedFiles: toCount(snapshot.orphaned_files),
            unmanagedFiles: toCount(snapshot.unmanaged_files),
            folderCount: toCount(snapshot.enrolled_folder_count),
            lastScanAt: snapshot.last_scan_at || null,
            ipcState: snapshot.ipc_state || 'inactive',
            scanState: currentScanState,
        };

        return {
            isEmpty: folders.length === 0,
            summary,
            folderRows: folders,
            attentionItems,
            emptyState: {
                title: 'No protected folders yet',
                detail: 'Add a protected folder to start scanning protection coverage in the desktop app.',
            },
            scanBanner: {
                state: currentScanState,
                processed,
                total,
                percent: scanPercent,
                rootCount: Object.keys(rootProgress).length,
            },
        };
    }

    function buildPersonalDevicesModel({ currentDeviceId = null, devices = [] } = {}) {
        const safeDevices = Array.isArray(devices) ? devices.slice() : [];
        const currentDevice = safeDevices.find(device =>
            Boolean(device && (device.is_current_device || device.device_id === currentDeviceId))
        ) || null;

        const trustedDevices = [];
        const setupDevices = [];
        const reviewDevices = [];

        safeDevices.forEach(device => {
            if (!device || device === currentDevice) {
                return;
            }

            switch (device.status) {
                case 'pending':
                case 'unverified':
                    setupDevices.push(device);
                    break;
                case 'stale':
                    reviewDevices.push(device);
                    break;
                default:
                    trustedDevices.push(device);
                    break;
            }
        });

        return {
            currentDevice,
            trustedDevices,
            setupDevices,
            reviewDevices,
            hasAttention: Boolean(
                (currentDevice && currentDevice.is_verified === false)
                || setupDevices.length
                || reviewDevices.length
            ),
        };
    }

    function getEmbeddedTerminalHeaderTitle() {
        return 'Embedded Terminal';
    }

    function getFolderRowStatusState({ isMounted = false, syncStatus = null, showSafetyAlert = false } = {}) {
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
    }

    const api = {
        getEmbeddedTerminalHeaderTitle,
        getFolderRowStatusState,
        buildPostQuantumStatusModel,
        buildWorkspaceHomeModel,
        buildFolderCoverageModel,
        buildFolderDetailModel,
        buildCoverageCenterModel,
        buildPersonalDevicesModel,
    };

    global.HybridCipherUiUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
