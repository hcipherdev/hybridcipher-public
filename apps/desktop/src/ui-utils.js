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

    function captureKeyedScrollPositions(container, selector = '[data-preserve-scroll-key]') {
        if (!container || typeof container.querySelectorAll !== 'function') {
            return {};
        }

        return Array.from(container.querySelectorAll(selector)).reduce((positions, element) => {
            const key = String(element?.dataset?.preserveScrollKey || '').trim();
            if (key) {
                positions[key] = Math.max(0, Number(element.scrollTop || 0));
            }
            return positions;
        }, {});
    }

    function restoreKeyedScrollPositions(container, positions = {}, selector = '[data-preserve-scroll-key]') {
        if (!container || typeof container.querySelectorAll !== 'function') {
            return;
        }

        Array.from(container.querySelectorAll(selector)).forEach(element => {
            const key = String(element?.dataset?.preserveScrollKey || '').trim();
            if (key && Object.prototype.hasOwnProperty.call(positions, key)) {
                element.scrollTop = Math.max(0, Number(positions[key] || 0));
            }
        });
    }

    function captureOpenDetailsKeys(container, selector = 'details[data-preserve-open-key]') {
        if (!container || typeof container.querySelectorAll !== 'function') {
            return [];
        }

        return Array.from(container.querySelectorAll(selector))
            .filter(element => element?.open)
            .map(element => String(element?.dataset?.preserveOpenKey || '').trim())
            .filter(Boolean);
    }

    function restoreOpenDetails(container, openKeys = [], selector = 'details[data-preserve-open-key]') {
        if (!container || typeof container.querySelectorAll !== 'function') {
            return;
        }

        const keys = new Set(openKeys);
        Array.from(container.querySelectorAll(selector)).forEach(element => {
            const key = String(element?.dataset?.preserveOpenKey || '').trim();
            if (key && keys.has(key)) {
                element.open = true;
            }
        });
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
        // A vault on this device with no folders yet has simply not started; there
        // is no account-side protection that could need review.
        localVault = false,
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
            } else if (localVault) {
                resolvedStatus = 'not_started';
                resolvedPrimaryText = 'Not started';
                resolvedSecondaryText = 'Add a protected folder to start securing files on this computer with post-quantum encryption.';
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
                    : (resolvedStatus === 'needs_review'
                        ? 'Protection needs review'
                        : (resolvedStatus === 'not_started' ? 'No folders protected yet' : 'Protection status unknown')),
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

    // `null`/`undefined` means "we could not determine this", which must never be
    // rendered as a confirmed protection failure.
    function optionalBoolean(value) {
        return value === null || value === undefined ? null : Boolean(value);
    }

    function shouldRetryWorkspaceStatusAfterSessionRefresh(unavailableSections) {
        if (!Array.isArray(unavailableSections)) return false;
        return unavailableSections.some(section =>
            section === 'sign-in protection' || section === 'this device'
        );
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
        const unavailableSections = Array.isArray(snapshot.unavailable_sections)
            ? snapshot.unavailable_sections.filter(Boolean).map(String)
            : [];
        // A vault on this device has no account, so sign-in protection, recovery
        // backups and device trust do not apply and are left out, not "unknown".
        const localVault = snapshot.local_vault === true;

        const mfaEnabled = optionalBoolean(snapshot.mfa_enabled);
        const recoveryBackupOk = optionalBoolean(snapshot.recovery_backup_ok);
        const recoveryAutoBackupOk = optionalBoolean(snapshot.recovery_auto_backup_ok);
        // Only treat a missing timestamp as "never scanned" when we know the scan
        // status was actually read. `scan_status_available === false` means unknown.
        const scanStatusKnown = snapshot.scan_status_available !== false;
        const scanIsFresh = scanAgeMs !== null && scanAgeMs <= 36 * 60 * 60 * 1000;

        const backupHealthy = recoveryBackupOk === null || recoveryAutoBackupOk === null
            ? null
            : recoveryBackupOk && recoveryAutoBackupOk;
        const deviceTrusted = currentDevice
            ? optionalBoolean(currentDevice.is_verified)
            : null;
        const folderIssues = toCount(folderAttention.conflicts) + toCount(folderAttention.recovery_copies);
        const postQuantum = buildPostQuantumStatusModel({
            protectedCount,
            status: snapshot.post_quantum_status || null,
            primaryText: snapshot.post_quantum_primary_text || null,
            secondaryText: snapshot.post_quantum_secondary_text || null,
            explainerAvailable: snapshot.post_quantum_explainer_available !== false,
            localVault,
        });

        const accountCardIds = new Set(['mfa', 'device']);
        const cards = [
            postQuantum.homeCard,
            mfaEnabled === null
                ? {
                    id: 'mfa',
                    title: 'Sign-in protection',
                    tone: 'unknown',
                    value: 'Unknown',
                    detail: 'HybridCipher could not check sign-in protection right now. Refresh to try again.',
                    ctaAction: 'refresh-workspace-status',
                    ctaLabel: 'Refresh',
                }
                : {
                    id: 'mfa',
                    title: 'Sign-in protection',
                    tone: mfaEnabled ? 'safe' : 'danger',
                    value: mfaEnabled ? 'On' : 'Off',
                    detail: mfaEnabled
                        ? 'Authenticator protection is enabled.'
                        : 'Turn on MFA to protect new sign-ins and recovery.',
                    ctaAction: mfaEnabled ? null : 'open-settings-mfa',
                },
            !scanStatusKnown
                ? {
                    id: 'scan',
                    title: 'Scan freshness',
                    tone: 'unknown',
                    value: 'Unknown',
                    detail: 'HybridCipher could not read the last scan time. Refresh to try again.',
                    ctaAction: 'refresh-workspace-status',
                    ctaLabel: 'Refresh',
                }
                : {
                    id: 'scan',
                    title: 'Scan freshness',
                    tone: scanIsFresh ? 'safe' : 'warning',
                    value: lastScanMs === null ? 'Not scanned yet' : (scanIsFresh ? 'Up to date' : 'Scan again'),
                    detail: lastScanMs === null
                        ? 'Run a scan to verify your protected folders are covered.'
                        : `Last scan ${new Date(lastScanMs).toISOString()}`,
                    ctaAction: 'run-coverage-scan',
                },
            deviceTrusted === null
                ? {
                    id: 'device',
                    title: 'This device',
                    tone: 'unknown',
                    value: 'Unknown',
                    detail: currentDevice?.device_id
                        ? `Trust status unavailable for ${currentDevice.device_id}. Refresh to try again.`
                        : 'HybridCipher could not check this device right now. Refresh to try again.',
                    ctaAction: 'refresh-workspace-status',
                    ctaLabel: 'Refresh',
                }
                : {
                    id: 'device',
                    title: 'This device',
                    tone: deviceTrusted ? 'safe' : 'danger',
                    value: deviceTrusted ? 'Trusted' : 'Needs verification',
                    detail: currentDevice?.device_id
                        ? `Device ID: ${currentDevice.device_id}`
                        : 'Current device information is unavailable.',
                    ctaAction: 'open-devices',
                },
        ].filter(card => !localVault || !accountCardIds.has(card.id));

        const attentionItems = [];
        if (unavailableSections.length > 0) {
            attentionItems.push({
                id: 'status-unavailable',
                title: 'Some protection checks could not be loaded',
                detail: `HybridCipher could not confirm ${unavailableSections.join(', ')}. The cards above show "Unknown" until this succeeds.`,
                action: {
                    id: 'refresh-workspace-status',
                    label: 'Refresh',
                },
            });
        }
        if (mfaEnabled === false) {
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
        if (backupHealthy === false) {
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
        // An empty vault is new, not overdue for a scan; the Home guide covers adding a folder.
        if (scanStatusKnown && !scanIsFresh && !(localVault && protectedCount === 0)) {
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
        if (deviceTrusted === false) {
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

        // A failed refresh is not the same as a confirmed problem, so it gets its
        // own softer tone instead of the red "Needs attention" state.
        const confirmedIssues = attentionItems.filter(item => item.id !== 'status-unavailable');
        let summaryTone = 'safe';
        let summaryLabel = 'Protected';
        if (confirmedIssues.length > 0) {
            summaryTone = 'danger';
            summaryLabel = 'Needs attention';
        } else if (unavailableSections.length > 0) {
            summaryTone = 'warning';
            summaryLabel = 'Status incomplete';
        } else if (localVault && protectedCount === 0) {
            summaryTone = 'idle';
            summaryLabel = 'Not started';
        }

        return {
            localVault,
            protectedCount,
            mountedCount,
            postQuantum,
            summaryTone,
            summaryLabel,
            unavailableSections,
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

    // Shared by the folder page "•••" menu and the sidebar right-click menu.
    // Destructive actions always come last so menus can draw a divider before them.
    function buildFolderSecondaryActions({ isMounted = false, isUnmounting = false, isMissing = false } = {}) {
        // A folder gone from its path can only be located again or dropped from the list.
        if (isMissing && !isMounted) {
            return [{ id: 'forget-missing-folder', label: 'Remove from list…', destructive: true }];
        }
        const actions = [
            { id: 'reveal-protected', label: 'Reveal encrypted source' },
            { id: 'run-coverage-scan', label: 'Scan for unprotected files' },
        ];
        if (isMounted) {
            actions.push({ id: 'unmount', label: isUnmounting ? 'Unmounting…' : 'Unmount folder…', destructive: true, disabled: isUnmounting });
        }
        actions.push({ id: 'remove-protection', label: 'Remove protection…', destructive: true, disabled: isUnmounting });
        return actions;
    }

    function buildFolderContextMenuActions({
        isMounted = false,
        isMounting = false,
        isUnmounting = false,
        hasConflicts = false,
        hasRecoveryCopies = false,
        isMissing = false,
    } = {}) {
        const actions = [];
        if (isMounted) {
            actions.push({ id: 'open-mounted', label: 'Open' });
        } else if (isMissing) {
            actions.push({ id: 'locate-folder', label: 'Locate folder…' });
        } else {
            actions.push({ id: 'mount', label: isMounting ? 'Mounting…' : 'Mount', disabled: isMounting || isUnmounting });
        }
        if (isMounted && hasConflicts) actions.push({ id: 'resolve-conflicts', label: 'Resolve conflicts' });
        if (isMounted && hasRecoveryCopies) actions.push({ id: 'resolve-recovery', label: 'Resolve recovery copies' });
        return actions.concat(buildFolderSecondaryActions({ isMounted, isUnmounting, isMissing }));
    }

    function buildFolderDetailModel({ folder = {}, mountInfo = null, isMounted = false, isMounting = false, isUnmounting = false, coverageReview = null } = {}) {
        const syncStatus = mountInfo?.syncStatus || mountInfo?.sync_status || {};
        const backend = mountInfo?.backend || null;
        const conflicts = toCount(syncStatus.pending_conflict_count);
        const recoveryCopies = toCount(syncStatus.recovered_pending_copy_count);
        const hasUnmountSafetyValue = Object.prototype.hasOwnProperty.call(syncStatus, 'safe_to_unmount');
        const safeToUnmount = isMounted && hasUnmountSafetyValue ? Boolean(syncStatus.safe_to_unmount) : null;
        const protection = buildPostQuantumStatusModel({ isProtectedFolder: Boolean(folder && (folder.root_id || folder.path)) }).folderDetail;
        // Renamed or moved outside the app; a running mount still serves it.
        const isMissing = folder?.available === false && !isMounted;
        const healthTone = isMissing || conflicts > 0 || recoveryCopies > 0 || safeToUnmount === false
            ? 'warning'
            : (isMounted ? 'safe' : 'idle');

        const pendingChanges = toCount(syncStatus.pending_writeback_count)
            + toCount(syncStatus.pending_refresh_count)
            + toCount(syncStatus.pending_open_unlinked_count);
        const secondaryActions = buildFolderSecondaryActions({ isMounted, isUnmounting, isMissing });

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
            isMissing,
            primaryAction: isMounted
                ? { id: 'open-mounted', label: 'Open mounted folder' }
                : (isMissing
                    ? { id: 'locate-folder', label: 'Locate folder…' }
                    : (isMounting
                        ? { id: 'mount', label: 'Mounting…', disabled: true }
                        : { id: 'mount', label: 'Mount folder' })),
            secondaryActions,
            attention: {
                conflicts,
                recoveryCopies,
                pendingChanges,
                mountStatusLabel: isUnmounting ? 'Unmounting' : (isMounted ? 'Mounted' : (isMounting ? 'Mounting' : 'Not mounted')),
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

    // The coverage IPC watcher is a Unix-socket-only channel, so on Windows the
    // backend always reports "unsupported". Coverage is still re-scanned by the
    // in-process watcher there, so don't surface a raw enum that reads like a
    // failure — say nothing rather than something alarming and wrong.
    function coverageWatcherLabel(ipcState) {
        switch (ipcState) {
            case 'active':
                return 'On';
            case 'inactive':
                return 'Off';
            case 'unsupported':
            default:
                return null;
        }
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
                    keyLabel: folder?.key_label || '',
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
            watcherLabel: coverageWatcherLabel(snapshot.ipc_state || 'inactive'),
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

    function formatDeviceFingerprintInput(value) {
        const compact = String(value || '').replace(/\s/g, '').toUpperCase();
        return compact.match(/.{1,4}/g)?.join(' ') || '';
    }

    function normalizeDeviceFingerprint(value) {
        const compact = String(value || '').replace(/\s/g, '').toUpperCase();
        return /^[0-9A-F]{16}$/.test(compact)
            ? compact.match(/.{4}/g).join(' ')
            : null;
    }

    function buildDeviceVerificationModel({ device = null, fingerprint = '' } = {}) {
        const userId = String(device?.user_id || '').trim();
        const email = String(device?.email || '').trim();
        const deviceId = String(device?.device_id || '').trim();
        const normalizedFingerprint = normalizeDeviceFingerprint(fingerprint);
        const userIdentifier = userId || email;

        return {
            userIdentifier,
            deviceId,
            fingerprint: normalizedFingerprint,
            canSubmit: Boolean(userIdentifier && deviceId && normalizedFingerprint),
        };
    }

    function buildDeviceVerificationCommand({ device = null, fingerprint = '', quoteArg = null } = {}) {
        const model = buildDeviceVerificationModel({ device, fingerprint });
        if (!model.canSubmit) {
            return null;
        }
        const quote = typeof quoteArg === 'function' ? quoteArg : value => String(value);
        return `hybridcipher pin verify ${quote(model.userIdentifier)} ${quote(model.deviceId)} --fingerprint ${quote(model.fingerprint)}`;
    }

    function getEmbeddedTerminalHeaderTitle() {
        return 'HybridCipher Console';
    }

    function filterProtectedFolders(folders, query) {
        const safeFolders = Array.isArray(folders) ? folders : [];
        const normalizedQuery = String(query || '').trim().toLocaleLowerCase();
        if (!normalizedQuery) {
            return safeFolders.slice();
        }

        return safeFolders.filter(folder => {
            const path = String(folder?.path || '');
            const displayPath = displayEnrolledPath(path);
            const basename = displayPath.split(/[\\/]/).filter(Boolean).pop() || '';
            return [folder?.name, basename, displayPath].some(value =>
                String(value || '').toLocaleLowerCase().includes(normalizedQuery)
            );
        });
    }

    function displayEnrolledPath(value) {
        const path = String(value || '');
        if (path.startsWith('\\\\?\\UNC\\')) {
            return `\\\\${path.slice(8)}`;
        }
        if (path.startsWith('\\\\?\\') && /^[A-Za-z]:[\\/]/.test(path.slice(4))) {
            return path.slice(4);
        }
        return path;
    }

    function isRoutineProviderReconciliation(syncStatus, observedDurationMs) {
        if (!syncStatus || syncStatus.safe_to_unmount !== false || syncStatus.last_error) return false;
        const reasons = syncStatus.unsafe_reasons;
        return Array.isArray(reasons)
            && reasons.length === 1
            && reasons[0]?.kind === 'provider_reconciliation'
            && Number.isFinite(observedDurationMs)
            && observedDurationMs >= 0
            && observedDurationMs < 30_000;
    }

    function buildAppModeUiModel(appMode) {
        const isIndividual = appMode === 'individual';
        return {
            searchPlaceholder: 'Filter folders…',
            showTechnicalNavigation: false,
            protectionNavigationLabel: isIndividual ? 'Protection status' : 'Coverage Center',
        };
    }

    const ADVANCED_SETTINGS_SECTION_IDS = new Set([
        'settingsAdvancedTools',
        'settingsAdvancedMountSection',
        'settingsAdvancedDeviceSection',
        'settingsAdvancedTrustSection',
        'settingsCoverageSection',
        'settingsTerminalSection',
    ]);

    function shouldExpandAdvancedSettings(sectionId) {
        return ADVANCED_SETTINGS_SECTION_IDS.has(String(sectionId || ''));
    }

    function getFolderRowStatusState({ isMounted = false, isMounting = false, isUnmounting = false, syncStatus = null, showSafetyAlert = false } = {}) {
        if (isUnmounting) {
            return {
                showMountedBadge: false,
                showMountingBadge: false,
                showUnmountingBadge: true,
                showAlertButton: false,
                healthDotTone: null,
            };
        }
        if (!isMounted) {
            return {
                showMountedBadge: false,
                showMountingBadge: Boolean(isMounting),
                showUnmountingBadge: false,
                showAlertButton: false,
                healthDotTone: null,
            };
        }

        const status = syncStatus || {};
        const hasConflicts = Number(status.pending_conflict_count || 0) > 0;
        const hasRecoveryCopies = Number(status.recovered_pending_copy_count || 0) > 0;

        return {
            showMountedBadge: true,
            showMountingBadge: false,
            showUnmountingBadge: false,
            showAlertButton: Boolean(showSafetyAlert),
            healthDotTone: hasConflicts || hasRecoveryCopies ? 'red' : 'green',
        };
    }

    function buildMountConflictReviewState({ records = [], syncStatus = null } = {}) {
        const listedCount = Array.isArray(records) ? records.length : 0;
        const statusAvailable = Boolean(syncStatus && typeof syncStatus === 'object');
        const reportedCount = statusAvailable
            ? Math.max(0, toCount(syncStatus.pending_conflict_count))
            : null;
        const mismatch = statusAvailable && listedCount !== reportedCount;
        const otherUnsafeReasons = statusAvailable && Array.isArray(syncStatus.unsafe_reasons)
            ? syncStatus.unsafe_reasons.filter(reason => reason?.kind !== 'conflict')
            : [];
        const hasOtherBlockingWork = statusAvailable
            ? syncStatus.safe_to_unmount === false && (reportedCount === 0 || otherUnsafeReasons.length > 0)
            : false;

        return {
            listedCount,
            reportedCount,
            statusAvailable,
            mismatch,
            isClear: statusAvailable && !mismatch && listedCount === 0,
            safeToUnmount: statusAvailable ? syncStatus.safe_to_unmount === true : null,
            hasOtherBlockingWork,
        };
    }

    function pendingOperationLabel(status = {}) {
        const count = Math.max(0, toCount(status.pending_operation_count));
        const files = Math.max(0, toCount(status.affected_file_count));
        const kind = count > 0 && toCount(status.pending_operation_counts?.rename) === count ? 'rename' : 'operation';
        return `${count} unresolved ${pluralize(count, kind, `${kind}s`)} affecting ${files} ${pluralize(files, 'file', 'files')}`;
    }

    function actionErrorMessage(error, fallback = 'Folder action failed.') {
        if (typeof error === 'string' && error.trim()) return error;
        if (typeof error?.message === 'string' && error.message.trim()) return error.message;
        return fallback;
    }

    function normalizeFolderMountStatus(status) {
        return status?.error === 'Mount not found'
            ? { success: true, data: null }
            : status;
    }

    async function runFolderUnenrollFlow({ rootId, path, choose, confirmCloudRisk,
        checkMount, confirmUnmount, unmount, invokeCommand }) {
        const choice = await choose(path);
        if (choice !== 'primary' && choice !== 'secondary') return null;

        const decrypt = choice === 'secondary';
        if (decrypt && !await confirmCloudRisk(path)) return null;

        const mountStatus = await checkMount(rootId);
        if (!mountStatus || mountStatus.success !== true) {
            throw new Error(mountStatus?.error || 'Could not check whether the folder is mounted.');
        }
        if (mountStatus.data) {
            if (!await confirmUnmount(mountStatus.data)) return null;
            if (!await unmount()) throw new Error('Unmount failed. Cannot proceed with removal.');
            const afterUnmount = await checkMount(rootId);
            if (!afterUnmount || afterUnmount.success !== true || afterUnmount.data) {
                throw new Error('Could not confirm that the folder is unmounted.');
            }
        }

        const command = decrypt ? 'unenroll_folder_and_decrypt' : 'unenroll_folder_keep_encrypted';
        const response = await invokeCommand(command, { rootId });
        if (!response?.success) throw new Error(response?.error || 'Folder removal failed.');
        return { decrypt, response };
    }

    const FOLDER_JOB_PHASE_LABELS = {
        encrypting: 'Encrypting files…',
        finalizing: 'Finishing up…',
        rescanning: 'Checking the folder…',
        decrypting: 'Decrypting files…',
    };

    /**
     * What the progress dialog and its background chip show for a folder job.
     * `progress` is the latest `folder_job_progress` payload, or null before the
     * first one, while files are still being counted; `percent` is then null so
     * the bar shows activity without a value.
     */
    function buildFolderJobProgressModel({ kind = 'protect', name = '', progress = null } = {}) {
        const folder = name || 'folder';
        const title = kind === 'unprotect' ? `Removing protection from ${folder}` : `Protecting ${folder}`;
        if (!progress) {
            const phaseLabel = 'Counting files…';
            return { title, percent: null, phaseLabel, detail: '', chipLabel: `${title} · ${phaseLabel}` };
        }
        const total = Math.max(0, toCount(progress.total_files));
        const processed = Math.min(total, Math.max(0, toCount(progress.processed_files)));
        const failed = Math.max(0, toCount(progress.failed_files));
        const percent = total === 0 ? 100 : Math.floor((processed * 100) / total);
        const phaseLabel = FOLDER_JOB_PHASE_LABELS[progress.phase] || 'Working…';
        const counted = total === 0
            ? 'No files to process'
            : `${processed.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} ${pluralize(total, 'file', 'files')} · ${percent}%`;
        const detail = failed > 0
            ? `${counted} · ${failed.toLocaleString('en-US')} could not be processed`
            : counted;
        return { title, percent, phaseLabel, detail, chipLabel: `${title} · ${percent}%` };
    }

    /**
     * Plain-language lines for a finished operation, taken from the CLI's own success lines
     * ("✓ …"), so the raw transcript can stay collapsed under technical details.
     */
    function summarizeOperationOutput(lines, limit = 4) {
        if (!Array.isArray(lines)) return [];
        const summary = [];
        for (const raw of lines) {
            const line = String(raw ?? '').replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').trim();
            const match = line.match(/^(?:✓|✔)\s*(?:✅\s*)?(.+)$/u);
            if (!match) continue;
            const text = match[1].trim();
            if (text && !summary.includes(text)) summary.push(text);
        }
        return summary.slice(-limit);
    }

    const PEOPLE_STATUS_ORDER = { ready_to_add: 0, has_access: 1, invited: 2 };

    /**
     * Rows for the People panel, limited to this group: who can open it, who an admin added to it
     * and still needs access, and who was invited to it and has not joined yet. Other organization
     * members are found through Add person, or on the Members & devices page.
     */
    /** One-line device summary for a People row, e.g. "2 devices · 1 inactive" or "1 device · active 2h ago". */
    function describeMemberDevices(devices, now = Date.now()) {
        const list = Array.isArray(devices) ? devices : [];
        if (!list.length) return 'No devices yet';
        const parts = [list.length === 1 ? '1 device' : `${list.length} devices`];
        const inactive = list.filter(device => device?.stale).length;
        if (inactive) {
            parts.push(`${inactive} inactive`);
        } else {
            const latest = Math.max(...list.map(device => Date.parse(device?.last_seen)).filter(Number.isFinite));
            const activity = describeActivity(latest, now);
            if (activity) parts.push(activity);
        }
        return parts.join(' · ');
    }

    /** "active within the hour", "active 5h ago" or "active 3d ago"; empty when unknown. */
    function describeActivity(lastSeenMs, now = Date.now()) {
        if (!Number.isFinite(lastSeenMs)) return '';
        const minutes = Math.max(0, Math.floor((now - lastSeenMs) / 60000));
        return minutes < 60 ? 'active within the hour'
            : minutes < 48 * 60 ? `active ${Math.floor(minutes / 60)}h ago`
                : `active ${Math.floor(minutes / 1440)}d ago`;
    }

    const MEMBER_DEVICE_STATUS = {
        pending: { rank: 0, label: 'Needs approval' },
        unverified: { rank: 1, label: 'Unverified' },
        missing_key: { rank: 2, label: 'Missed key update' },
        stale: { rank: 3, label: 'Stale' },
        trusted: { rank: 4, label: 'Trusted' },
    };
    const MEMBER_DEVICE_FILTERS = new Set(['all', 'attention', 'needs_access', 'invited', 'pending', 'unverified', 'missing_key', 'stale']);
    const groupRefs = value => (Array.isArray(value) ? value : []).filter(group => group?.id);

    /**
     * Rows for the organization "Members & devices" page. Devices and members are sorted most
     * urgent first, then open invitations; `filter` is 'all', 'attention', 'needs_access',
     * 'invited' or one device status, and `query` matches an email or a device name. Counts cover
     * the whole roster so the filter chips stay stable. A member an admin chose groups for still
     * needs those adds finished, which counts as attention. An unknown device status from a newer
     * server counts as unverified rather than trusted.
     */
    function buildMemberDeviceRows({ roster, invitations = [], filter = 'all', query = '', currentUserId = null, currentDeviceId = null,
        actorRole = 'admin', now = Date.now() } = {}) {
        const members = Array.isArray(roster?.members) ? roster.members : [];
        const counts = { members: members.length, devices: 0, attention: 0, needs_access: 0, invited: 0,
            pending: 0, unverified: 0, missing_key: 0, stale: 0 };
        const all = members.map(member => {
            const isSelf = Boolean(currentUserId) && member.user_id === currentUserId;
            // Only an owner may revoke an owner's devices; your own go through Devices.
            const canRevoke = !isSelf && ['owner', 'admin'].includes(actorRole) && (member.role !== 'owner' || actorRole === 'owner');
            const devices = (Array.isArray(member.devices) ? member.devices : []).map(device => {
                const status = MEMBER_DEVICE_STATUS[device.status] ? device.status : 'unverified';
                const missingKeyGroups = Array.isArray(device.missing_key_groups) ? device.missing_key_groups : [];
                // The member sets this one up from another trusted device of theirs; it keeps its
                // status but never asks the admin for attention.
                const ownerCanSetUp = device.owner_can_self_approve === true
                    && ['pending', 'unverified', 'missing_key'].includes(status);
                const reasons = [
                    ...(status === 'pending' ? [ownerCanSetUp ? 'They can give it access from another of their devices'
                        : 'No other trusted device: a group admin needs to give it access'] : []),
                    ...(device.approved === false && status !== 'pending' ? ['Not approved by another trusted device'] : []),
                    ...(device.approved !== false && device.fingerprint_verified === false
                        ? [ownerCanSetUp ? 'They can verify it from another of their devices' : 'Fingerprint not checked yet'] : []),
                    ...missingKeyGroups.map(group => `Missed the current key for ${group.name}${ownerCanSetUp ? '; their other device sends it' : ''}`),
                    ...(Array.isArray(device.stale_reasons) ? device.stale_reasons : []),
                ];
                return {
                    id: device.device_id,
                    name: device.device_name || device.device_id,
                    status,
                    label: MEMBER_DEVICE_STATUS[status].label,
                    reasons,
                    activity: describeActivity(Date.parse(device.last_seen), now),
                    missingKeyGroups,
                    isCurrent: Boolean(currentDeviceId) && device.device_id === currentDeviceId,
                    canRevoke: canRevoke && device.device_id !== currentDeviceId,
                    ownerCanSetUp,
                    needsAttention: status !== 'trusted' && !ownerCanSetUp,
                };
            }).sort((a, b) => MEMBER_DEVICE_STATUS[a.status].rank - MEMBER_DEVICE_STATUS[b.status].rank || a.name.localeCompare(b.name));
            for (const device of devices) {
                counts.devices += 1;
                if (device.status !== 'trusted') counts[device.status] += 1;
            }
            const worst = devices[0]?.status || null;
            const pendingGroups = groupRefs(member.pending_groups);
            if (pendingGroups.length) counts.needs_access += 1;
            const attention = pendingGroups.length > 0 || devices.some(device => device.needsAttention);
            if (attention) counts.attention += 1;
            const needing = devices.filter(device => device.needsAttention).length;
            return {
                kind: 'member',
                userId: member.user_id,
                email: String(member.email || ''),
                role: member.role || 'member',
                groups: (Array.isArray(member.groups) ? member.groups : []).map(group => group.name),
                groupIds: groupRefs(member.groups).map(group => group.id),
                pendingGroups,
                devices,
                worst,
                worstLabel: worst ? MEMBER_DEVICE_STATUS[worst].label : 'No devices',
                attention,
                isSelf,
                canRevoke,
                summary: !devices.length ? 'No devices yet'
                    : `${devices.length === 1 ? '1 device' : `${devices.length} devices`}${needing ? ` · ${needing} need${needing === 1 ? 's' : ''} attention` : ''}`,
            };
        });
        // Open invitations: people who hold a seat but have not joined yet.
        const invited = (Array.isArray(invitations) ? invitations : [])
            .filter(invite => invite?.status === 'pending' && Date.parse(invite.expires_at) > now)
            .map(invite => {
                const pendingGroups = groupRefs(invite.pending_groups);
                const names = list => list.map(group => group.name).join(', ');
                const ready = pendingGroups.filter(group => group.staged);
                const later = pendingGroups.filter(group => !group.staged);
                return {
                    kind: 'invitation',
                    invitationId: invite.id,
                    email: String(invite.email || ''),
                    pendingGroups,
                    devices: [],
                    attention: false,
                    summary: `Invited · ${[ready.length ? `gets ${names(ready)} when they accept` : '',
                        later.length ? `gets ${names(later)} after joining` : ''].filter(Boolean).join(' · ') || 'no group yet'}`,
                };
            })
            .sort((a, b) => a.email.localeCompare(b.email));
        counts.invited = invited.length;
        const selected = MEMBER_DEVICE_FILTERS.has(filter) ? filter : 'all';
        const needle = String(query || '').trim().toLowerCase();
        const matches = row => !needle || row.email.toLowerCase().includes(needle)
            || row.devices.some(device => device.name.toLowerCase().includes(needle));
        const memberRows = selected !== 'invited'
            ? all.filter(row => (selected === 'all'
                || (selected === 'attention' ? row.attention
                    : selected === 'needs_access' ? row.pendingGroups.length > 0
                        : row.devices.some(device => device.status === selected))) && matches(row))
                .sort((a, b) => Number(b.attention) - Number(a.attention)
                    || Number(b.pendingGroups.length > 0) - Number(a.pendingGroups.length > 0)
                    || (a.worst ? MEMBER_DEVICE_STATUS[a.worst].rank : 9) - (b.worst ? MEMBER_DEVICE_STATUS[b.worst].rank : 9)
                    || a.email.localeCompare(b.email))
            : [];
        const invitationRows = ['all', 'invited'].includes(selected) ? invited.filter(matches) : [];
        return { rows: [...memberRows, ...invitationRows], counts, filter: selected };
    }

    function buildPeopleRows({ directory, groupMembers, groupId, currentUserEmail, memberDevices = null, now = Date.now() } = {}) {
        const lower = value => String(value || '').trim().toLowerCase();
        // Device details are optional; without them rows keep their access-only labels.
        const devicesFor = (email, userId) => {
            if (!memberDevices) return {};
            const entry = memberDevices.get(lower(email)) || memberDevices.get(String(userId || ''));
            const devices = entry?.devices || [];
            return { devicesLabel: describeMemberDevices(devices, now), inactiveDevices: devices.filter(device => device?.stale).length };
        };
        const inGroup = new Map();
        for (const member of Array.isArray(groupMembers) ? groupMembers : []) {
            inGroup.set(lower(member.email) || member.user_id, member);
        }
        // The server lists the groups an admin chose for each member or invitation.
        const promised = entry => (Array.isArray(entry?.pending_groups) ? entry.pending_groups : [])
            .some(group => String(group?.id) === String(groupId));
        const me = lower(currentUserEmail);
        const rows = [];
        const seen = new Set();
        for (const member of Array.isArray(directory?.members) ? directory.members : []) {
            const email = lower(member.email);
            seen.add(email);
            const groupMember = inGroup.get(email) || inGroup.get(member.user_id);
            const self = Boolean(me) && email === me;
            if (groupMember) {
                rows.push({ key: `member:${member.user_id}`, email, userId: member.user_id, status: 'has_access',
                    label: self ? 'You · has access' : 'Has access',
                    action: self || groupMember.is_owner ? null : 'remove', ...devicesFor(email, member.user_id) });
            } else if (promised(member)) {
                rows.push({ key: `member:${member.user_id}`, email, userId: member.user_id, status: 'ready_to_add',
                    label: 'Joined · finish giving access', action: 'add' });
            }
        }
        for (const member of Array.isArray(groupMembers) ? groupMembers : []) {
            const email = lower(member.email);
            if (seen.has(email)) continue;
            seen.add(email);
            const self = Boolean(me) && email === me;
            rows.push({ key: `member:${member.user_id}`, email, userId: member.user_id, status: 'has_access',
                label: self ? 'You · has access' : 'Has access', action: self || member.is_owner ? null : 'remove',
                ...devicesFor(email, member.user_id) });
        }
        for (const invitation of Array.isArray(directory?.invitations) ? directory.invitations : []) {
            const email = lower(invitation.email);
            // Only invitations that bring someone into this group belong here.
            if (invitation.status !== 'pending' || Date.parse(invitation.expires_at) <= now || seen.has(email) || !promised(invitation)) continue;
            seen.add(email);
            const staged = (Array.isArray(invitation.pending_groups) ? invitation.pending_groups : [])
                .some(group => String(group?.id) === String(groupId) && group.staged);
            rows.push({ key: `invite:${invitation.id}`, email, invitationId: invitation.id, status: 'invited',
                label: staged ? 'Invited · gets access when they accept' : 'Invited · gets access to this group after joining',
                action: 'cancel_invite' });
        }
        return rows.sort((a, b) => PEOPLE_STATUS_ORDER[a.status] - PEOPLE_STATUS_ORDER[b.status] || a.email.localeCompare(b.email));
    }

    /** Plain-language outcome of a task-level Team action (see `team_tasks.rs`). */
    function describeTeamTaskResult(result) {
        if (!result || typeof result !== 'object') return [];
        const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
        const skipped = list => Array.isArray(list) && list.length
            ? [`${plural(list.length, 'device')} could not receive the new keys yet and will need approval.`] : [];
        // What the rotation did with this computer's files (`files` in the rotation result).
        const filesMoved = files => {
            if (!files || typeof files !== 'object') return [];
            if (files.error) return [`This computer's files were not moved yet (${files.error}). HybridCipher tries again within the hour.`];
            if (files.rotation_running) return ['This computer\'s files move to the new key once the server finishes the rotation.'];
            const lines = files.moved > 0 ? [`Moved ${plural(files.moved, 'file')} on this computer to the new key.`] : [];
            if (files.failed > 0) {
                const names = (Array.isArray(files.failures) ? files.failures : [])
                    .map(failure => `${String(failure.path || '').split(/[\\/]/).pop()}: ${failure.reason}`);
                lines.push(`${plural(files.failed, 'file')} could not be moved; HybridCipher tries again within the hour.`, ...names);
            }
            return lines;
        };
        // `on_accept`: their devices already hold the group key; otherwise a group admin's app adds them after they join.
        const invitationAccess = task => (task.access === 'on_accept'
            ? 'They get access to this group as soon as they accept the invitation in HybridCipher.'
            : 'They get access to this group after they sign up and accept; a group admin\'s app finishes adding them automatically.');
        switch (result.action) {
            case 'member_added': {
                const lines = [`${result.email} now has access to this group.`];
                if (result.devices_added > 0) lines.push(`${plural(result.devices_added, 'device')} received the group key.`);
                const unverified = Array.isArray(result.unverified_devices) ? result.unverified_devices.length : 0;
                if (unverified) lines.push(`${plural(unverified, 'device')} not verified yet. Compare fingerprints in Devices.`);
                return lines;
            }
            case 'person_invited':
                return [`Invitation sent to ${result.email}.`, invitationAccess(result)];
            case 'already_invited':
                return [`${result.email} already has a pending invitation. This group was added to it.`, invitationAccess(result)];
            case 'invitation_access':
                return [invitationAccess(result)];
            case 'access_removed':
                return [`Access removed for ${result.member}.`,
                    result.keys_rotated
                        ? 'Group keys were rotated, so they cannot open files added from now on.'
                        : 'Keys were not rotated. Rotate them in Keys & security to stop access to new files.',
                    ...skipped(result.rotation?.skipped_devices), ...filesMoved(result.rotation?.files)];
            case 'keys_rotated':
                return ['Group keys rotated. Current members receive the new keys automatically.',
                    ...skipped(result.rotation?.skipped_devices), ...filesMoved(result.rotation?.files)];
            case 'device_approved':
                return ['Device approved. It gets access the next time it syncs.'];
            default:
                return [];
        }
    }

    const counted = (count, singular, plural = `${singular}s`) => `${count} ${pluralize(count, singular, plural)}`;
    const byGroupName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) || a.id.localeCompare(b.id);

    /** A group's initial and one of six tones, stable for its id, so it reads the same in the sidebar and on cards. */
    function groupMark(group) {
        const id = String(group?.id || '');
        let hash = 0;
        for (const char of id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
        const name = String(group?.name || '').trim();
        return { initial: (name.match(/[\p{L}\p{N}]/u)?.[0] || '?').toUpperCase(), tone: hash % 6 };
    }

    /** Sidebar entries for a Team's groups, by name; only the selected group carries the attention count. */
    function buildSidebarGroupItems({ groups, activeGroupId = null, query = '', attentionCount = 0 } = {}) {
        const filter = String(query || '').trim().toLowerCase();
        return (Array.isArray(groups) ? groups : [])
            .filter(group => group?.id)
            .map(group => ({ id: String(group.id), name: String(group.name || 'Unnamed group') }))
            .filter(group => !filter || group.name.toLowerCase().includes(filter))
            .sort(byGroupName)
            .map(group => {
                const selected = group.id === String(activeGroupId || '');
                return { ...group, ...groupMark(group), selected, badge: selected && attentionCount > 0 ? String(attentionCount) : '' };
            });
    }

    /** Team overview cards: each group with its people, and for admins its key version, when the server summary has them. */
    function buildTeamGroupCards({ groups, summaries = [], activeGroupId = null, attentionCount = 0, showKeyVersion = true } = {}) {
        const summaryById = new Map((Array.isArray(summaries) ? summaries : []).map(summary => [String(summary?.id), summary]));
        return buildSidebarGroupItems({ groups, activeGroupId }).map(item => {
            const summary = summaryById.get(item.id);
            const facts = [];
            if (Number.isFinite(summary?.member_count)) facts.push(counted(summary.member_count, 'person', 'people'));
            if (showKeyVersion && Number.isFinite(summary?.current_key_version)) facts.push(`Key version ${summary.current_key_version}`);
            return { id: item.id, name: item.name, initial: item.initial, tone: item.tone, selected: item.selected,
                facts: facts.join(' · '), status: item.selected && attentionCount > 0 ? `${attentionCount} to do` : item.selected ? 'Selected' : '' };
        });
    }

    /** The group page's one-line summary: people, folders, key version, and the viewer's role. */
    function describeGroupFacts({ summary = null, folderCount = null, role = '' } = {}) {
        const facts = [];
        if (Number.isFinite(summary?.member_count)) facts.push(counted(summary.member_count, 'person', 'people'));
        if (Number.isFinite(folderCount)) facts.push(counted(folderCount, 'protected folder'));
        if (Number.isFinite(summary?.current_key_version)) facts.push(`Key version ${summary.current_key_version}`);
        const roleName = String(role || '').trim().toLowerCase();
        if (roleName === 'owner') facts.push('You are the owner');
        else if (roleName) facts.push(`You are ${/^[aeiou]/.test(roleName) ? 'an' : 'a'} ${roleName}`);
        return facts.join(' · ');
    }

    /**
     * The devices an admin is reminded about. A device whose owner has another trusted device
     * holding the key is the owner's to set up, and one that also waits for keys gets a single
     * "give access" entry, which verifies it along the way. Devices only this computer hasn't
     * verified are handled in the rotation dialog, where a skipped one is repaired by its owner.
     */
    function adminDeviceReminders({ pendingDevices = [], unverifiedDevices = [] } = {}) {
        const rows = buildDeviceAccessQueue({ pendingDevices, unverifiedDevices }).filter(row => row.needsAdmin);
        return {
            pending: rows.filter(row => row.action === 'give-access').map(row => row.device),
            unverified: rows.filter(row => row.action === 'verify').map(row => row.device),
        };
    }

    /**
     * The group's "Devices to set up" list: one row per device, devices waiting for keys first.
     * A waiting device gets "give access" (fingerprint, then keys); one that has keys but isn't
     * verified gets "verify". `needsAdmin` is false for a device its owner can set up and for one
     * only this computer hasn't verified; those stay listed but aren't counted.
     */
    function buildDeviceAccessQueue({ pendingDevices = [], unverifiedDevices = [] } = {}) {
        const list = value => (Array.isArray(value) ? value : []).filter(entry => entry?.device_id);
        const rows = [];
        const seen = new Set();
        const add = (device, action) => {
            if (seen.has(device.device_id)) return;
            seen.add(device.device_id);
            const selfApprovable = device.owner_can_self_approve === true;
            const notVerifiedHere = device.reason_code === 'not_verified_here';
            rows.push({
                device,
                action,
                needsAdmin: !selfApprovable && !notVerifiedHere,
                note: selfApprovable ? 'Their own trusted device can do this.'
                    : notVerifiedHere ? 'Not verified on this computer. Key rotations from here need it.'
                    : device.missing_current_key ? 'Missed the latest key rotation.'
                    : '',
            });
        };
        list(pendingDevices).forEach(device => add(device, 'give-access'));
        list(unverifiedDevices).forEach(device => add(device, 'verify'));
        return rows;
    }

    /**
     * The JSON line `hybridcipher repair-own-devices --json` prints:
     * `{ repaired: [{ device_id, groups_given, groups_needing_admin }], needs_check: [id], skipped }`,
     * or null when there is none.
     */
    function parseOwnDeviceRepairReport(output) {
        const line = String(output || '').split(/\r?\n/).reverse().find(text => text.trim().startsWith('{'));
        if (!line) return null;
        try {
            const report = JSON.parse(line);
            return {
                repaired: Array.isArray(report.repaired) ? report.repaired : [],
                needsCheck: Array.isArray(report.needs_check) ? report.needs_check : [],
                skipped: report.skipped === true,
            };
        } catch (_) {
            return null;
        }
    }

    /**
     * The summary `hybridcipher issue-welcome` prints after giving an own device access, e.g.
     * "Gave access in 1 of 2 groups; Design needs a group admin."; null when there is none.
     */
    function parseOwnDeviceAccessSummary(output) {
        const line = String(output || '')
            .replace(/\u001b\[[0-9;]*m/g, '')
            .split(/\r?\n/)
            .map(entry => entry.trim())
            .find(entry => entry.includes('Gave access in '));
        if (!line) return null;
        const message = line.slice(line.indexOf('Gave access in '));
        return { message, needsAdmin: /need(s)? a group admin/.test(message) };
    }

    /** The Home notice on a trusted device while other devices of the account wait for access. */
    function buildOwnDeviceAccessNotice({ pendingDevices = [], currentDeviceId = null, canGiveAccess = false } = {}) {
        const waiting = (Array.isArray(pendingDevices) ? pendingDevices : [])
            .filter(device => device?.device_id && device.device_id !== currentDeviceId);
        if (!canGiveAccess || !waiting.length) return { visible: false, devices: [] };
        const [first] = waiting;
        const name = first.device_name || `device ${String(first.device_id).slice(0, 8)}`;
        if (waiting.length > 1) {
            return { visible: true, devices: waiting, action: 'open-devices', actionLabel: 'Review devices',
                message: `${waiting.length} of your devices are waiting for access.` };
        }
        return { visible: true, devices: waiting, action: 'give-access', actionLabel: 'Give access', deviceId: first.device_id,
            message: first.missing_current_key
                ? `Your device ${name} is missing a group key. Send it from this device.`
                : `Your new device ${name} is waiting for access. Compare its code, then give it access from this device.` };
    }

    /**
     * What waits on an admin in the selected group, most direct first: people who joined and need access,
     * devices to give access, devices to verify, then one entry for inactive devices.
     */
    function buildTeamTodoItems({ groupName = 'this group', people = [], pendingDevices = [], unverifiedDevices = [], staleDevices = [] } = {}) {
        const list = value => (Array.isArray(value) ? value : []);
        const owner = device => device?.email || 'Unknown member';
        const deviceName = device => device?.device_name || `device ${String(device?.device_id || '').slice(0, 8)}`;
        const items = [];
        for (const row of list(people).filter(entry => entry?.status === 'ready_to_add' && entry.email)) {
            items.push({ key: `access:${row.email}`, kind: 'access', title: `Give ${row.email} access`,
                detail: `${groupName} · joined and waiting for access`, action: 'give_access', actionLabel: 'Give access', email: row.email });
        }
        const { pending, unverified } = adminDeviceReminders({ pendingDevices, unverifiedDevices });
        for (const device of pending) {
            items.push({ key: `approve:${device.device_id}`, kind: 'approve', title: `Give ${owner(device)}'s ${deviceName(device)} access`,
                detail: `${groupName} · ${device.missing_current_key ? 'missed the latest key rotation' : "waiting for this group's keys"}`,
                action: 'approve_device', actionLabel: 'Give access', deviceId: device.device_id });
        }
        for (const device of unverified) {
            items.push({ key: `verify:${device.device_id}`, kind: 'verify', title: `Verify ${owner(device)}'s ${deviceName(device)}`,
                detail: `${groupName} · compare its fingerprint before trusting it`, action: 'verify_device', actionLabel: 'Verify',
                deviceId: device.device_id });
        }
        const stale = list(staleDevices).length;
        if (stale) {
            items.push({ key: 'stale', kind: 'stale', title: counted(stale, 'inactive device'),
                detail: `${groupName} · not seen for 30+ days or missing a key`, action: 'review_stale', actionLabel: 'Review' });
        }
        return items;
    }

    const MOUNT_CENTER_WORKSPACE_ORDER = { personal: 0, team: 1, vault: 2, other: 3 };

    // What each step of a background mount is doing, as shown in the Mount Center.
    function mountStepLabel(step, platform = 'macos') {
        const finder = platform === 'windows' ? 'File Explorer' : 'Finder';
        return {
            checking: 'Checking access',
            registering: `Registering with ${finder}`,
            connecting_finder: `Waiting for ${finder}`,
            waking_extension: `Connecting ${finder} to the folder`,
            sync_fallback: 'Starting sync mount',
            ready: 'Ready',
            failed: 'Failed',
        }[step] || 'Starting';
    }

    // A mounted folder whose files are still being decrypted for the first time; they
    // open on demand meanwhile. Empty once that first pass is done.
    function mountPreparingLabel(syncStatus) {
        const preparing = syncStatus?.preparing_files;
        const total = Math.max(0, toCount(preparing?.total));
        if (!preparing || total === 0) return '';
        const done = Math.min(total, Math.max(0, toCount(preparing.processed)));
        const percent = Math.floor((done * 100) / total);
        return `Preparing files ${done.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} · ${percent}% · files open on demand`;
    }

    function formatMountSeconds(ms) {
        const seconds = Math.max(0, Math.round((Number(ms) || 0) / 1000));
        return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
    }

    // The unmount window: one row per folder of a batch. `batch.phase` is 'checking' while the
    // app looks for unsaved encrypted changes, 'unmounting' while the backend stops folders,
    // then 'done'. `batch.folders` maps root ids to the latest backend progress, with
    // `received_at` set when it arrived; `now` advances elapsed times between updates.
    function buildUnmountProgressModel(batch, { now = Date.now(), platform = 'macos' } = {}) {
        const finder = platform === 'windows' ? 'File Explorer' : 'Finder';
        const order = Array.isArray(batch?.order) ? batch.order : [];
        const folders = batch?.folders || {};
        const rows = order.map(rootId => {
            const folder = folders[rootId] || {};
            const status = String(folder.status || 'queued');
            let label = 'Waiting';
            if (batch?.phase === 'checking') label = 'Checking for unsaved changes';
            else if (status === 'running') label = folder.step === 'removing' ? 'Removing' : `Waiting for ${finder} to hand over edits`;
            else if (status === 'done') label = 'Unmounted';
            else if (status === 'failed') label = `Couldn’t unmount: ${folder.error || 'unknown error'}`;
            const elapsedMs = (Number(folder.elapsed_ms) || 0)
                + (status === 'running' && folder.received_at ? Math.max(0, now - folder.received_at) : 0);
            return {
                rootId: String(rootId),
                name: String(folder.name || rootId),
                status,
                label,
                elapsedLabel: status === 'running' || status === 'done' ? formatMountSeconds(elapsedMs) : '',
                failed: status === 'failed',
                notSafe: folder.error_code === 'UNMOUNT_NOT_SAFE',
            };
        });
        const done = rows.filter(row => row.status === 'done').length;
        const failed = rows.filter(row => row.failed).length;
        const total = rows.length;
        const running = batch?.phase !== 'done';
        const noun = count => `${count} folder${count === 1 ? '' : 's'}`;
        let summary;
        if (batch?.phase === 'checking') summary = `Checking ${noun(total)} for unsaved changes…`;
        else if (running) summary = `Unmounting ${noun(total)}… ${done} of ${total} done`;
        else if (failed > 0) summary = `${noun(failed)} couldn’t be unmounted. ${done} of ${total} unmounted.`;
        else if (batch?.error) summary = `Folders were unmounted, but cleanup reported: ${batch.error}`;
        else summary = `${total === 1 ? 'The folder is' : `All ${noun(total)} are`} unmounted and still protected.`;
        return {
            title: String(batch?.label || 'Unmounting folders'),
            rows,
            total,
            done,
            failed,
            running,
            summary,
            canRunInBackground: running && batch?.allowBackground !== false,
        };
    }

    // How to reach a Mount Center folder's page in the app: it is either in the selected group
    // ('here'), in the other workspace ('workspace'), in another Team group ('group'), or outside
    // every workspace ('unavailable').
    function planFolderPageRoute(folder, { activeWorkspaceType = 'personal', activeGroupId = '', localVaultMode = false } = {}) {
        const workspace = folder?.workspace;
        const groupId = folder?.group_id ? String(folder.group_id) : '';
        if (workspace === 'vault') return localVaultMode ? { kind: 'here' } : { kind: 'unavailable' };
        if ((workspace !== 'personal' && workspace !== 'team') || !groupId || localVaultMode) return { kind: 'unavailable' };
        if (workspace !== activeWorkspaceType) return { kind: 'workspace', workspace, groupId };
        if (groupId === String(activeGroupId || '')) return { kind: 'here' };
        return workspace === 'team' ? { kind: 'group', groupId } : { kind: 'workspace', workspace, groupId };
    }

    // Groups every enrolled folder of the account by workspace and group for the Mount Center.
    // `busy` maps root ids to 'mounting' or 'unmounting' while the app works on them itself.
    // `queue` maps root ids to the latest background mount job (from the backend queue, with
    // `received_at` set when it arrived); `now` is used to advance elapsed times between updates.
    // `results` maps root ids to { reason } for background mounts that need attention.
    function buildMountCenterModel(overview, {
        filter = 'all', query = '', busy = {}, results = {}, queue = {}, now = Date.now(), platform = 'macos',
    } = {}) {
        const folders = Array.isArray(overview?.folders) ? overview.folders : [];
        const selectedGroupId = String(overview?.selected_group_id || '');
        const normalizedQuery = String(query || '').trim().toLocaleLowerCase();
        const elapsedOf = job => (Number(job?.elapsed_ms) || 0)
            + (job?.status === 'running' && job?.received_at ? Math.max(0, now - job.received_at) : 0);
        const rows = folders.map(folder => {
            const rootId = String(folder?.root_id || '');
            const mount = folder?.mount || null;
            const busyState = busy?.[rootId] || null;
            const job = queue?.[rootId] || null;
            const jobActive = job?.status === 'queued' || job?.status === 'running';
            let status = 'unmounted';
            if (busyState === 'mounting' || busyState === 'unmounting') {
                status = busyState;
            } else if (jobActive) {
                status = job.status === 'queued' ? 'queued' : 'mounting';
            } else if (mount) {
                status = mount.availability === 'degraded' ? 'degraded' : 'mounted';
            } else if (!folder?.can_mount) {
                status = 'blocked';
            }
            // macOS: the File Provider extension never reached the bridge, so Finder isn't syncing.
            const finderUnreached = Boolean(mount) && mount.backend === 'macos-file-provider'
                && mount.operational_health?.extension_connected === false;
            const statusLabel = {
                mounted: 'Mounted',
                degraded: finderUnreached ? 'Finder isn’t syncing' : 'Needs attention',
                queued: 'Waiting to mount',
                mounting: 'Mounting…',
                unmounting: 'Unmounting…',
                unmounted: 'Not mounted',
                blocked: 'Unavailable',
            }[status];
            const lastResult = results?.[rootId]?.reason && !jobActive && status !== 'mounting' ? String(results[rootId].reason) : '';
            const canOpenFolderPage = ['personal', 'team', 'vault'].includes(folder?.workspace);
            const needsAttention = status === 'degraded' || status === 'blocked' || Boolean(lastResult);
            const actions = [];
            if (status === 'degraded' && finderUnreached) {
                const reconnecting = busyState === 'reconnecting';
                actions.push({ id: 'reconnect', label: reconnecting ? 'Reconnecting…' : 'Reconnect', disabled: reconnecting });
            }
            // A folder that needs attention leads to its page, where it can be repaired.
            if (needsAttention && canOpenFolderPage) actions.push({ id: 'folder-page', label: 'Folder page' });
            if (jobActive && !busyState) {
                if (!job.cancel_requested) actions.push({ id: 'cancel', label: 'Cancel' });
            } else if (mount && status !== 'unmounting' && status !== 'mounting') {
                if (status === 'mounted') actions.push({ id: 'open', label: 'Open' });
                actions.push({ id: 'unmount', label: 'Unmount' });
            } else if (status === 'unmounted') {
                actions.push({ id: 'mount', label: 'Mount' });
            }
            return {
                rootId,
                name: String(folder?.name || '') || displayEnrolledPath(folder?.path || ''),
                path: displayEnrolledPath(folder?.path || ''),
                workspace: MOUNT_CENTER_WORKSPACE_ORDER[folder?.workspace] === undefined ? 'other' : folder.workspace,
                groupId: folder?.group_id ? String(folder.group_id) : '',
                groupName: folder?.group_name ? String(folder.group_name) : '',
                status,
                statusLabel,
                isMounted: Boolean(mount),
                mountpoint: mount?.mountpoint || '',
                displayName: mount?.display_name || '',
                backendLabel: mount ? getMountBackendLabel(mount.backend) : null,
                blockedReason: status === 'blocked' ? String(folder?.blocked_reason || '') : '',
                autoMount: Boolean(folder?.auto_mount),
                canToggleAutoMount: folder?.workspace !== 'other' && MOUNT_CENTER_WORKSPACE_ORDER[folder?.workspace] !== undefined,
                lastResult,
                attentionDetail: status === 'degraded' && finderUnreached
                    ? 'macOS paused syncing this folder. Reconnect to resume.'
                    : '',
                canOpenFolderPage,
                needsAttention,
                // Background mount progress: the step, how long it has run, and earlier steps.
                stepLabel: jobActive
                    ? (job.status === 'queued' ? 'Waiting in queue' : (job.cancel_requested ? 'Stopping after this step' : mountStepLabel(job.step, platform)))
                    : '',
                preparingLabel: status === 'mounted' ? mountPreparingLabel(mount?.sync_status) : '',
                elapsedLabel: job?.status === 'running' ? formatMountSeconds(elapsedOf(job)) : '',
                slow: Boolean(job?.status === 'running' && job.slow),
                steps: jobActive || job?.status === 'failed'
                    ? (Array.isArray(job?.steps) ? job.steps : []).map(entry => ({
                        label: mountStepLabel(entry.step, platform),
                        duration: formatMountSeconds(entry.ms),
                    }))
                    : [],
                actions,
            };
        });

        const summary = {
            total: rows.length,
            mounted: rows.filter(row => row.isMounted).length,
            degraded: rows.filter(row => row.status === 'degraded').length,
            blocked: rows.filter(row => row.status === 'blocked').length,
            // Folders "Mount all" would start: not mounted, mountable, not already on their way.
            mountable: rows.filter(row => row.actions.some(action => action.id === 'mount')).length,
            autoMount: rows.filter(row => row.autoMount).length,
            canToggleAutoMount: rows.filter(row => row.canToggleAutoMount).length,
        };
        summary.autoMountState = autoMountState(rows.filter(row => row.canToggleAutoMount));

        const visible = rows.filter(row => {
            if (filter === 'mounted' && !row.isMounted) return false;
            if (filter === 'unmounted' && row.isMounted) return false;
            if (!normalizedQuery) return true;
            return [row.name, row.path, row.groupName].some(value =>
                value.toLocaleLowerCase().includes(normalizedQuery));
        });

        const sectionsByKey = new Map();
        for (const row of visible) {
            const key = row.workspace === 'team' ? `team:${row.groupId}` : row.workspace;
            if (!sectionsByKey.has(key)) {
                const title = {
                    personal: 'Personal',
                    team: row.groupName || 'Team group',
                    vault: 'On this device',
                    other: 'Other folders',
                }[row.workspace];
                sectionsByKey.set(key, {
                    key,
                    workspace: row.workspace,
                    title,
                    eyebrow: row.workspace === 'team' ? 'Team' : '',
                    groupId: row.workspace === 'other' ? '' : row.groupId,
                    selected: Boolean(row.groupId) && row.groupId === selectedGroupId && row.workspace !== 'other',
                    folders: [],
                });
            }
            sectionsByKey.get(key).folders.push(row);
        }
        const sections = Array.from(sectionsByKey.values()).map(section => {
            section.folders.sort((a, b) => a.name.localeCompare(b.name));
            const mounted = section.folders.filter(row => row.isMounted).length;
            const toggleable = section.folders.filter(row => row.canToggleAutoMount);
            return {
                ...section,
                autoMountState: autoMountState(toggleable),
                canToggleAutoMount: toggleable.length > 0,
                mountedCount: mounted,
                countLabel: `${mounted} of ${section.folders.length} mounted`,
                canUnmountAll: section.folders.some(row => row.actions.some(action => action.id === 'unmount')),
                canMountAll: section.folders.some(row => row.actions.some(action => action.id === 'mount')),
                hasRunningJob: section.folders.some(row => row.status === 'mounting'),
            };
        });
        sections.sort((a, b) =>
            (MOUNT_CENTER_WORKSPACE_ORDER[a.workspace] - MOUNT_CENTER_WORKSPACE_ORDER[b.workspace])
            || a.title.localeCompare(b.title));

        const jobs = Object.values(queue || {});
        const running = jobs.filter(job => job?.status === 'running').length;
        const waiting = jobs.filter(job => job?.status === 'queued').length;
        const slow = jobs.filter(job => job?.status === 'running' && job.slow).length;
        return {
            summary,
            sections,
            activity: running + waiting > 0
                ? {
                    running,
                    waiting,
                    label: [
                        running > 0 ? `Mounting ${running} folder${running === 1 ? '' : 's'}` : 'Starting',
                        waiting > 0 ? `${waiting} waiting` : '',
                        slow > 0 ? `${slow} taking longer than usual` : '',
                    ].filter(Boolean).join(' · '),
                }
                : null,
            empty: rows.length === 0,
            emptyFiltered: rows.length > 0 && visible.length === 0,
        };
    }

    // 'all', 'some' or 'none' of the rows mount automatically (a tri-state checkbox).
    function autoMountState(rows) {
        const on = rows.filter(row => row.autoMount).length;
        if (on === 0) return 'none';
        return on === rows.length ? 'all' : 'some';
    }

    const api = {
        actionErrorMessage,
        buildMountCenterModel,
        planFolderPageRoute,
        buildUnmountProgressModel,
        mountStepLabel,
        mountPreparingLabel,
        normalizeFolderMountStatus,
        runFolderUnenrollFlow,
        buildFolderJobProgressModel,
        pendingOperationLabel,
        captureKeyedScrollPositions,
        restoreKeyedScrollPositions,
        captureOpenDetailsKeys,
        restoreOpenDetails,
        filterProtectedFolders,
        displayEnrolledPath,
        isRoutineProviderReconciliation,
        buildAppModeUiModel,
        shouldExpandAdvancedSettings,
        getEmbeddedTerminalHeaderTitle,
        getFolderRowStatusState,
        buildMountConflictReviewState,
        buildPostQuantumStatusModel,
        shouldRetryWorkspaceStatusAfterSessionRefresh,
        buildWorkspaceHomeModel,
        buildFolderCoverageModel,
        buildFolderDetailModel,
        buildFolderSecondaryActions,
        buildFolderContextMenuActions,
        buildCoverageCenterModel,
        buildPersonalDevicesModel,
        formatDeviceFingerprintInput,
        normalizeDeviceFingerprint,
        buildDeviceVerificationModel,
        buildDeviceVerificationCommand,
        summarizeOperationOutput,
        buildPeopleRows,
        describeMemberDevices,
        buildMemberDeviceRows,
        describeTeamTaskResult,
        buildSidebarGroupItems,
        buildTeamGroupCards,
        describeGroupFacts,
        buildTeamTodoItems,
        adminDeviceReminders,
        buildDeviceAccessQueue,
        parseOwnDeviceRepairReport,
        parseOwnDeviceAccessSummary,
        buildOwnDeviceAccessNotice,
    };

    global.HybridCipherUiUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
