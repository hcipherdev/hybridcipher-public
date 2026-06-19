const test = require('node:test');
const assert = require('node:assert/strict');

const {
    getFolderRowStatusState,
    buildWorkspaceHomeModel,
    buildFolderDetailModel,
    buildFolderCoverageModel,
    buildCoverageCenterModel,
    buildPersonalDevicesModel,
} = require('./ui-utils');

test('getFolderRowStatusState keeps mounted rows green when no issues exist', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: true,
            syncStatus: {
                pending_conflict_count: 0,
                recovered_pending_copy_count: 0,
            },
            showSafetyAlert: false,
        }),
        {
            showMountedBadge: true,
            showAlertButton: false,
            healthDotTone: 'green',
        }
    );
});

test('buildWorkspaceHomeModel highlights missing protections and pending attention', () => {
    const model = buildWorkspaceHomeModel(
        {
            protected_count: 3,
            mounted_count: 1,
            attention_count: 4,
            mfa_enabled: false,
            recovery_backup_ok: false,
            recovery_auto_backup_ok: false,
            last_scan_at: null,
            last_backup_upload_at: null,
            current_device: {
                device_id: 'device-current',
                is_verified: false,
            },
            device_counts: {
                trusted: 1,
                pending: 1,
                unverified: 1,
                stale: 0,
            },
            folder_attention: {
                conflicts: 1,
                recovery_copies: 1,
            },
        },
        { nowMs: Date.parse('2026-03-24T12:00:00.000Z') }
    );

    assert.equal(model.summaryTone, 'danger');
    assert.equal(model.summaryLabel, 'Needs attention');
    assert.equal(model.attentionItems.length, 6);
    assert.deepEqual(
        model.attentionItems.map(item => item.id),
        ['mfa', 'backup', 'scan', 'device-trust', 'device-setup', 'folder-issues']
    );
    assert.deepEqual(
        model.cards.map(card => card.id),
        ['post-quantum', 'mfa', 'scan', 'device']
    );
    assert.equal(model.postQuantum.status, 'protected_now');
    assert.equal(model.postQuantum.primaryText, 'Protected now');
    assert.equal(
        model.cards.find(card => card.id === 'post-quantum').detail,
        'Your protected folders are secured now with quantum-resistant encryption.'
    );
    assert.equal(model.cards.find(card => card.id === 'mfa').tone, 'danger');
    assert.equal(model.cards.find(card => card.id === 'scan').tone, 'warning');
    assert.equal(model.cards.find(card => card.id === 'device').tone, 'danger');
});

test('buildWorkspaceHomeModel reports a safe workspace when protections are healthy', () => {
    const model = buildWorkspaceHomeModel(
        {
            protected_count: 2,
            mounted_count: 1,
            attention_count: 0,
            mfa_enabled: true,
            recovery_backup_ok: true,
            recovery_auto_backup_ok: true,
            last_scan_at: '2026-03-24T11:15:00.000Z',
            last_backup_upload_at: '2026-03-24T10:45:00.000Z',
            current_device: {
                device_id: 'device-current',
                is_verified: true,
            },
            device_counts: {
                trusted: 2,
                pending: 0,
                unverified: 0,
                stale: 0,
            },
            folder_attention: {
                conflicts: 0,
                recovery_copies: 0,
            },
        },
        { nowMs: Date.parse('2026-03-24T12:00:00.000Z') }
    );

    assert.equal(model.summaryTone, 'safe');
    assert.equal(model.summaryLabel, 'Protected');
    assert.deepEqual(model.attentionItems, []);
    assert.deepEqual(
        model.cards.map(card => card.id),
        ['post-quantum', 'mfa', 'scan', 'device']
    );
    assert.equal(model.postQuantum.status, 'protected_now');
    assert.equal(model.postQuantum.primaryText, 'Protected now');
    assert.equal(model.cards.find(card => card.id === 'post-quantum').tone, 'safe');
});

test('buildWorkspaceHomeModel marks post-quantum protection for review when no protected folders exist', () => {
    const model = buildWorkspaceHomeModel(
        {
            protected_count: 0,
            mounted_count: 0,
            attention_count: 0,
            mfa_enabled: true,
            recovery_backup_ok: true,
            recovery_auto_backup_ok: true,
            last_scan_at: '2026-03-24T11:15:00.000Z',
            last_backup_upload_at: '2026-03-24T10:45:00.000Z',
            current_device: {
                device_id: 'device-current',
                is_verified: true,
            },
            device_counts: {
                trusted: 1,
                pending: 0,
                unverified: 0,
                stale: 0,
            },
            folder_attention: {
                conflicts: 0,
                recovery_copies: 0,
            },
        },
        { nowMs: Date.parse('2026-03-24T12:00:00.000Z') }
    );

    assert.equal(model.postQuantum.status, 'needs_review');
    assert.equal(model.postQuantum.primaryText, 'Needs review');
    assert.equal(
        model.postQuantum.secondaryText,
        'Add a protected folder to start securing files now with post-quantum encryption.'
    );
    assert.equal(model.cards.find(card => card.id === 'post-quantum').tone, 'warning');
    assert.equal(model.postQuantum.shellBadge.action, 'open-post-quantum-attention');
});

test('buildWorkspaceHomeModel tells users to add a protected folder before scanning when none exist', () => {
    const model = buildWorkspaceHomeModel(
        {
            protected_count: 0,
            mounted_count: 0,
            attention_count: 0,
            mfa_enabled: true,
            recovery_backup_ok: true,
            recovery_auto_backup_ok: true,
            last_scan_at: null,
            last_backup_upload_at: '2026-03-24T10:45:00.000Z',
            current_device: {
                device_id: 'device-current',
                is_verified: true,
            },
            device_counts: {
                trusted: 1,
                pending: 0,
                unverified: 0,
                stale: 0,
            },
            folder_attention: {
                conflicts: 0,
                recovery_copies: 0,
            },
        },
        { nowMs: Date.parse('2026-03-24T12:00:00.000Z') }
    );

    const scanAttention = model.attentionItems.find(item => item.id === 'scan');

    assert.ok(scanAttention);
    assert.equal(scanAttention.title, 'No protected folders yet');
    assert.equal(
        scanAttention.detail,
        'Click Add Protected Folder on the left to start protecting folders before running a coverage scan.'
    );
});

test('buildFolderDetailModel promotes conflict resolution and mounted-folder actions', () => {
    const model = buildFolderDetailModel({
        folder: {
            root_id: 'root-1',
            path: '/Users/test/Documents/Taxes',
            last_scan: '2026-03-24T08:00:00.000Z',
            tracked_files: 128,
            coverage_ratio: 0.98,
        },
        mountInfo: {
            mountpoint: '/Volumes/HybridCipher/Taxes',
            sync_status: {
                safe_to_unmount: false,
                pending_conflict_count: 2,
                recovered_pending_copy_count: 1,
            },
        },
        isMounted: true,
    });

    assert.equal(model.healthTone, 'warning');
    assert.equal(model.primaryAction.id, 'open-mounted');
    assert.equal(model.secondaryActions.some(action => action.id === 'unmount'), true);
    assert.equal(model.secondaryActions.some(action => action.id === 'reveal-mounted'), false);
    assert.equal(model.attention.conflicts, 2);
    assert.equal(model.attention.recoveryCopies, 1);
    assert.equal(model.showResolveConflicts, true);
    assert.equal(model.showResolveRecoveryCopies, true);
    assert.equal(model.protection.isPostQuantumProtected, true);
    assert.equal(model.protection.primaryText, 'Protected now with post-quantum encryption');
    assert.equal(
        model.protection.secondaryText,
        'Files in this protected folder are secured now with quantum-resistant encryption.'
    );
});

test('buildFolderDetailModel labels macOS File Provider mounts and keeps recovery actions', () => {
    const model = buildFolderDetailModel({
        folder: {
            root_id: 'root-provider',
            path: '/Users/test/Documents/Designs',
        },
        mountInfo: {
            mountpoint: '/Users/test/Library/CloudStorage/HybridCipher-Designs-12345678',
            backend: 'macos-file-provider',
            sync_status: {
                safe_to_unmount: false,
                pending_conflict_count: 1,
                recovered_pending_copy_count: 2,
            },
        },
        isMounted: true,
    });

    assert.equal(model.backend, 'macos-file-provider');
    assert.equal(model.backendLabel, 'macOS File Provider');
    assert.equal(model.attention.conflicts, 1);
    assert.equal(model.attention.recoveryCopies, 2);
    assert.equal(model.showResolveConflicts, true);
    assert.equal(model.showResolveRecoveryCopies, true);
});

test('buildFolderDetailModel reports unmounted folders without an unmount-safety state', () => {
    const model = buildFolderDetailModel({
        folder: {
            root_id: 'root-2',
            path: '/Users/test/Documents/Archive',
        },
        mountInfo: null,
        isMounted: false,
    });

    assert.equal(model.healthTone, 'idle');
    assert.equal(model.attention.mountStatusLabel, 'Not mounted');
    assert.equal(model.attention.unmountSafetyLabel, null);
    assert.equal(model.attention.safeToUnmount, null);
});

test('buildFolderDetailModel reports mounted folders with unknown sync state as checking', () => {
    const model = buildFolderDetailModel({
        folder: {
            root_id: 'root-3',
            path: '/Users/test/Documents/Projects',
        },
        mountInfo: {
            mountpoint: '/Volumes/HybridCipher/Projects',
            sync_status: {},
        },
        isMounted: true,
    });

    assert.equal(model.attention.mountStatusLabel, 'Mounted');
    assert.equal(model.attention.unmountSafetyLabel, 'Checking...');
    assert.equal(model.attention.safeToUnmount, null);
});

test('buildFolderDetailModel reports mounted folders with explicit safe-to-unmount state', () => {
    const safeModel = buildFolderDetailModel({
        folder: {
            root_id: 'root-4',
            path: '/Users/test/Documents/Receipts',
        },
        mountInfo: {
            mountpoint: '/Volumes/HybridCipher/Receipts',
            sync_status: {
                safe_to_unmount: true,
            },
        },
        isMounted: true,
    });
    const unsafeModel = buildFolderDetailModel({
        folder: {
            root_id: 'root-5',
            path: '/Users/test/Documents/Notes',
        },
        mountInfo: {
            mountpoint: '/Volumes/HybridCipher/Notes',
            sync_status: {
                safe_to_unmount: false,
            },
        },
        isMounted: true,
    });

    assert.equal(safeModel.attention.unmountSafetyLabel, 'Safe');
    assert.equal(safeModel.attention.safeToUnmount, true);
    assert.equal(unsafeModel.attention.unmountSafetyLabel, 'Not safe yet');
    assert.equal(unsafeModel.attention.safeToUnmount, false);
});

test('buildFolderDetailModel accepts cached camelCase syncStatus payloads from the app runtime', () => {
    const model = buildFolderDetailModel({
        folder: {
            root_id: 'root-6',
            path: '/Users/test/Documents/Bills',
        },
        mountInfo: {
            mountpoint: '/Volumes/HybridCipher/Bills',
            syncStatus: {
                safe_to_unmount: true,
                pending_conflict_count: 0,
                recovered_pending_copy_count: 0,
            },
        },
        isMounted: true,
    });

    assert.equal(model.attention.unmountSafetyLabel, 'Safe');
    assert.equal(model.attention.safeToUnmount, true);
});

test('buildFolderCoverageModel marks fully protected folders clearly', () => {
    const model = buildFolderCoverageModel({
        folder: {
            coverage_ratio: 1,
            tracked_files: 42,
            orphaned_files: 0,
            unmanaged_files: 0,
        },
    });

    assert.equal(model.stateLabel, 'Fully protected');
    assert.equal(model.percentLabel, '100%');
    assert.equal(model.summaryText, 'Everything in this folder is currently covered.');
    assert.equal(model.primaryCta.id, 'run-coverage-scan');
});

test('buildFolderCoverageModel explains almost-fully-protected folders and shows review CTA', () => {
    const model = buildFolderCoverageModel({
        folder: {
            coverage_ratio: 0.99,
            tracked_files: 1485,
            orphaned_files: 15,
            unmanaged_files: 0,
        },
        review: {
            state_label: 'Almost fully protected',
            summary_text: '15 items need review to restore full protection.',
            unresolved_item_count: 15,
            groups: [
                {
                    id: 'clean_up_missing',
                    title: 'Missing items',
                    primary_cta_label: 'Clean up 15 missing items',
                    item_count: 15,
                    files: [
                        {
                            relative_path: 'Taxes/2024/return.pdf',
                            reason: 'Tracked before, now missing from disk',
                        },
                    ],
                },
            ],
        },
    });

    assert.equal(model.stateLabel, 'Almost fully protected');
    assert.equal(model.summaryText, '15 items need review to restore full protection.');
    assert.equal(model.primaryCta.id, 'review-uncovered-items');
    assert.equal(model.primaryCta.label, 'Review missing items');
    assert.equal(model.groups[0].files[0].relative_path, 'Taxes/2024/return.pdf');
});

test('buildFolderCoverageModel promotes higher-risk cleanup states', () => {
    const model = buildFolderCoverageModel({
        folder: {
            coverage_ratio: 0.87,
            tracked_files: 300,
            orphaned_files: 18,
            unmanaged_files: 24,
        },
        review: {
            state_label: 'Needs attention',
            summary_text: '42 items in this folder are outside protection and need review.',
            unresolved_item_count: 42,
            groups: [
                {
                    id: 'remove_leftover_data',
                    title: 'Remove leftover protected data',
                    primary_cta_label: 'Review cleanup',
                    item_count: 4,
                    files: [],
                },
            ],
        },
    });

    assert.equal(model.stateLabel, 'Needs attention');
    assert.equal(model.primaryCta.id, 'review-uncovered-items');
    assert.equal(model.groups[0].title, 'Remove leftover protected data');
});

test('buildCoverageCenterModel renders an empty state when no enrolled folders exist', () => {
    const model = buildCoverageCenterModel({
        overall_coverage_percent: 0,
        tracked_files: 0,
        orphaned_files: 0,
        unmanaged_files: 0,
        enrolled_folder_count: 0,
        last_scan_at: null,
        ipc_state: 'inactive',
        folders: [],
        attention_items: [],
    });

    assert.equal(model.isEmpty, true);
    assert.equal(model.summary.overallCoveragePercent, 0);
    assert.equal(model.summary.folderCount, 0);
    assert.equal(model.summary.scanState, 'idle');
    assert.equal(model.folderRows.length, 0);
    assert.equal(model.emptyState.title, 'No protected folders yet');
});

test('buildCoverageCenterModel aggregates folder state and attention items', () => {
    const model = buildCoverageCenterModel({
        overall_coverage_percent: 92,
        tracked_files: 920,
        orphaned_files: 30,
        unmanaged_files: 50,
        enrolled_folder_count: 2,
        last_scan_at: '2026-03-24T11:20:00.000Z',
        ipc_state: 'active',
        folders: [
            {
                root_id: 'root-1',
                path: '/Users/test/Documents/Taxes',
                kind: 'folder',
                state: 'active',
                last_scan: '2026-03-24T11:20:00.000Z',
                tracked_files: 500,
                orphaned_files: 0,
                unmanaged_files: 0,
                coverage_percent: 100,
                coverage_label: 'Fully protected',
                attention_label: 'No review needed',
                needs_attention: false,
                recommended_action_id: null,
                recommended_action_label: null,
            },
            {
                root_id: 'root-2',
                path: '/Users/test/Documents/Projects',
                kind: 'folder',
                state: 'active',
                last_scan: '2026-03-24T11:20:00.000Z',
                tracked_files: 420,
                orphaned_files: 30,
                unmanaged_files: 50,
                coverage_percent: 84,
                coverage_label: 'Needs attention',
                attention_label: '80 files need review',
                needs_attention: true,
                recommended_action_id: 'review-folder-coverage',
                recommended_action_label: 'Review fixes',
            },
        ],
        attention_items: [
            {
                id: 'root-2',
                title: 'Projects needs review',
                detail: '80 files need review',
                root_id: 'root-2',
                folder_path: '/Users/test/Documents/Projects',
                action_id: 'review-folder-coverage',
                action_label: 'Review fixes',
            },
        ],
    });

    assert.equal(model.isEmpty, false);
    assert.equal(model.summary.overallCoveragePercent, 92);
    assert.equal(model.summary.folderCount, 2);
    assert.equal(model.summary.ipcState, 'active');
    assert.equal(model.folderRows[1].coveragePercent, 84);
    assert.equal(model.folderRows[1].recommendedAction.id, 'review-folder-coverage');
    assert.equal(model.attentionItems[0].id, 'root-2');
});

test('buildCoverageCenterModel reflects running scan progress without changing the current data snapshot', () => {
    const model = buildCoverageCenterModel(
        {
            overall_coverage_percent: 67,
            tracked_files: 670,
            orphaned_files: 120,
            unmanaged_files: 210,
            enrolled_folder_count: 2,
            last_scan_at: '2026-03-24T10:00:00.000Z',
            ipc_state: 'active',
            folders: [],
            attention_items: [],
        },
        {
            scanState: {
                state: 'running',
                processed: 75,
                total: 150,
                rootProgress: {
                    '/Users/test/Documents/Taxes': { processed: 50, total: 100 },
                    '/Users/test/Documents/Projects': { processed: 25, total: 50 },
                },
            },
        }
    );

    assert.equal(model.summary.scanState, 'running');
    assert.equal(model.scanBanner.percent, 50);
    assert.equal(model.scanBanner.processed, 75);
    assert.equal(model.scanBanner.total, 150);
    assert.equal(model.scanBanner.rootCount, 2);
    assert.equal(model.summary.overallCoveragePercent, 67);
});

test('buildPersonalDevicesModel groups current, trusted, setup, and review devices', () => {
    const model = buildPersonalDevicesModel({
        currentDeviceId: 'device-current',
        devices: [
            { device_id: 'device-current', status: 'trusted', is_current_device: true, is_verified: true },
            { device_id: 'device-laptop', status: 'trusted', is_current_device: false, is_verified: true },
            { device_id: 'device-phone', status: 'pending', is_current_device: false, is_verified: false },
            { device_id: 'device-tablet', status: 'unverified', is_current_device: false, is_verified: false },
            { device_id: 'device-old', status: 'stale', is_current_device: false, is_verified: true },
        ],
    });

    assert.equal(model.currentDevice.device_id, 'device-current');
    assert.deepEqual(model.trustedDevices.map(device => device.device_id), ['device-laptop']);
    assert.deepEqual(model.setupDevices.map(device => device.device_id), ['device-phone', 'device-tablet']);
    assert.deepEqual(model.reviewDevices.map(device => device.device_id), ['device-old']);
    assert.equal(model.hasAttention, true);
});
