const test = require('node:test');
const assert = require('node:assert/strict');

const {
    pendingOperationLabel,
    getEmbeddedTerminalHeaderTitle,
    getFolderRowStatusState,
} = require('../src/ui-utils.js');

test('pending status counts logical operations independently of retry history', () => {
    assert.equal(pendingOperationLabel({ pending_operation_count: 1, affected_file_count: 1, pending_operation_counts: { rename: 1 }, pending_operations: [{ attempts: 122, merged_records: 121 }] }), '1 unresolved rename affecting 1 file');
    assert.equal(pendingOperationLabel({ pending_operation_count: 3, affected_file_count: 2, pending_operation_counts: { rename: 2, writeback: 1 } }), '3 unresolved operations affecting 2 files');
    assert.equal(pendingOperationLabel({ pending_operation_count: 2, affected_file_count: 1, pending_operation_counts: { rename: 2 } }), '2 unresolved renames affecting 1 file');
});

test('embedded terminal header title is always static', () => {
    assert.equal(getEmbeddedTerminalHeaderTitle(), 'Embedded Terminal');
});

test('mounted healthy folder shows mounted badge and green dot', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: true,
            syncStatus: {
                pending_conflict_count: 0,
                recovered_pending_copy_count: 0,
                pending_writeback_count: 0,
                pending_refresh_count: 0,
                pending_open_unlinked_count: 0,
                low_space_mode: 'healthy',
                safe_to_unmount: true,
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

test('mounted conflict folder shows alert button and red dot', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: true,
            syncStatus: {
                pending_conflict_count: 2,
                recovered_pending_copy_count: 0,
            },
            showSafetyAlert: true,
        }),
        {
            showMountedBadge: true,
            showAlertButton: true,
            healthDotTone: 'red',
        }
    );
});

test('mounted recovery-copy folder shows alert button and red dot', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: true,
            syncStatus: {
                pending_conflict_count: 0,
                recovered_pending_copy_count: 1,
            },
            showSafetyAlert: true,
        }),
        {
            showMountedBadge: true,
            showAlertButton: true,
            healthDotTone: 'red',
        }
    );
});

test('mounted pending-only folder stays non-red and does not surface extra pills', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: true,
            syncStatus: {
                pending_conflict_count: 0,
                recovered_pending_copy_count: 0,
                pending_writeback_count: 3,
                pending_refresh_count: 1,
                pending_open_unlinked_count: 0,
                low_space_mode: 'healthy',
            },
            showSafetyAlert: true,
        }),
        {
            showMountedBadge: true,
            showAlertButton: true,
            healthDotTone: 'green',
        }
    );
});

test('unmounted folder shows no mounted badge or dot', () => {
    assert.deepEqual(
        getFolderRowStatusState({
            isMounted: false,
            syncStatus: {
                pending_conflict_count: 4,
                recovered_pending_copy_count: 2,
            },
            showSafetyAlert: true,
        }),
        {
            showMountedBadge: false,
            showAlertButton: false,
            healthDotTone: null,
        }
    );
});
