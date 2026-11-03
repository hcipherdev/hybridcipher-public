// Tests how buildWorkspaceHomeModel() and buildPostQuantumStatusModel() in src/ui-utils.js describe Home for a vault on this device, which has no account checks.
const test = require('node:test');
const assert = require('node:assert/strict');

const { buildWorkspaceHomeModel, buildPostQuantumStatusModel } = require('../../src/ui-utils.js');

const nowMs = Date.parse('2026-10-27T12:00:00.000Z');

test('an empty vault has not started yet; nothing needs review', () => {
    const model = buildWorkspaceHomeModel({
        local_vault: true, protected_count: 0, scan_status_available: true, last_scan_at: null, unavailable_sections: [],
    }, { nowMs });

    assert.equal(model.postQuantum.status, 'not_started');
    assert.equal(model.postQuantum.shellBadge.label, 'No folders protected yet');
    assert.equal(model.postQuantum.tone, 'idle');
    assert.notEqual(model.postQuantum.shellBadge.action, 'open-post-quantum-attention');
    assert.deepEqual(model.attentionItems, []);
    assert.equal(model.summaryLabel, 'Not started');
    assert.equal(model.summaryTone, 'idle');
});

test('a vault leaves out the sign-in and device cards instead of showing them as unknown', () => {
    const model = buildWorkspaceHomeModel({
        local_vault: true, protected_count: 1, scan_status_available: true,
        last_scan_at: '2026-10-27T11:00:00.000Z', unavailable_sections: [],
    }, { nowMs });

    assert.deepEqual(model.cards.map(card => card.id), ['post-quantum', 'scan']);
    assert.equal(model.postQuantum.shellBadge.label, 'Protected now');
    assert.deepEqual(model.attentionItems, []);
    assert.equal(model.summaryLabel, 'Protected');
    assert.equal(model.localVault, true);
});

test('a vault with folders still asks for a scan when it has never been scanned', () => {
    const model = buildWorkspaceHomeModel({
        local_vault: true, protected_count: 1, scan_status_available: true, last_scan_at: null, unavailable_sections: [],
    }, { nowMs });

    assert.deepEqual(model.attentionItems.map(item => item.id), ['scan']);
    assert.equal(model.summaryLabel, 'Needs attention');
});

test('a vault whose scan time could not be read reports only the scan as incomplete', () => {
    const model = buildWorkspaceHomeModel({
        local_vault: true, protected_count: 1, scan_status_available: false, unavailable_sections: ['scan status'],
    }, { nowMs });

    assert.equal(model.summaryLabel, 'Status incomplete');
    assert.deepEqual(model.unavailableSections, ['scan status']);
    assert.equal(model.cards.find(card => card.id === 'scan').value, 'Unknown');
});

test('an account with no folders keeps its review state', () => {
    assert.equal(buildPostQuantumStatusModel({ protectedCount: 0 }).status, 'needs_review');
    assert.equal(buildPostQuantumStatusModel({ protectedCount: 0, localVault: true }).status, 'not_started');
});
