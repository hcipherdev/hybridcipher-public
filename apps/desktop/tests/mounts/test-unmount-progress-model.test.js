// Tests buildUnmountProgressModel() in src/ui-utils.js: row labels per phase, step and platform, elapsed times, failures, the summary line and when "Run in background" is offered.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const uiScope = {};
vm.runInNewContext(fs.readFileSync(new URL('../../src/ui-utils.js', import.meta.url), 'utf8'), uiScope);
const { buildUnmountProgressModel } = uiScope.HybridCipherUiUtils;
const plain = value => JSON.parse(JSON.stringify(value));

const batch = (phase, folders, extra = {}) => ({
    label: 'Unmounting all folders',
    phase,
    allowBackground: true,
    order: Object.keys(folders),
    folders,
    ...extra,
});

test('every folder shows the unsaved-changes check first', () => {
    const model = buildUnmountProgressModel(batch('checking', {
        a: { name: 'Taxes', status: 'queued' },
        b: { name: 'Specs', status: 'queued' },
    }));

    assert.deepEqual(plain(model.rows.map(row => row.label)), ['Checking for unsaved changes', 'Checking for unsaved changes']);
    assert.equal(model.summary, 'Checking 2 folders for unsaved changes…');
    assert.equal(model.running, true);
    assert.equal(model.canRunInBackground, true);
});

test('running folders show their step and elapsed time, per platform', () => {
    const folders = {
        a: { name: 'Taxes', status: 'running', step: 'waiting_for_finder', elapsed_ms: 2000, received_at: 1000 },
        b: { name: 'Specs', status: 'running', step: 'removing', elapsed_ms: 0 },
        c: { name: 'Photos', status: 'done', elapsed_ms: 900 },
        d: { name: 'Old', status: 'queued' },
    };
    const macos = buildUnmountProgressModel(batch('unmounting', folders), { now: 4000 });
    const windows = buildUnmountProgressModel(batch('unmounting', folders), { now: 4000, platform: 'windows' });

    assert.deepEqual(plain(macos.rows.map(row => row.label)), [
        'Waiting for Finder to hand over edits', 'Removing', 'Unmounted', 'Waiting',
    ]);
    assert.equal(windows.rows[0].label, 'Waiting for File Explorer to hand over edits');
    assert.equal(macos.rows[0].elapsedLabel, '5 s', 'reported time plus time since the update');
    assert.equal(macos.rows[3].elapsedLabel, '');
    assert.equal(macos.summary, 'Unmounting 4 folders… 1 of 4 done');
});

test('a finished batch summarizes success or names how many failed', () => {
    const success = buildUnmountProgressModel(batch('done', {
        a: { name: 'Taxes', status: 'done' },
        b: { name: 'Specs', status: 'done' },
    }));
    assert.equal(success.running, false);
    assert.equal(success.canRunInBackground, false);
    assert.equal(success.summary, 'All 2 folders are unmounted and still protected.');

    const partial = buildUnmountProgressModel(batch('done', {
        a: { name: 'Taxes', status: 'done' },
        b: { name: 'Specs', status: 'failed', error: 'pending conflict', error_code: 'UNMOUNT_NOT_SAFE' },
    }));
    assert.equal(partial.failed, 1);
    assert.equal(partial.rows[1].label, 'Couldn’t unmount: pending conflict');
    assert.equal(partial.rows[1].notSafe, true);
    assert.equal(partial.summary, '1 folder couldn’t be unmounted. 1 of 2 unmounted.');
});

test('a batch that must stay in view never offers the background', () => {
    const model = buildUnmountProgressModel(batch('unmounting', { a: { name: 'Taxes', status: 'running' } }, { allowBackground: false }));

    assert.equal(model.running, true);
    assert.equal(model.canRunInBackground, false);
});
