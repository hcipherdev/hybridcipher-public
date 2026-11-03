// Tests app.js moveFilesToCurrentKey() and describeKeyMigrationOutcome(): Move files runs inside the app with a rescan and reports how many files moved, which could not and why.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function method(name) {
    const start = new RegExp(`^    (?:async )?${name}\\(`, 'm').exec(source);
    assert.ok(start, name);
    const boundary = /\r?\n    }\r?\n/g;
    boundary.lastIndex = start.index;
    const end = boundary.exec(source);
    assert.ok(end, name);
    return source.slice(start.index, end.index + end[0].length);
}

function environment(invoke) {
    const methods = vm.runInNewContext(
        `({${['moveFilesToCurrentKey', 'describeKeyMigrationOutcome'].map(method).join(',\n')}})`,
        { invoke, String }
    );
    const shown = [];
    const events = [];
    const app = Object.assign({
        formatCount: value => String(value),
        basename: path => String(path).split(/[\\/]/).pop(),
        showActionProgressModal(message) { events.push(['progress', message]); },
        hideActionProgressModal() { events.push(['hide']); },
        async refreshLeftoverKeyFiles() { events.push(['refresh']); },
        async showActionPrompt(title, message, options) { shown.push({ title, message, ...options }); return true; },
    }, methods);
    return { app, shown, events };
}

test('Move files asks the app to rescan and move, then shows the result', async () => {
    const calls = [];
    const { app, shown, events } = environment(async (command, args) => {
        calls.push([command, args]);
        return { success: true, data: { migrated: 4, failed: 0, failures: [] } };
    });
    const data = await app.moveFilesToCurrentKey();
    assert.equal(data.migrated, 4);
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [['migrate_leftover_key_files', { rescan: true }]]);
    assert.deepEqual(events.map(event => event[0]), ['progress', 'hide', 'refresh']);
    assert.equal(shown[0].title, 'Files moved');
    assert.equal(shown[0].message, 'Moved 4 files to the current key.');
    assert.equal(shown[0].secondaryLabel, null);
});

test('files that could not be moved are listed with their reasons', async () => {
    const failures = Array.from({ length: 12 }, (_, i) => ({
        path: `C:\\Users\\xc\\Documents\\HUK\\file${i}.pdf.encrypted`, from_version: 6, reason: 'Key unwrap failed',
    }));
    const { app, shown } = environment(async () => ({ success: true, data: { migrated: 2, failed: 12, failures } }));
    await app.moveFilesToCurrentKey();
    assert.equal(shown[0].title, '12 files could not be moved');
    assert.equal(shown[0].message, 'Moved 2 files; 12 could not be moved and stay on the older key.');
    const lines = shown[0].detail.split('\n');
    assert.equal(lines[0], '• file0.pdf.encrypted: Key unwrap failed');
    assert.equal(lines.length, 11);
    assert.equal(lines[10], '…and 2 more');
});

test('a running rotation, nothing to move and errors each get their own message', async () => {
    const running = environment(async () => ({ success: true, data: { migrated: 0, failed: 0, rotation_running: true } }));
    await running.app.moveFilesToCurrentKey();
    assert.equal(running.shown[0].title, 'Rotation still running');

    const idle = environment(async () => ({ success: true, data: { migrated: 0, failed: 0, failures: [] } }));
    await idle.app.moveFilesToCurrentKey();
    assert.equal(idle.shown[0].title, 'Nothing to move');

    const failing = environment(async () => { throw new Error('offline'); });
    assert.equal(await failing.app.moveFilesToCurrentKey(), null);
    assert.equal(failing.shown[0].title, "Files weren't moved");
    assert.equal(failing.shown[0].message, 'offline');
    assert.deepEqual(failing.events.map(event => event[0]), ['progress', 'hide', 'refresh']);
});
