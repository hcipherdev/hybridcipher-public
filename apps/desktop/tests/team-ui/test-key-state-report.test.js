// Tests app.js copyKeyStateReport(): Copy key diagnostics puts the key state report on the clipboard and says what it contains, or why it could not.
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
    const copied = [];
    const methods = vm.runInNewContext(`({${method('copyKeyStateReport')}})`, {
        invoke,
        JSON,
        navigator: { clipboard: { writeText: async text => { copied.push(text); } } },
    });
    const notes = [];
    const app = Object.assign({ showNotification: (message, tone) => notes.push([tone, message]) }, methods);
    return { app, copied, notes };
}

test('the report is copied as JSON and the notice says it names no files', async () => {
    const data = { app_version: '0.1.1', platform: 'windows', report: { current_version: 7, folders: [] } };
    const { app, copied, notes } = environment(async () => ({ success: true, data }));
    assert.equal(await app.copyKeyStateReport(), true);
    assert.equal(JSON.parse(copied[0]).report.current_version, 7);
    assert.equal(notes[0][0], 'success');
    assert.match(notes[0][1], /not file names/);
});

test('a failure is reported instead of copying anything', async () => {
    const { app, copied, notes } = environment(async () => ({ success: false, error: 'No active group selected' }));
    assert.equal(await app.copyKeyStateReport(), false);
    assert.equal(copied.length, 0);
    assert.equal(notes[0][0], 'error');
    assert.match(notes[0][1], /No active group selected/);
});
