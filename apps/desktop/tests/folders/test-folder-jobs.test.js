// Tests buildFolderJobProgressModel() and missing-folder actions in src/ui-utils.js, and runFolderJob()/addEnrolledFolder() relocation in src/app.js
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const uiUtils = require('../../src/ui-utils.js');
const {
    buildFolderJobProgressModel,
    buildFolderDetailModel,
    buildFolderContextMenuActions,
} = uiUtils;

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function method(name) {
    const start = source.indexOf(`    ${name}(`);
    assert.ok(start >= 0, `${name} is available`);
    const next = source.slice(start + 4).search(/\n    (?:async )?[A-Za-z_]+\([^)]*\) \{\n/);
    return source.slice(start, start + 4 + next + 1);
}

test('a job shows an indeterminate bar while files are counted', () => {
    const model = buildFolderJobProgressModel({ kind: 'protect', name: 'Photos', progress: null });
    assert.equal(model.title, 'Protecting Photos');
    assert.equal(model.percent, null);
    assert.equal(model.phaseLabel, 'Counting files…');
    assert.equal(model.chipLabel, 'Protecting Photos · Counting files…');
});

test('progress reads as files done, total and a whole percent', () => {
    const model = buildFolderJobProgressModel({
        kind: 'protect',
        name: 'Photos',
        progress: { phase: 'encrypting', processed_files: 1240, total_files: 8000, failed_files: 0 },
    });
    assert.equal(model.percent, 15);
    assert.equal(model.phaseLabel, 'Encrypting files…');
    assert.equal(model.detail, '1,240 of 8,000 files · 15%');
    assert.equal(model.chipLabel, 'Protecting Photos · 15%');
});

test('finishing phases stay at 100% and failures are counted', () => {
    const model = buildFolderJobProgressModel({
        kind: 'unprotect',
        name: 'Taxes',
        progress: { phase: 'decrypting', processed_files: 10, total_files: 10, failed_files: 2 },
    });
    assert.equal(model.title, 'Removing protection from Taxes');
    assert.equal(model.percent, 100);
    assert.equal(model.phaseLabel, 'Decrypting files…');
    assert.match(model.detail, /2 could not be processed$/);
    const rescanning = buildFolderJobProgressModel({
        progress: { phase: 'rescanning', processed_files: 5, total_files: 5 },
    });
    assert.equal(rescanning.percent, 100);
    assert.equal(rescanning.phaseLabel, 'Checking the folder…');
});

test('an empty folder is complete rather than stuck at 0%', () => {
    const model = buildFolderJobProgressModel({
        name: 'Empty',
        progress: { phase: 'encrypting', processed_files: 0, total_files: 0 },
    });
    assert.equal(model.percent, 100);
    assert.equal(model.detail, 'No files to process');
});

test('a folder gone from its path can only be located or removed from the list', () => {
    const missing = { root_id: 'r1', path: '/Users/me/Old name', available: false };
    const model = buildFolderDetailModel({ folder: missing });
    assert.equal(model.isMissing, true);
    assert.equal(model.healthTone, 'warning');
    assert.deepEqual(model.primaryAction, { id: 'locate-folder', label: 'Locate folder…' });
    assert.deepEqual(model.secondaryActions.map(action => action.id), ['forget-missing-folder']);
    assert.deepEqual(
        buildFolderContextMenuActions({ isMissing: true }).map(action => action.id),
        ['locate-folder', 'forget-missing-folder']
    );
});

test('a mounted folder keeps its usual actions even if its source path moved', () => {
    const model = buildFolderDetailModel({
        folder: { root_id: 'r1', path: '/Users/me/Old name', available: false },
        isMounted: true,
    });
    assert.equal(model.isMissing, false);
    assert.equal(model.primaryAction.id, 'open-mounted');
    const ordinary = buildFolderDetailModel({ folder: { root_id: 'r2', path: '/x', available: true } });
    assert.equal(ordinary.primaryAction.id, 'mount');
    assert.ok(ordinary.secondaryActions.some(action => action.id === 'remove-protection'));
});

function jobApp(invoke) {
    const methods = [
        method('ensureNoFolderJob'),
        method('async runFolderJob'),
        method('handleFolderJobProgress'),
        method('setFolderJobBackgrounded'),
        method('async addEnrolledFolder'),
        method('async findMovedEnrolledFolder'),
        method('async offerFolderRelocation'),
    ].join('\n');
    const App = Function('invoke', 'uiUtils', 'displayEnrolledPathValue', 'window',
        `return class { ${methods} }`)(invoke, uiUtils, path => path, globalThis.__testWindow);
    const app = new App();
    app.folderJob = null;
    app.notices = [];
    app.renders = 0;
    app.renderFolderJob = () => { app.renders += 1; };
    app.showNotification = (message, level) => app.notices.push([message, level]);
    app.basename = path => String(path).split(/[\\/]/).filter(Boolean).pop();
    app.formatCount = value => String(value);
    app.captureWorkspaceReadContext = () => () => true;
    app.workspaceGroupContext = { group_id: 'personal-group' };
    app.loadEnrolledFolders = async () => true;
    return app;
}

test('a job follows only its own progress events and clears when it ends', async () => {
    let finish;
    const calls = [];
    const app = jobApp((command, args) => {
        calls.push([command, args]);
        return new Promise(resolve => { finish = resolve; });
    });
    const running = app.runFolderJob({
        kind: 'protect', path: '/Users/me/Photos', command: 'enroll_folder_and_hydrate', args: { folderPath: '/Users/me/Photos' },
    });
    const jobId = calls[0][1].jobId;
    assert.ok(jobId);
    assert.equal(calls[0][1].folderPath, '/Users/me/Photos');
    assert.equal(app.folderJob.name, 'Photos');

    app.handleFolderJobProgress({ job_id: 'some-older-job', processed_files: 9, total_files: 10 });
    assert.equal(app.folderJob.progress, null);
    app.handleFolderJobProgress({ job_id: jobId, phase: 'encrypting', processed_files: 3, total_files: 10 });
    assert.equal(app.folderJob.progress.processed_files, 3);

    app.setFolderJobBackgrounded(true);
    assert.equal(app.folderJob.backgrounded, true);
    assert.equal(app.ensureNoFolderJob(), false, 'a second job waits for the first');
    assert.equal(app.folderJob.backgrounded, false, 'and the running one is shown again');

    finish({ success: true });
    assert.deepEqual(await running, { success: true });
    assert.equal(app.folderJob, null);
    assert.equal(app.ensureNoFolderJob(), true);
});

test('a failed job still clears so the next one can start', async () => {
    const app = jobApp(async () => { throw new Error('disk full'); });
    await assert.rejects(app.runFolderJob({ kind: 'unprotect', path: '/x', command: 'unenroll_folder_and_decrypt', args: {} }), /disk full/);
    assert.equal(app.folderJob, null);
});

test('adding a renamed protected folder offers to update its location instead', async () => {
    const calls = [];
    globalThis.__testWindow = { __TAURI__: { dialog: { open: async () => '/Users/me/New name' } } };
    const moved = { root_id: 'r1', path: '/Users/me/Old name', available: false };
    const app = jobApp(async (command, args) => {
        calls.push(command);
        if (command === 'find_moved_enrolled_folder') {
            assert.equal(args.folderPath, '/Users/me/New name');
            return { success: true, data: moved };
        }
        throw new Error(`Unexpected IPC ${command}`);
    });
    const prompts = [];
    app.showActionPrompt = async (title, message) => { prompts.push([title, message]); return true; };
    const relocations = [];
    app.relocateEnrolledFolder = async (folder, newPath) => { relocations.push([folder.root_id, newPath]); return true; };

    await app.addEnrolledFolder();
    assert.deepEqual(calls, ['find_moved_enrolled_folder']);
    assert.match(prompts[0][0], /Is this "Old name"\?/);
    assert.deepEqual(relocations, [['r1', '/Users/me/New name']]);
    delete globalThis.__testWindow;
});
