const test = require('node:test');
const assert = require('node:assert/strict');

const {
    classifyEnrollmentFailure,
    buildForceUnmountConfirmation,
    buildMountProgressModel,
    buildMountTimeoutMessage,
} = require('./beta-ux-utils');

test('classifyEnrollmentFailure maps permission-denied output to actionable guidance', () => {
    const model = classifyEnrollmentFailure({
        folderPath: '/Users/test/Documents/Taxes',
        lines: ['Error: permission denied while scanning folder'],
    });

    assert.equal(model.kind, 'permission-denied');
    assert.match(model.title, /access this folder/i);
    assert.match(model.detail, /full disk access|permissions/i);
});

test('classifyEnrollmentFailure maps already-enrolled output to refresh guidance', () => {
    const model = classifyEnrollmentFailure({
        folderPath: '/Users/test/Documents/Taxes',
        lines: ['Error: folder is already enrolled in coverage'],
    });

    assert.equal(model.kind, 'already-enrolled');
    assert.match(model.title, /already protected/i);
    assert.equal(model.retryLabel, 'Refresh folders');
});

test('classifyEnrollmentFailure falls back to generic retry guidance', () => {
    const model = classifyEnrollmentFailure({
        folderPath: '/Users/test/Documents/Taxes',
        lines: ['Error: backend exploded unexpectedly'],
    });

    assert.equal(model.kind, 'generic');
    assert.match(model.detail, /review the terminal output/i);
});

test('buildForceUnmountConfirmation requires a second explicit confirmation phrase', () => {
    const model = buildForceUnmountConfirmation({
        folderLabel: 'Taxes',
        folderPath: '/Users/test/Documents/Taxes',
        unsafeReasons: ['2 pending encrypted commits'],
    });

    assert.match(model.title, /force unmount/i);
    assert.equal(model.confirmationToken, 'FORCE');
    assert.match(model.detail, /file loss/i);
    assert.match(model.detail, /Taxes/);
});

test('buildForceUnmountConfirmation handles all-folder force unmount copy', () => {
    const model = buildForceUnmountConfirmation({
        folderLabel: 'all mounted folders',
        folderPath: '',
        unsafeReasons: ['1 recovery copy still needs review'],
    });

    assert.match(model.message, /all mounted folders/i);
    assert.match(model.detail, /recovery copy/i);
});

test('buildMountProgressModel includes folder identity and countdown copy before backgrounding', () => {
    const model = buildMountProgressModel({
        folderLabel: 'Taxes',
        folderPath: '/Users/test/Documents/Taxes',
        elapsedMs: 4000,
        continueEnableMs: 10000,
    });

    assert.equal(model.title, 'Mounting Taxes');
    assert.equal(model.folderLabel, 'Taxes');
    assert.match(model.hint, /6s/i);
});

test('buildMountProgressModel switches copy after backgrounding is available', () => {
    const model = buildMountProgressModel({
        folderLabel: 'Taxes',
        folderPath: '/Users/test/Documents/Taxes',
        elapsedMs: 12000,
        continueEnableMs: 10000,
    });

    assert.match(model.status, /background/i);
    assert.match(model.hint, /continue in background/i);
});

test('buildMountTimeoutMessage names the folder and gives recovery guidance', () => {
    const message = buildMountTimeoutMessage({
        folderLabel: 'Taxes',
        folderPath: '/Users/test/Documents/Taxes',
        inBackground: true,
    });

    assert.match(message, /Taxes/);
    assert.match(message, /embedded terminal/i);
    assert.match(message, /already mounted|retry/i);
});
