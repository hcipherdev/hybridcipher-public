// Tests renderMissingKeyNotice(), notifyMissingKeyFolders() and the restore-older-keys folder action in apps/desktop/src/app.js
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
function method(name) {
    const start = source.indexOf(`    ${name}(`);
    assert.ok(start >= 0, `${name} is available`);
    const next = source.slice(start + 4).search(/\n    (?:async )?[A-Za-z_]+\([^)]*\) \{\n/);
    return source.slice(start, start + 4 + next + 1);
}
const methods = [method('renderMissingKeyNotice'), method('async handleFolderDetailAction'), method('notifyMissingKeyFolders')].join('\n');
const App = Function('displayEnrolledPathValue', `return class { ${methods} }`)(path => path);

function app() {
    const instance = new App();
    instance.notices = [];
    instance.showNotification = (message, level) => instance.notices.push([message, level]);
    instance.basename = path => String(path).split(/[\\/]/).pop();
    instance.enrolledFolders = [{ root_id: 'huk', path: 'C:\\Users\\xc\\Documents\\HUK-zahn-insurance' }];
    return instance;
}

test('the folder notice explains the missing key and offers both fixes', () => {
    const html = app().renderMissingKeyNotice();
    assert.match(html, /older key this device doesn't have/);
    assert.match(html, /moves the files to the current key/);
    assert.match(html, /password and recovery code/);
    assert.match(html, /data-folder-detail-action="restore-older-keys"/);
});

test('restoring older keys opens the password and recovery code form', async () => {
    const instance = app();
    let opened = 0;
    instance.openRecoveryAutoBackupModal = () => { opened += 1; };
    await instance.handleFolderDetailAction({ root_id: 'huk' }, 'restore-older-keys');
    assert.equal(opened, 1);
    assert.deepEqual(instance.notices, []);
});

test('a folder that reports a missing key is announced once until the problem clears', () => {
    const instance = app();
    const missing = { huk: { compatibility: { last_read_error: 'key_unavailable' } } };
    instance.notifyMissingKeyFolders(missing);
    instance.notifyMissingKeyFolders(missing);
    assert.equal(instance.notices.length, 1);
    assert.match(instance.notices[0][0], /HUK-zahn-insurance use an older key/);
    assert.equal(instance.notices[0][1], 'warning');
    instance.notifyMissingKeyFolders({ huk: { compatibility: { last_read_error: null } } });
    instance.notifyMissingKeyFolders(missing);
    assert.equal(instance.notices.length, 2, 'a new occurrence after it cleared is announced again');
    instance.notifyMissingKeyFolders({ huk: { compatibility: { last_read_error: 'integrity_failure' } } });
    assert.equal(instance.notices.length, 2, 'other read errors keep their own notices');
});
