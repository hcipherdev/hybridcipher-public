import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
const start = source.indexOf('    renderLegacyFileNotice(');
const end = source.indexOf('    renderFolderDetailView(', start);
assert.ok(start >= 0 && end > start, 'legacy notice renderer is available');
const noticeMethod = source.slice(start, end);
const NoticeApp = Function(`return class { ${noticeMethod} }`)();
const app = new NoticeApp();
app.formatCount = value => new Intl.NumberFormat('en-US').format(value);
app.escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);

const status = overrides => ({
    enabled: false,
    legacy_file_count: 0,
    last_read_error: null,
    encrypted_backup_directory: 'C:\\recovery\\legacy_ciphertext',
    ...overrides,
});

test('no older-file notice appears when the count is zero, including after access was enabled', () => {
    assert.equal(app.renderLegacyFileNotice(null), '');
    assert.equal(app.renderLegacyFileNotice(status({ enabled: false })), '');
    assert.equal(app.renderLegacyFileNotice(status({ enabled: true })), '');
});

test('older files without access show a review action and collapsed technical details', () => {
    const html = app.renderLegacyFileNotice(status({ legacy_file_count: 2 }));
    assert.match(html, /2 older encrypted files/);
    assert.match(html, /data-folder-detail-action="enable-legacy-compatibility"/);
    assert.match(html, /<details class="folder-legacy-notice-details">/);
    assert.match(html, /cannot prove every original chunk is present/);
});

test('enabled access shows a neutral status and escapes the recovery path', () => {
    const html = app.renderLegacyFileNotice(status({
        enabled: true,
        legacy_file_count: 1,
        encrypted_backup_directory: 'C:\\originals\\<private>&',
    }));
    assert.match(html, /1 older encrypted file</);
    assert.match(html, /Access enabled\. Edits save in the current format\./);
    assert.doesNotMatch(html, /enable-legacy-compatibility/);
    assert.match(html, /<code>C:\\originals\\&lt;private&gt;&amp;<\/code>/);
    assert.doesNotMatch(html, /tone-safe/);
});

test('a consent-required read still offers review when the inventory count is stale', () => {
    const html = app.renderLegacyFileNotice(status({ last_read_error: 'legacy_consent_required' }));
    assert.match(html, /An older encrypted file needs access/);
    assert.match(html, /enable-legacy-compatibility/);
    assert.doesNotMatch(html, /0 older encrypted files/);
});
