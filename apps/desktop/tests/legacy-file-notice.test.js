// Tests renderLegacyFileNotice(), renderLegacyFileList() and joinMountPath() in apps/desktop/src/app.js
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
app.formatFileSize = bytes => `${bytes} B`;
app.escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);

app.escapeHtmlAttr = app.escapeHtml;

const joinStart = source.indexOf('    joinMountPath(');
const joinEnd = source.indexOf('    async loadLegacyFiles(', joinStart);
assert.ok(joinStart >= 0 && joinEnd > joinStart, 'mount path joiner is available');
const PathApp = Function(`return class { ${source.slice(joinStart, joinEnd)} }`)();

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
    assert.match(html, /<details class="folder-legacy-notice-details" data-preserve-open-key="legacy-notice-details">/);
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

test('older file list shows each file with open and upgrade actions once access is enabled', () => {
    app.legacyFilesByRootId = {
        root: { files: [{ relative_path: 'Taxes/<2019> & notes.md', content_size: 300 }] },
    };
    const html = app.renderLegacyFileNotice(status({ enabled: true, legacy_file_count: 1 }), 'root');
    assert.match(html, /data-folder-detail-action="toggle-legacy-files" aria-expanded="true">Hide files/);
    assert.match(html, /data-folder-detail-action="upgrade-legacy-files"[^>]*>Upgrade file</);
    assert.match(html, /Taxes\/&lt;2019&gt; &amp; notes\.md/);
    assert.doesNotMatch(html, /<2019>/);
    assert.match(html, /data-folder-detail-action="open-legacy-file" data-relative-path="Taxes\/&lt;2019&gt; &amp; notes\.md"/);
    assert.match(html, /data-folder-detail-action="upgrade-legacy-file"/);
    app.legacyFilesByRootId = {};
});

test('older files cannot be opened or upgraded before access is reviewed', () => {
    app.legacyFilesByRootId = { root: { files: [{ relative_path: 'a.md', content_size: 1 }] } };
    const html = app.renderLegacyFileNotice(status({ legacy_file_count: 2 }), 'root');
    assert.match(html, /Hide files/);
    assert.match(html, /enable-legacy-compatibility/);
    assert.doesNotMatch(html, /upgrade-legacy-file/);
    assert.match(html, /data-folder-detail-action="open-legacy-file"[^>]*disabled/);
    app.legacyFilesByRootId = {};
});

test('collapsed older file list offers to show files and shows upgrade progress', () => {
    const collapsed = app.renderLegacyFileNotice(status({ enabled: true, legacy_file_count: 5 }), 'root');
    assert.match(collapsed, /aria-expanded="false">Show files/);
    assert.match(collapsed, />Upgrade all</);
    assert.doesNotMatch(collapsed, /folder-legacy-file-list/);

    app.legacyFilesByRootId = { root: { files: [], upgrading: true } };
    const busy = app.renderLegacyFileNotice(status({ enabled: true, legacy_file_count: 5 }), 'root');
    assert.match(busy, /data-folder-detail-action="upgrade-legacy-files" disabled>Upgrading…/);
    app.legacyFilesByRootId = {};
});

test('older file paths open inside the mounted folder on macOS and Windows', () => {
    const paths = new PathApp();
    assert.equal(
        paths.joinMountPath('/Users/me/Library/CloudStorage/HybridCipher-Taxes/', 'a/b.md'),
        '/Users/me/Library/CloudStorage/HybridCipher-Taxes/a/b.md'
    );
    assert.equal(paths.joinMountPath('C:\\Users\\me\\Taxes', 'a/b.md'), 'C:\\Users\\me\\Taxes\\a\\b.md');
});
