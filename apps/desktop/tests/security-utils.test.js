const test = require('node:test');
const assert = require('node:assert/strict');

const {
    quoteShellArg,
    escapeHtml,
} = require('../src/security-utils.js');

test('quoteShellArg wraps simple values in single quotes', () => {
    assert.equal(quoteShellArg('hello world'), "'hello world'");
});

test('quoteShellArg neutralizes command substitution and single quotes', () => {
    assert.equal(
        quoteShellArg("$(rm -rf /) `whoami` o'hai"),
        `'$(rm -rf /) \`whoami\` o'"'"'hai'`
    );
});

test('quoteShellArg preserves empty strings safely', () => {
    assert.equal(quoteShellArg(''), "''");
});

test('escapeHtml escapes HTML-significant characters', () => {
    assert.equal(
        escapeHtml(`<img src=x onerror="alert('xss')"> & test`),
        '&lt;img src=x onerror=&quot;alert(&#39;xss&#39;)&quot;&gt; &amp; test'
    );
});
