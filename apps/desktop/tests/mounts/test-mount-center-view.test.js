// Tests that setWorkspaceView() in src/app-team-methods.js (which replaces the one in src/app.js) shows the Mount Center view.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const teamSource = fs.readFileSync(new URL('../../src/app-team-methods.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');

test('the workspace view switch knows the Mount Center section', () => {
    const start = teamSource.indexOf('setWorkspaceView(view) {');
    const body = teamSource.slice(start, teamSource.indexOf('teamNavigationVisible()', start));

    assert.match(body, /mounts:\s*'mountCenterView'/);
    assert.match(html, /id="mountCenterView"/);
});
