// Tests trusted Windows executable quoting, removal of generated PTY workflows, that the embedded console no longer starts a login shell, and that reveal actions never launch files.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const source = fs.readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
const start = source.indexOf('    resolveCliCommand(command, cliPath) {');
const end = source.indexOf('    async runSettingsCliCommand', start);
const app = new (Function(`return class { ${source.slice(start, end)} }`)())();
app.platformInfo = { os_type: 'windows' };

test('generated Windows commands use the trusted absolute executable', () => {
    assert.equal(app.resolveCliCommand('hybridcipher status', 'C:\\Trusted $& App\\hybridcipher.exe'), '"C:\\Trusted $& App\\hybridcipher.exe" status');
    assert.throws(() => app.resolveCliCommand('hybridcipher status', ''));
    assert.throws(() => app.resolveCliCommand('hybridcipher status', 'C:\\%EVIL%\\hybridcipher.exe'));
    assert.throws(() => app.resolveCliCommand('hybridcipher status', 'C:\\!EVIL!\\hybridcipher.exe'));
    assert.throws(() => app.resolveCliCommand('hybridcipher status', 'hybridcipher.exe'));
    assert.equal(app.resolveCliCommand('hybridcipher status', '\\\\?\\UNC\\server\\share\\hybridcipher.exe'), '"\\\\server\\share\\hybridcipher.exe" status');
});

test('normal workflows have no generated PTY execution helper', () => {
    assert.ok(!source.includes('async executeCommandDirectly('));
    const dialogs = fs.readFileSync(new URL('../src/app-team-methods.js', import.meta.url), 'utf8');
    assert.ok(dialogs.includes("'start_desktop_operation'"));
    assert.ok(!dialogs.includes('write_terminal_stdin'));
    assert.ok(!dialogs.includes('run_shell_command'));
});

test('the embedded console never starts a login shell', () => {
    const main = fs.readFileSync(new URL('../src-tauri/src/main.rs', import.meta.url), 'utf8');
    const commands = fs.readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
    for (const removed of ['run_shell_command', 'start_terminal_session', 'default_shell_command']) {
        assert.ok(!source.includes(removed), `app.js still references ${removed}`);
        assert.ok(!main.includes(removed), `main.rs still registers ${removed}`);
        assert.ok(!commands.includes(removed), `commands.rs still defines ${removed}`);
    }
    assert.ok(source.includes("invoke('start_cli_terminal_command'"));
    assert.ok(main.includes('start_cli_terminal_command'));
});

test('reveal actions never hand a file to the OS launcher', () => {
    const main = fs.readFileSync(new URL('../src-tauri/src/main.rs', import.meta.url), 'utf8');
    const commands = fs.readFileSync(new URL('../src-tauri/src/commands.rs', import.meta.url), 'utf8');
    assert.ok(main.includes('reveal_path_in_shell'));
    for (const revealer of ['async revealConflictPath(', 'async revealRecoveryPath(']) {
        const start = source.indexOf(revealer);
        const body = source.slice(start, source.indexOf('\n    }\n', start));
        assert.ok(body.includes("invoke('reveal_path_in_shell'"), revealer);
        assert.ok(!body.includes('open_path_in_shell'), revealer);
    }
    assert.ok(source.includes("case 'reveal-protected':\n                    await invoke('reveal_path_in_shell'"));
    // Every call that hands a path to the OS launcher sits behind decide_open().
    const launches = commands.split('open_path_with_system_handler(').length - 1;
    assert.equal(launches, 4, 'expected 2 definitions + 2 guarded calls of open_path_with_system_handler');
    assert.ok(commands.includes('path_opener::decide_open(&target)'));
});
test('CMD ignores a planted current-directory CLI for app-generated commands', { skip: process.platform !== 'win32' }, () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'hc-cli-resolution-'));
    const planted = path.join(cwd, 'hybridcipher.cmd');
    try {
        fs.writeFileSync(planted, '@echo UNTRUSTED_EXECUTABLE\r\n');
        const command = app.resolveCliCommand('hybridcipher -e "console.log(123456789)"', path.toNamespacedPath(process.execPath));
        const result = spawnSync(path.join(process.env.SystemRoot, 'System32', 'cmd.exe'), ['/d', '/q', '/v:off'], {
            cwd, input: command + '\r\nexit\r\n', encoding: 'utf8', windowsHide: true,
        });
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /123456789\r?\n/);
        assert.doesNotMatch(result.stdout, /UNTRUSTED_EXECUTABLE/);
    } finally {
        fs.unlinkSync(planted);
        fs.rmdirSync(cwd);
    }
});
