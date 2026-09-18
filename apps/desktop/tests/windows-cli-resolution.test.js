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

test('settings and dashboard commands are resolved before sending to the PTY', async () => {
    const begin = source.indexOf('    async executeCommandDirectly(');
    const finish = source.indexOf('    async getCliBinaryPath()', begin);
    const sent = [];
    const terminalApp = new (Function('invoke', `return class { ${source.slice(begin, finish)} ${source.slice(start, end)} }`)(async (name, args) => sent.push({ name, ...args })))();
    Object.assign(terminalApp, {
        platformInfo: { os_type: 'windows' }, activeWorkspaceView: 'terminal',
        handleRestrictedIndividualCliCommand: async () => false,
        getTerminalCwd: () => 'C:\\Untrusted', updateTerminalCwdDisplay() {},
        shouldPreflightSessionForCommand: () => false, updateActiveTabTitle() {},
        getActiveTab: () => ({ id: 'fixture', sessionId: 'fixture' }),
        isWelcomeTab: () => false,
        getCliBinaryPath: async () => 'C:\\Trusted\\hybridcipher.exe',
    });
    await terminalApp.executeCommandDirectly('hybridcipher status');
    assert.deepEqual(sent, [{ name: 'write_terminal_stdin', sessionId: 'fixture', data: '"C:\\Trusted\\hybridcipher.exe" status\r' }]);
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
