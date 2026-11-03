// Tests createLineEditor() and applyLineEditorInput() in src/terminal-utils.js: local line editing for the HybridCipher console (typing, backspace, submit, Ctrl+C, Ctrl+U, paste and history).
const test = require('node:test');
const assert = require('node:assert/strict');

const { createLineEditor, applyLineEditorInput, CONSOLE_PROMPT } = require('../../src/terminal-utils.js');

function feed(...chunks) {
    let state = createLineEditor();
    let last;
    for (const chunk of chunks) {
        last = applyLineEditorInput(state, chunk);
        state = last.state;
    }
    return last;
}

test('typing echoes characters and Enter submits the trimmed line', () => {
    const result = feed('  status ', '\r');
    assert.equal(result.submitted, 'status');
    assert.equal(result.echo, '\r\n');
    assert.equal(result.state.line, '');
    assert.equal(result.reprompt, false);
});

test('backspace removes characters and stops at the start of the line', () => {
    const result = feed('ab', '\x7f\x7f\x7f', 'help\r');
    assert.equal(result.submitted, 'help');
    assert.equal(feed('ab', '\x7f').echo, '\b \b');
    assert.equal(feed('\x7f').echo, '');
});

test('an empty Enter asks for a fresh prompt instead of submitting', () => {
    const result = feed('   \r');
    assert.equal(result.submitted, null);
    assert.equal(result.reprompt, true);
    assert.equal(CONSOLE_PROMPT, 'hybridcipher> ');
});

test('Ctrl+C cancels the line and Ctrl+U clears it', () => {
    const cancelled = feed('rekey start', '\x03');
    assert.equal(cancelled.submitted, null);
    assert.equal(cancelled.echo, '^C\r\n');
    assert.equal(cancelled.reprompt, true);
    assert.equal(cancelled.state.line, '');

    const cleared = feed('wrong', '\x15', 'status\r');
    assert.equal(cleared.submitted, 'status');
});

test('a pasted newline submits the first line and returns the rest', () => {
    const result = feed('status\r\nhelp\r');
    assert.equal(result.submitted, 'status');
    assert.equal(result.rest, 'help\r');
});

test('control and escape sequences other than history are not inserted', () => {
    const result = feed('sta\x1b[Dtus\x1b[3~\t\r');
    assert.equal(result.submitted, 'status');
});

test('up and down arrows walk the history', () => {
    let state = createLineEditor();
    for (const line of ['status\r', 'help\r']) {
        state = applyLineEditorInput(state, line).state;
    }
    const up = applyLineEditorInput(state, '\x1b[A');
    assert.equal(up.state.line, 'help');
    const upAgain = applyLineEditorInput(up.state, '\x1b[A');
    assert.equal(upAgain.state.line, 'status');
    const down = applyLineEditorInput(upAgain.state, '\x1b[B\x1b[B');
    assert.equal(down.state.line, '');
    assert.equal(applyLineEditorInput(upAgain.state, '\r').submitted, 'status');
});
