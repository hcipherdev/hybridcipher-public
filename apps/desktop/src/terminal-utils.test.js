const test = require('node:test');
const assert = require('node:assert/strict');

const {
    getStoredTerminalRenderer,
    isStoredTerminalDebugEnabled,
    createTerminalDiagnosticSnapshot,
} = require('./terminal-utils');

function createStorage(map = {}) {
    return {
        getItem(key) {
            return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
        },
    };
}

test('getStoredTerminalRenderer defaults to xterm and honors fallback override', () => {
    assert.equal(getStoredTerminalRenderer(createStorage()), 'xterm');
    assert.equal(
        getStoredTerminalRenderer(createStorage({ hybridcipher_terminal_renderer: 'fallback' })),
        'fallback'
    );
    assert.equal(
        getStoredTerminalRenderer(createStorage({ hybridcipher_terminal_renderer: 'bogus' })),
        'xterm'
    );
});

test('isStoredTerminalDebugEnabled parses common truthy values', () => {
    assert.equal(isStoredTerminalDebugEnabled(createStorage()), false);
    assert.equal(
        isStoredTerminalDebugEnabled(createStorage({ hybridcipher_xterm_debug: 'true' })),
        true
    );
    assert.equal(
        isStoredTerminalDebugEnabled(createStorage({ hybridcipher_xterm_debug: '1' })),
        true
    );
    assert.equal(
        isStoredTerminalDebugEnabled(createStorage({ hybridcipher_xterm_debug: 'false' })),
        false
    );
});

test('createTerminalDiagnosticSnapshot captures focus, sizing, and selection facts', () => {
    const textarea = { id: 'ta' };
    const termElement = {
        classList: { contains: (name) => name === 'focus' },
        querySelectorAll: (selector) => selector === '.xterm-selection div' ? [{}, {}] : [],
    };
    const host = {
        offsetParent: {},
        offsetWidth: 640,
        offsetHeight: 360,
        getBoundingClientRect: () => ({ width: 640, height: 360 }),
        contains: (node) => node === textarea,
    };
    const body = {
        getBoundingClientRect: () => ({ width: 640, height: 360 }),
    };
    const snapshot = createTerminalDiagnosticSnapshot({
        tabId: 4,
        sessionId: 'session-123',
        event: 'focus-check',
        term: {
            textarea,
            element: termElement,
            rows: 32,
            cols: 120,
            hasSelection: () => true,
            getSelection: () => 'selected text',
        },
        host,
        body,
        documentLike: {
            activeElement: textarea,
            elementFromPoint: () => textarea,
        },
    });

    assert.equal(snapshot.tabId, 4);
    assert.equal(snapshot.sessionId, 'session-123');
    assert.equal(snapshot.event, 'focus-check');
    assert.equal(snapshot.textareaIsActive, true);
    assert.equal(snapshot.xtermHasFocusClass, true);
    assert.equal(snapshot.rows, 32);
    assert.equal(snapshot.cols, 120);
    assert.equal(snapshot.hostVisible, true);
    assert.equal(snapshot.hostWidth, 640);
    assert.equal(snapshot.hostHeight, 360);
    assert.equal(snapshot.hostOccluded, false);
    assert.equal(snapshot.occludingElementTag, null);
    assert.equal(snapshot.occludingElementId, null);
    assert.equal(snapshot.selectionOverlayCount, 2);
    assert.equal(snapshot.termHasSelection, true);
    assert.equal(snapshot.selectionTextLength, 13);
});
