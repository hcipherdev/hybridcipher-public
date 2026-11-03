(function (global) {
    const TERMINAL_RENDERER_STORAGE_KEY = 'hybridcipher_terminal_renderer';
    const TERMINAL_DEBUG_STORAGE_KEY = 'hybridcipher_xterm_debug';
    const TERMINAL_RENDERER_XTERM = 'xterm';
    const TERMINAL_RENDERER_FALLBACK = 'fallback';

    function normalizeTerminalRenderer(value) {
        const normalized = String(value ?? '').trim().toLowerCase();
        if (normalized === TERMINAL_RENDERER_FALLBACK) {
            return TERMINAL_RENDERER_FALLBACK;
        }
        return TERMINAL_RENDERER_XTERM;
    }

    function getStoredTerminalRenderer(storageLike) {
        const raw = storageLike?.getItem?.(TERMINAL_RENDERER_STORAGE_KEY);
        return normalizeTerminalRenderer(raw);
    }

    function isStoredTerminalDebugEnabled(storageLike) {
        const raw = storageLike?.getItem?.(TERMINAL_DEBUG_STORAGE_KEY);
        if (raw == null) {
            return false;
        }
        const normalized = String(raw).trim().toLowerCase();
        return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
    }

    function normalizedOptionalString(value, maxLength) {
        if (value == null) {
            return null;
        }
        const text = String(value).trim();
        if (!text) {
            return null;
        }
        return text.slice(0, maxLength);
    }

    function getHostOcclusionSnapshot(host, documentLike) {
        if (!host || typeof host.getBoundingClientRect !== 'function' || typeof documentLike?.elementFromPoint !== 'function') {
            return {
                hostOccluded: null,
                occludingElementTag: null,
                occludingElementId: null,
            };
        }

        const rect = host.getBoundingClientRect();
        if (!rect || rect.width <= 0 || rect.height <= 0) {
            return {
                hostOccluded: null,
                occludingElementTag: null,
                occludingElementId: null,
            };
        }

        const sampleX = rect.left + (rect.width / 2);
        const sampleY = rect.top + Math.min(rect.height / 2, 24);
        const topElement = documentLike.elementFromPoint(sampleX, sampleY);

        if (!topElement) {
            return {
                hostOccluded: null,
                occludingElementTag: null,
                occludingElementId: null,
            };
        }

        const hostContainsTopElement = topElement === host || typeof host.contains === 'function' && host.contains(topElement);
        return {
            hostOccluded: hostContainsTopElement ? false : true,
            occludingElementTag: hostContainsTopElement ? null : normalizedOptionalString(topElement.tagName, 32),
            occludingElementId: hostContainsTopElement ? null : normalizedOptionalString(topElement.id, 64),
        };
    }

    function createTerminalDiagnosticSnapshot({
        tabId,
        sessionId = null,
        event,
        term = null,
        host = null,
        body = null,
        documentLike = typeof document !== 'undefined' ? document : null,
    } = {}) {
        const textarea = term?.textarea || null;
        const activeElement = documentLike?.activeElement || null;
        const termElement = term?.element || null;
        const overlays = termElement?.querySelectorAll?.('.xterm-selection div') || [];
        const hostRect = host?.getBoundingClientRect?.() || body?.getBoundingClientRect?.() || null;
        const selectionText = typeof term?.getSelection === 'function' ? term.getSelection() || '' : '';
        const occlusionSnapshot = getHostOcclusionSnapshot(host, documentLike);

        return {
            tabId: Number.isFinite(tabId) ? tabId : null,
            sessionId: normalizedOptionalString(sessionId, 96),
            event: normalizedOptionalString(event, 64) || 'unknown',
            textareaIsActive: Boolean(textarea && activeElement === textarea),
            xtermHasFocusClass: Boolean(termElement?.classList?.contains?.('focus')),
            rows: Number.isFinite(term?.rows) ? term.rows : null,
            cols: Number.isFinite(term?.cols) ? term.cols : null,
            hostVisible: Boolean(host && host.offsetParent !== null),
            hostWidth: Number.isFinite(host?.offsetWidth) ? host.offsetWidth : Math.round(hostRect?.width || 0) || null,
            hostHeight: Number.isFinite(host?.offsetHeight) ? host.offsetHeight : Math.round(hostRect?.height || 0) || null,
            hostOccluded: occlusionSnapshot.hostOccluded,
            occludingElementTag: occlusionSnapshot.occludingElementTag,
            occludingElementId: occlusionSnapshot.occludingElementId,
            selectionOverlayCount: overlays.length || 0,
            termHasSelection: Boolean(typeof term?.hasSelection === 'function' ? term.hasSelection() : selectionText),
            selectionTextLength: selectionText.length,
            activeElementTag: normalizedOptionalString(activeElement?.tagName, 32),
            activeElementId: normalizedOptionalString(activeElement?.id, 64),
        };
    }

    const CONSOLE_PROMPT = 'hybridcipher> ';
    const CONSOLE_HISTORY_LIMIT = 100;

    function createLineEditor() {
        return { line: '', history: [], historyIndex: null };
    }

    function eraseEcho(text) {
        return '\b \b'.repeat([...text].length);
    }

    // Length of the escape sequence starting at data[index] (ESC [ ... final, ESC O x, or ESC x).
    function escapeSequenceLength(data, index) {
        const next = data[index + 1];
        if (next === '[') {
            let end = index + 2;
            while (end < data.length && !/[@-~]/.test(data[end])) end += 1;
            return Math.min(end + 1, data.length) - index;
        }
        if (next === 'O') return Math.min(3, data.length - index);
        return Math.min(2, data.length - index);
    }

    /**
     * Local line editing for the HybridCipher console while no command runs (there is no
     * shell to do it). Returns the new state, text to echo, the submitted line (or null),
     * input left over after a submit, and whether the caller should print a fresh prompt.
     */
    function applyLineEditorInput(state, data) {
        const next = {
            line: state?.line || '',
            history: Array.isArray(state?.history) ? [...state.history] : [],
            historyIndex: Number.isInteger(state?.historyIndex) ? state.historyIndex : null,
        };
        let echo = '';
        const input = String(data ?? '');

        const replaceLine = (value) => {
            echo += eraseEcho(next.line) + value;
            next.line = value;
        };

        for (let index = 0; index < input.length; index += 1) {
            const ch = input[index];
            if (ch === '\r' || ch === '\n') {
                const submitted = next.line.trim();
                let rest = input.slice(index + 1);
                if (ch === '\r' && rest.startsWith('\n')) rest = rest.slice(1);
                echo += '\r\n';
                next.line = '';
                next.historyIndex = null;
                if (submitted && next.history[next.history.length - 1] !== submitted) {
                    next.history.push(submitted);
                    next.history = next.history.slice(-CONSOLE_HISTORY_LIMIT);
                }
                return { state: next, echo, submitted: submitted || null, rest, reprompt: !submitted };
            }
            if (ch === '\u0003') {
                next.line = '';
                next.historyIndex = null;
                return { state: next, echo: echo + '^C\r\n', submitted: null, rest: '', reprompt: true };
            }
            if (ch === '\u007f' || ch === '\b') {
                const chars = [...next.line];
                if (chars.length > 0) {
                    chars.pop();
                    next.line = chars.join('');
                    echo += '\b \b';
                }
                continue;
            }
            if (ch === '\u0015') {
                replaceLine('');
                continue;
            }
            if (ch === '\u001b') {
                const length = escapeSequenceLength(input, index);
                const sequence = input.slice(index, index + length);
                if ((sequence === '\u001b[A' || sequence === '\u001bOA') && next.history.length > 0) {
                    next.historyIndex = next.historyIndex === null
                        ? next.history.length - 1
                        : Math.max(0, next.historyIndex - 1);
                    replaceLine(next.history[next.historyIndex]);
                } else if ((sequence === '\u001b[B' || sequence === '\u001bOB') && next.historyIndex !== null) {
                    next.historyIndex += 1;
                    if (next.historyIndex >= next.history.length) {
                        next.historyIndex = null;
                        replaceLine('');
                    } else {
                        replaceLine(next.history[next.historyIndex]);
                    }
                }
                index += length - 1;
                continue;
            }
            if (ch >= ' ') {
                next.line += ch;
                echo += ch;
            }
        }

        return { state: next, echo, submitted: null, rest: '', reprompt: false };
    }

    const api = {
        CONSOLE_PROMPT,
        createLineEditor,
        applyLineEditorInput,
        TERMINAL_RENDERER_STORAGE_KEY,
        TERMINAL_DEBUG_STORAGE_KEY,
        TERMINAL_RENDERER_XTERM,
        TERMINAL_RENDERER_FALLBACK,
        normalizeTerminalRenderer,
        getStoredTerminalRenderer,
        isStoredTerminalDebugEnabled,
        createTerminalDiagnosticSnapshot,
    };

    global.HybridCipherTerminalUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
