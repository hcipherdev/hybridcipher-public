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

    const api = {
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
