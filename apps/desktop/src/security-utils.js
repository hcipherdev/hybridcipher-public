(function (global) {
    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function quoteShellArg(value) {
        const text = String(value ?? '');
        if (text.length === 0) {
            return "''";
        }
        return `'${text.replace(/'/g, `'\"'\"'`)}'`;
    }

    const api = {
        escapeHtml,
        quoteShellArg,
    };

    global.HybridCipherSecurityUtils = api;

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }
})(typeof globalThis !== 'undefined' ? globalThis : this);
