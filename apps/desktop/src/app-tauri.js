// Tauri API helpers that support both Tauri v1 and v2 global shapes.
(function attachHybridCipherTauri(global) {
    function resolveTauriInvoke() {
        const tauriGlobal = global.__TAURI__;

        if (!tauriGlobal) {
            return null;
        }

        return tauriGlobal.core?.invoke || tauriGlobal.tauri?.invoke || tauriGlobal.invoke || null;
    }

    async function invoke(command, args = {}) {
        const invokeFn = resolveTauriInvoke();

        if (!invokeFn) {
            console.error('Tauri API is not available yet. Are you running inside the Tauri shell?');
            throw new Error('Tauri API is not available');
        }

        return invokeFn(command, args);
    }

    global.HybridCipherTauri = {
        invoke,
        resolveTauriInvoke,
    };
}(window));
