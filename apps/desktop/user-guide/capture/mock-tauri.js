// Fake Tauri backend for user-guide screenshots. Every value here is made up.
// Injected before the app loads; `window.__GUIDE_STATE__` seeds the scenario and
// the handlers below update it, so clicking through the real UI moves it forward.
(function () {
    const S = Object.assign({ folders: [], mounted: [] }, window.__GUIDE_STATE__ || {});
    const ok = (data) => ({ success: true, data, error: null, error_code: null });
    // Recent enough that scans and backups read as fresh on the day the capture runs.
    const now = new Date(Date.now() - 2 * 3600 * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
    const email = S.email || 'alex@example.com';

    const vault = Object.assign({
        available: false, active: false, group_id: null, created_at: null, kit_saved: false,
        upgrade_email: null, upgrade_phase: null, storage_missing: false, merge_email: null,
        can_merge: false, fresh_device: false,
    }, S.localVault || {});

    function folderRecord(path, i) {
        return {
            path,
            root_id: `root-demo-${i + 1}`,
            kind: 'personal',
            state: 'enrolled',
            enrolled_at: now,
            last_scan: now,
            tracked_files: 42,
            tracked_bytes: 18_400_000,
            orphaned_files: 0,
            unmanaged_files: 0,
            coverage_ratio: 1,
        };
    }
    const folders = () => S.folders.map(folderRecord);
    const mountpointFor = (f) => `/Volumes/HybridCipher/${f.path.split('/').pop()}`;
    const mountFor = (f) => ({
        root_id: f.root_id, mountpoint: mountpointFor(f), encrypted_dir: f.path,
        backend: 'fskit', availability: 'available', fallback_reason: null,
        sync_status: { safe_to_unmount: true, pending_conflict_count: 0, recovered_pending_copy_count: 0 },
    });

    const handlers = {
        get_platform_info: () => ok({
            os_type: 'macos', os_name: 'macOS Sonoma', shell: 'zsh', username: 'alex',
            hostname: 'Alex-MacBook', home_dir: '/Users/alex', update_channel: 'self',
        }),
        get_session_health_config: () => ok({
            check_interval_ms: 600000, expiry_grace_ms: 60000, mount_continue_enable_ms: 3000,
            mount_cancel_enable_ms: 3000, mount_background_timeout_ms: 60000,
        }),
        get_session_info: () => S.signedIn
            ? { status: 'active', email, device_id: 'dev-demo-mac', expires_at: 4102444800, refreshed: false, persistent: true, error: null }
            : { status: 'none', email: null, device_id: null, expires_at: null, refreshed: false, persistent: true, error: null },
        logout_user: () => ok(null),
        get_legal_documents: () => ok({
            version: '2026-09', updated_at: '2026-09-01', support_email: 'support@example.com',
            required_acceptance: true,
            documents: [
                { id: 'terms', title: 'Terms of Service', filename: 'TERMS.md', content: '# Terms of Service\n\nSample terms text shown for illustration in this guide.' },
                { id: 'privacy', title: 'Privacy Notice', filename: 'PRIVACY.md', content: '# Privacy Notice\n\nSample privacy text.' },
            ],
        }),

        local_vault_status: () => ok(Object.assign({}, vault)),
        create_local_vault: () => {
            Object.assign(vault, { available: true, active: true, group_id: 'grp-demo-local', created_at: now, fresh_device: false });
            return ok(Object.assign({}, vault));
        },
        create_local_recovery_kit: () => ok({ recovery_code: 'HCRK-7Q4M-2XWD-9PLF-K3TB-R8NV' }),
        confirm_local_recovery_kit: () => {
            vault.kit_saved = true;
            return ok(Object.assign({}, vault));
        },

        list_enrolled_folders: () => ok(folders()),
        enroll_folder_and_hydrate: ({ folderPath }) => {
            if (!S.folders.includes(folderPath)) S.folders.push(folderPath);
            return ok(null);
        },
        list_active_mounts: () => ok(folders().filter((f) => S.mounted.includes(f.path)).map(mountFor)),
        check_mount_status_by_root_id: ({ rootId }) => {
            const f = folders().find((x) => x.root_id === rootId && S.mounted.includes(x.path));
            return f ? ok(mountFor(f)) : ok(null);
        },
        mount_enrolled_folder: ({ rootId }) => {
            const f = folders().find((x) => x.root_id === rootId);
            if (f && !S.mounted.includes(f.path)) S.mounted.push(f.path);
            return ok({ mountpoint: mountpointFor(f), backend: 'fskit', availability: 'available', fallback_reason: null });
        },
        get_coverage_center_snapshot: () => ok({ last_scan_at: now }),
        open_path_in_shell: () => ok(null),
        reveal_path_in_shell: () => ok(null),
    };

    // Scenario-specific handlers (e.g. the team data in mock-team.js) override the base ones.
    Object.assign(handlers, (window.__GUIDE_EXTRA_HANDLERS__ || (() => ({})))({ S, ok, now, email, folders }));

    const calls = (window.__guideCalls = []);
    async function invoke(cmd, args) {
        calls.push(cmd);
        const h = handlers[cmd];
        return h ? h(args || {}) : ok(null);
    }
    window.__GUIDE_MOCK__ = { state: S, vault };
    window.__TAURI__ = {
        core: { invoke },
        dialog: {
            open: async (opts) => (opts && opts.directory
                ? (S.pickFolder || '/Users/alex/Documents/Personal')
                : '/Users/alex/Desktop/HybridCipher Recovery Kit.hcrk'),
            save: async () => '/Volumes/USB/HybridCipher Recovery Kit.hcrk',
        },
        event: { listen: async () => () => {}, emit: async () => {} },
        window: { getCurrentWindow: () => ({ onCloseRequested: async () => () => {} }) },
    };
})();
