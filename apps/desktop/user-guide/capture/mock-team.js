// Team (admin) demo data for user-guide screenshots, layered on mock-tauri.js.
// A made-up organization "Northwind Studio" with one admin and a few members.
(function () {
    const ORG_ID = '7d1c2a4e-0000-4000-8000-00000000a001';
    const GROUPS = [
        { id: 'grp-finance', name: 'Finance', description: 'Budgets, invoices and payroll', members: ['maria', 'daniel', 'priya'] },
        { id: 'grp-design', name: 'Design', description: 'Client artwork and brand files', members: ['maria', 'tom', 'aiko', 'sam'] },
        { id: 'grp-leadership', name: 'Leadership', description: 'Board papers and contracts', members: ['maria', 'daniel'] },
    ];
    const PEOPLE = {
        maria: { email: 'maria@northwind.example', device: 'Maria’s MacBook Pro', role: 'owner' },
        daniel: { email: 'daniel@northwind.example', device: 'Daniel’s ThinkPad', role: 'member' },
        priya: { email: 'priya@northwind.example', device: 'Priya’s MacBook Air', role: 'member' },
        tom: { email: 'tom@northwind.example', device: 'Tom’s iMac', role: 'member' },
        aiko: { email: 'aiko@northwind.example', device: 'Aiko’s Surface', role: 'member' },
        sam: { email: 'sam@northwind.example', device: 'Sam’s MacBook Pro', role: 'member' },
    };
    const userId = (key) => `user-${key}`;
    const deviceId = (key) => `dev-${key}-01`;

    window.__GUIDE_EXTRA_HANDLERS__ = ({ S, ok, now }) => {
        const T = Object.assign({
            groups: GROUPS.map((g) => Object.assign({}, g, { members: g.members.slice() })),
            activeGroup: 'grp-finance',
            pending: [],       // device approvals waiting on the admin: [{ key, since }]
            invited: [],       // emails invited to the team but not joined yet
            folders: { 'grp-finance': ['/Users/maria/Northwind/Finance'], 'grp-design': ['/Users/maria/Northwind/Design'] },
            mounted: [],
        }, S.team || {});
        S.team = T;
        const group = (id) => T.groups.find((g) => g.id === id) || T.groups[0];
        const summary = (g, i) => ({
            id: g.id, organization_id: ORG_ID, name: g.name, description: g.description,
            created_at: '2026-09-02T10:00:00Z', member_count: g.members.length, device_count: g.members.length,
            current_epoch_id: `epoch-${g.id}-3`, current_key_version: 3 + i, user_role: 'admin',
        });
        const memberDevices = (key) => [{
            device_id: deviceId(key), device_name: PEOPLE[key].device,
            last_seen: '2026-10-26T16:40:00Z', added_at: '2026-09-03T09:00:00Z', stale: false,
        }];
        const groupFolders = () => (T.folders[T.activeGroup] || []).map((path, i) => ({
            path, root_id: `root-${T.activeGroup}-${i + 1}`, kind: 'team', state: 'enrolled',
            enrolled_at: now, last_scan: now, tracked_files: 128 + 37 * i, tracked_bytes: 96_000_000,
            orphaned_files: 0, unmanaged_files: 0, coverage_ratio: 1,
        }));
        const mountpoint = (f) => `/Volumes/HybridCipher/${f.path.split('/').pop()}`;
        const mountFor = (f) => ({
            root_id: f.root_id, mountpoint: mountpoint(f), encrypted_dir: f.path, backend: 'fskit',
            availability: 'available', fallback_reason: null,
            sync_status: { safe_to_unmount: true, pending_conflict_count: 0, recovered_pending_copy_count: 0 },
        });

        return {
            get_session_info: () => ({
                status: 'active', email: PEOPLE.maria.email, device_id: deviceId('maria'),
                expires_at: 4102444800, refreshed: false, persistent: true, error: null,
            }),
            run_bundled_cli: ({ args = [] }) => {
                const stdout = args[0] === 'list-groups'
                    ? JSON.stringify(T.groups.map((g, i) => summary(g, i)))
                    : '';
                return ok({ stdout, stderr: '', status: 0 });
            },
            get_team_license_status: () => ({
                workspace: 'team',
                organization: {
                    id: ORG_ID, name: 'Northwind Studio', role: 'owner', license_status: 'active',
                    seat_limit: 10, seats_used: Object.keys(PEOPLE).length, entitlement_version: 4,
                    default_group_id: T.groups[0].id,
                },
                entitlement_expires_at: 4102444800, can_write: true, online: true, revoked: false, message: null,
            }),
            get_workspace_group_context: ({ workspace }) => {
                if (workspace === 'personal') {
                    return { group_id: 'grp-maria-personal', name: 'Personal', organization_id: null, role: 'owner', readiness: 'ready', groups: [] };
                }
                const g = group(T.activeGroup);
                return {
                    group_id: g.id, name: g.name, organization_id: ORG_ID, role: 'owner', readiness: 'ready',
                    groups: T.groups.map((x, i) => summary(x, i)),
                };
            },
            get_device_trust_status: () => ok({
                device_id: deviceId('maria'), identity_key_sha256: '9f2c…', approved: true,
                fingerprint_verified: true, can_revoke_other_devices: true, can_approve_devices: true,
                can_verify_devices: true, confirmation_required: false, blocking_reason: null, source: 'bootstrap',
            }),
            get_security_status: () => ok({
                mfa_enabled: true, recovery_backup_ok: true, recovery_auto_backup_ok: true,
                recovery_auto_backup_state: 'ok',
            }),
            refresh_join_card: () => ok(false),
            group_key_update_available: () => ok(false),
            report_key_receipts: () => ok(null),
            migrate_leftover_key_files: () => ok(null),
            list_my_team_invitations: () => [],
            get_group_summaries: () => ok(T.groups.map((g, i) => summary(g, i))),
            get_group_member_details: ({ groupId }) => ok(group(groupId || T.activeGroup).members.map((key) => ({
                user_id: userId(key), email: PEOPLE[key].email, joined_at: '2026-09-03T09:00:00Z',
                last_seen: '2026-10-26T16:40:00Z', devices: memberDevices(key),
            }))),
            get_group_members: ({ groupId }) => ok(group(groupId || T.activeGroup).members.map((key) => ({
                user_id: userId(key), email: PEOPLE[key].email, is_owner: key === 'maria',
            }))),
            get_group_pending_devices: () => ok(T.pending.map((p) => ({
                device_id: `dev-${p.key}-new`, email: PEOPLE[p.key].email, device_name: p.device || PEOPLE[p.key].device,
                pending_since: p.since || '2026-10-26T15:12:00Z', missing_current_key: true,
            }))),
            get_team_directory: () => ({
                online: true,
                role: 'owner',
                members: Object.entries(PEOPLE).map(([key, p]) => ({
                    user_id: userId(key), email: p.email, role: p.role, status: 'active',
                    joined_at: '2026-09-03T09:00:00Z',
                })),
                invitations: T.invited.map((email) => ({
                    email, status: 'pending', created_at: '2026-10-26T11:00:00Z', expires_at: '2026-11-02T11:00:00Z',
                })),
            }),
            get_individual_home_status: () => {
                const fs = groupFolders();
                return ok({
                    protected_count: fs.length, mounted_count: fs.filter((f) => T.mounted.includes(f.path)).length,
                    attention_count: T.pending.length,
                    post_quantum_status: 'protected_now', post_quantum_primary_text: 'Protected now',
                    post_quantum_secondary_text: 'Your protected folders are secured now with post-quantum encryption.',
                    post_quantum_explainer_available: true, mfa_enabled: true,
                    recovery_backup_ok: true, recovery_auto_backup_ok: true,
                    scan_status_available: true, last_scan_at: now, last_backup_upload_at: now,
                    current_device: { device_id: deviceId('maria'), is_verified: true },
                    device_counts: { trusted: 6, pending: T.pending.length, stale: 0, unverified: 0 },
                    folder_attention: { conflicts: 0, recovery_copies: 0 },
                    unavailable_sections: [],
                });
            },
            list_enrolled_folders: () => ok(groupFolders()),
            enroll_folder_and_hydrate: ({ folderPath }) => {
                const list = (T.folders[T.activeGroup] = T.folders[T.activeGroup] || []);
                if (!list.includes(folderPath)) list.push(folderPath);
                return ok(null);
            },
            list_active_mounts: () => ok(groupFolders().filter((f) => T.mounted.includes(f.path)).map(mountFor)),
            check_mount_status_by_root_id: ({ rootId }) => {
                const f = groupFolders().find((x) => x.root_id === rootId && T.mounted.includes(x.path));
                return f ? ok(mountFor(f)) : ok(null);
            },
            mount_enrolled_folder: ({ rootId }) => {
                const f = groupFolders().find((x) => x.root_id === rootId);
                if (f && !T.mounted.includes(f.path)) T.mounted.push(f.path);
                return ok({ mountpoint: mountpoint(f), backend: 'fskit', availability: 'available', fallback_reason: null });
            },
            get_pending_devices: () => ok(T.pending.map((p) => ({
                device_id: `dev-${p.key}-new`, email: PEOPLE[p.key].email, device_name: p.device || PEOPLE[p.key].device,
                pending_since: p.since || '2026-10-26T15:12:00Z', missing_current_key: true,
            }))),
            get_team_member_devices: () => ok({
                organization_id: ORG_ID, generated_at: now, stale_threshold_days: 30,
                members: Object.entries(PEOPLE).map(([key, p]) => ({
                    user_id: userId(key), email: p.email, role: p.role,
                    groups: T.groups.filter((g) => g.members.includes(key)).map((g) => ({ id: g.id, name: g.name })),
                    devices: [{
                        device_id: deviceId(key), device_name: p.device, created_at: '2026-09-03T09:00:00Z',
                        last_seen: now, status: 'trusted', pending: false, approved: true,
                        fingerprint_verified: true, stale: false, stale_reasons: [], missing_key_groups: [],
                    }].concat(T.pending.filter((x) => x.key === key).map((x) => ({
                        device_id: `dev-${key}-new`, device_name: x.device, created_at: now, last_seen: now,
                        status: 'pending', pending: true, approved: false, fingerprint_verified: false,
                        stale: false, stale_reasons: [], missing_key_groups: T.groups.filter((g) => g.members.includes(key)).map((g) => ({ id: g.id, name: g.name })),
                    }))),
                })),
            }),
            invite_team_member: ({ email }) => {
                if (!T.invited.includes(email)) T.invited.push(email);
                return ok({ invitation_code: 'NW-4Q7K-PX2M-9DTR', email });
            },
            get_stale_devices: () => ok([]),
            get_unverified_devices: () => ok([]),
            get_coverage_center_snapshot: () => ok({ last_scan_at: now }),
            // Long-running desktop operations finish at once here, with the state change applied.
            start_desktop_operation: ({ request = {} }) => {
                let result = {};
                if (request.kind === 'team_setup') result = { readiness: 'ready', group_id: T.groups[0].id, first_setup: false };
                if (request.kind === 'switch_group' && request.group_id) T.activeGroup = request.group_id;
                if (request.kind === 'create_group') {
                    const id = `grp-${request.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
                    if (!T.groups.some((g) => g.id === id)) {
                        T.groups.push({ id, name: request.name, description: request.description || null, members: ['maria'] });
                    }
                    T.activeGroup = id;
                    result = { group_id: id, readiness: 'ready' };
                }
                const target = group(request.group_id || T.activeGroup);
                const personKey = Object.keys(PEOPLE).find((k) => PEOPLE[k].email === request.email);
                if (['add_person', 'add_member'].includes(request.kind) && personKey && !target.members.includes(personKey)) {
                    target.members.push(personKey);
                }
                if (request.kind === 'remove_access') {
                    target.members = target.members.filter((k) => userId(k) !== request.member && PEOPLE[k].email !== request.member);
                }
                if (request.kind === 'approve_device') T.pending = T.pending.filter((x) => `dev-${x.key}-new` !== request.device_id);
                return ok({ id: `op-${Date.now()}`, kind: request.kind, status: 'succeeded', phase: 'Done', result });
            },
        };
    };
})();
