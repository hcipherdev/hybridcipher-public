// Tests that the desktop commands the accountless vault uses in apps/desktop/src-tauri/src/commands.rs accept an open vault.
//
// These commands start with an access check. An account-only check rejects the
// vault with "Please login through the desktop app", so each one must use a
// vault-aware check and find its storage without reading the account session.

const SOURCE: &str = include_str!("../../src/commands.rs");

/// Commands the folder screens call while the vault is open.
const VAULT_COMMANDS: &[&str] = &[
    "open_path_in_shell",
    "mount_enrolled_folder",
    "check_mount_status_by_root_id",
    "list_active_mounts",
    "list_mount_conflicts",
    "get_mount_conflict_preview",
    "resolve_mount_conflict",
    "list_mount_recovery_copies",
    "get_mount_recovery_copy_preview",
    "resolve_mount_recovery_copy",
];

const VAULT_GUARDS: &[&str] = &[
    "ensure_account_or_local_vault(",
    "ensure_local_data_or_vault(",
    "ensure_local_team_write_or_vault(",
];

const ACCOUNT_ONLY_GUARDS: &[&str] = &[
    "ensure_authenticated(",
    "ensure_local_data_access(",
    "ensure_local_team_write(",
];

fn command_body(name: &str) -> &'static str {
    let start = SOURCE
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("command {name} is missing from commands.rs"));
    let rest = &SOURCE[start..];
    // A Windows checkout may have CRLF line endings.
    let end = rest
        .find("\n}\n")
        .or_else(|| rest.find("\r\n}\r\n"))
        .expect("command body ends");
    &rest[..end]
}

#[test]
fn vault_commands_use_a_vault_aware_access_check() {
    for name in VAULT_COMMANDS {
        let body = command_body(name);
        let guard = body
            .lines()
            .find(|line| line.contains("let _operation_guard = "))
            .unwrap_or_else(|| panic!("{name} has no access check"));
        assert!(
            VAULT_GUARDS.iter().any(|check| guard.contains(check)),
            "{name} rejects the vault: {}",
            guard.trim()
        );
        for check in ACCOUNT_ONLY_GUARDS {
            assert!(
                !guard.contains(check),
                "{name} uses account-only {check}"
            );
        }
    }
}

#[test]
fn vault_commands_find_storage_without_the_account_session() {
    for name in VAULT_COMMANDS {
        let body = command_body(name);
        assert!(
            !body.contains("get_user_dir(&email, &server_url)"),
            "{name} finds its storage from the account email and server"
        );
    }
}
