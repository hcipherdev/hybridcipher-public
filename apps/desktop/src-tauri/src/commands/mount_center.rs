//! The Mount Center: every folder the open account (or vault) has enrolled,
//! across Personal and its Team groups, with mount state. Listing and mounting
//! here never change the group selected in the UI.

use super::*;

#[derive(Debug, Serialize)]
pub struct MountOverviewFolder {
    pub root_id: String,
    pub path: String,
    pub name: String,
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    /// "personal", "team", "vault", or "other" for a group outside the
    /// account's current workspaces.
    pub workspace: String,
    pub can_mount: bool,
    pub blocked_reason: Option<String>,
    pub mount: Option<MountInfo>,
    /// Mounted in the background when the account or vault opens.
    pub auto_mount: bool,
}

#[derive(Debug, Serialize)]
pub struct MountOverview {
    pub local_vault: bool,
    pub selected_group_id: Option<String>,
    pub folders: Vec<MountOverviewFolder>,
    /// False until auto-mount choices were saved once; the app then carries
    /// over the older "auto-mount last folder" setting.
    pub auto_mount_configured: bool,
}

/// Local config key for the folders mounted automatically. It lives in the
/// open account's (or vault's) storage on this device.
const AUTO_MOUNT_CONFIG_KEY: &str = "desktop_auto_mount_roots";

#[derive(Debug, Default, Serialize, Deserialize)]
struct AutoMountConfig {
    version: u32,
    root_ids: Vec<String>,
}

async fn load_auto_mount_config(client: &LocalClient) -> Result<Option<AutoMountConfig>, String> {
    let stored = client
        .load_local_config(AUTO_MOUNT_CONFIG_KEY)
        .await
        .map_err(|error| error.to_string())?;
    // An unreadable value counts as configured with nothing selected, so the
    // one-time migration does not run again over it.
    Ok(stored.map(|json| serde_json::from_str(&json).unwrap_or_default()))
}

/// The saved selection after turning `ids` on or off. Folders that are no
/// longer enrolled are dropped; the existing order is kept.
fn update_auto_mount_set(
    stored: &[String],
    enrolled: &[String],
    ids: &[String],
    enabled: bool,
) -> Vec<String> {
    let mut next: Vec<String> = stored
        .iter()
        .filter(|id| enrolled.contains(id))
        .filter(|id| enabled || !ids.contains(id))
        .cloned()
        .collect();
    if enabled {
        for id in ids {
            if enrolled.contains(id) && !next.contains(id) {
                next.push(id.clone());
            }
        }
    }
    next
}

/// A group the overview can place a folder in.
struct OverviewGroup {
    workspace: &'static str,
    name: Option<String>,
    metadata: Value,
}

pub(super) fn folder_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

/// Places a folder's group in a workspace, from the cached group list, the
/// Personal snapshot and the Team license. Groups outside them get `None`.
fn overview_group(
    group_id: Uuid,
    groups: &[Value],
    personal: Option<&Value>,
    team_organization: Option<&str>,
) -> Option<OverviewGroup> {
    let id = group_id.to_string();
    if let Some(personal) = personal.filter(|personal| personal["state"] == "available") {
        if personal["personal_default_group_id"].as_str() == Some(id.as_str()) {
            return Some(OverviewGroup {
                workspace: "personal",
                name: Some("Personal".to_string()),
                metadata: personal["group"].clone(),
            });
        }
    }
    let group = groups
        .iter()
        .find(|group| group["id"].as_str() == Some(id.as_str()))?;
    let organization = group["organization_id"].as_str()?;
    if team_organization != Some(organization) {
        return None;
    }
    Some(OverviewGroup {
        workspace: "team",
        name: group["name"].as_str().map(str::to_string),
        metadata: group.clone(),
    })
}

const GROUP_KEYS_UNAVAILABLE: &str =
    "This device doesn't have this group's keys yet. Open the group to finish setting up this device.";
const GROUP_OUTSIDE_WORKSPACES: &str =
    "This folder belongs to a group outside your Personal and Team workspaces.";

/// Each enrolled root with its owning group. Older roots record the group only
/// in the registry.
pub(super) async fn enrolled_roots_with_groups(
    client: &LocalClient,
) -> Result<Vec<(hybridcipher_client::coverage::CoverageRoot, Option<Uuid>)>, String> {
    let roots = client
        .coverage_roots()
        .await
        .map_err(desktop_safe_client_error)?;
    let registry = client
        .coverage_root_registry_entries()
        .await
        .map_err(desktop_safe_client_error)?;
    Ok(roots
        .into_iter()
        .filter(|root| root.state == CoverageRootState::Active)
        .map(|root| {
            let group_id = root.group_id.or_else(|| {
                registry
                    .iter()
                    .find(|entry| match entry.root_id {
                        Some(root_id) => root_id == root.root_id,
                        None => Path::new(&entry.path) == root.path,
                    })
                    .map(|entry| entry.group_id)
            });
            (root, group_id)
        })
        .collect())
}

#[tauri::command]
pub async fn list_mount_overview(
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountOverview>, String> {
    let _operation_guard = ensure_local_data_or_vault(&state).await?;
    let local_vault_group = state.local_vault_group().await;
    let user_dir = active_storage_dir(&state).await?;
    let client = state.local_client.client().await?;
    let roots = match enrolled_roots_with_groups(&client).await {
        Ok(roots) => roots,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let mut mounts = load_active_mounts_internal(&state, &user_dir).await?;
    let auto_mount_config = load_auto_mount_config(&client).await?;
    let auto_mount_configured = auto_mount_config.is_some();
    let auto_mount_ids = auto_mount_config.unwrap_or_default().root_ids;

    let mut folders = Vec::new();
    let selected_group_id;
    if let Some(vault_group) = local_vault_group {
        selected_group_id = Some(vault_group.to_string());
        for (root, group_id) in roots {
            if group_id.is_some_and(|group_id| group_id != vault_group) {
                continue;
            }
            let root_id = root.root_id.to_string();
            let mount = take_mount(&mut mounts, &root_id);
            let auto_mount = auto_mount_ids.contains(&root_id);
            folders.push(MountOverviewFolder {
                name: folder_name(&root.path),
                path: root.path.display().to_string(),
                root_id,
                group_id: Some(vault_group.to_string()),
                group_name: None,
                workspace: "vault".to_string(),
                can_mount: true,
                blocked_reason: None,
                auto_mount,
                mount,
            });
        }
    } else {
        let session = current_local_session(&state).await?;
        selected_group_id = client
            .load_local_config("desktop_ui_group_id")
            .await
            .map_err(|error| error.to_string())?;
        // Cached lists only: this view refreshes often and must work offline.
        let groups = operations::cached_group_list(&state, &session, false).await?;
        let personal = personal_workspace::personal_workspace_snapshot(&state, &session, false)
            .await
            .ok();
        let team_organization = license::verified_claims(&session, true)
            .ok()
            .flatten()
            .map(|claims| claims.organization_id);
        for (root, group_id) in roots {
            let root_id = root.root_id.to_string();
            let mount = take_mount(&mut mounts, &root_id);
            let auto_mount = auto_mount_ids.contains(&root_id);
            let placed = group_id.and_then(|group_id| {
                overview_group(
                    group_id,
                    &groups,
                    personal.as_ref(),
                    team_organization.as_deref(),
                )
            });
            let blocked_reason = match (&placed, group_id) {
                (Some(group), Some(group_id)) => {
                    let has_keys = match operations::group_epoch_uuid(&group.metadata) {
                        Ok(Some(epoch)) => client
                            .has_cached_group_epoch_key(group_id, epoch)
                            .await
                            .unwrap_or(false),
                        _ => false,
                    };
                    (!has_keys).then(|| GROUP_KEYS_UNAVAILABLE.to_string())
                }
                _ => Some(GROUP_OUTSIDE_WORKSPACES.to_string()),
            };
            folders.push(MountOverviewFolder {
                name: folder_name(&root.path),
                path: root.path.display().to_string(),
                root_id,
                group_id: group_id.map(|id| id.to_string()),
                group_name: placed.as_ref().and_then(|group| group.name.clone()),
                workspace: placed
                    .as_ref()
                    .map(|group| group.workspace)
                    .unwrap_or("other")
                    .to_string(),
                can_mount: blocked_reason.is_none(),
                blocked_reason,
                auto_mount,
                mount,
            });
        }
    }

    // Mounts whose folder is no longer enrolled can still be unmounted here.
    for mount in mounts {
        folders.push(MountOverviewFolder {
            root_id: mount.root_id.clone(),
            name: folder_name(Path::new(&mount.encrypted_dir)),
            path: mount.encrypted_dir.clone(),
            group_id: None,
            group_name: None,
            workspace: "other".to_string(),
            can_mount: false,
            blocked_reason: Some("This folder is no longer protected in this workspace.".into()),
            auto_mount: false,
            mount: Some(mount),
        });
    }

    Ok(CommandResponse::ok(MountOverview {
        local_vault: local_vault_group.is_some(),
        selected_group_id,
        folders,
        auto_mount_configured,
    }))
}

/// Turns automatic mounting on or off for the given folders and returns the
/// folders now selected.
#[tauri::command]
pub async fn set_auto_mount_folders(
    root_ids: Vec<String>,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<CommandResponse<Vec<String>>, String> {
    let _operation_guard = ensure_local_data_or_vault(&state).await?;
    let client = state.local_client.client().await?;
    let enrolled = match enrolled_roots_with_groups(&client).await {
        Ok(roots) => roots
            .into_iter()
            .map(|(root, _)| root.root_id.to_string())
            .collect::<Vec<_>>(),
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let stored = load_auto_mount_config(&client)
        .await?
        .unwrap_or_default()
        .root_ids;
    let ids = root_ids
        .iter()
        .map(|id| id.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let config = AutoMountConfig {
        version: 1,
        root_ids: update_auto_mount_set(&stored, &enrolled, &ids, enabled),
    };
    client
        .store_local_config(
            AUTO_MOUNT_CONFIG_KEY,
            &serde_json::to_string(&config).map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(CommandResponse::ok(config.root_ids))
}

fn take_mount(mounts: &mut Vec<MountInfo>, root_id: &str) -> Option<MountInfo> {
    let index = mounts.iter().position(|mount| mount.root_id == root_id)?;
    Some(mounts.swap_remove(index))
}

/// Mounts an enrolled folder of any of the account's groups, using that
/// folder's own group. The group selected in the UI stays as it is.
#[tauri::command]
pub async fn mount_folder_by_root_id(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountStatusPayload>, String> {
    let _operation_guard = ensure_local_team_write_or_vault(&state).await?;
    tracing::info!("Mount Center mount request with root_id: {}", root_id);
    mount_root_by_id(&state, root_id, None).await
}

/// Resolves the folder's own group, checks this device can use it, and mounts
/// it. The caller holds the operation gate.
/// How long one server access check covers further mounts in the same group,
/// so "Mount all" asks once per group instead of once per folder. Short, so a
/// revocation is still caught by the next mount request after a few seconds.
const GROUP_ACCESS_REUSE: Duration = Duration::from_secs(30);

/// Recent successful access checks; failures are never kept. Cleared on every
/// sign-in, sign-out, account or vault change (`mount_queue::cancel_for_transition`).
struct GroupAccessCheck {
    account: String,
    group_id: Uuid,
    checked_at: std::time::Instant,
    group: Value,
}

#[derive(Default)]
pub(super) struct GroupAccessChecks {
    entries: Vec<GroupAccessCheck>,
}

impl GroupAccessChecks {
    pub(super) fn get(
        &self,
        account: &str,
        group_id: Uuid,
        now: std::time::Instant,
    ) -> Option<Value> {
        self.entries
            .iter()
            .find(|check| {
                check.account == account
                    && check.group_id == group_id
                    && now.saturating_duration_since(check.checked_at) < GROUP_ACCESS_REUSE
            })
            .map(|check| check.group.clone())
    }

    pub(super) fn put(
        &mut self,
        account: &str,
        group_id: Uuid,
        now: std::time::Instant,
        group: Value,
    ) {
        self.entries.retain(|check| {
            !(check.account == account && check.group_id == group_id)
                && now.saturating_duration_since(check.checked_at) < GROUP_ACCESS_REUSE
        });
        self.entries.push(GroupAccessCheck {
            account: account.to_string(),
            group_id,
            checked_at: now,
            group,
        });
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
}

static GROUP_ACCESS_CHECKS: Lazy<std::sync::Mutex<GroupAccessChecks>> =
    Lazy::new(|| std::sync::Mutex::new(GroupAccessChecks::default()));

fn group_access_checks() -> std::sync::MutexGuard<'static, GroupAccessChecks> {
    GROUP_ACCESS_CHECKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn forget_group_access_checks() {
    group_access_checks().clear();
}

pub(super) async fn mount_root_by_id(
    state: &AppState,
    root_id: String,
    progress: Option<&super::mount_queue::MountProgress>,
) -> Result<CommandResponse<MountStatusPayload>, String> {
    let parsed_root_id =
        Uuid::parse_str(&root_id).map_err(|e| format!("Invalid root_id format: {}", e))?;

    if state.local_vault_group().await.is_some() {
        // The vault has a single group, which is always the selected one.
        let (group_id, _) = match ensure_local_active_group_with_metadata(state).await {
            Ok(selection) => selection,
            Err(err) => return Ok(CommandResponse::err(err)),
        };
        return mount_root_in_group(state, root_id, group_id, None, progress).await;
    }

    let session = current_local_session(state).await?;
    let client = state.local_client.client().await?;
    let group_id = match enrolled_roots_with_groups(&client).await {
        Ok(roots) => roots
            .into_iter()
            .find(|(root, _)| root.root_id == parsed_root_id)
            .and_then(|(_, group_id)| group_id),
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let Some(group_id) = group_id else {
        return Ok(CommandResponse::err(format!(
            "No enrolled folder found with root_id: {}",
            root_id
        )));
    };

    let refresh = session.expires_at > chrono::Utc::now().timestamp();
    let recent = group_access_checks().get(&session.email, group_id, std::time::Instant::now());
    let group = match recent {
        Some(group) => group,
        None => match validate_desktop_workspace_group(state, &session, group_id, refresh).await {
            Ok(group) => {
                group_access_checks().put(
                    &session.email,
                    group_id,
                    std::time::Instant::now(),
                    group.clone(),
                );
                group
            }
            Err(err) => return Ok(CommandResponse::err(err)),
        },
    };
    let Some(epoch) = operations::group_epoch_uuid(&group)? else {
        return Ok(CommandResponse::err(
            "The workspace encryption keys are not initialized",
        ));
    };
    let mut has_keys = client
        .has_cached_group_epoch_key(group_id, epoch)
        .await
        .map_err(|error| error.to_string())?;
    if !has_keys && refresh {
        let _ = client.refresh_committed_group_epoch(group_id).await;
        has_keys = client
            .has_cached_group_epoch_key(group_id, epoch)
            .await
            .map_err(|error| error.to_string())?;
    }
    if !has_keys {
        return Ok(CommandResponse::err_with_code(
            "GROUP_KEYS_UNAVAILABLE",
            GROUP_KEYS_UNAVAILABLE,
        ));
    }
    mount_root_in_group(state, root_id, group_id, Some(&group), progress).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_access_check_covers_the_same_group_for_a_short_while_only() {
        let start = std::time::Instant::now();
        let group = Uuid::new_v4();
        let mut checks = GroupAccessChecks::default();
        checks.put(
            "me@example.com",
            group,
            start,
            json!({"id": group.to_string()}),
        );

        assert!(checks
            .get("me@example.com", group, start + Duration::from_secs(5))
            .is_some());
        assert!(
            checks
                .get("me@example.com", Uuid::new_v4(), start)
                .is_none(),
            "other group"
        );
        assert!(
            checks.get("other@example.com", group, start).is_none(),
            "other account"
        );
        assert!(
            checks
                .get("me@example.com", group, start + GROUP_ACCESS_REUSE)
                .is_none(),
            "expired"
        );

        checks.clear();
        assert!(
            checks.get("me@example.com", group, start).is_none(),
            "cleared on account changes"
        );
    }

    fn personal_snapshot(group_id: &str) -> Value {
        json!({
            "state": "available",
            "personal_default_group_id": group_id,
            "group": {"id": group_id, "name": "Me", "organization_id": null},
        })
    }

    #[test]
    fn overview_places_personal_team_and_outside_groups() {
        let personal_id = Uuid::new_v4();
        let team_id = Uuid::new_v4();
        let other_org_id = Uuid::new_v4();
        let stray_personal_id = Uuid::new_v4();
        let groups = vec![
            json!({"id": team_id.to_string(), "name": "Engineering", "organization_id": "org-a"}),
            json!({"id": other_org_id.to_string(), "name": "Partner", "organization_id": "org-b"}),
            json!({"id": stray_personal_id.to_string(), "name": "Old", "organization_id": null}),
        ];
        let personal = personal_snapshot(&personal_id.to_string());

        let placed = overview_group(personal_id, &groups, Some(&personal), Some("org-a")).unwrap();
        assert_eq!(placed.workspace, "personal");
        assert_eq!(placed.name.as_deref(), Some("Personal"));

        let placed = overview_group(team_id, &groups, Some(&personal), Some("org-a")).unwrap();
        assert_eq!(placed.workspace, "team");
        assert_eq!(placed.name.as_deref(), Some("Engineering"));

        assert!(overview_group(other_org_id, &groups, Some(&personal), Some("org-a")).is_none());
        assert!(overview_group(team_id, &groups, Some(&personal), None).is_none());
        assert!(
            overview_group(stray_personal_id, &groups, Some(&personal), Some("org-a")).is_none()
        );
        assert!(overview_group(Uuid::new_v4(), &groups, Some(&personal), Some("org-a")).is_none());
    }

    #[test]
    fn overview_ignores_a_personal_workspace_that_needs_repair() {
        let personal_id = Uuid::new_v4();
        let mut personal = personal_snapshot(&personal_id.to_string());
        personal["state"] = json!("needs_repair");

        assert!(overview_group(personal_id, &[], Some(&personal), None).is_none());
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn auto_mount_set_adds_and_removes_enrolled_folders_in_order() {
        let enrolled = ids(&["a", "b", "c"]);

        let added = update_auto_mount_set(&ids(&["b"]), &enrolled, &ids(&["c", "a", "b"]), true);
        assert_eq!(added, ids(&["b", "c", "a"]));

        let removed = update_auto_mount_set(&added, &enrolled, &ids(&["c"]), false);
        assert_eq!(removed, ids(&["b", "a"]));
    }

    #[test]
    fn auto_mount_set_drops_folders_that_are_not_enrolled() {
        let enrolled = ids(&["a"]);

        let next = update_auto_mount_set(&ids(&["gone", "a"]), &enrolled, &ids(&["unknown"]), true);
        assert_eq!(next, ids(&["a"]));

        // Saving an empty selection still writes the key (marks it configured).
        assert!(update_auto_mount_set(&[], &enrolled, &[], true).is_empty());
    }

    #[test]
    fn folder_name_uses_the_last_path_component() {
        assert_eq!(folder_name(Path::new("/Users/me/Taxes 2026")), "Taxes 2026");
        assert_eq!(folder_name(Path::new("/")), "/");
    }
}
