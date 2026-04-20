use crate::ClientConfig;
use std::fs;
use std::path::PathBuf;

const EMBEDDED_CLIENT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/client_config.toml"
));

#[derive(Debug, Default)]
struct ClientConfigOverrides {
    state_save_debounce_ms: Option<u64>,
    migration_state_save_batch_size: Option<u64>,
    migration_state_save_max_interval_secs: Option<u64>,
    file_index_cache_max_roots: Option<usize>,
    metadata_cache_max_entries: Option<usize>,
    migration_heartbeat_min_interval_secs: Option<u64>,
    migration_automation_enabled: Option<bool>,
    coverage_watchers_enabled: Option<bool>,
    coverage_ipc_opt_out_env: Option<String>,
    transparency_enabled: Option<bool>,
    membership_proof_max_age_hours: Option<u64>,
    admin_operations_refresh_interval_secs: Option<u64>,
    require_second_party_verification: Option<bool>,
    excluded_file_patterns: Option<Vec<String>>,
    session_health_check_interval_secs: Option<u64>,
    session_health_expiry_grace_secs: Option<u64>,
    mount_continue_enable_secs: Option<u64>,
    mount_cancel_enable_secs: Option<u64>,
    mount_background_timeout_secs: Option<u64>,
}

fn parse_server_url_from_str(contents: &str, source: &str) -> Option<String> {
    let parsed: toml::Value = match toml::from_str(contents) {
        Ok(val) => val,
        Err(err) => {
            log::warn!("Failed to parse {} for server_url: {}", source, err);
            return None;
        }
    };
    let client_section = parsed.get("client")?;
    let server_url = client_section.get("server_url")?.as_str()?.trim();
    if server_url.is_empty() {
        return None;
    }
    Some(server_url.to_string())
}

pub fn embedded_client_server_url() -> Option<String> {
    parse_server_url_from_str(EMBEDDED_CLIENT_CONFIG, "embedded client_config.toml")
}

pub fn default_server_url() -> String {
    embedded_client_server_url().unwrap_or_else(|| "https://api.hybridcipher.com".to_string())
}

fn merge_overrides(
    mut primary: ClientConfigOverrides,
    secondary: ClientConfigOverrides,
) -> ClientConfigOverrides {
    if primary.state_save_debounce_ms.is_none() {
        primary.state_save_debounce_ms = secondary.state_save_debounce_ms;
    }
    if primary.migration_state_save_batch_size.is_none() {
        primary.migration_state_save_batch_size = secondary.migration_state_save_batch_size;
    }
    if primary.migration_state_save_max_interval_secs.is_none() {
        primary.migration_state_save_max_interval_secs =
            secondary.migration_state_save_max_interval_secs;
    }
    if primary.file_index_cache_max_roots.is_none() {
        primary.file_index_cache_max_roots = secondary.file_index_cache_max_roots;
    }
    if primary.metadata_cache_max_entries.is_none() {
        primary.metadata_cache_max_entries = secondary.metadata_cache_max_entries;
    }
    if primary.migration_heartbeat_min_interval_secs.is_none() {
        primary.migration_heartbeat_min_interval_secs =
            secondary.migration_heartbeat_min_interval_secs;
    }
    if primary.migration_automation_enabled.is_none() {
        primary.migration_automation_enabled = secondary.migration_automation_enabled;
    }
    if primary.coverage_watchers_enabled.is_none() {
        primary.coverage_watchers_enabled = secondary.coverage_watchers_enabled;
    }
    if primary.coverage_ipc_opt_out_env.is_none() {
        primary.coverage_ipc_opt_out_env = secondary.coverage_ipc_opt_out_env;
    }
    if primary.transparency_enabled.is_none() {
        primary.transparency_enabled = secondary.transparency_enabled;
    }
    if primary.membership_proof_max_age_hours.is_none() {
        primary.membership_proof_max_age_hours = secondary.membership_proof_max_age_hours;
    }
    if primary.admin_operations_refresh_interval_secs.is_none() {
        primary.admin_operations_refresh_interval_secs =
            secondary.admin_operations_refresh_interval_secs;
    }
    if primary.require_second_party_verification.is_none() {
        primary.require_second_party_verification = secondary.require_second_party_verification;
    }
    if primary.excluded_file_patterns.is_none() {
        primary.excluded_file_patterns = secondary.excluded_file_patterns;
    }
    if primary.session_health_check_interval_secs.is_none() {
        primary.session_health_check_interval_secs = secondary.session_health_check_interval_secs;
    }
    if primary.session_health_expiry_grace_secs.is_none() {
        primary.session_health_expiry_grace_secs = secondary.session_health_expiry_grace_secs;
    }
    if primary.mount_continue_enable_secs.is_none() {
        primary.mount_continue_enable_secs = secondary.mount_continue_enable_secs;
    }
    if primary.mount_cancel_enable_secs.is_none() {
        primary.mount_cancel_enable_secs = secondary.mount_cancel_enable_secs;
    }
    if primary.mount_background_timeout_secs.is_none() {
        primary.mount_background_timeout_secs = secondary.mount_background_timeout_secs;
    }

    primary
}

pub fn config_file_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = std::env::var("HYBRIDCIPHER_CONFIG_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            candidates.push(path);
        }
    }

    let client_config_root = PathBuf::from("client_config.toml");
    if client_config_root.exists() && !candidates.contains(&client_config_root) {
        candidates.push(client_config_root);
    }

    let env_name = std::env::var("RUST_ENV").unwrap_or_else(|_| "production".to_string());
    let env_path = PathBuf::from(format!("config/{}.toml", env_name));
    if env_path.exists() && !candidates.contains(&env_path) {
        candidates.push(env_path);
    }

    let prod_default = PathBuf::from("config/production.toml");
    if prod_default.exists() && !candidates.contains(&prod_default) {
        candidates.push(prod_default);
    }

    candidates
}

pub fn load_client_config_from_files() -> ClientConfig {
    let mut config = ClientConfig::default();
    if let Some(overrides) = load_client_config_overrides() {
        if let Some(debounce_ms) = overrides.state_save_debounce_ms {
            config.state_save_debounce_ms = debounce_ms;
        }
        if let Some(batch_size) = overrides.migration_state_save_batch_size {
            config.migration_state_save_batch_size = batch_size;
        }
        if let Some(max_interval) = overrides.migration_state_save_max_interval_secs {
            config.migration_state_save_max_interval_secs = max_interval;
        }
        if let Some(max_roots) = overrides.file_index_cache_max_roots {
            config.file_index_cache_max_roots = max_roots;
        }
        if let Some(max_entries) = overrides.metadata_cache_max_entries {
            config.metadata_cache_max_entries = max_entries;
        }
        if let Some(min_interval) = overrides.migration_heartbeat_min_interval_secs {
            config.migration_heartbeat_min_interval_secs = min_interval;
        }
        if let Some(enabled) = overrides.migration_automation_enabled {
            config.migration_automation_enabled = enabled;
        }
        if let Some(enabled) = overrides.coverage_watchers_enabled {
            config.coverage_watchers_enabled = enabled;
        }
        if let Some(env_name) = overrides.coverage_ipc_opt_out_env {
            config.coverage_ipc_opt_out_env = env_name;
        }
        if let Some(enabled) = overrides.transparency_enabled {
            config.transparency_config.enabled = enabled;
        }
        if let Some(max_age_hours) = overrides.membership_proof_max_age_hours {
            config.membership_proof_max_age_hours = max_age_hours;
        }
        if let Some(interval_secs) = overrides.admin_operations_refresh_interval_secs {
            config.admin_operations_refresh_interval_secs = interval_secs;
        }
        if let Some(interval_secs) = overrides.session_health_check_interval_secs {
            config.session_health_check_interval_secs = interval_secs;
        }
        if let Some(grace_secs) = overrides.session_health_expiry_grace_secs {
            config.session_health_expiry_grace_secs = grace_secs;
        }
        if let Some(continue_secs) = overrides.mount_continue_enable_secs {
            config.mount_continue_enable_secs = continue_secs;
        }
        if let Some(cancel_secs) = overrides.mount_cancel_enable_secs {
            config.mount_cancel_enable_secs = cancel_secs;
        }
        if let Some(timeout_secs) = overrides.mount_background_timeout_secs {
            config.mount_background_timeout_secs = timeout_secs;
        }
        if let Some(required) = overrides.require_second_party_verification {
            config.pinning_config.require_second_party_verification = required;
        }
        if let Some(patterns) = overrides.excluded_file_patterns {
            config.excluded_file_patterns = patterns;
        }
    }
    config
}

fn load_client_config_overrides_from_str(
    contents: &str,
    source: &str,
) -> Option<ClientConfigOverrides> {
    let parsed: toml::Value = match toml::from_str(contents) {
        Ok(val) => val,
        Err(err) => {
            log::warn!("Failed to parse {} for client config: {}", source, err);
            return None;
        }
    };
    let client_section = parsed.get("client");

    let mut overrides = ClientConfigOverrides::default();

    if let Some(value) = client_section.and_then(|section| section.get("state_save_debounce_ms")) {
        if let Some(int_val) = value.as_integer() {
            overrides.state_save_debounce_ms = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("migration_state_save_batch_size"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.migration_state_save_batch_size = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("migration_state_save_max_interval_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.migration_state_save_max_interval_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("file_index_cache_max_roots"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.file_index_cache_max_roots = Some(int_val.max(0) as usize);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("metadata_cache_max_entries"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.metadata_cache_max_entries = Some(int_val.max(0) as usize);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("migration_heartbeat_min_interval_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.migration_heartbeat_min_interval_secs = Some(int_val.max(1) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("migration_automation_enabled"))
    {
        if let Some(bool_val) = value.as_bool() {
            overrides.migration_automation_enabled = Some(bool_val);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("membership_proof_max_age_hours"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.membership_proof_max_age_hours = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) = client_section.and_then(|section| section.get("coverage_watchers_enabled"))
    {
        if let Some(bool_val) = value.as_bool() {
            overrides.coverage_watchers_enabled = Some(bool_val);
        }
    }

    if let Some(value) = client_section.and_then(|section| section.get("coverage_ipc_opt_out_env"))
    {
        if let Some(env_name) = value.as_str() {
            overrides.coverage_ipc_opt_out_env = Some(env_name.trim().to_string());
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("admin_operations_refresh_interval_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.admin_operations_refresh_interval_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("session_health_check_interval_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.session_health_check_interval_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("session_health_expiry_grace_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.session_health_expiry_grace_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("mount_continue_enable_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.mount_continue_enable_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) = client_section.and_then(|section| section.get("mount_cancel_enable_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.mount_cancel_enable_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("mount_background_timeout_secs"))
    {
        if let Some(int_val) = value.as_integer() {
            overrides.mount_background_timeout_secs = Some(int_val.max(0) as u64);
        }
    }

    if let Some(value) =
        client_section.and_then(|section| section.get("require_second_party_verification"))
    {
        if let Some(bool_val) = value.as_bool() {
            overrides.require_second_party_verification = Some(bool_val);
        }
    }

    // Parse [coverage] section for excluded file patterns
    if let Some(patterns) = parsed
        .get("coverage")
        .and_then(|section| section.get("exclude_files"))
        .and_then(|val| val.as_array())
    {
        let list: Vec<String> = patterns
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            overrides.excluded_file_patterns = Some(list);
        }
    }

    // Parse [security] section for transparency settings
    if let Some(security_section) = parsed.get("security") {
        if let Some(value) = security_section.get("transparency_log") {
            if let Some(bool_val) = value.as_bool() {
                overrides.transparency_enabled = Some(bool_val);
            }
        }
    }

    if overrides.state_save_debounce_ms.is_some()
        || overrides.migration_state_save_batch_size.is_some()
        || overrides.migration_state_save_max_interval_secs.is_some()
        || overrides.file_index_cache_max_roots.is_some()
        || overrides.metadata_cache_max_entries.is_some()
        || overrides.migration_heartbeat_min_interval_secs.is_some()
        || overrides.migration_automation_enabled.is_some()
        || overrides.coverage_watchers_enabled.is_some()
        || overrides.coverage_ipc_opt_out_env.is_some()
        || overrides.transparency_enabled.is_some()
        || overrides.membership_proof_max_age_hours.is_some()
        || overrides.admin_operations_refresh_interval_secs.is_some()
        || overrides.session_health_check_interval_secs.is_some()
        || overrides.session_health_expiry_grace_secs.is_some()
        || overrides.mount_continue_enable_secs.is_some()
        || overrides.mount_cancel_enable_secs.is_some()
        || overrides.mount_background_timeout_secs.is_some()
        || overrides.require_second_party_verification.is_some()
        || overrides.excluded_file_patterns.is_some()
    {
        return Some(overrides);
    }

    None
}

fn load_client_config_overrides() -> Option<ClientConfigOverrides> {
    let candidates = config_file_candidates();
    let embedded = load_client_config_overrides_from_str(
        EMBEDDED_CLIENT_CONFIG,
        "embedded client_config.toml",
    );
    let mut saw_any = embedded.is_some();
    let mut merged = embedded.unwrap_or_default();

    for path in candidates {
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) => {
                log::warn!(
                    "Failed to read config file {} for client config: {}",
                    path.display(),
                    err
                );
                continue;
            }
        };
        let source = path.display().to_string();
        if let Some(overrides) = load_client_config_overrides_from_str(&contents, &source) {
            merged = merge_overrides(merged, overrides);
            saw_any = true;
        }
    }

    if saw_any {
        Some(merged)
    } else {
        None
    }
}
