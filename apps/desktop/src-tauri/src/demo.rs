//! Demo Mode - Offline demonstration functionality for investor demos
//!
//! Provides a deterministic, offline demo experience without server dependencies.
//! Demo data is bundled with the app and copied to a sandbox directory at runtime.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::fs;

use crate::state::AppState;

fn format_local_datetime() -> String {
    let local = chrono::Local::now();
    let offset = local.format("%:z");
    format!("{} UTC{}", local.format("%Y-%m-%d %H:%M:%S"), offset)
}

// ============================================================================
// Demo State Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoUser {
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoGroup {
    pub group_id: String,
    pub name: String,
    pub members: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoAuditSummary {
    pub status: String,
    pub file: String,
    pub hash: String,
    pub timestamp: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoStatus {
    pub initialized: bool,
    pub active: bool,
    pub current_step: u8,
    pub total_steps: u8,
    pub user: Option<DemoUser>,
    pub group: Option<DemoGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoStepResult {
    pub step: u8,
    pub label: String,
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

// ============================================================================
// Global Demo State
// ============================================================================

static DEMO_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);
static DEMO_CURRENT_STEP: AtomicU8 = AtomicU8::new(0);

// ============================================================================
// Demo Store
// ============================================================================

pub struct DemoStore {
    /// Path to the demo data directory in app support
    pub demo_dir: PathBuf,
    /// Path to the bundled seed data in app resources
    pub seed_dir: PathBuf,
}

impl DemoStore {
    pub fn new<R: Runtime>(app: &AppHandle<R>) -> Result<Self, String> {
        // Get app data directory: ~/Library/Application Support/com.hybridcipher.vault/
        let app_data = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("Failed to get app data dir: {}", e))?;

        let demo_dir = app_data.join("demo");

        // Get resource directory where demo_seed is bundled
        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|e| format!("Failed to get resource dir: {}", e))?;

        let mut seed_dir = resource_dir.join("demo_seed");
        if !seed_dir.exists() {
            // Dev fallback: use project resources when running from cargo
            let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("demo_seed");
            if fallback.exists() {
                seed_dir = fallback;
            }
        }

        Ok(Self { demo_dir, seed_dir })
    }

    /// Check if demo data has been initialized
    pub fn is_initialized(&self) -> bool {
        self.demo_dir.exists() && self.demo_dir.join("identity").exists()
    }

    /// Get path to demo user JSON
    pub fn user_path(&self) -> PathBuf {
        self.demo_dir.join("identity").join("demo_user.json")
    }

    /// Get path to demo group JSON
    pub fn group_path(&self) -> PathBuf {
        self.demo_dir.join("groups").join("demo_group.json")
    }

    /// Get path to demo files directory
    pub fn files_dir(&self) -> PathBuf {
        self.demo_dir.join("files")
    }

    /// Get path to demo audit summary JSON
    pub fn audit_path(&self) -> PathBuf {
        self.demo_dir.join("audit").join("summary.json")
    }

    /// Load demo user from JSON
    pub async fn get_user(&self) -> Result<DemoUser, String> {
        let path = self.user_path();
        let content = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("Failed to read demo user: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse demo user: {}", e))
    }

    /// Load demo group from JSON
    pub async fn get_group(&self) -> Result<DemoGroup, String> {
        let path = self.group_path();
        let content = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("Failed to read demo group: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse demo group: {}", e))
    }

    /// Load demo audit summary from JSON
    pub async fn get_audit_summary(&self) -> Result<DemoAuditSummary, String> {
        let path = self.audit_path();
        let content = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("Failed to read demo audit summary: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse demo audit summary: {}", e))
    }
}

// ============================================================================
// Tauri Commands
// ============================================================================

/// Initialize demo mode - copies seed data to app data directory
#[tauri::command]
pub async fn demo_init<R: Runtime>(app: AppHandle<R>) -> Result<DemoStatus, String> {
    let store = DemoStore::new(&app)?;

    // If already initialized, just return status
    if store.is_initialized() {
        tracing::info!("Demo data already initialized");
        return demo_status_internal(&store).await;
    }

    tracing::info!("Initializing demo data from seed: {:?}", store.seed_dir);

    // Check seed exists
    if !store.seed_dir.exists() {
        return Err(format!("Demo seed not found at {:?}", store.seed_dir));
    }

    // Create demo directory
    fs::create_dir_all(&store.demo_dir)
        .await
        .map_err(|e| format!("Failed to create demo dir: {}", e))?;

    // Copy seed contents to demo dir
    copy_dir_recursive(&store.seed_dir, &store.demo_dir).await?;

    tracing::info!("Demo data initialized successfully at {:?}", store.demo_dir);

    demo_status_internal(&store).await
}

/// Reset demo mode - deletes demo data and recopies from seed
#[tauri::command]
pub async fn demo_reset<R: Runtime>(app: AppHandle<R>) -> Result<DemoStatus, String> {
    let store = DemoStore::new(&app)?;

    // Stop demo if running
    DEMO_MODE_ACTIVE.store(false, Ordering::SeqCst);
    DEMO_CURRENT_STEP.store(0, Ordering::SeqCst);

    // Remove existing demo data
    if store.demo_dir.exists() {
        tracing::info!("Removing existing demo data at {:?}", store.demo_dir);
        fs::remove_dir_all(&store.demo_dir)
            .await
            .map_err(|e| format!("Failed to remove demo dir: {}", e))?;
    }

    // Reinitialize
    demo_init(app).await
}

/// Get current demo status
#[tauri::command]
pub async fn demo_status<R: Runtime>(app: AppHandle<R>) -> Result<DemoStatus, String> {
    let store = DemoStore::new(&app)?;
    demo_status_internal(&store).await
}

/// Check if demo mode is currently active
#[tauri::command]
pub fn is_demo_mode() -> bool {
    DEMO_MODE_ACTIVE.load(Ordering::SeqCst)
}

/// Set demo mode active state
#[tauri::command]
pub fn set_demo_mode(active: bool) {
    DEMO_MODE_ACTIVE.store(active, Ordering::SeqCst);
    if !active {
        DEMO_CURRENT_STEP.store(0, Ordering::SeqCst);
    }
    tracing::info!("Demo mode set to: {}", active);
}

/// Run the full demo sequence (8 steps)
#[tauri::command]
pub async fn demo_run<R: Runtime>(
    app: AppHandle<R>,
    _state: State<'_, AppState>,
) -> Result<Vec<DemoStepResult>, String> {
    let store = DemoStore::new(&app)?;

    // Ensure demo is initialized
    if !store.is_initialized() {
        demo_init(app.clone()).await?;
    }

    // Activate demo mode
    DEMO_MODE_ACTIVE.store(true, Ordering::SeqCst);
    DEMO_CURRENT_STEP.store(0, Ordering::SeqCst);

    let mut results = Vec::new();

    // Step 1: Login (demo user)
    results.push(run_demo_step_1(&store).await);

    // Step 2: Select group
    results.push(run_demo_step_2(&store).await);

    // Step 3: Enroll folder
    results.push(run_demo_step_3(&store).await);

    // Step 4: Mount folder
    results.push(run_demo_step_4(&store).await);

    // Step 5: Open file
    results.push(run_demo_step_5(&store).await);

    // Step 6: Edit file
    results.push(run_demo_step_6(&store).await);

    // Step 7: Unmount
    results.push(run_demo_step_7(&store).await);

    // Step 8: Show audit proof
    results.push(run_demo_step_8(&store).await);

    Ok(results)
}

/// Run a single demo step
#[tauri::command]
pub async fn demo_run_step<R: Runtime>(
    app: AppHandle<R>,
    step: u8,
) -> Result<DemoStepResult, String> {
    let store = DemoStore::new(&app)?;

    if !store.is_initialized() {
        return Err("Demo not initialized. Call demo_init first.".to_string());
    }

    DEMO_CURRENT_STEP.store(step, Ordering::SeqCst);

    match step {
        1 => Ok(run_demo_step_1(&store).await),
        2 => Ok(run_demo_step_2(&store).await),
        3 => Ok(run_demo_step_3(&store).await),
        4 => Ok(run_demo_step_4(&store).await),
        5 => Ok(run_demo_step_5(&store).await),
        6 => Ok(run_demo_step_6(&store).await),
        7 => Ok(run_demo_step_7(&store).await),
        8 => Ok(run_demo_step_8(&store).await),
        _ => Err(format!("Invalid demo step: {}", step)),
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

async fn demo_status_internal(store: &DemoStore) -> Result<DemoStatus, String> {
    let initialized = store.is_initialized();
    let active = DEMO_MODE_ACTIVE.load(Ordering::SeqCst);
    let current_step = DEMO_CURRENT_STEP.load(Ordering::SeqCst);

    let user = if initialized {
        store.get_user().await.ok()
    } else {
        None
    };

    let group = if initialized {
        store.get_group().await.ok()
    } else {
        None
    };

    Ok(DemoStatus {
        initialized,
        active,
        current_step,
        total_steps: 8,
        user,
        group,
    })
}

/// Recursively copy a directory
async fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> Result<(), String> {
    fs::create_dir_all(dst)
        .await
        .map_err(|e| format!("Failed to create dir {:?}: {}", dst, e))?;

    let mut entries = fs::read_dir(src)
        .await
        .map_err(|e| format!("Failed to read dir {:?}: {}", src, e))?;

    while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
        let path = entry.path();
        let file_name = entry.file_name();
        let dest_path = dst.join(&file_name);

        // Skip .DS_Store files
        if file_name == ".DS_Store" {
            continue;
        }

        if path.is_dir() {
            Box::pin(copy_dir_recursive(&path, &dest_path)).await?;
        } else {
            fs::copy(&path, &dest_path)
                .await
                .map_err(|e| format!("Failed to copy {:?} to {:?}: {}", path, dest_path, e))?;
        }
    }

    Ok(())
}

// ============================================================================
// Demo Steps Implementation
// ============================================================================

async fn run_demo_step_1(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(1, Ordering::SeqCst);

    match store.get_user().await {
        Ok(user) => DemoStepResult {
            step: 1,
            label: "Login".to_string(),
            success: true,
            message: format!("Logged in as {}", user.email),
            data: Some(serde_json::to_value(&user).unwrap_or_default()),
        },
        Err(e) => DemoStepResult {
            step: 1,
            label: "Login".to_string(),
            success: false,
            message: format!("Login failed: {}", e),
            data: None,
        },
    }
}

async fn run_demo_step_2(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(2, Ordering::SeqCst);

    match store.get_group().await {
        Ok(group) => DemoStepResult {
            step: 2,
            label: "Select Group".to_string(),
            success: true,
            message: format!("Selected group: {}", group.name),
            data: Some(serde_json::to_value(&group).unwrap_or_default()),
        },
        Err(e) => DemoStepResult {
            step: 2,
            label: "Select Group".to_string(),
            success: false,
            message: format!("Group selection failed: {}", e),
            data: None,
        },
    }
}

async fn run_demo_step_3(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(3, Ordering::SeqCst);

    let files_dir = store.files_dir();
    let documents_dir = files_dir.join("documents");

    if documents_dir.exists() {
        DemoStepResult {
            step: 3,
            label: "Enroll Folder".to_string(),
            success: true,
            message: "Enrolled demo workspace folder".to_string(),
            data: Some(serde_json::json!({
                "path": documents_dir.to_string_lossy(),
                "type": "demo_workspace"
            })),
        }
    } else {
        DemoStepResult {
            step: 3,
            label: "Enroll Folder".to_string(),
            success: false,
            message: "Demo documents folder not found".to_string(),
            data: None,
        }
    }
}

async fn run_demo_step_4(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(4, Ordering::SeqCst);

    // Simulated mount - for demo we just verify files exist
    let files_dir = store.files_dir();

    if files_dir.exists() {
        // Add small delay to simulate mount operation
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        DemoStepResult {
            step: 4,
            label: "Mount".to_string(),
            success: true,
            message: "Mounted encrypted folder (simulated)".to_string(),
            data: Some(serde_json::json!({
                "mount_path": files_dir.to_string_lossy(),
                "simulated": true
            })),
        }
    } else {
        DemoStepResult {
            step: 4,
            label: "Mount".to_string(),
            success: false,
            message: "Failed to mount: files directory not found".to_string(),
            data: None,
        }
    }
}

async fn run_demo_step_5(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(5, Ordering::SeqCst);

    let demo_file = store.files_dir().join("documents").join("hybridcipher.md");

    match fs::read_to_string(&demo_file).await {
        Ok(content) => DemoStepResult {
            step: 5,
            label: "Open File".to_string(),
            success: true,
            message: "Opened demo document".to_string(),
            data: Some(serde_json::json!({
                "file": demo_file.to_string_lossy(),
                "content_preview": content.chars().take(200).collect::<String>(),
                "size_bytes": content.len()
            })),
        },
        Err(e) => DemoStepResult {
            step: 5,
            label: "Open File".to_string(),
            success: false,
            message: format!("Failed to open file: {}", e),
            data: None,
        },
    }
}

async fn run_demo_step_6(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(6, Ordering::SeqCst);

    let demo_file = store.files_dir().join("documents").join("hybridcipher.md");

    // Read current content
    let current_content = match fs::read_to_string(&demo_file).await {
        Ok(c) => c,
        Err(e) => {
            return DemoStepResult {
                step: 6,
                label: "Edit File".to_string(),
                success: false,
                message: format!("Failed to read file: {}", e),
                data: None,
            };
        }
    };

    // Add a visible change with timestamp
    let timestamp = format_local_datetime();
    let edit_line = format!("\n\n---\n*Demo edit performed at {}*\n", timestamp);
    let new_content = format!("{}{}", current_content, edit_line);

    match fs::write(&demo_file, &new_content).await {
        Ok(_) => DemoStepResult {
            step: 6,
            label: "Edit File".to_string(),
            success: true,
            message: format!("Added demo edit at {}", timestamp),
            data: Some(serde_json::json!({
                "file": demo_file.to_string_lossy(),
                "added_line": edit_line.trim(),
                "timestamp": timestamp
            })),
        },
        Err(e) => DemoStepResult {
            step: 6,
            label: "Edit File".to_string(),
            success: false,
            message: format!("Failed to write file: {}", e),
            data: None,
        },
    }
}

async fn run_demo_step_7(_store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(7, Ordering::SeqCst);

    // Simulated unmount
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    DemoStepResult {
        step: 7,
        label: "Unmount".to_string(),
        success: true,
        message: "Safely unmounted encrypted folder".to_string(),
        data: Some(serde_json::json!({
            "simulated": true
        })),
    }
}

async fn run_demo_step_8(store: &DemoStore) -> DemoStepResult {
    DEMO_CURRENT_STEP.store(8, Ordering::SeqCst);

    // Generate a deterministic proof for the demo
    let demo_file = store.files_dir().join("documents").join("hybridcipher.md");
    let timestamp = format_local_datetime();

    // Read file for hash
    let content = fs::read_to_string(&demo_file).await.unwrap_or_default();
    let hash = format!("{:x}", md5::compute(content.as_bytes()));

    // Also try to read the bundled audit summary
    let audit_summary = store.get_audit_summary().await.ok();

    DemoStepResult {
        step: 8,
        label: "Audit Proof".to_string(),
        success: true,
        message: "Local demo proof generated".to_string(),
        data: Some(serde_json::json!({
            "status": "verified (local demo)",
            "file": demo_file.to_string_lossy(),
            "hash": hash,
            "timestamp": timestamp,
            "note": "This is a local demo proof for demonstration purposes only.",
            "bundled_summary": audit_summary
        })),
    }
}
