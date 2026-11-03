// Tests enrolled_folder_from_root() and build_coverage_center_snapshot() for protected folders gone from their saved path.
use super::*;
use hybridcipher_client::coverage::{CoverageRoot, CoverageRootKind, CoverageRootState};
use hybridcipher_client::state::client::CoverageRootStats;

fn root_at(path: PathBuf) -> CoverageRoot {
    CoverageRoot {
        root_id: Uuid::new_v4(),
        path,
        group_id: None,
        kind: CoverageRootKind::Folder,
        state: CoverageRootState::Active,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_scan: None,
    }
}

fn stats_for(root: CoverageRoot, orphaned_files: usize) -> CoverageRootStats {
    CoverageRootStats {
        root,
        tracked_files: 10,
        tracked_bytes: 0,
        orphaned_files,
        orphaned_bytes: 0,
        orphan_wrong_epoch: 0,
        orphan_missing_file: 0,
        orphan_missing_metadata: orphaned_files,
        orphan_outcast: 0,
        unmanaged_files: 0,
        unmanaged_bytes: 0,
        coverage_ratio: 1.0,
        recent_orphans: vec![],
        recent_unmanaged: vec![],
        keys: Default::default(),
    }
}

fn settings() -> SettingsStatus {
    SettingsStatus {
        coverage_last_scan: None,
        coverage_ipc_active: true,
        coverage_ipc_supported: true,
        registry_last_upload: None,
        registry_version: None,
    }
}

#[test]
fn enrolled_folder_reports_whether_its_path_exists() {
    let dir = tempfile::tempdir().unwrap();
    assert!(enrolled_folder_from_root(&root_at(dir.path().to_path_buf())).available);
    assert!(!enrolled_folder_from_root(&root_at(dir.path().join("renamed-away"))).available);
}

#[test]
fn a_missing_folder_asks_to_be_located_instead_of_reviewed() {
    let missing = root_at(PathBuf::from("/Users/test/Documents/Taxes"));
    let snapshot = build_coverage_center_snapshot(&[stats_for(missing, 3)], &settings(), |_| false);

    let row = &snapshot.folders[0];
    assert!(!row.available);
    assert!(row.needs_attention);
    assert_eq!(row.coverage_label, "Folder not found");
    assert_eq!(row.recommended_action_id, None);
    assert_eq!(snapshot.attention_items[0].title, "Taxes can’t be found");
    assert_eq!(snapshot.attention_items[0].action_id, None);
}
