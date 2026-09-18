//! Compile with `rustc --test -C debug-assertions=no` into an isolated directory.
//! This exercises the actual release resolver without building an installer.
#[path = "../src-tauri/src/cli_utils.rs"]
mod cli_utils;

#[test]
fn release_cli_ignores_working_directory_and_requires_its_bundle() {
    assert!(!cfg!(debug_assertions));
    let executable = std::env::current_exe().unwrap();
    let root = executable.parent().unwrap();
    let cwd = root.join("untrusted-cwd");
    let planted_dir = cwd.join("target/release");
    std::fs::create_dir_all(&planted_dir).unwrap();
    let filename = format!("hybridcipher{}", std::env::consts::EXE_SUFFIX);
    let planted = planted_dir.join(&filename);
    std::fs::write(&planted, b"inert untrusted marker").unwrap();
    let original = std::env::current_dir().unwrap();
    struct RestoreCwd(std::path::PathBuf);
    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }
    let restore = RestoreCwd(original);
    std::env::set_current_dir(&cwd).unwrap();
    #[cfg(windows)]
    let loose = {
        let loose = root.join(&filename);
        std::fs::write(&loose, b"inert loose executable").unwrap();
        loose
    };
    assert!(cli_utils::locate_cli_binary().is_err());
    let bundled_dir = root.join("resources/bin");
    std::fs::create_dir_all(&bundled_dir).unwrap();
    let bundled = bundled_dir.join(filename);
    std::fs::write(&bundled, b"inert bundled marker").unwrap();
    assert_eq!(
        cli_utils::locate_cli_binary().unwrap().0,
        bundled.canonicalize().unwrap()
    );
    std::fs::remove_file(bundled).unwrap();
    assert!(cli_utils::locate_cli_binary().is_err());
    drop(restore);
    #[cfg(windows)]
    std::fs::remove_file(loose).unwrap();
    std::fs::remove_file(planted).unwrap();
    std::fs::remove_dir(planted_dir).unwrap();
    std::fs::remove_dir(cwd.join("target")).unwrap();
    std::fs::remove_dir(cwd).unwrap();
    std::fs::remove_dir(bundled_dir).unwrap();
    std::fs::remove_dir(root.join("resources")).unwrap();
}
