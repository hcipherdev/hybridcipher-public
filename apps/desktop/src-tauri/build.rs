use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

fn main() {
    build_macos_file_provider_bridge();
    stage_bundled_cli();
    tauri_build::build()
}

fn build_macos_file_provider_bridge() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    println!("cargo:rerun-if-changed=src/macos_file_provider_native.m");
    cc::Build::new()
        .file("src/macos_file_provider_native.m")
        .flag("-fobjc-arc")
        .compile("hybridcipher_desktop_macos_file_provider_native");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=FileProvider");
}

fn stage_bundled_cli() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()));
    let workspace_root = manifest_dir
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.clone());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let exe_suffix = if target_os == "windows" { ".exe" } else { "" };
    let binary_name = format!("hybridcipher{}", exe_suffix);
    let source = workspace_root
        .join("target")
        .join(&profile)
        .join(&binary_name);
    let staged_dir = manifest_dir.join("resources").join("bin");
    let staged_path = staged_dir.join(&binary_name);

    println!("cargo:rerun-if-env-changed=HYBRIDCIPHER_CLI_PATH");
    println!("cargo:rerun-if-changed={}", source.display());

    let override_source = std::env::var_os("HYBRIDCIPHER_CLI_PATH").map(PathBuf::from);
    let candidate = override_source.as_ref().unwrap_or(&source);

    if !candidate.exists() {
        println!(
            "cargo:warning=Bundled CLI staging skipped; {} was not found",
            candidate.display()
        );
        return;
    }

    if let Err(err) = fs::create_dir_all(&staged_dir) {
        println!(
            "cargo:warning=Failed to create bundled CLI staging directory {}: {}",
            staged_dir.display(),
            err
        );
        return;
    }

    match files_match(candidate, &staged_path) {
        Ok(true) => {
            println!(
                "cargo:warning=Bundled CLI resource already up to date at {}",
                staged_path.display()
            );
            return;
        }
        Ok(false) => {}
        Err(err) => println!(
            "cargo:warning=Could not compare bundled CLI resource {} with {}: {}",
            candidate.display(),
            staged_path.display(),
            err
        ),
    }

    match fs::copy(candidate, &staged_path) {
        Ok(_) => {
            wait_for_file_readable(&staged_path);
            println!(
                "cargo:warning=Staged bundled CLI resource at {}",
                staged_path.display()
            );
        }
        Err(err) => println!(
            "cargo:warning=Failed to stage bundled CLI resource from {} to {}: {}",
            candidate.display(),
            staged_path.display(),
            err
        ),
    }
}

fn files_match(source: &Path, staged: &Path) -> io::Result<bool> {
    let source_meta = fs::metadata(source)?;
    let staged_meta = match fs::metadata(staged) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };

    if source_meta.len() != staged_meta.len() {
        return Ok(false);
    }

    let mut source_file = fs::File::open(source)?;
    let mut staged_file = fs::File::open(staged)?;
    let mut source_buf = [0_u8; 64 * 1024];
    let mut staged_buf = [0_u8; 64 * 1024];

    loop {
        let source_len = source_file.read(&mut source_buf)?;
        let staged_len = staged_file.read(&mut staged_buf)?;

        if source_len != staged_len {
            return Ok(false);
        }

        if source_len == 0 {
            return Ok(true);
        }

        if source_buf[..source_len] != staged_buf[..staged_len] {
            return Ok(false);
        }
    }
}

fn wait_for_file_readable(path: &Path) {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    for _ in 0..20 {
        match fs::File::open(path) {
            Ok(_) => return,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return,
        }
    }
}
