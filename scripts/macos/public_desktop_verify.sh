#!/usr/bin/env bash
# Purpose: Build canonical unsigned HybridCipher macOS desktop verification
# artifacts from public source and write SHA-256 files beside them.
#
# Usage from the repository root:
#   MODE=silicon ./scripts/macos/public_desktop_verify.sh
#   MODE=full ./scripts/macos/public_desktop_verify.sh
#   MODE=custom DESKTOP_TARGETS="aarch64-apple-darwin" ./scripts/macos/public_desktop_verify.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
FILE_PROVIDER_BUILD_SCRIPT="$SCRIPT_DIR/build_file_provider_extension.sh"

ARTIFACTS=()
BUILD_MODE=""
BUILD_TARGETS=""

log() {
  printf "\n==> %s\n" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

canonical_arch_suffix() {
  local target="$1"
  echo "${target%%-*}"
}

canonical_unsigned_artifact_name() {
  local target="$1"
  printf 'HybridCipher_%s.unsigned.app.tar.gz\n' "$(canonical_arch_suffix "$target")"
}

create_deterministic_tar_gz() {
  local source_dir="$1"
  local output_path="$2"
  local archive_root="$3"

  python3 - "$source_dir" "$output_path" "$archive_root" <<'PY'
import gzip
import os
import sys
import tarfile
from pathlib import Path

source_dir = Path(sys.argv[1]).resolve()
output_path = Path(sys.argv[2]).resolve()
archive_root = sys.argv[3].strip("/")

if not source_dir.is_dir():
    raise SystemExit(f"Source directory does not exist: {source_dir}")

def normalized_mode(path: Path) -> int:
    if path.is_dir():
        return 0o755
    return 0o755 if os.access(path, os.X_OK) else 0o644

def add_path(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    info = tarfile.TarInfo(arcname)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.mode = normalized_mode(path)

    if path.is_symlink():
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        info.size = 0
        tar.addfile(info)
        return

    if path.is_dir():
        info.type = tarfile.DIRTYPE
        info.size = 0
        tar.addfile(info)
        return

    info.type = tarfile.REGTYPE
    info.size = path.stat().st_size
    with path.open("rb") as fh:
        tar.addfile(info, fh)

with output_path.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            add_path(tar, source_dir, archive_root)
            for path in sorted(source_dir.rglob("*")):
                rel = path.relative_to(source_dir)
                add_path(tar, path, f"{archive_root}/{rel.as_posix()}")
PY
}

create_canonical_unsigned_app_archive() {
  local target="$1"
  local app_path="$2"
  local output_dir="$3"
  local artifact_name
  local artifact_path
  local sha_path
  local sha

  artifact_name="$(canonical_unsigned_artifact_name "$target")"
  artifact_path="$output_dir/$artifact_name"
  sha_path="${artifact_path}.sha256"

  mkdir -p "$output_dir"
  create_deterministic_tar_gz "$app_path" "$artifact_path" "$(basename "$app_path")"

  sha="$(sha256_file "$artifact_path")"
  printf '%s  %s\n' "$sha" "$(basename "$artifact_path")" > "$sha_path"
  echo "$artifact_path"
}

cleanup_stale_temp_files() {
  log "Cleaning up stale temp files from previous runs"
  rm -f /tmp/hybridcipher-*.json 2>/dev/null || true
  rm -f /tmp/hybridcipher-*.zip 2>/dev/null || true
  rm -f /tmp/hybridcipher-public-tauri.*.json 2>/dev/null || true
  rm -rf /tmp/hybridcipher-fileprovider.* 2>/dev/null || true
}

desktop_app_version() {
  awk -F '"' '/^version = / { print $2; exit }' "$ROOT_DIR/apps/desktop/src-tauri/Cargo.toml"
}

desktop_tauri_config_version() {
  awk -F '"' '/"version"[[:space:]]*:/ { print $4; exit }' "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json"
}

validate_desktop_version_consistency() {
  local cargo_version
  local tauri_version
  cargo_version="$(desktop_app_version)"
  tauri_version="$(desktop_tauri_config_version)"

  if [[ -z "$cargo_version" ]]; then
    echo "Failed to detect desktop version from apps/desktop/src-tauri/Cargo.toml" >&2
    exit 1
  fi
  if [[ -z "$tauri_version" ]]; then
    echo "Failed to detect desktop version from apps/desktop/src-tauri/tauri.conf.json" >&2
    exit 1
  fi
  if [[ "$cargo_version" != "$tauri_version" ]]; then
    echo "Desktop version mismatch: Cargo.toml=$cargo_version tauri.conf.json=$tauri_version" >&2
    exit 1
  fi
}

require_file_provider_extension_in_app() {
  local app_path="$1"
  local appex="$app_path/Contents/PlugIns/HybridCipherFileProvider.appex"
  local appex_info="$appex/Contents/Info.plist"
  local bundle_id

  if [[ ! -d "$appex" ]]; then
    echo "File Provider extension bundle not found: $appex" >&2
    exit 1
  fi
  if [[ ! -f "$appex_info" ]]; then
    echo "File Provider extension Info.plist not found: $appex_info" >&2
    exit 1
  fi

  bundle_id="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$appex_info" 2>/dev/null || true)"
  if [[ "$bundle_id" != "com.hybridcipher.app.HybridCipherFileProvider" ]]; then
    echo "Unexpected File Provider extension bundle id: ${bundle_id:-missing}" >&2
    exit 1
  fi
}

stage_file_provider_runtime_in_app() {
  local app_path="$1"
  local version="$2"
  local file_provider_build_dir
  local staged_appex="$app_path/Contents/PlugIns/HybridCipherFileProvider.appex"
  local bundled_providerctl="$app_path/Contents/Resources/bin/providerctl-native"

  if [[ ! -x "$FILE_PROVIDER_BUILD_SCRIPT" ]]; then
    echo "File Provider build helper missing or not executable: $FILE_PROVIDER_BUILD_SCRIPT" >&2
    exit 1
  fi

  file_provider_build_dir="$(mktemp -d /tmp/hybridcipher-fileprovider.XXXXXX)"
  log "Building and staging macOS File Provider runtime"
  VERSION_OVERRIDE="$version" \
    APPLE_APPLICATION_IDENTITY="-" \
    APPLE_TEAM_ID="" \
    "$FILE_PROVIDER_BUILD_SCRIPT" "$file_provider_build_dir"

  rm -rf "$staged_appex"
  mkdir -p "$app_path/Contents/PlugIns" "$app_path/Contents/Resources/bin"
  cp -R "$file_provider_build_dir/HybridCipherFileProvider.appex" "$staged_appex"
  install -m 0755 "$file_provider_build_dir/providerctl-native" "$bundled_providerctl"

  require_file_provider_extension_in_app "$app_path"
  rm -rf "$file_provider_build_dir"
}

create_public_verify_tauri_config() {
  local config_path
  config_path="$(mktemp /tmp/hybridcipher-public-tauri.XXXXXX.json)"

  python3 - "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json" "$config_path" <<'PY'
import json
import sys

source_path = sys.argv[1]
output_path = sys.argv[2]

with open(source_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

data.setdefault("bundle", {})
data["bundle"]["createUpdaterArtifacts"] = False

with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=True)
    fh.write("\n")
PY

  echo "$config_path"
}

build_cli_for_target() {
  local target="$1"
  local -a cargo_build_cmd=(cargo build --release --bin hybridcipher --target "$target")

  if [[ "${INDIVIDUAL_EDITION:-0}" == "1" ]]; then
    cargo_build_cmd+=(--features individual-edition)
  fi

  log "Building CLI for $target" >&2
  (cd "$ROOT_DIR" && "${cargo_build_cmd[@]}")

  local cli_bin="$ROOT_DIR/target/${target}/release/hybridcipher"
  if [[ ! -x "$cli_bin" ]]; then
    echo "CLI binary missing after build: $cli_bin" >&2
    exit 1
  fi

  echo "$cli_bin"
}

stage_bundled_cli_resource() {
  local cli_bin="$1"
  local bundled_cli="$ROOT_DIR/apps/desktop/src-tauri/resources/bin/hybridcipher"

  log "Staging bundled CLI resource" >&2
  mkdir -p "$ROOT_DIR/apps/desktop/src-tauri/resources/bin"
  install -m 0755 "$cli_bin" "$bundled_cli"
  echo "$bundled_cli"
}

build_tauri_bundle_for_target() {
  local target="$1"
  local config_path="$2"
  local bundled_cli="$3"
  local -a tauri_build_cmd=(npx tauri build --target "$target" --config "$config_path")

  if [[ "${INDIVIDUAL_EDITION:-0}" == "1" ]]; then
    tauri_build_cmd+=(--features individual-edition)
  fi

  log "Building unsigned Tauri bundle for $target"
  (
    cd "$ROOT_DIR/apps/desktop"
    env "HYBRIDCIPHER_CLI_PATH=$bundled_cli" "${tauri_build_cmd[@]}"
  )
}

find_app_bundle_path() {
  local target="$1"
  local app_path
  app_path="$(find "$ROOT_DIR" -type d -path "*/${target}/release/bundle/macos/*.app" | head -1 || true)"
  if [[ -z "$app_path" ]]; then
    echo "No .app bundle found for target: $target" >&2
    exit 1
  fi
  echo "$app_path"
}

determine_build_targets() {
  BUILD_MODE="${MODE:-silicon}"
  BUILD_TARGETS=""

  case "$BUILD_MODE" in
    silicon)
      BUILD_TARGETS="aarch64-apple-darwin"
      if [[ -n "${DESKTOP_TARGETS:-}" ]]; then
        log "Ignoring DESKTOP_TARGETS because MODE is silicon"
      fi
      ;;
    full)
      BUILD_TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
      if [[ -n "${DESKTOP_TARGETS:-}" ]]; then
        log "Ignoring DESKTOP_TARGETS because MODE is full"
      fi
      ;;
    custom)
      BUILD_TARGETS="${DESKTOP_TARGETS:-}"
      if [[ -z "$BUILD_TARGETS" ]]; then
        echo "MODE=custom requires DESKTOP_TARGETS to be set" >&2
        exit 1
      fi
      ;;
    *)
      echo "Invalid MODE: $BUILD_MODE (expected: silicon, full, or custom)" >&2
      exit 1
      ;;
  esac

  log "Using MODE: $BUILD_MODE"
  log "Using targets: $BUILD_TARGETS"
}

install_desktop_frontend_dependencies() {
  log "Installing desktop frontend dependencies"
  (cd "$ROOT_DIR/apps/desktop" && npm install --prefer-offline --no-audit)
}

build_public_verify_target() {
  local target="$1"
  local cli_bin
  local bundled_cli
  local config_path
  local app_path
  local canonical_artifact
  local version

  cli_bin="$(build_cli_for_target "$target")"
  bundled_cli="$(stage_bundled_cli_resource "$cli_bin")"

  config_path="$(create_public_verify_tauri_config)"
  build_tauri_bundle_for_target "$target" "$config_path" "$bundled_cli"
  rm -f "$config_path"

  app_path="$(find_app_bundle_path "$target")"
  version="$(desktop_app_version)"
  stage_file_provider_runtime_in_app "$app_path" "$version"
  canonical_artifact="$(create_canonical_unsigned_app_archive "$target" "$app_path" "$(dirname "$app_path")")"

  ARTIFACTS+=("$canonical_artifact" "${canonical_artifact}.sha256")
}

dedupe_artifacts() {
  local uniq=()
  local item
  local seen

  for item in "${ARTIFACTS[@]+"${ARTIFACTS[@]}"}"; do
    seen=0
    for existing in "${uniq[@]+"${uniq[@]}"}"; do
      if [[ "$existing" == "$item" ]]; then
        seen=1
        break
      fi
    done
    if [[ "$seen" -eq 0 ]]; then
      uniq+=("$item")
    fi
  done

  ARTIFACTS=("${uniq[@]+"${uniq[@]}"}")
}

public_verify_main() {
  cleanup_stale_temp_files

  require_cmd cargo
  require_cmd npm
  require_cmd npx
  require_cmd xcrun
  require_cmd plutil
  require_cmd codesign
  require_cmd /usr/libexec/PlistBuddy
  require_cmd python3

  validate_desktop_version_consistency
  install_desktop_frontend_dependencies

  determine_build_targets
  for target in $BUILD_TARGETS; do
    build_public_verify_target "$target"
  done

  dedupe_artifacts

  log "Canonical unsigned artifacts built locally"
  printf '%s\n' "${ARTIFACTS[@]}"
}

public_verify_main "$@"
