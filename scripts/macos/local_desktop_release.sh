#!/usr/bin/env bash
set -euo pipefail

# HybridCipher desktop release builder/publisher for macOS.
#
# What this script does:
# - Builds HybridCipher desktop app bundles and installer packages (.pkg)
# - Signs, notarizes, staples (when signing/notary env vars are provided)
# - Optionally publishes release artifacts to a GitHub release
#
# Build modes:
# - MODE=silicon (default): builds Apple Silicon only (aarch64-apple-darwin)
# - MODE=full: builds both Apple Silicon and Intel
#   (aarch64-apple-darwin x86_64-apple-darwin)
# - MODE=custom: builds targets listed in DESKTOP_TARGETS
#
# use INDIVIDUAL_EDITION=1 ./scripts/macos/local_desktop_release.sh
# to build with individual-edition feature enabled (for testing only; not for public releases)
# Overrides:
# - DESKTOP_TARGETS is used only when MODE=custom
# - ENV_FILE can override env file path (default: scripts/macos/.env.local)
#
# Usage:
#   ./scripts/macos/local_desktop_release.sh
#   MODE=full ./scripts/macos/local_desktop_release.sh
#   MODE=custom DESKTOP_TARGETS="aarch64-apple-darwin" ./scripts/macos/local_desktop_release.sh
#   PUBLISH_PUBLIC_RELEASE=1 ./scripts/macos/local_desktop_release.sh
#
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env.local}"
FILE_PROVIDER_BUILD_SCRIPT="$SCRIPT_DIR/build_file_provider_extension.sh"
APP_ENTITLEMENTS_TEMPLATE="$ROOT_DIR/apps/desktop/src-tauri/entitlements.plist"
DEFAULT_APPLE_TEAM_ID="G2L88C9692"

ARTIFACTS=()
KEYCHAIN_PATH=""
KEYCHAIN_PASSWORD=""
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

base64_decode_to_file() {
  local output_file="$1"
  if base64 --help 2>&1 | grep -q -- "--decode"; then
    base64 --decode > "$output_file"
  else
    base64 -D > "$output_file"
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
import stat
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

load_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing env file: $ENV_FILE" >&2
    echo "Create it from .env.local template first." >&2
    exit 1
  fi

  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

load_secret_from_file_var() {
  local file_var="$1"
  local value_var="$2"
  local file_path="${!file_var:-}"

  if [[ -n "$file_path" ]]; then
    if [[ ! -f "$file_path" ]]; then
      echo "Configured file not found for $file_var: $file_path" >&2
      exit 1
    fi
    export "$value_var"="$(cat "$file_path")"
  fi
}

ensure_not_placeholder() {
  local var_name="$1"
  local value="${!var_name:-}"

  if [[ -z "$value" ]] || [[ "$value" == fake_* ]] || [[ "$value" == */ABSOLUTE/PATH/TO/* ]]; then
    echo "Variable $var_name is missing or still using placeholder value." >&2
    exit 1
  fi
}

extract_version_from_release_tag() {
  local tag="$1"
  # Accept desktop-vX.Y.Z or vX.Y.Z
  if [[ "$tag" =~ ^desktop-v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

desktop_app_version() {
  awk -F '"' '/^version = / { print $2; exit }' "$ROOT_DIR/apps/desktop/src-tauri/Cargo.toml"
}

desktop_tauri_config_version() {
  awk -F '"' '/"version"[[:space:]]*:/ { print $4; exit }' "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json"
}

sync_desktop_tauri_config_version() {
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
    log "Syncing tauri.conf.json version to Cargo.toml version ($cargo_version)"
    python3 - "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json" "$cargo_version" <<'PY'
import json, sys

path = sys.argv[1]
version = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

data["version"] = version

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=True)
    f.write("\n")
PY
  fi
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
    echo "Failed to keep versions in sync; check tauri.conf.json write permissions." >&2
    exit 1
  fi
}

set_default_release_tag_from_version() {
  local version
  version="$(desktop_app_version)"
  if [[ -z "$version" ]]; then
    echo "Failed to detect desktop version from apps/desktop/src-tauri/Cargo.toml" >&2
    exit 1
  fi

  if [[ -z "${RELEASE_TAG:-}" ]]; then
    RELEASE_TAG="desktop-v${version}"
    export RELEASE_TAG
    log "RELEASE_TAG not set; defaulting to ${RELEASE_TAG}"
  fi
}

validate_release_tag_version_alignment() {
  local version
  local tag_version
  version="$(desktop_app_version)"
  if [[ -z "$version" ]]; then
    echo "Failed to detect desktop version from apps/desktop/src-tauri/Cargo.toml" >&2
    exit 1
  fi

  if [[ -z "${RELEASE_TAG:-}" ]]; then
    return
  fi

  if ! tag_version="$(extract_version_from_release_tag "$RELEASE_TAG")"; then
    echo "RELEASE_TAG must be desktop-vX.Y.Z or vX.Y.Z. Got: $RELEASE_TAG" >&2
    exit 1
  fi

  if [[ "$tag_version" != "$version" ]]; then
    echo "Version mismatch: app is $version but RELEASE_TAG implies $tag_version" >&2
    echo "Update app version or RELEASE_TAG before publishing to avoid false updater prompts." >&2
    exit 1
  fi
}

setup_signing_keychain_if_needed() {
  if [[ -z "${APPLE_CERTIFICATE_BASE64:-}" && -n "${APPLE_CERTIFICATE_P12_FILE:-}" ]]; then
    if [[ ! -f "$APPLE_CERTIFICATE_P12_FILE" ]]; then
      echo "APPLE_CERTIFICATE_P12_FILE not found: $APPLE_CERTIFICATE_P12_FILE" >&2
      exit 1
    fi
    APPLE_CERTIFICATE_BASE64="$(base64 < "$APPLE_CERTIFICATE_P12_FILE" | tr -d '\n')"
    export APPLE_CERTIFICATE_BASE64
  fi

  if [[ -z "${APPLE_CERTIFICATE_BASE64:-}" || -z "${APPLE_CERTIFICATE_PASSWORD:-}" ]]; then
    log "Skipping certificate import (APPLE_CERTIFICATE_BASE64 and/or APPLE_CERTIFICATE_PASSWORD missing)"
    return
  fi

  ensure_not_placeholder APPLE_CERTIFICATE_BASE64
  ensure_not_placeholder APPLE_CERTIFICATE_PASSWORD

  KEYCHAIN_PATH="$(mktemp -u /tmp/hybridcipher-signing.XXXXXX.keychain-db)"
  KEYCHAIN_PASSWORD="$(openssl rand -hex 32)"

  log "Importing Apple certificate into temporary keychain"
  security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
  security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
  security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

  local cert_path
  cert_path="$(mktemp /tmp/hybridcipher-cert.XXXXXX.p12)"
  printf "%s" "$APPLE_CERTIFICATE_BASE64" | base64_decode_to_file "$cert_path"

  security import "$cert_path" \
    -P "$APPLE_CERTIFICATE_PASSWORD" \
    -A -t cert -f pkcs12 \
    -k "$KEYCHAIN_PATH"
  rm -f "$cert_path"

  security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

  security list-keychains -d user -s "$KEYCHAIN_PATH" login.keychain-db
}

cleanup_signing_keychain() {
  if [[ -n "$KEYCHAIN_PATH" ]]; then
    security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
  fi
}

cleanup_stale_temp_files() {
  log "Cleaning up stale temp files from previous runs"
  rm -f /tmp/hybridcipher-*.json 2>/dev/null || true
  rm -f /tmp/hybridcipher-*.p8 2>/dev/null || true
  rm -f /tmp/hybridcipher-*.zip 2>/dev/null || true
  rm -f /tmp/hybridcipher-*.dmg 2>/dev/null || true
  rm -f /tmp/hybridcipher-*.p12 2>/dev/null || true
  rm -f /tmp/hybridcipher-cert.*.p12 2>/dev/null || true
  rm -f /tmp/hybridcipher-signing.*.keychain-db 2>/dev/null || true
  rm -f /tmp/AuthKey_*.p8 2>/dev/null || true
  rm -rf /tmp/hybridcipher-pkg-*.* 2>/dev/null || true
  rm -f /tmp/hybridcipher-public-tauri.*.json 2>/dev/null || true
}

find_component_index() {
  local plist_path="$1"
  local bundle_identifier="$2"
  local root_relative_bundle_path="$3"
  local idx=0
  local current_bundle_identifier
  local current_root_relative_bundle_path

  while /usr/libexec/PlistBuddy -c "Print :$idx" "$plist_path" >/dev/null 2>&1; do
    current_bundle_identifier="$(/usr/libexec/PlistBuddy -c "Print :$idx:BundleIdentifier" "$plist_path" 2>/dev/null || true)"
    current_root_relative_bundle_path="$(/usr/libexec/PlistBuddy -c "Print :$idx:RootRelativeBundlePath" "$plist_path" 2>/dev/null || true)"
    if [[ "$current_bundle_identifier" == "$bundle_identifier" ]]; then
      echo "$idx"
      return 0
    fi
    if [[ "$current_root_relative_bundle_path" == "$root_relative_bundle_path" ]]; then
      echo "$idx"
      return 0
    fi
    idx=$((idx + 1))
  done

  return 1
}

upsert_component_key() {
  local plist_path="$1"
  local component_index="$2"
  local key="$3"
  local value_type="$4"
  local value="$5"
  local key_path=":${component_index}:${key}"

  if /usr/libexec/PlistBuddy -c "Print $key_path" "$plist_path" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set $key_path $value" "$plist_path"
  else
    /usr/libexec/PlistBuddy -c "Add $key_path $value_type $value" "$plist_path"
  fi
}

require_file_provider_extension_in_app() {
  local app_path="$1"
  local appex="$app_path/Contents/PlugIns/HybridCipherFileProvider.appex"
  local appex_info="$appex/Contents/Info.plist"
  local bundle_id

  if [[ ! -d "$appex" ]]; then
    echo "File Provider extension bundle not found: $appex" >&2
    echo "Build/package output is missing HybridCipherFileProvider.appex; refusing to publish an app that will fall back to sync mounts." >&2
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

generate_desktop_app_entitlements() {
  local output_path="$1"
  local team_id="$2"
  local team_prefix=""

  if [[ -n "$team_id" ]]; then
    team_prefix="${team_id}."
  fi

  sed \
    -e "s/\$(TeamIdentifierPrefix)/$team_prefix/g" \
    -e "s/\$(AppIdentifierPrefix)/$team_prefix/g" \
    "$APP_ENTITLEMENTS_TEMPLATE" > "$output_path"
  plutil -lint "$output_path" >/dev/null
}

stage_file_provider_runtime_in_app() {
  local app_path="$1"
  local signing_identity="$2"
  local team_id="$3"
  local version="$4"
  local file_provider_build_dir
  local staged_appex="$app_path/Contents/PlugIns/HybridCipherFileProvider.appex"
  local bundled_providerctl="$app_path/Contents/Resources/bin/providerctl-native"

  file_provider_build_dir="$(mktemp -d /tmp/hybridcipher-fileprovider.XXXXXX)"
  log "Building and staging macOS File Provider runtime"
  VERSION_OVERRIDE="$version" \
    APPLE_APPLICATION_IDENTITY="$signing_identity" \
    APPLE_TEAM_ID="$team_id" \
    "$FILE_PROVIDER_BUILD_SCRIPT" "$file_provider_build_dir"

  rm -rf "$staged_appex"
  mkdir -p "$app_path/Contents/PlugIns" "$app_path/Contents/Resources/bin"
  cp -R "$file_provider_build_dir/HybridCipherFileProvider.appex" "$staged_appex"
  install -m 0755 "$file_provider_build_dir/providerctl-native" "$bundled_providerctl"

  if [[ "$signing_identity" != "-" ]]; then
    local app_entitlements="$file_provider_build_dir/HybridCipherApp.entitlements"
    generate_desktop_app_entitlements "$app_entitlements" "$team_id"
    log "Re-signing app bundle after staging File Provider runtime"
    codesign --force \
      --sign "$signing_identity" \
      --entitlements "$app_entitlements" \
      --timestamp \
      --options runtime \
      "$app_path"
  fi

  require_file_provider_extension_in_app "$app_path"
  rm -rf "$file_provider_build_dir"
}

should_notarize() {
  [[ -n "${APPLE_API_KEY:-}" ]] && [[ -n "${APPLE_API_KEY_ID:-}" ]] && [[ -n "${APPLE_API_ISSUER:-}" ]]
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

sign_staged_bundled_cli() {
  local bundled_cli="$1"

  log "Signing bundled CLI with Developer ID"
  codesign --sign "$APPLE_SIGNING_IDENTITY" \
    --options runtime \
    --timestamp \
    --force \
    "$bundled_cli"
}

build_tauri_bundle_for_target() {
  local target="$1"
  local mode="${2:-signed}"
  local config_path="${3:-}"
  local bundled_cli_override="${4:-}"
  local -a tauri_build_cmd=(npx tauri build --target "$target")
  local -a tauri_env=()

  if [[ "${INDIVIDUAL_EDITION:-0}" == "1" ]]; then
    tauri_build_cmd+=(--features individual-edition)
  fi

  if [[ -n "$config_path" ]]; then
    tauri_build_cmd+=(--config "$config_path")
  fi

  if [[ -n "$bundled_cli_override" ]]; then
    tauri_env+=("HYBRIDCIPHER_CLI_PATH=$bundled_cli_override")
  fi

  if [[ "$mode" == "signed" ]]; then
    log "Building Tauri bundle for $target"
    (
      cd "$ROOT_DIR/apps/desktop"
      env \
        "TAURI_SIGNING_PRIVATE_KEY=$TAURI_SIGNING_PRIVATE_KEY" \
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD=$TAURI_SIGNING_PRIVATE_KEY_PASSWORD" \
        "APPLE_SIGNING_IDENTITY=$APPLE_SIGNING_IDENTITY" \
        "${tauri_env[@]}" \
        "${tauri_build_cmd[@]}"
    )
    return
  fi

  log "Building unsigned Tauri bundle for $target"
  (
    cd "$ROOT_DIR/apps/desktop"
    env "${tauri_env[@]}" "${tauri_build_cmd[@]}"
  )
}

extract_notary_json_value() {
  local json_path="$1"
  local key="$2"

  python3 - "$json_path" "$key" <<'PY'
import json
import sys

path = sys.argv[1]
key = sys.argv[2]

with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

value = data.get(key, "")
if isinstance(value, str):
    print(value)
PY
}

ensure_notary_submission_accepted() {
  local submit_json="$1"
  shift
  local -a auth_args=("$@")
  local notary_status
  local notary_id

  notary_status="$(extract_notary_json_value "$submit_json" "status" 2>/dev/null || true)"
  notary_id="$(extract_notary_json_value "$submit_json" "id" 2>/dev/null || true)"

  if [[ "$notary_status" == "Accepted" ]]; then
    return 0
  fi

  echo "Notarization failed with status: ${notary_status:-unknown}" >&2
  if [[ -n "$notary_id" ]]; then
    echo "Retrieving notarization log for submission id: $notary_id" >&2
    xcrun notarytool log "${auth_args[@]}" "$notary_id" || true
  fi
  exit 1
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

  if [[ -z "$BUILD_TARGETS" ]]; then
    echo "Unable to determine build targets" >&2
    exit 1
  fi

  log "Using MODE: $BUILD_MODE"
  log "Using targets: $BUILD_TARGETS"
}

install_desktop_frontend_dependencies() {
  log "Installing desktop frontend dependencies"
  (cd "$ROOT_DIR/apps/desktop" && npm install --prefer-offline --no-audit)
}

notarize_app_bundle() {
  local target="$1"
  local app_path="$2"

  if ! should_notarize; then
    log "Skipping app notarization for $target (APPLE_API_KEY, APPLE_API_KEY_ID, APPLE_API_ISSUER required)"
    return
  fi

  ensure_not_placeholder APPLE_API_KEY
  ensure_not_placeholder APPLE_API_KEY_ID
  ensure_not_placeholder APPLE_API_ISSUER

  local api_key_path
  local zip_path
  local submit_json

  api_key_path="$(mktemp /tmp/AuthKey_${APPLE_API_KEY_ID}.XXXXXX.p8)"
  zip_path="$(mktemp /tmp/hybridcipher-notarize-app.XXXXXX.zip)"
  submit_json="$(mktemp /tmp/hybridcipher-notary-app.XXXXXX.json)"

  printf "%s" "$APPLE_API_KEY" > "$api_key_path"

  log "Submitting app for notarization ($target)"
  ditto -c -k --sequesterRsrc --keepParent "$app_path" "$zip_path"
  xcrun notarytool submit "$zip_path" \
    --key "$api_key_path" \
    --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER" \
    --wait --timeout 45m \
    --output-format json > "$submit_json"
  cat "$submit_json"
  ensure_notary_submission_accepted \
    "$submit_json" \
    --key "$api_key_path" \
    --key-id "$APPLE_API_KEY_ID" \
    --issuer "$APPLE_API_ISSUER"

  local staple_ok=0
  for attempt in 1 2 3 4 5 6; do
    if xcrun stapler staple -v "$app_path"; then
      staple_ok=1
      break
    fi
    echo "App stapler attempt ${attempt} failed; retrying in 60 seconds..."
    sleep 60
  done

  if [[ "$staple_ok" -eq 1 ]]; then
    xcrun stapler validate -v "$app_path"
  else
    echo "WARNING: App stapler failed after retries; continuing with notarized app" >&2
  fi

  local dmg_path
  dmg_path="$(find "$ROOT_DIR" -type f -path "*/${target}/release/bundle/dmg/*.dmg" | head -1 || true)"
  if [[ -n "$dmg_path" ]]; then
    local temp_dmg
    temp_dmg="$(mktemp /tmp/hybridcipher-dmg.XXXXXX.dmg)"
    hdiutil create -volname "HybridCipher" -srcfolder "$app_path" -ov -format UDZO "$temp_dmg"
    mv "$temp_dmg" "$dmg_path"
  fi

  rm -f "$api_key_path" "$zip_path" "$submit_json"
}

build_pkg_installer() {
  local target="$1"
  local app_path="$2"

  local version
  version="$(desktop_app_version)"
  if [[ -z "$version" ]]; then
    echo "Failed to detect desktop version" >&2
    exit 1
  fi

  local pkg_work
  local pkg_root
  local pkg_scripts
  local pkg_unsigned
  local component_plist
  local bundle_dir
  local pkg_out_dir
  local pkg_final

  pkg_work="$(mktemp -d /tmp/hybridcipher-pkg-${target}.XXXXXX)"
  pkg_root="$pkg_work/root"
  pkg_scripts="$pkg_work/scripts"
  pkg_unsigned="$pkg_work/HybridCipher-${target}-${version}-unsigned.pkg"
  component_plist="$pkg_work/component.plist"
  bundle_dir="$(cd "$(dirname "$app_path")/.." && pwd)"
  pkg_out_dir="$bundle_dir/pkg"
  pkg_final="$pkg_out_dir/HybridCipher-${target}-${version}.pkg"

  mkdir -p "$pkg_root/Applications" "$pkg_scripts" "$pkg_out_dir"
  cp -R "$app_path" "$pkg_root/Applications/HybridCipher.app"

  cat > "$pkg_scripts/postinstall" << 'POSTINSTALL'
#!/bin/sh
set -u

TARGET=""
TARGET_ROOT="${3:-}"
for CANDIDATE in \
  "${TARGET_ROOT}/Applications/HybridCipher.app/Contents/Resources/bin/hybridcipher" \
  "${TARGET_ROOT}/Applications/HybridCipher.app/Contents/Resources/resources/bin/hybridcipher" \
  "/Applications/HybridCipher.app/Contents/Resources/bin/hybridcipher" \
  "/Applications/HybridCipher.app/Contents/Resources/resources/bin/hybridcipher"; do
  if [ -x "$CANDIDATE" ]; then
    TARGET="$CANDIDATE"
    break
  fi
done

if [ -z "$TARGET" ]; then
  echo "WARNING: HybridCipher bundled CLI not found in app resources; skipping global symlink setup" >&2
  exit 0
fi

if ! mkdir -p "/usr/local/bin"; then
  echo "WARNING: Failed to create /usr/local/bin; skipping global symlink setup" >&2
  exit 0
fi

if ! ln -sfn "$TARGET" "/usr/local/bin/hybridcipher"; then
  echo "WARNING: Failed to set /usr/local/bin/hybridcipher symlink; app install will continue" >&2
fi

FILE_PROVIDER=""
for CANDIDATE in \
  "${TARGET_ROOT}/Applications/HybridCipher.app/Contents/PlugIns/HybridCipherFileProvider.appex" \
  "/Applications/HybridCipher.app/Contents/PlugIns/HybridCipherFileProvider.appex"; do
  if [ -d "$CANDIDATE" ]; then
    FILE_PROVIDER="$CANDIDATE"
    break
  fi
done

if [ -n "$FILE_PROVIDER" ]; then
  /usr/bin/pluginkit -a "$FILE_PROVIDER" >/dev/null 2>&1 || true
else
  echo "WARNING: HybridCipher File Provider extension not found after install; File Provider mounts may fall back to sync" >&2
fi

exit 0
POSTINSTALL
  chmod 0755 "$pkg_scripts/postinstall"

  pkgbuild --analyze --root "$pkg_root" "$component_plist"
  local app_bundle_identifier
  local app_component_index
  app_bundle_identifier="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$pkg_root/Applications/HybridCipher.app/Contents/Info.plist" 2>/dev/null || true)"
  if [[ -z "$app_bundle_identifier" ]]; then
    echo "Failed to read CFBundleIdentifier from staged app bundle" >&2
    exit 1
  fi
  if ! app_component_index="$(find_component_index "$component_plist" "$app_bundle_identifier" "Applications/HybridCipher.app")"; then
    echo "Failed to locate app component in pkg component plist" >&2
    exit 1
  fi
  upsert_component_key "$component_plist" "$app_component_index" "BundleIsRelocatable" "bool" "false"
  upsert_component_key "$component_plist" "$app_component_index" "BundleHasStrictIdentifier" "bool" "true"
  upsert_component_key "$component_plist" "$app_component_index" "BundleOverwriteAction" "string" "upgrade"

  pkgbuild \
    --root "$pkg_root" \
    --component-plist "$component_plist" \
    --scripts "$pkg_scripts" \
    --identifier "com.hybridcipher.app.installer" \
    --version "$version" \
    --install-location "/" \
    "$pkg_unsigned"

  if [[ -n "${APPLE_INSTALLER_IDENTITY:-}" ]]; then
    ensure_not_placeholder APPLE_INSTALLER_IDENTITY
    productsign --sign "$APPLE_INSTALLER_IDENTITY" "$pkg_unsigned" "$pkg_final"
  else
    echo "WARNING: APPLE_INSTALLER_IDENTITY is not set; publishing unsigned pkg"
    cp "$pkg_unsigned" "$pkg_final"
  fi

  if [[ -n "${APPLE_INSTALLER_IDENTITY:-}" ]]; then
    pkgutil --check-signature "$pkg_final"
  fi

  if [[ -n "${APPLE_INSTALLER_IDENTITY:-}" ]] && should_notarize; then
    local api_key_path
    local submit_json

    api_key_path="$(mktemp /tmp/AuthKey_${APPLE_API_KEY_ID}.XXXXXX.p8)"
    submit_json="$(mktemp /tmp/hybridcipher-notary-pkg.XXXXXX.json)"
    printf "%s" "$APPLE_API_KEY" > "$api_key_path"

    xcrun notarytool submit "$pkg_final" \
      --key "$api_key_path" \
      --key-id "$APPLE_API_KEY_ID" \
      --issuer "$APPLE_API_ISSUER" \
      --wait --timeout 45m \
      --output-format json > "$submit_json"
    cat "$submit_json"
    ensure_notary_submission_accepted \
      "$submit_json" \
      --key "$api_key_path" \
      --key-id "$APPLE_API_KEY_ID" \
      --issuer "$APPLE_API_ISSUER"

    local staple_ok=0
    for attempt in 1 2 3 4 5 6; do
      if xcrun stapler staple -v "$pkg_final"; then
        staple_ok=1
        break
      fi
      echo "PKG stapler attempt ${attempt} failed; retrying in 60 seconds..."
      sleep 60
    done

    if [[ "$staple_ok" -eq 1 ]]; then
      xcrun stapler validate -v "$pkg_final"
      spctl -a -vv -t install "$pkg_final"
    else
      echo "WARNING: PKG stapler failed after retries; continuing with notarized pkg"
    fi

    rm -f "$api_key_path" "$submit_json"
  else
    log "Skipping pkg notarization for $target"
  fi

  ARTIFACTS+=("$pkg_final")
  rm -rf "$pkg_work"
}

collect_target_artifacts() {
  local target="$1"
  local found=()
  local arch_suffix
  arch_suffix="${target%%-*}"  # extracts 'aarch64' or 'x86_64'

  # Collect only:
  # - .pkg files (for installation)
  # - arch-specific .app.tar.gz and .sig files (for auto-updater)
  # Skip: .dmg files and non-arch-specific tarballs
  while IFS= read -r item; do
    local basename="${item##*/}"
    # Skip .dmg files
    [[ "$basename" == *.dmg ]] && continue
    # For .app.tar.gz files, only include arch-specific ones (e.g., HybridCipher_aarch64.app.tar.gz)
    if [[ "$basename" == *.app.tar.gz ]] || [[ "$basename" == *.app.tar.gz.sig ]]; then
      [[ "$basename" != *"_${arch_suffix}"* ]] && continue
    fi
    found+=("$item")
  done < <(find "$ROOT_DIR" -type f \
    \( -name "*.app.tar.gz" -o -name "*.app.tar.gz.sig" -o -name "*.pkg" \) \
    -path "*/${target}/release/bundle/*")

  if [[ "${#found[@]}" -eq 0 ]]; then
    echo "No build artifacts found for target $target" >&2
    exit 1
  fi

  ARTIFACTS+=("${found[@]}")
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

publish_artifacts() {
  if [[ "${PUBLISH_PUBLIC_RELEASE:-0}" != "1" ]]; then
    log "Publishing disabled (PUBLISH_PUBLIC_RELEASE=0). Build artifacts are ready locally."
    return
  fi

  require_cmd gh

  ensure_not_placeholder GH_TOKEN
  ensure_not_placeholder RELEASE_TAG
  ensure_not_placeholder PUBLIC_RELEASE_REPO

  local release_title
  release_title="${RELEASE_NAME:-HybridCipher Desktop ${RELEASE_TAG}}"

  log "Preparing release ${RELEASE_TAG} in ${PUBLIC_RELEASE_REPO}"
  if ! gh release view "$RELEASE_TAG" --repo "$PUBLIC_RELEASE_REPO" >/dev/null 2>&1; then
    if [[ -n "${RELEASE_NOTES_FILE:-}" && -f "${RELEASE_NOTES_FILE}" ]]; then
      gh release create "$RELEASE_TAG" \
        --repo "$PUBLIC_RELEASE_REPO" \
        --title "$release_title" \
        --notes-file "$RELEASE_NOTES_FILE"
    else
      gh release create "$RELEASE_TAG" \
        --repo "$PUBLIC_RELEASE_REPO" \
        --title "$release_title" \
        --notes "Local desktop release upload"
    fi
  fi

  log "Uploading artifacts to ${PUBLIC_RELEASE_REPO}:${RELEASE_TAG}"
  gh release upload "$RELEASE_TAG" "${ARTIFACTS[@]}" --repo "$PUBLIC_RELEASE_REPO" --clobber
}

build_target() {
  local target="$1"
  local cli_bin
  local bundled_cli
  local app_path
  local version

  cli_bin="$(build_cli_for_target "$target")"
  bundled_cli="$(stage_bundled_cli_resource "$cli_bin")"
  sign_staged_bundled_cli "$bundled_cli"
  build_tauri_bundle_for_target "$target" "signed" "" "$bundled_cli"

  app_path="$(find_app_bundle_path "$target")"
  version="$(desktop_app_version)"
  stage_file_provider_runtime_in_app \
    "$app_path" \
    "$APPLE_SIGNING_IDENTITY" \
    "${APPLE_TEAM_ID:-$DEFAULT_APPLE_TEAM_ID}" \
    "$version"
  require_file_provider_extension_in_app "$app_path"

  notarize_app_bundle "$target" "$app_path"
  build_pkg_installer "$target" "$app_path"

  # Rename .app.tar.gz files to include architecture for unique asset names
  local arch_suffix
  arch_suffix="${target%%-*}"  # extracts 'aarch64' or 'x86_64'
  local bundle_macos_dir="$ROOT_DIR/target/${target}/release/bundle/macos"
  for tarball in "$bundle_macos_dir"/HybridCipher.app.tar.gz*; do
    if [[ -f "$tarball" ]]; then
      local basename="${tarball##*/}"
      local newname="${basename/HybridCipher.app/HybridCipher_${arch_suffix}.app}"
      mv "$tarball" "$bundle_macos_dir/$newname"
    fi
  done

  collect_target_artifacts "$target"
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
  build_tauri_bundle_for_target "$target" "unsigned" "$config_path" "$bundled_cli"
  rm -f "$config_path"

  app_path="$(find_app_bundle_path "$target")"
  version="$(desktop_app_version)"
  stage_file_provider_runtime_in_app "$app_path" "-" "" "$version"
  require_file_provider_extension_in_app "$app_path"
  canonical_artifact="$(create_canonical_unsigned_app_archive "$target" "$app_path" "$(dirname "$app_path")")"

  ARTIFACTS+=("$canonical_artifact" "${canonical_artifact}.sha256")
}

main() {
  trap cleanup_signing_keychain EXIT

  cleanup_stale_temp_files

  require_cmd cargo
  require_cmd npm
  require_cmd npx
  require_cmd xcrun
  require_cmd pkgbuild
  require_cmd hdiutil
  require_cmd productsign
  require_cmd pkgutil
  require_cmd spctl

  load_env_file

  load_secret_from_file_var TAURI_SIGNING_PRIVATE_KEY_FILE TAURI_SIGNING_PRIVATE_KEY
  load_secret_from_file_var APPLE_API_KEY_FILE APPLE_API_KEY

  ensure_not_placeholder TAURI_SIGNING_PRIVATE_KEY
  ensure_not_placeholder TAURI_SIGNING_PRIVATE_KEY_PASSWORD
  ensure_not_placeholder APPLE_SIGNING_IDENTITY

  if [[ -z "${PUBLIC_RELEASE_REPO:-}" ]]; then
    PUBLIC_RELEASE_REPO="HybridCipher/desktop-releases"
  fi

  sync_desktop_tauri_config_version
  validate_desktop_version_consistency

  if [[ "${PUBLISH_PUBLIC_RELEASE:-0}" == "1" ]]; then
    set_default_release_tag_from_version
    validate_release_tag_version_alignment
  fi

  setup_signing_keychain_if_needed

  install_desktop_frontend_dependencies

  determine_build_targets
  for target in $BUILD_TARGETS; do
    build_target "$target"
  done

  dedupe_artifacts

  log "Artifacts built locally"
  printf '%s\n' "${ARTIFACTS[@]}"

  publish_artifacts

  log "Done"
}

public_verify_main() {
  cleanup_stale_temp_files

  require_cmd cargo
  require_cmd npm
  require_cmd npx
  require_cmd xcrun

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

if [[ "${HYBRIDCIPHER_DESKTOP_RELEASE_SOURCE_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
