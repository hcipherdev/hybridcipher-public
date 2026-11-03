#!/usr/bin/env bash
set -euo pipefail

# Purpose: Shared macOS desktop build and File Provider validation routines used
# by public verification builds, signed releases, and local package builds.
#
# This file is exported to the public source repository. It never loads the
# release env file, signing credentials, notarization keys, or publish settings;
# those live only in the private scripts/macos/desktop_release_pkg.sh.
#
# Usage:
#   ./scripts/macos/desktop_build_common.sh --public-verify
#       Build canonical unsigned Apple Silicon artifacts and SHA-256 files.
#   MODE=full ./scripts/macos/desktop_build_common.sh --public-verify
#       Build canonical unsigned Apple Silicon and Intel artifacts.
#   MODE=custom DESKTOP_TARGETS="aarch64-apple-darwin" ./scripts/macos/desktop_build_common.sh --public-verify
#       Build canonical unsigned artifacts for the listed targets.
#   ./scripts/macos/desktop_build_common.sh --build-file-provider [OUTPUT_DIR]
#       Build the File Provider extension and providerctl helper (ad-hoc signed
#       unless APPLE_APPLICATION_IDENTITY and APPLE_TEAM_ID are set).
#   ./scripts/macos/desktop_build_common.sh --validate-file-provider
#       Validate File Provider sources and entitlements.
#   ./scripts/macos/desktop_build_common.sh --validate-file-provider /path/to/HybridCipher.app
#       Also validate a built app bundle's staged extension and signatures.
#   source scripts/macos/desktop_build_common.sh
#       Load the routines without running a command.
#
# VERSION_OVERRIDE may only forward the canonical macOS version.
# HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS defaults to the published list in
# apps/desktop/team-verification-keys.txt; use that list to reproduce the
# published verification hashes.

DESKTOP_BUILD_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DESKTOP_BUILD_COMMON_DIR/../.." && pwd)"
source "$DESKTOP_BUILD_COMMON_DIR/app_version.sh"
APP_ENTITLEMENTS_TEMPLATE="$ROOT_DIR/apps/desktop/src-tauri/entitlements.plist"
RELEASE_NOTES_PATH="$ROOT_DIR/apps/desktop/release-notes/releases.macos.json"
TEAM_VERIFICATION_KEYS_FILE="$ROOT_DIR/apps/desktop/team-verification-keys.txt"

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

published_team_verification_keys() {
  [[ -f "$TEAM_VERIFICATION_KEYS_FILE" ]] || return 0
  awk '{ gsub(/[[:space:]]/, "") }
    $0 != "" && substr($0, 1, 1) != "#" { out = out (out == "" ? "" : ",") $0 }
    END { print out }' "$TEAM_VERIFICATION_KEYS_FILE"
}

check_team_verification_keys() {
  local published
  published="$(published_team_verification_keys)"

  if [[ -z "${HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS:-}" && -n "$published" ]]; then
    export HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS="$published"
    echo "Using published Team verification keys from apps/desktop/team-verification-keys.txt" >&2
  elif [[ -n "${HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS:-}" && -n "$published" \
    && "$HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS" != "$published" ]]; then
    echo "WARNING: HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS differs from apps/desktop/team-verification-keys.txt; this build will not match the published verification hashes." >&2
  fi

  if [[ -n "${HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS:-}" ]]; then
    return 0
  fi

  case "${ALLOW_MISSING_TEAM_KEY:-0}" in
    1|true)
      echo "WARNING: Building without Team verification keys. Personal folders remain available; Team activation and writes are unavailable." >&2
      ;;
    *)
      echo "Set HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS or restore apps/desktop/team-verification-keys.txt before building, or explicitly set ALLOW_MISSING_TEAM_KEY=1 for a temporary build without Team access." >&2
      return 1
      ;;
  esac
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

desktop_app_version() {
  macos_app_version
}

pinned_rust_toolchain_matches() {
  local toolchain_file="$ROOT_DIR/rust-toolchain.toml"
  local pinned
  local active

  [[ -f "$toolchain_file" ]] || return 0
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is not installed, so rust-toolchain.toml is ignored. Install rustup; other compilers produce binaries that do not match the published verification hashes." >&2
    return 1
  fi
  pinned="$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$toolchain_file")"
  active="$(cd "$ROOT_DIR" && rustc --version 2>/dev/null | awk '{print $2}')"
  if [[ -n "$pinned" && "$active" != "$pinned" ]]; then
    echo "rustc ${active:-is missing} but rust-toolchain.toml pins $pinned. Use rustup so the pinned toolchain is selected; other compilers produce binaries that do not match the published verification hashes." >&2
    return 1
  fi
}

cleanup_stale_build_temp_files() {
  log "Cleaning up stale temp files from previous runs"
  rm -f /tmp/hybridcipher-public-tauri.*.json 2>/dev/null || true
  rm -f "$ROOT_DIR/apps/desktop/src-tauri"/tauri.macos-public.*.json 2>/dev/null || true
}

warn_if_release_notes_missing() {
  local version="$1"
  local path="$2"

  python3 - "$version" "$path" <<'PY'
import json
import sys

version, path = sys.argv[1:]
try:
    with open(path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    releases = document.get("releases")
    if not isinstance(releases, list):
        raise ValueError("the document must contain a releases array")
    if not any(isinstance(entry, dict) and entry.get("version") == version for entry in releases):
        print(
            f"WARNING: No release notes were found for version {version} in '{path}'. "
            "Add a matching macOS release entry; the build will continue.",
            file=sys.stderr,
        )
except Exception as error:
    print(
        f"WARNING: Could not check macOS release notes for version {version} in '{path}': "
        f"{error}. Add or repair the matching release entry; the build will continue.",
        file=sys.stderr,
    )
PY
}

# Shared by signed releases, public verification, and local package builds.
codesign_file_provider_artifact() {
  local target="$1"
  local identity="$2"
  local entitlements="$3"
  local -a args=(--force --sign "$identity" --entitlements "$entitlements")
  if [[ "$identity" != "-" ]]; then
    args+=(--timestamp --options runtime)
  fi
  codesign "${args[@]}" "$target"
}

build_file_provider_runtime() {
  local PROVIDER_ROOT="$ROOT_DIR/apps/desktop/macos-fileprovider"
  local EXTENSION_ROOT="$PROVIDER_ROOT/HybridCipherFileProvider"
  local OUTPUT_DIR="${1:-$ROOT_DIR/dist/macos/fileprovider-build}"
  local APPEX="$OUTPUT_DIR/HybridCipherFileProvider.appex"
  local APPEX_CONTENTS="$APPEX/Contents"
  local APPEX_MACOS="$APPEX_CONTENTS/MacOS"
  local MODULE_NAME="HybridCipherFileProvider"
  local EXECUTABLE_NAME="HybridCipherFileProvider"
  local PROVIDERCTL="$OUTPUT_DIR/providerctl-native"
  local INFO_PLIST="$APPEX_CONTENTS/Info.plist"
  local ENTITLEMENTS="$OUTPUT_DIR/HybridCipherFileProvider.entitlements"
  local PROVIDERCTL_ENTITLEMENTS="$OUTPUT_DIR/ProviderCtl.entitlements"
  local MODULE_CACHE="$OUTPUT_DIR/module-cache"

  require_cmd xcrun
  require_cmd plutil
  require_cmd codesign
  require_cmd /usr/libexec/PlistBuddy
  require_cmd python3

  local version
  version="$(macos_app_version)" || return 1
  if [[ -z "$version" ]]; then
    echo "Failed to detect desktop app version." >&2
    exit 1
  fi

  validate_file_provider_source

  rm -rf "$OUTPUT_DIR"
  mkdir -p "$APPEX_MACOS" "$MODULE_CACHE"

  local team_prefix=""
  if [[ -n "${APPLE_TEAM_ID:-}" ]]; then
    team_prefix="${APPLE_TEAM_ID}."
  fi

  sed "s/\$(TeamIdentifierPrefix)/$team_prefix/g" \
    "$EXTENSION_ROOT/Info.plist" >"$INFO_PLIST"
  /usr/libexec/PlistBuddy -c "Set :CFBundleDevelopmentRegion en" "$INFO_PLIST"
  /usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $EXECUTABLE_NAME" "$INFO_PLIST"
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$INFO_PLIST"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" "$INFO_PLIST"
  /usr/libexec/PlistBuddy -c "Set :NSExtension:NSExtensionPrincipalClass $MODULE_NAME.HybridCipherFileProviderExtension" "$INFO_PLIST"
  plutil -lint "$INFO_PLIST" >/dev/null

  sed "s/\$(TeamIdentifierPrefix)/$team_prefix/g" \
    "$EXTENSION_ROOT/HybridCipherFileProvider.entitlements" >"$ENTITLEMENTS"
  plutil -lint "$ENTITLEMENTS" >/dev/null
  sed "s/\$(TeamIdentifierPrefix)/$team_prefix/g" \
    "$PROVIDER_ROOT/ProviderCtl/ProviderCtl.entitlements" >"$PROVIDERCTL_ENTITLEMENTS"
  plutil -lint "$PROVIDERCTL_ENTITLEMENTS" >/dev/null

  local -a swift_sources=("$EXTENSION_ROOT"/Sources/*.swift)
  local extension_main_obj="$OUTPUT_DIR/ExtensionMain.o"
  xcrun clang \
    -fobjc-arc \
    -fmodules \
    -fmodules-cache-path="$MODULE_CACHE/clang" \
    -c "$EXTENSION_ROOT/Sources/ExtensionMain.m" \
    -o "$extension_main_obj"

  xcrun swiftc \
    -O \
    -application-extension \
    -module-name "$MODULE_NAME" \
    "${swift_sources[@]}" \
    "$extension_main_obj" \
    -module-cache-path "$MODULE_CACHE" \
    -Xcc -fmodules-cache-path="$MODULE_CACHE/clang" \
    -o "$APPEX_MACOS/$EXECUTABLE_NAME"

  xcrun swiftc \
    -O \
    "$PROVIDER_ROOT/ProviderCtl/main.swift" \
    -module-cache-path "$MODULE_CACHE" \
    -Xcc -fmodules-cache-path="$MODULE_CACHE/clang" \
    -o "$PROVIDERCTL"

  codesign_file_provider_artifact "$APPEX" "${APPLE_APPLICATION_IDENTITY:--}" "$ENTITLEMENTS"
  codesign_file_provider_artifact "$PROVIDERCTL" "${APPLE_APPLICATION_IDENTITY:--}" "$PROVIDERCTL_ENTITLEMENTS"

  echo "Built File Provider extension: $APPEX"
  echo "Built provider control helper: $PROVIDERCTL"
}

file_provider_require_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "Missing required file: $file" >&2
    exit 1
  fi
}

file_provider_require_executable() {
  local file="$1"
  if [[ ! -x "$file" ]]; then
    echo "Missing required executable: $file" >&2
    exit 1
  fi
}

file_provider_require_text() {
  local file="$1"
  local text="$2"
  if ! grep -Fq "$text" "$file"; then
    echo "Expected '$text' in $file" >&2
    exit 1
  fi
}

file_provider_require_plist_bool_true() {
  local file="$1"
  local key="$2"
  local value
  if ! value="$(/usr/libexec/PlistBuddy -c "Print $key" "$file" 2>/dev/null)"; then
    echo "Expected plist key $key in $file" >&2
    exit 1
  fi
  if [[ "$value" != "true" ]]; then
    echo "Expected plist key $key to be true in $file; got $value" >&2
    exit 1
  fi
}

file_provider_require_no_unexpanded_placeholders() {
  local label="$1"
  local content="$2"
  if grep -Fq "\$(" <<<"$content"; then
    echo "$label contains unexpanded entitlement placeholders." >&2
    exit 1
  fi
}

file_provider_validate_providerctl_command_support() {
  local providerctl="$1"
  local status_output
  status_output="$("$providerctl" status 2>&1)"
  python3 - "$status_output" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
if payload.get("ok") is not True:
    raise SystemExit("providerctl-native status returned ok=false")
PY

  local command
  for command in register unregister signal; do
    local output
    if output="$("$providerctl" "$command" 2>&1)"; then
      echo "providerctl-native $command without required options unexpectedly succeeded." >&2
      exit 1
    fi
    if grep -Fq "registration must run inside HybridCipher.app" <<<"$output"; then
      echo "providerctl-native $command is still the packaging-only stub: $output" >&2
      exit 1
    fi
    if ! grep -Fq "missing required option: --domain-id" <<<"$output"; then
      echo "providerctl-native $command did not expose command-specific argument validation: $output" >&2
      exit 1
    fi
  done
}

file_provider_validate_plist() {
  local file="$1"
  plutil -lint "$file" >/dev/null
}

validate_file_provider_source() {
  local PROVIDER_DIR="$ROOT_DIR/apps/desktop/macos-fileprovider/HybridCipherFileProvider"
  local PROVIDERCTL_ENTITLEMENTS="$ROOT_DIR/apps/desktop/macos-fileprovider/ProviderCtl/ProviderCtl.entitlements"
  local APP_ENTITLEMENTS="$ROOT_DIR/apps/desktop/src-tauri/entitlements.plist"
  local EXTENSION_ENTITLEMENTS="$PROVIDER_DIR/HybridCipherFileProvider.entitlements"
  local EXTENSION_INFO="$PROVIDER_DIR/Info.plist"
  local EXTENSION_BUNDLE_ID="com.hybridcipher.app.HybridCipherFileProvider"
  local APP_GROUP="group.com.hybridcipher.macOS"
  local TEAM_PREFIX_PLACEHOLDER="\$(TeamIdentifierPrefix)"

  file_provider_require_file "$APP_ENTITLEMENTS"
  file_provider_require_file "$EXTENSION_ENTITLEMENTS"
  file_provider_require_file "$PROVIDERCTL_ENTITLEMENTS"
  file_provider_require_file "$EXTENSION_INFO"
  file_provider_require_file "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/ProviderAppGroup.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/ProviderErrorMapping.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/ProviderModels.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/ProviderWritebackStager.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/FileProviderEnumerator.swift"
  file_provider_require_file "$PROVIDER_DIR/Sources/FileProviderItem.swift"

  file_provider_validate_plist "$APP_ENTITLEMENTS"
  file_provider_validate_plist "$EXTENSION_ENTITLEMENTS"
  file_provider_validate_plist "$PROVIDERCTL_ENTITLEMENTS"
  file_provider_validate_plist "$EXTENSION_INFO"

  file_provider_require_text "$APP_ENTITLEMENTS" "$APP_GROUP"
  file_provider_require_text "$EXTENSION_ENTITLEMENTS" "$APP_GROUP"
  file_provider_require_text "$PROVIDERCTL_ENTITLEMENTS" "$APP_GROUP"
  file_provider_require_text "$EXTENSION_ENTITLEMENTS" "com.apple.security.network.client"
  file_provider_require_text "$EXTENSION_INFO" "$EXTENSION_BUNDLE_ID"
  file_provider_require_text "$EXTENSION_INFO" "com.apple.fileprovider-nonui"
  file_provider_require_text "$EXTENSION_INFO" "${TEAM_PREFIX_PLACEHOLDER}${APP_GROUP}"
  file_provider_require_plist_bool_true "$EXTENSION_INFO" ":NSExtension:NSExtensionFileProviderSupportsEnumeration"
  file_provider_require_text "$PROVIDER_DIR/Sources/FileProviderItem.swift" "FileProviderRootItem"
  file_provider_require_text "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift" \
    "completionHandler(FileProviderRootItem(displayName: domain.displayName), nil)"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift" \
    "containerURL(forSecurityApplicationGroupIdentifier:"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift" \
    "ProviderAppGroup.identifier()"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderErrorMapping.swift" \
    "NSFileProviderError(.serverUnreachable)"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderAppGroup.swift" \
    "fallbackIdentifier"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderAppGroup.swift" \
    "containerURL(forSecurityApplicationGroupIdentifier:"
  file_provider_require_text "$PROVIDER_DIR/Sources/ProviderWritebackStager.swift" \
    "copyItem(at: contentsURL"
  file_provider_require_text "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift" \
    "ProviderWritebackStager.stage"

  if grep -Fq "com.apple.developer.fileprovider.testing-mode" "$EXTENSION_ENTITLEMENTS"; then
    echo "Release extension entitlements must not include File Provider testing-mode." >&2
    exit 1
  fi
}

validate_file_provider_built_app() {
  local EXTENSION_BUNDLE_ID="com.hybridcipher.app.HybridCipherFileProvider"
  local APP_GROUP="group.com.hybridcipher.macOS"
  local app="$1"
  local appex="$app/Contents/PlugIns/HybridCipherFileProvider.appex"
  local appex_info="$appex/Contents/Info.plist"
  local providerctl="$app/Contents/Resources/bin/providerctl-native"
  local app_info="$app/Contents/Info.plist"

  if [[ ! -d "$app" ]]; then
    echo "App bundle not found: $app" >&2
    exit 1
  fi
  if [[ ! -d "$appex" ]]; then
    echo "File Provider extension bundle not found: $appex" >&2
    exit 1
  fi
  file_provider_require_file "$app_info"
  file_provider_require_file "$appex_info"
  file_provider_require_executable "$providerctl"
  file_provider_validate_plist "$app_info"
  file_provider_validate_plist "$appex_info"

  local app_bundle_id
  app_bundle_id="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$app_info")"
  local bundle_id
  bundle_id="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$appex_info")"
  if [[ "$bundle_id" != "$EXTENSION_BUNDLE_ID" ]]; then
    echo "Unexpected extension bundle id: $bundle_id" >&2
    exit 1
  fi
  if [[ "$bundle_id" != "$app_bundle_id".* ]]; then
    echo "Extension bundle id $bundle_id is not namespaced under containing app $app_bundle_id." >&2
    exit 1
  fi

  codesign --verify --deep --strict --verbose=2 "$app" >/dev/null
  codesign --verify --strict --verbose=2 "$app" >/dev/null
  codesign --verify --strict --verbose=2 "$appex" >/dev/null
  local app_entitlements
  app_entitlements="$(codesign -d --entitlements :- "$app" 2>/dev/null)"
  file_provider_require_no_unexpanded_placeholders "Signed app entitlements" "$app_entitlements"
  local document_group
  document_group="$(/usr/libexec/PlistBuddy -c "Print :NSExtension:NSExtensionFileProviderDocumentGroup" "$appex_info")"
  if [[ "$document_group" == *"\$("* ]]; then
    echo "File Provider document group contains an unexpanded placeholder: $document_group" >&2
    exit 1
  fi
  file_provider_require_plist_bool_true "$appex_info" ":NSExtension:NSExtensionFileProviderSupportsEnumeration"
  if ! grep -Fq "<string>${document_group}</string>" <<<"$app_entitlements"; then
    echo "Signed app is missing File Provider document group entitlement $document_group." >&2
    exit 1
  fi
  local appex_entitlements
  appex_entitlements="$(codesign -d --entitlements :- "$appex" 2>/dev/null)"
  file_provider_require_no_unexpanded_placeholders "Signed extension entitlements" "$appex_entitlements"
  if ! grep -Fq "<string>${document_group}</string>" <<<"$appex_entitlements"; then
    echo "Signed extension is missing File Provider document group entitlement $document_group." >&2
    exit 1
  fi
  if ! grep -Fq "<key>com.apple.security.network.client</key>" <<<"$appex_entitlements"; then
    echo "Signed extension is missing network client entitlement for provider bridge IPC." >&2
    exit 1
  fi
  if codesign -d --entitlements :- "$appex" 2>/dev/null | grep -Fq "com.apple.developer.fileprovider.testing-mode"; then
    echo "Signed extension contains File Provider testing-mode entitlement." >&2
    exit 1
  fi
  if ! codesign -d --entitlements :- "$appex" 2>/dev/null | grep -Fq "$APP_GROUP"; then
    echo "Signed extension is missing app-group entitlement $APP_GROUP." >&2
    exit 1
  fi
  codesign --verify --strict --verbose=2 "$providerctl" >/dev/null
  local providerctl_entitlements
  providerctl_entitlements="$(codesign -d --entitlements :- "$providerctl" 2>/dev/null)"
  file_provider_require_no_unexpanded_placeholders "Signed providerctl entitlements" "$providerctl_entitlements"
  if ! grep -Fq "<string>${document_group}</string>" <<<"$providerctl_entitlements"; then
    echo "Signed providerctl-native is missing File Provider document group entitlement $document_group." >&2
    exit 1
  fi
  file_provider_validate_providerctl_command_support "$providerctl"
}

validate_file_provider_runtime() {
  require_cmd plutil
  require_cmd /usr/libexec/PlistBuddy
  validate_file_provider_source
  if [[ -n "${1:-}" ]]; then
    require_cmd codesign
    require_cmd python3
    validate_file_provider_built_app "$1"
  fi
  echo "macOS File Provider runtime validation passed."
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

stage_file_provider_runtime_in_app() (
  local app_path="$1"
  local signing_identity="$2"
  local team_id="$3"
  local version="$4"
  local file_provider_build_dir
  local staged_appex="$app_path/Contents/PlugIns/HybridCipherFileProvider.appex"
  local bundled_providerctl="$app_path/Contents/Resources/bin/providerctl-native"

  file_provider_build_dir="$(mktemp -d /tmp/hybridcipher-fileprovider.XXXXXX)"
  trap 'rm -rf "$file_provider_build_dir"' EXIT
  log "Building and staging macOS File Provider runtime"
  VERSION_OVERRIDE="$version" \
    APPLE_APPLICATION_IDENTITY="$signing_identity" \
    APPLE_TEAM_ID="$team_id" \
    build_file_provider_runtime "$file_provider_build_dir"

  rm -rf "$staged_appex"
  mkdir -p "$app_path/Contents/PlugIns" "$app_path/Contents/Resources/bin"
  cp -R "$file_provider_build_dir/HybridCipherFileProvider.appex" "$staged_appex"
  install -m 0755 "$file_provider_build_dir/providerctl-native" "$bundled_providerctl"

  local app_entitlements="$file_provider_build_dir/HybridCipherApp.entitlements"
  generate_desktop_app_entitlements "$app_entitlements" "$team_id"
  if [[ "$signing_identity" == "-" ]]; then
    # Tauri's unsigned CLI resource may have no signature on Intel. Give each
    # bundled executable an ad-hoc signature before validating the containing app.
    local bundled_cli
    for bundled_cli in \
      "$app_path/Contents/Resources/bin/hybridcipher" \
      "$app_path/Contents/Resources/resources/bin/hybridcipher"; do
      if [[ -f "$bundled_cli" ]]; then
        codesign --force --sign "-" "$bundled_cli"
      fi
    done
  fi
  log "Re-signing app bundle after staging File Provider runtime"
  codesign_file_provider_artifact "$app_path" "$signing_identity" "$app_entitlements"
  validate_file_provider_built_app "$app_path"
)

create_public_verify_tauri_config() {
  local config_path
  config_path="$(mktemp "$ROOT_DIR/apps/desktop/src-tauri/tauri.macos-public.XXXXXX.json")"

  python3 - "$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json" "$config_path" "$(macos_app_version)" <<'PY'
import json
import sys

source_path = sys.argv[1]
output_path = sys.argv[2]

with open(source_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

data["version"] = sys.argv[3]
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
  check_team_verification_keys || return 1

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
  local mode="${2:-signed}"
  local config_path="${3:-}"
  local bundled_cli_override="${4:-}"
  local -a tauri_build_cmd=(npx tauri build --target "$target")
  local -a tauri_env=()

  check_team_verification_keys || return 1

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
    env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD \
      -u TAURI_SIGNING_PRIVATE_KEY -u TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
      "${tauri_env[@]}" "${tauri_build_cmd[@]}"
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
  if ! build_tauri_bundle_for_target "$target" "unsigned" "$config_path" "$bundled_cli"; then
    rm -f "$config_path"
    return 1
  fi
  rm -f "$config_path"

  app_path="$(find_app_bundle_path "$target")"
  version="$(desktop_app_version)"
  stage_file_provider_runtime_in_app "$app_path" "-" "" "$version"
  require_file_provider_extension_in_app "$app_path"
  canonical_artifact="$(create_canonical_unsigned_app_archive "$target" "$app_path" "$(dirname "$app_path")")"

  ARTIFACTS+=("$canonical_artifact" "${canonical_artifact}.sha256")
}

public_verify_main() {
  cleanup_stale_build_temp_files

  require_cmd cargo
  require_cmd npm
  require_cmd npx
  require_cmd xcrun
  require_cmd plutil
  require_cmd codesign
  require_cmd /usr/libexec/PlistBuddy
  require_cmd python3

  pinned_rust_toolchain_matches || echo "WARNING: continuing with a compiler that differs from the pinned toolchain." >&2
  macos_app_version >/dev/null
  validate_file_provider_source
  warn_if_release_notes_missing "$(desktop_app_version)" "$RELEASE_NOTES_PATH"
  install_desktop_frontend_dependencies

  determine_build_targets
  for target in $BUILD_TARGETS; do
    build_public_verify_target "$target"
  done

  dedupe_artifacts

  log "Canonical unsigned artifacts built locally"
  printf '%s\n' "${ARTIFACTS[@]}"
}

desktop_build_common_main() {
  local command="${1:-}"
  case "$command" in
    --build-file-provider|--validate-file-provider)
      shift
      if [[ "$#" -gt 1 ]]; then
        echo "$command accepts at most one path argument." >&2
        return 1
      fi
      if [[ "$command" == "--build-file-provider" ]]; then
        build_file_provider_runtime "$@"
      else
        validate_file_provider_runtime "$@"
      fi
      ;;
    --public-verify)
      shift
      if [[ "$#" -ne 0 ]]; then
        echo "--public-verify does not accept arguments; use MODE and DESKTOP_TARGETS." >&2
        return 1
      fi
      public_verify_main
      ;;
    --help|-h)
      printf '%s\n' \
        'Usage: desktop_build_common.sh --public-verify | --build-file-provider [OUTPUT_DIR] | --validate-file-provider [APP_BUNDLE]' \
        'MODE selects silicon, full, or custom targets for --public-verify.'
      ;;
    "") echo "Missing command (use --help)." >&2; return 1 ;;
    *) echo "Unknown argument: $command (use --help)." >&2; return 1 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  desktop_build_common_main "$@"
fi
