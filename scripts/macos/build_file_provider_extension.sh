#!/usr/bin/env bash
# Purpose: Build the HybridCipher macOS File Provider extension bundle and the
# native provider control helper from checked-in Swift source.
#
# Usage:
#   scripts/macos/build_file_provider_extension.sh [OUTPUT_DIR]
#
# Environment:
#   VERSION_OVERRIDE: bundle version to stamp into Info.plist.
#   APPLE_APPLICATION_IDENTITY: codesigning identity. Defaults to ad-hoc "-".
#   APPLE_TEAM_ID: optional Team ID used to expand app-group entitlements.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROVIDER_ROOT="$ROOT_DIR/apps/desktop/macos-fileprovider"
EXTENSION_ROOT="$PROVIDER_ROOT/HybridCipherFileProvider"
APP_CRATE_DIR="$ROOT_DIR/apps/desktop/src-tauri"
OUTPUT_DIR="${1:-$ROOT_DIR/dist/macos/fileprovider-build}"
APPEX="$OUTPUT_DIR/HybridCipherFileProvider.appex"
APPEX_CONTENTS="$APPEX/Contents"
APPEX_MACOS="$APPEX_CONTENTS/MacOS"
MODULE_NAME="HybridCipherFileProvider"
EXECUTABLE_NAME="HybridCipherFileProvider"
PROVIDERCTL="$OUTPUT_DIR/providerctl-native"
INFO_PLIST="$APPEX_CONTENTS/Info.plist"
ENTITLEMENTS="$OUTPUT_DIR/HybridCipherFileProvider.entitlements"
PROVIDERCTL_ENTITLEMENTS="$OUTPUT_DIR/ProviderCtl.entitlements"
MODULE_CACHE="$OUTPUT_DIR/module-cache"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_version() {
  if [[ -n "${VERSION_OVERRIDE:-}" ]]; then
    echo "$VERSION_OVERRIDE"
    return
  fi
  awk -F '"' '/^version = / { print $2; exit }' "$APP_CRATE_DIR/Cargo.toml"
}

codesign_extension() {
  local target="$1"
  local identity="${APPLE_APPLICATION_IDENTITY:--}"
  local -a args=(--force --sign "$identity" --entitlements "$ENTITLEMENTS")
  if [[ "$identity" != "-" ]]; then
    args+=(--timestamp --options runtime)
  fi
  codesign "${args[@]}" "$target"
}

codesign_helper() {
  local target="$1"
  local identity="${APPLE_APPLICATION_IDENTITY:--}"
  local -a args=(--force --sign "$identity" --entitlements "$PROVIDERCTL_ENTITLEMENTS")
  if [[ "$identity" != "-" ]]; then
    args+=(--timestamp --options runtime)
  fi
  codesign "${args[@]}" "$target"
}

main() {
  require_cmd xcrun
  require_cmd plutil
  require_cmd codesign
  require_cmd /usr/libexec/PlistBuddy

  local version
  version="$(detect_version)"
  if [[ -z "$version" ]]; then
    echo "Failed to detect desktop app version." >&2
    exit 1
  fi

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

  codesign_extension "$APPEX"
  codesign_helper "$PROVIDERCTL"

  echo "Built File Provider extension: $APPEX"
  echo "Built provider control helper: $PROVIDERCTL"
}

main "$@"
