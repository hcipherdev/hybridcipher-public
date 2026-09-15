#!/usr/bin/env bash
# Purpose: Validate the source and optional built-bundle pieces required for the
# HybridCipher macOS File Provider runtime.
#
# Usage:
#   scripts/macos/validate_file_provider_runtime.sh
#   scripts/macos/validate_file_provider_runtime.sh /Applications/HybridCipher.app
#
# The first form validates checked-in source metadata and entitlements. The
# second form also validates that the app bundle contains and signs
# HybridCipherFileProvider.appex without release-blocking testing entitlements.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_BUNDLE="${1:-}"
PROVIDER_DIR="$ROOT_DIR/apps/desktop/macos-fileprovider/HybridCipherFileProvider"
PROVIDERCTL_ENTITLEMENTS="$ROOT_DIR/apps/desktop/macos-fileprovider/ProviderCtl/ProviderCtl.entitlements"
APP_ENTITLEMENTS="$ROOT_DIR/apps/desktop/src-tauri/entitlements.plist"
EXTENSION_ENTITLEMENTS="$PROVIDER_DIR/HybridCipherFileProvider.entitlements"
EXTENSION_INFO="$PROVIDER_DIR/Info.plist"
EXTENSION_BUNDLE_ID="com.hybridcipher.app.HybridCipherFileProvider"
APP_GROUP="group.com.hybridcipher.macOS"
TEAM_PREFIX_PLACEHOLDER="\$(TeamIdentifierPrefix)"

require_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "Missing required file: $file" >&2
    exit 1
  fi
}

require_executable() {
  local file="$1"
  if [[ ! -x "$file" ]]; then
    echo "Missing required executable: $file" >&2
    exit 1
  fi
}

require_text() {
  local file="$1"
  local text="$2"
  if ! grep -Fq "$text" "$file"; then
    echo "Expected '$text' in $file" >&2
    exit 1
  fi
}

require_plist_bool_true() {
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

require_no_unexpanded_placeholders() {
  local label="$1"
  local content="$2"
  if grep -Fq "\$(" <<<"$content"; then
    echo "$label contains unexpanded entitlement placeholders." >&2
    exit 1
  fi
}

validate_providerctl_command_support() {
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

validate_plist() {
  local file="$1"
  plutil -lint "$file" >/dev/null
}

validate_source_tree() {
  require_file "$APP_ENTITLEMENTS"
  require_file "$EXTENSION_ENTITLEMENTS"
  require_file "$PROVIDERCTL_ENTITLEMENTS"
  require_file "$EXTENSION_INFO"
  require_file "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift"
  require_file "$PROVIDER_DIR/Sources/ProviderAppGroup.swift"
  require_file "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift"
  require_file "$PROVIDER_DIR/Sources/ProviderErrorMapping.swift"
  require_file "$PROVIDER_DIR/Sources/ProviderModels.swift"
  require_file "$PROVIDER_DIR/Sources/ProviderWritebackStager.swift"
  require_file "$PROVIDER_DIR/Sources/FileProviderEnumerator.swift"
  require_file "$PROVIDER_DIR/Sources/FileProviderItem.swift"

  validate_plist "$APP_ENTITLEMENTS"
  validate_plist "$EXTENSION_ENTITLEMENTS"
  validate_plist "$PROVIDERCTL_ENTITLEMENTS"
  validate_plist "$EXTENSION_INFO"

  require_text "$APP_ENTITLEMENTS" "$APP_GROUP"
  require_text "$EXTENSION_ENTITLEMENTS" "$APP_GROUP"
  require_text "$PROVIDERCTL_ENTITLEMENTS" "$APP_GROUP"
  require_text "$EXTENSION_ENTITLEMENTS" "com.apple.security.network.client"
  require_text "$EXTENSION_INFO" "$EXTENSION_BUNDLE_ID"
  require_text "$EXTENSION_INFO" "com.apple.fileprovider-nonui"
  require_text "$EXTENSION_INFO" "${TEAM_PREFIX_PLACEHOLDER}${APP_GROUP}"
  require_plist_bool_true "$EXTENSION_INFO" ":NSExtension:NSExtensionFileProviderSupportsEnumeration"
  require_text "$PROVIDER_DIR/Sources/FileProviderItem.swift" "FileProviderRootItem"
  require_text "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift" \
    "completionHandler(FileProviderRootItem(displayName: domain.displayName), nil)"
  require_text "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift" \
    "containerURL(forSecurityApplicationGroupIdentifier:"
  require_text "$PROVIDER_DIR/Sources/ProviderBridgeClient.swift" \
    "ProviderAppGroup.identifier()"
  require_text "$PROVIDER_DIR/Sources/ProviderErrorMapping.swift" \
    "NSFileProviderError(.serverUnreachable)"
  require_text "$PROVIDER_DIR/Sources/ProviderAppGroup.swift" \
    "fallbackIdentifier"
  require_text "$PROVIDER_DIR/Sources/ProviderAppGroup.swift" \
    "containerURL(forSecurityApplicationGroupIdentifier:"
  require_text "$PROVIDER_DIR/Sources/ProviderWritebackStager.swift" \
    "copyItem(at: contentsURL"
  require_text "$PROVIDER_DIR/Sources/HybridCipherFileProviderExtension.swift" \
    "ProviderWritebackStager.stage"

  if grep -Fq "com.apple.developer.fileprovider.testing-mode" "$EXTENSION_ENTITLEMENTS"; then
    echo "Release extension entitlements must not include File Provider testing-mode." >&2
    exit 1
  fi
}

validate_built_app() {
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
  require_file "$app_info"
  require_file "$appex_info"
  require_executable "$providerctl"
  validate_plist "$app_info"
  validate_plist "$appex_info"

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
  require_no_unexpanded_placeholders "Signed app entitlements" "$app_entitlements"
  local document_group
  document_group="$(/usr/libexec/PlistBuddy -c "Print :NSExtension:NSExtensionFileProviderDocumentGroup" "$appex_info")"
  if [[ "$document_group" == *"\$("* ]]; then
    echo "File Provider document group contains an unexpanded placeholder: $document_group" >&2
    exit 1
  fi
  require_plist_bool_true "$appex_info" ":NSExtension:NSExtensionFileProviderSupportsEnumeration"
  if ! grep -Fq "<string>${document_group}</string>" <<<"$app_entitlements"; then
    echo "Signed app is missing File Provider document group entitlement $document_group." >&2
    exit 1
  fi
  local appex_entitlements
  appex_entitlements="$(codesign -d --entitlements :- "$appex" 2>/dev/null)"
  require_no_unexpanded_placeholders "Signed extension entitlements" "$appex_entitlements"
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
  require_no_unexpanded_placeholders "Signed providerctl entitlements" "$providerctl_entitlements"
  if ! grep -Fq "<string>${document_group}</string>" <<<"$providerctl_entitlements"; then
    echo "Signed providerctl-native is missing File Provider document group entitlement $document_group." >&2
    exit 1
  fi
  validate_providerctl_command_support "$providerctl"
}

main() {
  validate_source_tree
  if [[ -n "$APP_BUNDLE" ]]; then
    validate_built_app "$APP_BUNDLE"
  fi
  echo "macOS File Provider runtime validation passed."
}

main "$@"
