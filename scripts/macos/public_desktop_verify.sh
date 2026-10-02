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
# Loading the shared routines does not run signed release setup or read .env.local.
source "$SCRIPT_DIR/desktop_release_pkg.sh"
public_verify_main "$@"
