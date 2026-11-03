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
# The shared build routines contain no signed release setup and never read the release env file.
source "$SCRIPT_DIR/desktop_build_common.sh"
public_verify_main "$@"
