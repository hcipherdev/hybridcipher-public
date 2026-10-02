#!/usr/bin/env bash
# Read only the macOS app version; never fall back to Cargo or the shared config.
macos_app_version() {
  local config_path="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/apps/desktop/src-tauri/tauri.macos.conf.json}"
  python3 - "$config_path" "${VERSION_OVERRIDE:-}" <<'PY'
import json
import re
from pathlib import Path
import sys

path, forwarded = sys.argv[1:]
try:
    with open(path, encoding="utf-8-sig") as source:
        version = json.load(source).get("version")
    if not isinstance(version, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("version must be a numeric major.minor.patch string")
    if any(int(part) > 2**64 - 1 for part in version.split(".")):
        raise ValueError("version exceeds semantic version component limits")
    overlay_path = Path(path).with_name("tauri.macos.release.conf.json")
    if overlay_path.exists():
        with overlay_path.open(encoding="utf-8-sig") as overlay_source:
            overlay = json.load(overlay_source)
        if "version" in overlay and overlay["version"] != version:
            raise ValueError(f"conflicting app version in {overlay_path}; edit only tauri.macos.conf.json")
    if forwarded and forwarded != version:
        raise ValueError(f"VERSION_OVERRIDE={forwarded} conflicts with canonical version {version}")
except (OSError, ValueError, AttributeError) as error:
    sys.exit(f"Invalid macOS app version in '{path}': {error}")
print(version)
PY
}
