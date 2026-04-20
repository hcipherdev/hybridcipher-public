#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/oss/write_desktop_release_manifest.sh \
    --release-tag <desktop-vX.Y.Z> \
    --source-ref <source-tag-or-commit> \
    --canonical-dir <dir> \
    [--signed-dir <dir>] \
    --output <file>
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

release_tag=""
source_ref=""
canonical_dir=""
signed_dir=""
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-tag)
      release_tag="${2:-}"
      shift 2
      ;;
    --source-ref)
      source_ref="${2:-}"
      shift 2
      ;;
    --canonical-dir)
      canonical_dir="${2:-}"
      shift 2
      ;;
    --signed-dir)
      signed_dir="${2:-}"
      shift 2
      ;;
    --output)
      output_path="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$release_tag" ]] || fail "--release-tag is required"
[[ -n "$source_ref" ]] || fail "--source-ref is required"
[[ -d "$canonical_dir" ]] || fail "--canonical-dir must point to a directory"
[[ -n "$output_path" ]] || fail "--output is required"
if [[ -n "$signed_dir" && ! -d "$signed_dir" ]]; then
  fail "--signed-dir must point to a directory"
fi

mkdir -p "$(dirname "$output_path")"

canonical_tmp="$(mktemp)"
signed_tmp="$(mktemp)"
trap 'rm -f "$canonical_tmp" "$signed_tmp"' EXIT

while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  printf '%s\t%s\t%s\n' \
    "$(basename "$path")" \
    "$(sha256_file "$path")" \
    "$(wc -c < "$path" | tr -d ' ')" >> "$canonical_tmp"
done < <(find "$canonical_dir" -maxdepth 1 -type f -name '*.unsigned.app.tar.gz' | sort)

if [[ -n "$signed_dir" ]]; then
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    printf '%s\t%s\t%s\n' \
      "$(basename "$path")" \
      "$(sha256_file "$path")" \
      "$(wc -c < "$path" | tr -d ' ')" >> "$signed_tmp"
  done < <(find "$signed_dir" -maxdepth 1 -type f ! -name '*.sha256' | sort)
fi

python3 - "$release_tag" "$source_ref" "$canonical_tmp" "$signed_tmp" "$output_path" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

release_tag, source_ref, canonical_tmp, signed_tmp, output_path = sys.argv[1:]

def load_rows(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            name, sha256, size = line.split("\t")
            rows.append({
                "name": name,
                "sha256": sha256,
                "size_bytes": int(size),
            })
    return rows

data = {
    "release_tag": release_tag,
    "source_ref": source_ref,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "canonical_unsigned_artifacts": load_rows(canonical_tmp),
    "signed_release_artifacts": load_rows(signed_tmp),
}

with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=True)
    fh.write("\n")
PY
