#!/usr/bin/env sh
set -eu

SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST_DIR="$SRC_DIR/dist"
OUT="$DIST_DIR/checksums.txt"

mkdir -p "$DIST_DIR"
tmp="${OUT}.tmp"
: > "$tmp"

find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.deb' \) | sort | while IFS= read -r file; do
  (
    cd "$DIST_DIR"
    sha256sum "$(basename "$file")"
  ) >> "$tmp"
done

mv "$tmp" "$OUT"
echo "$OUT"
