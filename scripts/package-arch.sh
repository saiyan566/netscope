#!/usr/bin/env sh
set -eu

SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v makepkg >/dev/null 2>&1; then
  echo "makepkg is required. On Arch Linux install base-devel, then run this again." >&2
  echo "Manual path: cd packaging/arch && makepkg -f" >&2
  exit 1
fi

cd "$SRC_DIR/packaging/arch"
makepkg -f --clean
mkdir -p "$SRC_DIR/dist/arch"
cp netscope-*.pkg.tar.* "$SRC_DIR/dist/arch/"
ls "$SRC_DIR/dist/arch"/netscope-*.pkg.tar.*
echo "install with: sudo pacman -U $SRC_DIR/dist/arch/netscope-*.pkg.tar.*"
