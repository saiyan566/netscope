#!/usr/bin/env sh
set -eu

SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_DIR="${REPO_DIR:-/opt/netscope-pacman}"
PKG_FILE="$(ls "$SRC_DIR"/dist/arch/netscope-*.pkg.tar.* 2>/dev/null | tail -n 1 || true)"

if [ -z "$PKG_FILE" ]; then
  echo "No Arch package found. Run on Arch Linux: make package-arch" >&2
  exit 1
fi

if ! command -v repo-add >/dev/null 2>&1; then
  echo "repo-add is required. On Arch Linux install pacman-contrib." >&2
  exit 1
fi

sudo mkdir -p "$REPO_DIR"
sudo cp "$PKG_FILE" "$REPO_DIR/"
sudo repo-add "$REPO_DIR/netscope.db.tar.gz" "$REPO_DIR"/netscope-*.pkg.tar.*

if ! grep -q '^\[netscope\]' /etc/pacman.conf; then
  {
    echo ""
    echo "[netscope]"
    echo "SigLevel = Optional TrustAll"
    echo "Server = file://$REPO_DIR"
  } | sudo tee -a /etc/pacman.conf >/dev/null
fi

sudo pacman -Sy
echo "local pacman repo ready. Install with: sudo pacman -S netscope"
