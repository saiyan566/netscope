#!/usr/bin/env sh
set -eu

SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_DIR="${REPO_DIR:-/usr/local/share/netscope-apt}"
DEB_FILE="$(ls "$SRC_DIR"/dist/netscope_*_*.deb 2>/dev/null | tail -n 1 || true)"

if [ -z "$DEB_FILE" ]; then
  echo "No .deb found. Run: make package-deb" >&2
  exit 1
fi

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
  echo "dpkg-scanpackages is required. Install it with: sudo apt install dpkg-dev" >&2
  exit 1
fi

sudo mkdir -p "$REPO_DIR"
sudo cp "$DEB_FILE" "$REPO_DIR/"
(
  cd "$REPO_DIR"
  sudo sh -c 'dpkg-scanpackages . /dev/null | gzip -9c > Packages.gz'
)

echo "deb [trusted=yes] file:$REPO_DIR ./" | sudo tee /etc/apt/sources.list.d/netscope.list >/dev/null
sudo apt update
echo "local apt repo ready. Install with: sudo apt install netscope"
