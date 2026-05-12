#!/usr/bin/env sh
set -eu

SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="${VERSION:-$(cat "$SRC_DIR/VERSION" 2>/dev/null || printf '0.3.0-beta')}"
DIST_DIR="$SRC_DIR/dist"
WORK_DIR="${TMPDIR:-/tmp}/netscope-release-$$"
OS_NAME="${OS_NAME:-linux}"

case "${ARCH:-$(uname -m)}" in
  x86_64|amd64) ARCH_NAME=amd64 ;;
  aarch64|arm64) ARCH_NAME=arm64 ;;
  *) ARCH_NAME="$(uname -m)" ;;
esac

if [ ! -f "$SRC_DIR/build/netscope" ] || [ ! -f "$SRC_DIR/build/netscope-engine" ]; then
  echo "build/netscope and build/netscope-engine are required. Run: make build" >&2
  exit 1
fi

trap 'rm -rf "$WORK_DIR"' EXIT
PACKAGE="netscope_${VERSION}_${OS_NAME}_${ARCH_NAME}"
ROOT="$WORK_DIR/$PACKAGE"
OUT="$DIST_DIR/$PACKAGE.tar.gz"

rm -rf "$WORK_DIR" "$OUT"
mkdir -p "$ROOT/bin" "$ROOT/templates" "$DIST_DIR"

install -m 0755 "$SRC_DIR/build/netscope" "$ROOT/bin/netscope"
install -m 0755 "$SRC_DIR/build/netscope-engine" "$ROOT/bin/netscope-engine"
install -m 0644 "$SRC_DIR/README.md" "$ROOT/README.md"
install -m 0644 "$SRC_DIR/LICENSE" "$ROOT/LICENSE"
install -m 0644 "$SRC_DIR/NOTICE" "$ROOT/NOTICE"
install -m 0644 "$SRC_DIR/SECURITY.md" "$ROOT/SECURITY.md"
install -m 0644 "$SRC_DIR/CHANGELOG.md" "$ROOT/CHANGELOG.md"
cp "$SRC_DIR/templates/"* "$ROOT/templates/" 2>/dev/null || true

cat > "$ROOT/install.sh" <<'EOF_INSTALL'
#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-}"
if [ -z "${PREFIX:-}" ]; then
  PREFIX=/usr/local/bin
  if [ ! -w "$PREFIX" ]; then
    PREFIX="$HOME/.local/bin"
  fi
fi

mkdir -p "$PREFIX"
install -m 0755 bin/netscope "$PREFIX/netscope"
install -m 0755 bin/netscope-engine "$PREFIX/netscope-engine"
echo "installed netscope to $PREFIX"
echo "run: netscope doctor"
EOF_INSTALL
chmod 0755 "$ROOT/install.sh"

(
  cd "$WORK_DIR"
  tar -czf "$OUT" "$PACKAGE"
)

echo "$OUT"
