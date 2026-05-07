#!/usr/bin/env sh
set -eu

VERSION="${VERSION:-0.1.0}"
MAINTAINER="${MAINTAINER:-Netscope Maintainers <maintainers@example.invalid>}"
HOMEPAGE="${HOMEPAGE:-https://github.com/saiyan566/netscope}"
SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST_DIR="$SRC_DIR/dist"
WORK_DIR="${TMPDIR:-/tmp}/netscope-deb-$$"
trap 'rm -rf "$WORK_DIR"' EXIT

if command -v dpkg >/dev/null 2>&1; then
  ARCH="$(dpkg --print-architecture)"
else
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH="$(uname -m)" ;;
  esac
fi

PKG_ROOT="$WORK_DIR/netscope_${VERSION}_${ARCH}"
OUT="$DIST_DIR/netscope_${VERSION}_${ARCH}.deb"

if [ ! -f "$SRC_DIR/build/netscope" ] || [ ! -f "$SRC_DIR/build/netscope-engine" ]; then
  echo "build/netscope and build/netscope-engine are required. Run: make build" >&2
  exit 1
fi

rm -rf "$WORK_DIR" "$OUT"
mkdir -p "$PKG_ROOT/DEBIAN" "$PKG_ROOT/usr/bin" "$PKG_ROOT/usr/share/doc/netscope" "$PKG_ROOT/usr/share/netscope/templates" "$DIST_DIR"

install -m 0755 "$SRC_DIR/build/netscope" "$PKG_ROOT/usr/bin/netscope"
install -m 0755 "$SRC_DIR/build/netscope-engine" "$PKG_ROOT/usr/bin/netscope-engine"
install -m 0644 "$SRC_DIR/README.md" "$PKG_ROOT/usr/share/doc/netscope/README.md"
cp "$SRC_DIR/templates/"* "$PKG_ROOT/usr/share/netscope/templates/" 2>/dev/null || true
find "$PKG_ROOT/usr/share" -type f -exec chmod 0644 {} \;

cat > "$PKG_ROOT/DEBIAN/control" <<EOF_CONTROL
Package: netscope
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Depends: ca-certificates
Suggests: libcap2-bin
Homepage: $HOMEPAGE
Description: Defensive Linux CLI scanner with passive recon
 Netscope provides authorized host discovery, TCP/UDP scanning,
 passive domain/subdomain recon, SSH audit hints, and remediation-first
 vulnerability findings.
EOF_CONTROL

cat > "$PKG_ROOT/DEBIAN/postinst" <<'EOF_POSTINST'
#!/usr/bin/env sh
set -eu
echo "netscope installed. Run: netscope doctor"
if command -v setcap >/dev/null 2>&1; then
  echo "optional raw-socket setup: sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/netscope-engine"
fi
EOF_POSTINST
chmod 0755 "$PKG_ROOT/DEBIAN/postinst"

find "$PKG_ROOT" -type d -exec chmod 0755 {} \;
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$OUT"
echo "$OUT"
echo "install with: sudo apt install \"$OUT\""
