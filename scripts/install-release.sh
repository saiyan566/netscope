#!/usr/bin/env sh
set -eu

REPO="${NETSCOPE_REPO:-saiyan566/netscope}"
VERSION="${VERSION:-v0.3.0-beta}"
PREFIX="${PREFIX:-}"

case "$(uname -s)" in
  Linux) OS_NAME=linux ;;
  *)
    echo "unsupported OS: $(uname -s). Netscope releases are Linux-first." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH_NAME=amd64 ;;
  aarch64|arm64) ARCH_NAME=arm64 ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
VERSION_LABEL="${VERSION#v}"
TARBALL="netscope_${VERSION_LABEL}_${OS_NAME}_${ARCH_NAME}.tar.gz"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$out"
  else
    echo "curl or wget is required" >&2
    exit 1
  fi
}

download "$BASE_URL/$TARBALL" "$tmpdir/$TARBALL"
download "$BASE_URL/checksums.txt" "$tmpdir/checksums.txt"

(
  cd "$tmpdir"
  if ! grep -F "  $TARBALL" checksums.txt | sha256sum -c -; then
    echo "checksum verification failed" >&2
    exit 1
  fi
)

tar -xzf "$tmpdir/$TARBALL" -C "$tmpdir"
root="$(find "$tmpdir" -maxdepth 1 -type d -name 'netscope_*' | head -n 1)"

if [ -z "$PREFIX" ]; then
  if [ -w /usr/local/bin ]; then
    PREFIX=/usr/local/bin
  else
    PREFIX="$HOME/.local/bin"
  fi
fi

mkdir -p "$PREFIX"
install -m 0755 "$root/bin/netscope" "$PREFIX/netscope"
install -m 0755 "$root/bin/netscope-engine" "$PREFIX/netscope-engine"

echo "installed netscope to $PREFIX"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    echo "add this to your shell profile:"
    echo "export PATH=\"$PREFIX:\$PATH\""
    ;;
esac
echo "run: netscope doctor"
