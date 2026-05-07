#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-}"
SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -z "$PREFIX" ]; then
  if [ -w /usr/local/bin ]; then
    PREFIX=/usr/local/bin
  else
    PREFIX="$HOME/.local/bin"
  fi
fi

mkdir -p "$PREFIX"

if [ ! -f "$SRC_DIR/build/netscope" ] || [ ! -f "$SRC_DIR/build/netscope-engine" ]; then
  echo "build/netscope and build/netscope-engine are required. Build the release binaries first." >&2
  exit 1
fi

install -m 0755 "$SRC_DIR/build/netscope" "$PREFIX/netscope"
install -m 0755 "$SRC_DIR/build/netscope-engine" "$PREFIX/netscope-engine"

echo "installed netscope to $PREFIX"

case ":$PATH:" in
  *":$PREFIX:"*)
    echo "path already contains $PREFIX"
    ;;
  *)
    if [ "$PREFIX" = "$HOME/.local/bin" ]; then
      PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
    else
      PATH_LINE="export PATH=\"$PREFIX:\$PATH\""
    fi

    for rc in "$HOME/.bashrc" "$HOME/.profile"; do
      if [ -f "$rc" ] && ! grep -F "$PATH_LINE" "$rc" >/dev/null 2>&1; then
        {
          echo ""
          echo "# Added by netscope installer"
          echo "$PATH_LINE"
        } >> "$rc"
        echo "added $PREFIX to PATH in $rc"
      fi
    done

    echo "restart your shell or run: . ~/.bashrc"
    ;;
esac

if command -v setcap >/dev/null 2>&1; then
  echo "optional: sudo setcap cap_net_raw,cap_net_admin+ep $PREFIX/netscope-engine"
fi
