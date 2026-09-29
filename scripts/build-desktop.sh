#!/usr/bin/env bash
#
# Build the desktop binary.
#
#   ./scripts/build-desktop.sh [output-path]
#
# The GUI lives behind the `desktop` build tag, so the plain build stays pure Go.
# This script exists for one reason: `github.com/webview/webview_go` asks
# pkg-config for webkit2gtk-4.0, and Ubuntu 24.04+ (including the GitHub runners)
# only ships webkit2gtk-4.1. The C++ library behind the binding already loads
# either shared object at runtime, so an alias .pc file is enough - no patching
# and no vendoring.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO/ssha}"
VERSION="$(git -C "$REPO" describe --tags --always --dirty 2>/dev/null || echo dev)"

# Windows links WebView2 and macOS links WebKit, both of which are part of the
# platform. Only Linux needs the GTK/WebKit development packages, and only Linux
# has the 4.0/4.1 split.
case "$(uname -s)" in
Linux)
  if ! pkg-config --exists gtk+-3.0; then
    echo "gtk+-3.0 development files are missing." >&2
    echo "  Debian/Ubuntu: sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev" >&2
    echo "  Fedora:        sudo dnf install gtk3-devel webkit2gtk4.1-devel" >&2
    echo "  Arch:          sudo pacman -S gtk3 webkit2gtk-4.1" >&2
    exit 1
  fi

  SHIM=""
  cleanup() { [ -n "$SHIM" ] && rm -rf "$SHIM"; }
  trap cleanup EXIT

  if pkg-config --exists webkit2gtk-4.0; then
    echo "using webkit2gtk-4.0"
  else
    if ! pkg-config --exists webkit2gtk-4.1; then
      echo "Neither webkit2gtk-4.0 nor webkit2gtk-4.1 is available." >&2
      echo "  Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-dev" >&2
      exit 1
    fi
    SHIM="$(mktemp -d)"
    version="$(pkg-config --modversion webkit2gtk-4.1)"
    cat > "$SHIM/webkit2gtk-4.0.pc" <<EOF
Name: webkit2gtk-4.0 (alias)
Description: alias to webkit2gtk-4.1, which is what this system ships
Version: $version
Requires: webkit2gtk-4.1
EOF
    export PKG_CONFIG_PATH="$SHIM${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    echo "using webkit2gtk-4.1 through a pkg-config alias"
  fi
  ;;
*)
  echo "building for $(uname -s); the system webview is linked by the platform"
  ;;
esac

cd "$REPO"
CGO_ENABLED=1 go build \
  -tags desktop \
  -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" \
  -o "$OUT" ./cmd/ssha
echo "built $OUT ($VERSION)"
