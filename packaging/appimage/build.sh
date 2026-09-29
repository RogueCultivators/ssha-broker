#!/usr/bin/env bash
#
# Build an AppImage.
#
#   ./packaging/appimage/build.sh <binary> <version> <output.AppImage>
#
# The AppImage carries ssha and its icon; it does NOT carry WebKitGTK. Bundling a
# browser engine (and its several hundred megabytes of dependencies) is a project
# of its own, so the AppImage uses the system webview and declares the packages
# it needs in the desktop file's comment. On a current Ubuntu or Fedora desktop
# they are already there.

set -euo pipefail

BIN="${1:?usage: build.sh <binary> <version> <output>}"
VERSION="${2:?}"
OUT="${3:?}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v appimagetool >/dev/null 2>&1; then
  echo "appimagetool is not on PATH." >&2
  echo "  get it from https://github.com/AppImage/appimagetool/releases" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/ssha.AppImage.d"

mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/512x512/apps" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
         "$APPDIR/usr/share/ssha/skills/ssha-agent"

install -m 0755 "$BIN" "$APPDIR/usr/bin/ssha"
install -m 0644 "$REPO/packaging/linux/ssha.desktop" "$APPDIR/usr/share/applications/ssha.desktop"
install -m 0644 "$REPO/packaging/icons/ssha-512.png" "$APPDIR/usr/share/icons/hicolor/512x512/apps/ssha.png"
install -m 0644 "$REPO/packaging/icons/ssha-256.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/ssha.png"
install -m 0644 "$REPO/skills/ssha-agent/SKILL.md" "$APPDIR/usr/share/ssha/skills/ssha-agent/SKILL.md"

# appimagetool wants the desktop file and the icon at the AppDir root as well.
cp "$REPO/packaging/linux/ssha.desktop" "$APPDIR/ssha.desktop"
cp "$REPO/packaging/icons/ssha-512.png" "$APPDIR/ssha.png"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
# Resolve symlinks so $HERE is the mounted AppDir even when launched through a link.
SELF="$0"
while [ -L "$SELF" ]; do SELF="$(readlink "$SELF")"; done
HERE="$(cd "$(dirname "$SELF")" && pwd)"
export PATH="$HERE/usr/bin:$PATH"
exec "$HERE/usr/bin/ssha" "$@"
EOF
chmod 0755 "$APPDIR/AppRun"

# A .desktop without a version stamp makes some launchers cache a stale icon.
sed -i "s/^Version=.*/Version=${VERSION}/" "$APPDIR/ssha.desktop"
cp "$APPDIR/ssha.desktop" "$APPDIR/usr/share/applications/ssha.desktop"

mkdir -p "$(dirname "$OUT")"
ARCH="${ARCH:-$(uname -m)}" appimagetool --no-appstream "$APPDIR" "$OUT"
echo "built $OUT"
