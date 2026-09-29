#!/usr/bin/env bash
#
# Build a macOS .app bundle.
#
#   ./packaging/macos/bundle.sh <binary> <version> <output.app>
#
# The bundle is what makes the app behave like an app on macOS: a Dock icon, a
# menu bar, and a window that can be brought forward. A bare binary works too,
# but has none of that.

set -euo pipefail

BIN="${1:?usage: bundle.sh <binary> <version> <output.app>}"
VERSION="${2:?}"
APP="${3:?}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

install -m 0755 "$BIN" "$APP/Contents/MacOS/ssha"
install -m 0644 "$REPO/packaging/icons/ssha.icns" "$APP/Contents/Resources/AppIcon.icns"
sed "s/__VERSION__/${VERSION}/g" "$REPO/packaging/macos/Info.plist.in" > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# The skill rides along so `ssha skill install` works from the bundle.
mkdir -p "$APP/Contents/Resources/skills/ssha-agent"
install -m 0644 "$REPO/skills/ssha-agent/SKILL.md" "$APP/Contents/Resources/skills/ssha-agent/SKILL.md"

echo "built $APP"
