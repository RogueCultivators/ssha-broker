#!/usr/bin/env bash
#
# Install ssha.
#
#   ./packaging/install.sh --user                 the desktop app for this user
#   sudo ./packaging/install.sh --system          the same, system wide
#   sudo ./packaging/install.sh --system --with-mcp    ...plus the agent gateway
#
# Options:
#   --user / --system          who the install is for (one is required)
#   --with-mcp                 also install the MCP http service for agents
#   --headless-service         keep an always-on editor on a local port for a
#                              browser (the old way; off by default)
#   --port N                   editor port for --headless-service (8770)
#   --mcp-port N               MCP port for --with-mcp (8765)
#   --no-build                 use an existing ./ssha instead of building
#
# Idempotent: re-running upgrades the binary, the icons and the launcher, and
# never touches an existing config, secret or audit log.

set -euo pipefail

MODE=""
WITH_MCP=0
HEADLESS=0
PORT=8770
MCP_PORT=8765
BUILD=1
SYSTEM_USER="ssha"

while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE=user ;;
    --system) MODE=system ;;
    --with-mcp) WITH_MCP=1 ;;
    --headless-service) HEADLESS=1 ;;
    --port) PORT="$2"; shift ;;
    --mcp-port) MCP_PORT="$2"; shift ;;
    --user-name) SYSTEM_USER="$2"; shift ;;
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -n "$MODE" ] || { echo "pick one: --user (no root) or --system (needs root)" >&2; exit 2; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(git -C "$REPO" describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0)"
say() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
warn() { printf '   \033[33m%s\033[0m\n' "$*"; }

# --- build -----------------------------------------------------------------
DESKTOP=1
BIN="$REPO/ssha"
if [ "$BUILD" = "1" ]; then
  say "building ssha $VERSION"
  if ! "$REPO/scripts/build-desktop.sh" "$REPO/ssha.desktop-build" >/tmp/ssha-build.log 2>&1; then
    DESKTOP=0
    warn "无法编译桌面界面，改装纯命令行版本："
    sed 's/^/     /' /tmp/ssha-build.log | tail -6
    ( cd "$REPO" && go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o ssha.desktop-build ./cmd/ssha )
  fi
  BIN="$REPO/ssha.desktop-build"
  note "$($BIN version)"
else
  BIN="$REPO/ssha"
  [ -x "$BIN" ] || { echo "--no-build needs an existing $BIN" >&2; exit 1; }
fi

install_icons() { # install_icons <icon-root>
  local root="$1" size
  for size in 16 24 32 48 64 128 256 512 1024; do
    install -d "$root/hicolor/${size}x${size}/apps"
    install -m 0644 "$REPO/packaging/icons/ssha-$size.png" "$root/hicolor/${size}x${size}/apps/ssha.png"
  done
  note "icons → $root/hicolor/*/apps/ssha.png"
}

refresh_caches() { # refresh_caches <applications-dir> <icon-root>
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$1" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f "$2/hicolor" 2>/dev/null || true
}

drop_legacy_service() { # drop_legacy_service <unit-dir> <systemctl...>
  local unit="$1"; shift
  if [ -f "$unit/ssha-ui.service" ]; then
    # Older versions installed an always-on editor that served a browser. The
    # default `ssha ui` opens a window now, so leaving that unit in place would
    # pop a window at every login.
    "$@" disable --now ssha-ui.service >/dev/null 2>&1 || true
    rm -f "$unit/ssha-ui.service"
    note "removed the old browser-mode ssha-ui.service"
    note "  (reinstall it with --headless-service if you still want it)"
  fi
}

install_headless_unit() { # install_headless_unit <unit-dir> <systemctl...>
  local unit="$1"; shift
  install -d "$unit"
  sed -e "s#%h/.local/bin/ssha#%h/.local/bin/ssha#" \
      -e "s#--addr 127.0.0.1:8770#--addr 127.0.0.1:$PORT#" \
      -e "s#ui --addr#ui --headless --addr#" \
      "$REPO/packaging/systemd/ssha-ui.user.service" > "$unit/ssha-ui.service"
  "$@" daemon-reload
  "$@" enable ssha-ui.service
  "$@" restart ssha-ui.service
  note "headless editor service on http://127.0.0.1:$PORT"
}

# --- user install -----------------------------------------------------------
if [ "$MODE" = "user" ]; then
  BINDIR="$HOME/.local/bin"
  ICONS="$HOME/.local/share/icons"
  APPS="$HOME/.local/share/applications"
  UNITDIR="$HOME/.config/systemd/user"

  say "installing the binary"
  install -d "$BINDIR"
  install -m 0755 "$BIN" "$BINDIR/ssha"
  note "$BINDIR/ssha"
  [ "$DESKTOP" = "1" ] || warn "这个版本没有窗口，ssha ui 会提示用 --headless"

  say "installing the icon and the launcher"
  install_icons "$ICONS"
  install -d "$APPS"
  install -m 0644 "$REPO/packaging/linux/ssha.desktop" "$APPS/ssha.desktop"
  note "$APPS/ssha.desktop"
  refresh_caches "$APPS" "$ICONS"

  say "services"
  drop_legacy_service "$UNITDIR" systemctl --user
  if [ "$HEADLESS" = "1" ]; then
    install_headless_unit "$UNITDIR" systemctl --user
  else
    note "没有安装后台服务：从应用菜单打开 ssha，或者跑 ssha ui"
  fi

  say "done"
  note "打开：应用菜单里找 ssha，或者直接跑  ssha ui"
  note "配置：~/.config/ssha/config.yaml"
  [ "$HEADLESS" = "1" ] && note "浏览器模式：ssha ui --headless  （现在是后台服务了）"

# --- system install ---------------------------------------------------------
else
  [ "$(id -u)" = "0" ] || { echo "--system needs root: sudo $0 --system" >&2; exit 1; }

  say "installing the binary"
  install -m 0755 "$BIN" /usr/local/bin/ssha
  note "/usr/local/bin/ssha"

  say "installing the icon and the launcher"
  install_icons /usr/share/icons
  install -d /usr/share/applications
  install -m 0644 "$REPO/packaging/linux/ssha.desktop" /usr/share/applications/ssha.desktop
  install -d /usr/share/ssha/skills/ssha-agent
  install -m 0644 "$REPO/skills/ssha-agent/SKILL.md" /usr/share/ssha/skills/ssha-agent/SKILL.md
  refresh_caches /usr/share/applications /usr/share/icons
  note "/usr/share/applications/ssha.desktop"

  if [ "$WITH_MCP" = "1" ] || [ "$HEADLESS" = "1" ]; then
    say "creating the $SYSTEM_USER user for the services"
    if id "$SYSTEM_USER" >/dev/null 2>&1; then
      note "user $SYSTEM_USER already exists"
    else
      useradd --system --create-home --home-dir "/var/lib/$SYSTEM_USER" \
        --shell /usr/sbin/nologin "$SYSTEM_USER"
      note "created $SYSTEM_USER"
    fi
    install -d -m 0700 -o "$SYSTEM_USER" -g "$SYSTEM_USER" /etc/ssha "/var/lib/$SYSTEM_USER"
    if [ -f /etc/ssha/config.yaml ]; then
      note "keeping the existing /etc/ssha/config.yaml"
    else
      install -m 0600 -o "$SYSTEM_USER" -g "$SYSTEM_USER" \
        "$REPO/internal/cli/template.yaml" /etc/ssha/config.yaml
      note "wrote a starter /etc/ssha/config.yaml"
    fi
  fi

  if [ "$WITH_MCP" = "1" ]; then
    say "installing the MCP service for agents"
    install -m 0644 "$REPO/packaging/systemd/ssha-mcp.service" /etc/systemd/system/ssha-mcp.service
    sed -i "s#--http 127.0.0.1:8765#--http 127.0.0.1:$MCP_PORT#" /etc/systemd/system/ssha-mcp.service
    systemctl daemon-reload
    systemctl enable ssha-mcp.service
    systemctl restart ssha-mcp.service
    note "agents connect to http://127.0.0.1:$MCP_PORT/mcp (needs server.tokens in the config)"
  fi

  if [ "$HEADLESS" = "1" ]; then
    say "installing the headless editor service"
    install -m 0644 "$REPO/packaging/systemd/ssha-ui.service" /etc/systemd/system/ssha-ui.service
    sed -i -e "s#--addr 127.0.0.1:8770#--addr 127.0.0.1:$PORT#" -e "s#ui --addr#ui --headless --addr#" \
      /etc/systemd/system/ssha-ui.service
    systemctl daemon-reload
    systemctl enable ssha-ui.service
    systemctl restart ssha-ui.service
    note "browser mode on http://127.0.0.1:$PORT"
  fi

  say "done"
  note "用户在自己的桌面里从应用菜单打开 ssha；配置在各自的 ~/.config/ssha/"
  [ "$WITH_MCP" = "1" ] && note "agent 侧配置：见 DEPLOY.md 的 MCP 一节"
fi

rm -f "$REPO/ssha.desktop-build"
