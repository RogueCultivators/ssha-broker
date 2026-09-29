#!/usr/bin/env bash
#
# Install ssha and its systemd units.
#
#   ./packaging/install.sh --user            no root: binary in ~/.local/bin, a
#                                            systemd *user* service
#   sudo ./packaging/install.sh --system     a dedicated ssha user, binary in
#                                            /usr/local/bin, system services
#
# Idempotent: running it again upgrades the binary and refreshes the units
# without touching an existing config or audit log.

set -euo pipefail

MODE=""
WITH_MCP=0
PORT=8770
MCP_PORT=8765
SYSTEM_USER="ssha"
while [ $# -gt 0 ]; do
  case "$1" in
    --user) MODE=user ;;
    --system) MODE=system ;;
    --with-mcp) WITH_MCP=1 ;;
    --port) PORT="$2"; shift ;;
    --mcp-port) MCP_PORT="$2"; shift ;;
    --user-name) SYSTEM_USER="$2"; shift ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "$MODE" ]; then
  echo "pick one: --user (no root) or --system (needs root)" >&2
  exit 2
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(git -C "$REPO" describe --tags --always --dirty 2>/dev/null || echo dev)"
BIN="$(mktemp -d)/ssha"

say() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }

say "building ssha $VERSION"
(cd "$REPO" && go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$BIN" ./cmd/ssha)
"$BIN" version

install_unit() { # install_unit <source> <destination>
  install -m 0644 "$1" "$2"
  note "installed $2"
}

# ---------------------------------------------------------------------------
if [ "$MODE" = "user" ]; then
  BINDIR="$HOME/.local/bin"
  CONFDIR="$HOME/.config/ssha"
  STATEDIR="$HOME/.local/state/ssha"
  UNITDIR="$HOME/.config/systemd/user"

  say "installing the binary"
  install -d "$BINDIR"
  install -m 0755 "$BIN" "$BINDIR/ssha"
  note "$BINDIR/ssha"

  say "preparing the config"
  install -d -m 0700 "$CONFDIR" "$STATEDIR"
  if [ -f "$CONFDIR/config.yaml" ]; then
    note "keeping the existing $CONFDIR/config.yaml"
  else
    install -m 0600 "$REPO/internal/cli/template.yaml" "$CONFDIR/config.yaml"
    note "wrote a starter $CONFDIR/config.yaml - edit it, or use the editor itself"
  fi

  say "installing the user service"
  install -d "$UNITDIR"
  install_unit "$REPO/packaging/systemd/ssha-ui.user.service" "$UNITDIR/ssha-ui.service"

  systemctl --user daemon-reload
  systemctl --user enable --now ssha-ui.service
  note "started ssha-ui.service"

  # Without linger the service stops when you log out.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
    if loginctl enable-linger "$USER" 2>/dev/null; then
      note "enabled linger so the service survives logout"
    else
      note "could not enable linger; run: sudo loginctl enable-linger $USER"
    fi
  fi

  say "open the editor"
  for _ in $(seq 1 40); do
    [ -s "$STATEDIR/ui.token" ] && break
    sleep 0.25
  done
  if [ -s "$STATEDIR/ui.token" ]; then
    note "http://127.0.0.1:$PORT/?token=$(tr -d '\n' < "$STATEDIR/ui.token")"
    note "(the token is kept in $STATEDIR/ui.token, so this URL survives restarts)"
  else
    note "the service did not write a token; check: systemctl --user status ssha-ui"
  fi
  note ""
  note "logs:    journalctl --user -u ssha-ui -f"
  note "restart: systemctl --user restart ssha-ui"
  note "stop:    systemctl --user disable --now ssha-ui"

# ---------------------------------------------------------------------------
else
  if [ "$(id -u)" != "0" ]; then
    echo "--system needs root: sudo $0 --system" >&2
    exit 1
  fi

  say "creating the $SYSTEM_USER user"
  if id "$SYSTEM_USER" >/dev/null 2>&1; then
    note "user $SYSTEM_USER already exists"
  else
    useradd --system --create-home --home-dir "/var/lib/$SYSTEM_USER" \
      --shell /usr/sbin/nologin "$SYSTEM_USER"
    note "created user $SYSTEM_USER"
  fi

  say "installing the binary"
  install -m 0755 "$BIN" /usr/local/bin/ssha
  note "/usr/local/bin/ssha"

  say "preparing /etc/ssha"
  install -d -m 0700 -o "$SYSTEM_USER" -g "$SYSTEM_USER" /etc/ssha
  if [ -f /etc/ssha/config.yaml ]; then
    note "keeping the existing /etc/ssha/config.yaml"
  else
    install -m 0600 -o "$SYSTEM_USER" -g "$SYSTEM_USER" \
      "$REPO/internal/cli/template.yaml" /etc/ssha/config.yaml
    note "wrote a starter /etc/ssha/config.yaml - edit it before enabling agents"
  fi
  # StateDirectory= in the unit creates /var/lib/ssha, but create it now so the
  # token file has somewhere to go on first start.
  install -d -m 0700 -o "$SYSTEM_USER" -g "$SYSTEM_USER" "/var/lib/$SYSTEM_USER"

  say "installing the services"
  install_unit "$REPO/packaging/systemd/ssha-ui.service" /etc/systemd/system/ssha-ui.service
  if [ "$WITH_MCP" = "1" ]; then
    install_unit "$REPO/packaging/systemd/ssha-mcp.service" /etc/systemd/system/ssha-mcp.service
  fi

  # Reflect the chosen ports in the units.
  sed -i "s#--addr 127.0.0.1:8770#--addr 127.0.0.1:$PORT#" /etc/systemd/system/ssha-ui.service
  [ "$WITH_MCP" = "1" ] && sed -i "s#--http 127.0.0.1:8765#--http 127.0.0.1:$MCP_PORT#" /etc/systemd/system/ssha-mcp.service

  systemctl daemon-reload
  systemctl enable --now ssha-ui.service
  note "started ssha-ui.service"
  if [ "$WITH_MCP" = "1" ]; then
    systemctl enable --now ssha-mcp.service
    note "started ssha-mcp.service (agents connect to http://127.0.0.1:$MCP_PORT/mcp)"
  fi

  say "open the editor"
  for _ in $(seq 1 40); do
    [ -s "/var/lib/$SYSTEM_USER/ui.token" ] && break
    sleep 0.25
  done
  if [ -s "/var/lib/$SYSTEM_USER/ui.token" ]; then
    note "http://127.0.0.1:$PORT/?token=$(tr -d '\n' < "/var/lib/$SYSTEM_USER/ui.token")"
    note "readable only by root and $SYSTEM_USER - that is the point"
  fi
  note ""
  note "logs:    journalctl -u ssha-ui -f"
  note "restart: systemctl restart ssha-ui"
  note "next:    sudo -u $SYSTEM_USER ssha --config /etc/ssha/config.yaml hosts list"
fi
