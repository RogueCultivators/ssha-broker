#!/usr/bin/env bash
#
# End-to-end test for ssha against a throwaway sshd container.
#
#   ./scripts/e2e.sh            build, run everything, clean up
#   KEEP=1 ./scripts/e2e.sh     leave the container and workdir behind
#
# Requires: docker, ssh-keygen, ssh-keyscan, go, python3

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-2222}"
IMAGE="ssha-e2e-sshd"
CONTAINER="ssha-e2e"
WORK="$(mktemp -d)"
BIN="$WORK/ssha"
FAILED=0

log()  { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }
pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }

check() { # check <description> <expected-exit> <actual-exit>
  if [ "$2" = "$3" ]; then pass "$1 (exit $3)"; else fail "$1: expected exit $2, got $3"; fi
}

contains() { # contains <description> <needle> <haystack>
  if printf '%s' "$3" | grep -qF -- "$2"; then pass "$1"; else fail "$1: %q not found in output" "$2"; printf '%s\n' "$3" | head -20; fi
}

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    rm -rf "$WORK"
  else
    echo "kept: container=$CONTAINER workdir=$WORK"
  fi
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker is required"; exit 1; }
docker info >/dev/null 2>&1 || { echo "cannot talk to the docker daemon"; exit 1; }

# ---------------------------------------------------------------------------
log "build ssha"
( cd "$REPO" && go build -o "$BIN" ./cmd/ssha ) || exit 1
"$BIN" version

# ---------------------------------------------------------------------------
log "start sshd container on 127.0.0.1:$PORT"
docker rm -f "$CONTAINER" >/dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519"
mkdir -p "$WORK/image"
cp "$WORK/id_ed25519.pub" "$WORK/image/authorized_keys"
cat > "$WORK/image/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache openssh bash coreutils grep procps && ssh-keygen -A
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY authorized_keys /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "PermitRootLogin=yes", "-o", "PasswordAuthentication=no"]
EOF
docker build -q -t "$IMAGE" "$WORK/image" >/dev/null || exit 1
docker run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:22" "$IMAGE" >/dev/null || exit 1
for _ in $(seq 1 30); do
  ssh-keyscan -p "$PORT" 127.0.0.1 > "$WORK/known_hosts" 2>/dev/null && [ -s "$WORK/known_hosts" ] && break
  sleep 0.5
done
[ -s "$WORK/known_hosts" ] || { echo "sshd did not come up"; exit 1; }
pass "sshd is reachable and its host keys are pinned"

# ---------------------------------------------------------------------------
log "write config"
cat > "$WORK/ssha.yaml" <<EOF
version: 1
defaults:
  timeout: 30s
  max_output_bytes: 65536
policy:
  mode: allow
  deny_commands:
    - '\bmkfs\b'
audit:
  path: $WORK/audit.jsonl
  store_output: true
hosts:
  - name: testbox
    description: read-only test container
    addr: 127.0.0.1
    port: $PORT
    user: root
    tags: [test, ro]
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {known_hosts: $WORK/known_hosts}
    work_dir: /tmp
    policy:
      mode: readonly
      allow_commands:
        - '^uname\b'
        - '^whoami\b'
        - '^pwd\b'
        - '^ls\b'
        - '^cat\b'
        - '^echo\b'
        - '^id\b'
        - '^hostname\b'
  - name: testbox-rw
    description: read-write test container
    addr: 127.0.0.1
    port: $PORT
    user: root
    tags: [test, rw]
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {known_hosts: $WORK/known_hosts}
    work_dir: /tmp
    policy:
      mode: allow
EOF
export SSHA_CONFIG="$WORK/ssha.yaml"

# ---------------------------------------------------------------------------
log "cli: hosts and policy"
out=$("$BIN" hosts list); contains "hosts list shows both hosts" "testbox-rw" "$out"
out=$("$BIN" hosts list --tag rw); contains "tag filter works" "testbox-rw" "$out"
if printf '%s' "$out" | grep -q "  testbox  "; then fail "tag filter leaked testbox"; else pass "tag filter excludes testbox"; fi

"$BIN" policy check testbox -- ls >/dev/null; check "policy allows ls on readonly host" 0 $?
"$BIN" policy check testbox -- 'curl http://example.com' >/dev/null; check "policy denies curl on readonly host" 77 $?
"$BIN" policy check testbox-rw -- 'mkdir -p /tmp/x' >/dev/null; check "policy allows mkdir on rw host" 0 $?

# ---------------------------------------------------------------------------
log "cli: run"
out=$("$BIN" run testbox -- uname -s); check "run uname on readonly host" 0 $?
contains "run returns stdout" "Linux" "$out"

out=$("$BIN" run testbox --cwd /etc -- pwd); contains "cwd flag is honoured" "/etc" "$out"
out=$("$BIN" run testbox -e FOO=bar -- echo "FOO=\$FOO"); contains "env flag is honoured" "FOO=bar" "$out"
out=$("$BIN" run --json testbox -- uname -s)
contains "json output has audit_id" '"audit_id"' "$out"
contains "json output has decision allowed" '"decision": "allowed"' "$out"

out=$("$BIN" run testbox -- mkfs.ext4 /dev/sda); code=$?
check "denied run exits 77" 77 "$code"
contains "denied run explains itself" "DENIED" "$out"
contains "denied run names the rule" "mkfs" "$out"

out=$("$BIN" run testbox-rw -- 'exit 7'); check "remote exit code is propagated" 7 $?

out=$("$BIN" run testbox-rw --json -- head -c 200000 /dev/zero)
contains "large output is marked truncated" '"truncated": true' "$out"
contains "large output reports the real byte count" '"bytes": 200000' "$out"

# ---------------------------------------------------------------------------
log "cli: multi"
out=$("$BIN" multi --tag test -- uptime); code=$?
check "multi reports denied when one host denies" 77 "$code"
contains "multi reports the allowed host" "testbox-rw" "$out"
contains "multi marks the denied host" "[DENIED]" "$out"

out=$("$BIN" multi --tag rw --json -- uptime); contains "multi json results" '"results"' "$out"

# ---------------------------------------------------------------------------
log "cli: files"
echo "hello from ssha" > "$WORK/hello.txt"
out=$("$BIN" upload testbox-rw "$WORK/hello.txt" /tmp/uploaded/hello.txt); check "upload" 0 $?
contains "upload reports audit id" "audit 2026" "$out"

out=$("$BIN" download testbox-rw /tmp/uploaded/hello.txt -); check "download to stdout" 0 $?
contains "download content round-trips" "hello from ssha" "$out"

"$BIN" download testbox-rw /tmp/uploaded/hello.txt "$WORK/dl.txt" >/dev/null 2>&1
check "download to file" 0 $?
[ "$(cat "$WORK/dl.txt")" = "hello from ssha" ] && pass "downloaded file matches" || fail "downloaded file differs"

out=$("$BIN" upload testbox "$WORK/hello.txt" /tmp/nope.txt 2>&1); code=$?
check "readonly host denies upload" 77 "$code"
contains "readonly upload denial explains itself" "file writes are not permitted" "$out"
out=$("$BIN" download testbox /tmp/uploaded/hello.txt - 2>&1); code=$?
check "readonly host allows download" 0 "$code"

# ---------------------------------------------------------------------------
log "cli: audit"
out=$("$BIN" audit ls --decision denied); contains "audit lists denials" "denied" "$out"
out=$("$BIN" audit ls --host testbox-rw --type upload); contains "audit filters by type" "upload" "$out"
"$BIN" audit verify >/dev/null; check "audit chain verifies" 0 $?

python3 - "$WORK/audit.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
lines = open(p).read().splitlines()
rec = json.loads(lines[1])
rec["command"] = "tampered"
lines[1] = json.dumps(rec, separators=(",", ":"))
open(p, "w").write("\n".join(lines) + "\n")
PY
out=$("$BIN" audit verify 2>&1); code=$?
check "tampering is detected" 1 "$code"
contains "tamper report names the record" "hash mismatch" "$out"

id=$("$BIN" audit ls --json --limit 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["records"][0]["id"])')
out=$("$BIN" audit show "$id"); contains "audit show finds a record" "$id" "$out"

# ---------------------------------------------------------------------------
log "skill"
out=$("$BIN" skill print); contains "skill has frontmatter" "name: ssh-agent" "$out"
out=$("$BIN" skill install --dir "$WORK/skills"); check "skill install" 0 $?
[ -f "$WORK/skills/ssha-agent/SKILL.md" ] && pass "SKILL.md was written" || fail "SKILL.md missing"

# ---------------------------------------------------------------------------
log "mcp over stdio"
out=$(python3 "$REPO/scripts/mcp_smoke.py" "$WORK/ssha.yaml" "$BIN" 2>&1); code=$?
check "mcp smoke test" 0 "$code"
printf '%s\n' "$out" | grep -E '^(MCP SMOKE TEST PASSED|=== tools/call)' | sed 's/^/  /'

# ---------------------------------------------------------------------------
log "mcp over http"
"$BIN" mcp --http 127.0.0.1:8799 >/dev/null 2>&1 &
MCP_PID=$!
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8799/healthz)
[ "$code" = "200" ] && pass "healthz responds" || fail "healthz returned $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8799/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}')
[ "$code" = "200" ] && pass "anonymous loopback MCP initializes" || fail "initialize returned $code"
kill "$MCP_PID" 2>/dev/null

# non-loopback without tokens must refuse to start
out=$("$BIN" mcp --http 0.0.0.0:8798 2>&1); code=$?
check "http without tokens refuses non-loopback" 1 "$code"
contains "refusal explains why" "without tokens" "$out"

# ---------------------------------------------------------------------------
if [ "$FAILED" = "0" ]; then
  printf '\n\033[1;32mALL E2E CHECKS PASSED\033[0m\n'
else
  printf '\n\033[1;31mE2E FAILURES\033[0m\n'
fi
exit "$FAILED"
