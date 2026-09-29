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
# Ports for the throwaway servers are derived from the pid. Fixed ports let a
# process left over from an earlier run answer the requests instead, which
# produces baffling failures.
BASE_PORT=$(( 18000 + ($$ % 400) * 8 ))
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
  # A herestring, not a pipe: with `set -o pipefail`, `grep -q` exiting on the
  # first match can kill the writer with SIGPIPE and mark the pipeline failed.
  if grep -qF -- "$2" <<<"$3"; then pass "$1"; else fail "$1: \"$2\" not found in output"; head -20 <<<"$3"; fi
}

lacks() { # lacks <description> <needle> <haystack>
  if grep -qF -- "$2" <<<"$3"; then fail "$1: \"$2\" should not be in output"; head -20 <<<"$3"; else pass "$1"; fi
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
# Password auth is enabled too, so the password paths can be tested.
RUN echo 'root:e2e-secret' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e", \
     "-o", "PermitRootLogin=yes", \
     "-o", "PasswordAuthentication=yes"]
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
    # The note is what an agent searches, so it carries the operational detail:
    # what runs here, the unit names and the log paths.
    description: |
      read-only test container. Runs payment-api (systemd unit
      payment-api.service, port 8080, log /var/log/payment/api.log) behind
      nginx, for the checkout flow. Owned by team-payments.
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
  - name: testbox-pw
    description: password auth from an environment variable
    addr: 127.0.0.1
    port: $PORT
    user: root
    tags: [auth]
    auth: {type: password, password_env: SSHA_E2E_PASSWORD}
    host_key: {known_hosts: $WORK/known_hosts}
    policy: {mode: allow}
  - name: testbox-pwfile
    description: password auth from a file
    addr: 127.0.0.1
    port: $PORT
    user: root
    tags: [auth]
    auth: {type: password, password_file: $WORK/password.txt}
    host_key: {known_hosts: $WORK/known_hosts}
    policy: {mode: allow}
  # The identity of this host must never reach the agent.
  - name: secret
    description: identity withheld from agents
    addr: 127.0.0.1
    port: $PORT
    user: root
    tags: [secret]
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {known_hosts: $WORK/known_hosts}
    work_dir: /tmp
    policy:
      mode: allow
      disclosure: alias
      redact_output: true
      redact_patterns: ['\bSECRET-[A-Z0-9]+\b']
EOF
printf 'e2e-secret\n' > "$WORK/password.txt"
chmod 600 "$WORK/password.txt"
export SSHA_CONFIG="$WORK/ssha.yaml"

# ---------------------------------------------------------------------------
log "cli: help"

# A command's own flags only appear here; the general usage lists commands. This
# is how --headless is discoverable, and asking for help is not a usage error.
out=$("$BIN" ui --help 2>&1); code=$?
check "ui --help exits successfully" 0 "$code"
contains "ui --help lists --headless" "--headless" "$out"
lacks "ui --help does not print an internal error" "flag: help requested" "$out"

out=$("$BIN" run --help 2>&1); code=$?
check "run --help exits successfully" 0 "$code"
contains "run --help lists --dry-run" "--dry-run" "$out"

out=$("$BIN" --help 2>&1); code=$?
check "the global --help exits successfully" 0 "$code"
contains "the global --help lists commands" "audit verify" "$out"

# A command with subcommands dispatches on its first argument, so help there has
# to be answered before the dispatch, not reported as an unknown subcommand.
for group in hosts audit policy skill; do
  out=$("$BIN" "$group" --help 2>&1); code=$?
  check "$group --help exits successfully" 0 "$code"
  contains "$group --help lists its subcommands" "Subcommands" "$out"
  lacks "$group --help is not an unknown subcommand" "unknown" "$out"
done

# Every command answers --help with exit 0: a help request is not a mistake.
for c in init hosts host-key run multi upload download policy audit mcp ui skill; do
  out=$("$BIN" "$c" --help 2>&1); code=$?
  check "$c --help exits successfully" 0 "$code"
  lacks "$c --help is not an internal error" "flag: help requested" "$out"
done

# ...including the nested ones.
for c in "hosts test" "hosts show" "hosts import" "audit ls" "audit show" "skill install" "skill print"; do
  # shellcheck disable=SC2086
  out=$("$BIN" $c --help 2>&1); code=$?
  check "$c --help exits successfully" 0 "$code"
done

# An unknown flag is still a usage error, not a help request.
out=$("$BIN" run --nonsense 2>&1); code=$?
check "an unknown flag is a usage error" 2 "$code"
contains "and it says which flag" "nonsense" "$out"

# ---------------------------------------------------------------------------
log "cli: hosts and policy"
out=$("$BIN" hosts list); contains "hosts list shows both hosts" "testbox-rw" "$out"
out=$("$BIN" hosts list --tag rw); contains "tag filter works" "testbox-rw" "$out"
if grep -q "  testbox  " <<<"$out"; then fail "tag filter leaked testbox"; else pass "tag filter excludes testbox"; fi

"$BIN" policy check testbox -- ls >/dev/null; check "policy allows ls on readonly host" 0 $?
"$BIN" policy check testbox -- 'curl http://example.com' >/dev/null; check "policy denies curl on readonly host" 77 $?
"$BIN" policy check testbox-rw -- 'mkdir -p /tmp/x' >/dev/null; check "policy allows mkdir on rw host" 0 $?

# ---------------------------------------------------------------------------
log "cli: discovery (find a host by what it says about itself)"

out=$("$BIN" hosts find payment); check "find by a word from the note" 0 $?
contains "the host is found" "testbox" "$out"
contains "the note is shown in the table" "payment-api" "$out"

out=$("$BIN" hosts find team-payments); contains "the note is searchable by team" "testbox" "$out"
out=$("$BIN" hosts find "systemd unit"); contains "a multi-word phrase works" "testbox" "$out"
out=$("$BIN" hosts find nosuchservice); check "an unmatched query is not an error" 0 $?
contains "an unmatched query says so" "no host matches" "$out"

out=$("$BIN" hosts list --json --query payment)
count=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])' <<<"$out")
[ "$count" = "1" ] && pass "--query filters the host list" || fail "--query matched $count hosts, want 1"
contains "the json carries the note" "payment-api.service" "$out"

out=$("$BIN" hosts show testbox)
contains "hosts show prints the note" "payment-api.service" "$out"
contains "hosts show prints the log path" "/var/log/payment/api.log" "$out"

out=$("$BIN" multi --query payment -- whoami); check "multi --query selects by the note" 0 $?
contains "only the matching host ran" "testbox" "$out"
if printf '%s' "$out" | grep -q "testbox-rw" <<<"$out"; then fail "multi --query was too broad"; else pass "multi --query did not include other hosts"; fi

# ---------------------------------------------------------------------------
log "cli: auth methods"
export SSHA_E2E_PASSWORD="e2e-secret"

out=$("$BIN" hosts test testbox --json); check "key auth self-test" 0 $?
contains "self-test reports the host key fingerprint" 'SHA256:' "$out"
contains "self-test reports the policy mode" '"policy_mode": "readonly"' "$out"

out=$("$BIN" hosts test testbox); check "key auth self-test renders a table" 0 $?
contains "the self-test table shows the host" "testbox" "$out"

out=$("$BIN" hosts test testbox-pw); check "password from an environment variable" 0 $?
out=$("$BIN" hosts test testbox-pwfile); check "password from a file" 0 $?

# Selecting hosts without naming them
out=$("$BIN" hosts test --tag auth 2>&1); check "hosts test --tag" 0 $?
contains "hosts test --tag covers both password hosts" "testbox-pwfile" "$out"

# Without a source and without a terminal, this must fail fast, never hang.
unset SSHA_E2E_PASSWORD
out=$(SSHA_E2E_PASSWORD= "$BIN" hosts test testbox-pw --no-prompt 2>&1); code=$?
check "a missing password source fails instead of hanging" 1 "$code"
contains "the failure names the missing env var" "SSHA_E2E_PASSWORD" "$out"
contains "the failure names the host" "testbox-pw" "$out"
export SSHA_E2E_PASSWORD="e2e-secret"

out=$("$BIN" hosts test --all --json); check "hosts test --all" 0 $?
contains "self-test json carries the fingerprint" '"host_key_fingerprint"' "$out"
contains "self-test json carries the latency" '"latency_ms"' "$out"

# A wrong password fails with the server's rejection, not with a hang.
out=$(SSHA_E2E_PASSWORD=wrong "$BIN" hosts test testbox-pw --no-prompt 2>&1); code=$?
check "a wrong password is reported as a failure" 1 "$code"
contains "the wrong-password failure points at the password" "password is probably wrong" "$out"

# ---------------------------------------------------------------------------
log "cli: host-key onboarding"
SCANNED="$WORK/scanned_known_hosts"

out=$("$BIN" host-key 127.0.0.1:"$PORT" --known-hosts "$SCANNED" 2>&1); check "host-key scans an address" 0 $?
contains "host-key lists the ed25519 key" "ssh-ed25519" "$out"
contains "host-key prints a fingerprint" "SHA256:" "$out"
contains "host-key brackets a non-default port" "[127.0.0.1]:$PORT" "$out"
if [ -f "$SCANNED" ]; then fail "host-key wrote the file without --write"; else pass "host-key does not write without --write"; fi

out=$("$BIN" host-key 127.0.0.1:"$PORT" --known-hosts "$SCANNED" --write); check "host-key --write" 0 $?
[ -s "$SCANNED" ] && pass "known_hosts was written" || fail "known_hosts is empty"

again=$("$BIN" host-key 127.0.0.1:"$PORT" --known-hosts "$SCANNED" --write --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["added"])')
[ "$again" = "0" ] && pass "host-key --write is idempotent" || fail "second --write added $again lines"

out=$("$BIN" host-key testbox 2>&1); check "host-key accepts a configured host name" 0 $?

# The scanned file must actually work on a real connection.
cat > "$WORK/scanned.yaml" <<EOF
version: 1
audit: {path: $WORK/audit.jsonl}
hosts:
  - name: scanned
    addr: 127.0.0.1
    port: $PORT
    user: root
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {known_hosts: $SCANNED}
    policy: {mode: allow}
EOF
out=$("$BIN" -c "$WORK/scanned.yaml" run scanned -- uname -s); check "a scanned known_hosts works for real" 0 $?
contains "the scanned connection returned output" "Linux" "$out"

# A pinned fingerprint that does not match must be rejected, with both shown.
cat > "$WORK/wrongfp.yaml" <<EOF
version: 1
audit: {path: $WORK/audit.jsonl}
hosts:
  - name: wpinned
    addr: 127.0.0.1
    port: $PORT
    user: root
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {fingerprints: ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}
    policy: {mode: allow}
EOF
out=$("$BIN" -c "$WORK/wrongfp.yaml" run wpinned -- uname -s 2>&1); code=$?
check "a wrong pinned fingerprint is rejected" 1 "$code"
contains "the rejection quotes the fingerprint the server offered" "SHA256:" "$out"
contains "the rejection says it is not configured" "not in the configured fingerprints" "$out"

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
log "cli: privacy (disclosure and redaction)"

# The agent-facing view must not carry the address or the user name.
out=$("$BIN" hosts show secret); check "hosts show on a hidden host" 0 $?
contains "the hidden host keeps its description" "identity withheld" "$out"
contains "the hidden host still shows its policy" "policy mode" "$out"
contains "the hidden host says the address is withheld" "withheld by policy" "$out"
if grep -qE '127\.0\.0\.1|root@' <<<"$out"; then fail "hosts show leaked the address or user"; else pass "hosts show reveals no address or user"; fi

# The operator can always look; that is what --reveal is for.
out=$("$BIN" --reveal hosts show secret)
contains "--reveal shows the address again" "root@127.0.0.1:$PORT" "$out"

# The machine-readable form matters most: that is what an agent parses.
if "$BIN" hosts list --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
h = [x for x in d["hosts"] if x["name"] == "secret"][0]
sys.exit(0 if "addr" not in h and "user" not in h and "auth" not in h else 1)
'; then
  pass "the json host list omits addr, user and auth"
else
  fail "the json host list leaked identity"
fi

# Redaction covers whatever a command happens to print. Put the secrets in a
# file on the remote so the command itself stays clean - that is the realistic
# case, and it means only the output can leak them.
printf 'addr=127.0.0.1:%s user=root token=SECRET-ABC123\n' "$PORT" > "$WORK/leak.txt"
"$BIN" upload secret "$WORK/leak.txt" /tmp/leak.txt >/dev/null; check "upload to a hidden host" 0 $?

out=$("$BIN" run secret -- cat /tmp/leak.txt)
check "a command on a hidden host runs" 0 $?
contains "the address is redacted" "addr=<host>" "$out"
contains "the user name is redacted" "user=<user>" "$out"
contains "a custom redact_pattern is replaced" "token=<redacted>" "$out"
if grep -qE '127\.0\.0\.1|SECRET-ABC123' <<<"$out"; then fail "raw identity survived redaction"; else pass "no raw identity or secret survived"; fi

out=$("$BIN" run secret -- whoami)
contains "whoami is redacted" "<user>" "$out"

out=$("$BIN" run secret --json -- cat /tmp/leak.txt)
check "a redacted json run succeeds" 0 $?
if grep -qE '127\.0\.0\.1|SECRET-ABC123' <<<"$out"; then fail "the json result leaked"; else pass "the json result is redacted too"; fi

# The self-test is an operator tool, but an agent can run it too.
out=$("$BIN" hosts test secret --json)
check "hosts test on a hidden host" 0 $?
contains "hosts test still reports success" '"ok": true' "$out"
if grep -qE '127\.0\.0\.1|"addr"|"user"|"auth"|SHA256:' <<<"$out"; then
  fail "hosts test leaked identity or the host key"
else
  pass "hosts test omits the identity fields and the host key"
fi
out=$("$BIN" --reveal hosts test secret)
contains "--reveal shows the host key fingerprint" "SHA256:" "$out"

# An error message is the easiest place to leak an address by accident.
cat > "$WORK/badhost.yaml" <<EOF
version: 1
audit: {path: $WORK/audit.jsonl}
hosts:
  - name: unreachable
    addr: 127.0.0.1
    port: 1
    user: root
    auth: {type: key, key_path: $WORK/id_ed25519}
    host_key: {insecure: true}
    policy: {mode: allow, disclosure: alias, redact_output: true, timeout: 1s}
EOF
out=$($BIN -c "$WORK/badhost.yaml" run unreachable -- uname -s 2>&1)
if grep -qE '127\.0\.0\.1|:1\b' <<<"$out"; then fail "a connection error leaked the address"; else pass "connection errors are redacted too"; fi

# The same must hold on the self-test failure path, which is easy to forget.
out=$($BIN -c "$WORK/badhost.yaml" hosts test unreachable --json 2>&1)
if grep -qE '127\.0\.0\.1|"addr"|"user"|"auth"' <<<"$out"; then
  fail "a failed self-test leaked identity"
else
  pass "a failed self-test is clean too"
fi
contains "the failed self-test still explains why" "connection refused" "$out"

# The audit log is the operator's own record: it keeps the original text.
if grep -q "SECRET-ABC123" "$WORK/audit.jsonl"; then pass "the audit log keeps the raw output"; else fail "the audit log lost the raw output"; fi

# ...but the agent's read of that log is scrubbed as well.
out=$("$BIN" audit ls --host secret --json)
if grep -q "SECRET-ABC123" <<<"$out"; then fail "the agent-facing audit leaked the pattern"; else pass "the agent-facing audit is redacted"; fi
out=$("$BIN" --reveal audit ls --host secret --json)
contains "--reveal restores the raw audit" "SECRET-ABC123" "$out"

# A denial reason must not leak either.
out=$("$BIN" run secret -- mkfs.ext4 /dev/sda 2>&1); code=$?
check "a denied command on a hidden host" 77 "$code"
if grep -qE '127\.0\.0\.1|root@' <<<"$out"; then fail "the denial leaked identity"; else pass "the denial is clean"; fi

# MCP is the surface an agent actually uses, so prove it holds the line.
if out=$(python3 "$REPO/scripts/mcp_privacy.py" "$WORK/ssha.yaml" "$BIN" 127.0.0.1 2>&1); then
  pass "mcp never reveals host identity"
else
  fail "mcp privacy check"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

# ...and it must not be possible to talk it out of hiding things, even if the
# operator passes the flag that normally reveals them at the CLI.
if out=$(python3 "$REPO/scripts/mcp_privacy.py" "$WORK/ssha.yaml" "$BIN" 127.0.0.1 --reveal 2>&1); then
  pass "mcp ignores --reveal"
else
  fail "mcp honoured --reveal"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

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
log "cli: import from an ssh config"

# Mirror the test container the way a user's ssh config would, and give HOME a
# known_hosts so the imported host can verify the server with no extra setup.
mkdir -p "$WORK/home/.ssh"
cp "$WORK/known_hosts" "$WORK/home/.ssh/known_hosts"
cat > "$WORK/ssh_config" <<EOF
# imported by the e2e run
Host *
    User root

Host testbox-imported
    HostName 127.0.0.1
    Port $PORT
    IdentityFile $WORK/id_ed25519

Host *.example.com
    User someone
EOF
as_home() { env HOME="$WORK/home" SSHA_CONFIG="$WORK/ssha.yaml" "$BIN" "$@"; }

out=$(as_home hosts import --file "$WORK/ssh_config" --policy-mode readonly --dry-run)
check "a dry run reports what it would do" 0 $?
contains "the dry run lists the alias" "testbox-imported" "$out"
contains "the dry run warns about the pattern block" "*.example.com" "$out"
if grep -q "testbox-imported" "$WORK/ssha.yaml"; then fail "a dry run wrote to the config"; else pass "a dry run writes nothing"; fi

out=$(as_home hosts import --file "$WORK/ssh_config" --policy-mode readonly --tag imported-test)
check "the import runs" 0 $?
contains "the import reports the alias" "testbox-imported" "$out"
contains "the extra tag was applied" "imported-test" "$(cat "$WORK/ssha.yaml")"
contains "the readonly mode seeded an allow list" "allow_commands" "$(cat "$WORK/ssha.yaml")"

# The whole point: an imported host is immediately usable.
out=$(as_home hosts test testbox-imported); check "the imported host connects" 0 $?
contains "it verified the server against the default known_hosts" "SHA256:" "$out"
out=$(as_home run testbox-imported -- uname -s); check "the imported host runs a command" 0 $?
contains "and returns output" "Linux" "$out"
out=$(as_home run testbox-imported -- mkfs.ext4 /dev/sda 2>&1); code=$?
check "the seeded readonly allow list still blocks a destructive command" 77 "$code"

out=$(as_home hosts import --file "$WORK/ssh_config" --policy-mode readonly)
check "a second import is not an error" 0 $?
contains "a second import skips what is already there" "skipped" "$out"

# ---------------------------------------------------------------------------
log "ui (config editor)"

# This is the pure Go build, so asking for a window must explain itself rather
# than fail obscurely. A desktop build is exercised by the desktop workflow.
out=$("$BIN" -c "$WORK/ssha.yaml" ui 2>&1); code=$?
check "ui without a desktop build exits with a message" 1 "$code"
contains "the message says how to get a window" "桌面界面" "$out"
contains "and points at the headless mode" "--headless" "$out"

UI_PORT=$(( BASE_PORT + 0 ))
# Start from the commented template so the edit has real comments to preserve.
"$BIN" init --out "$WORK/ui.yaml" --force >/dev/null
# Its own HOME, so the skill locations the editor offers land in the work dir
# instead of the machine's real ~/.agents/skills.
mkdir -p "$WORK/home"
# --headless: this build is the pure Go one, so `ui` on its own has no window
# and says so. The headless mode is the same handler, which is why it is what
# the tests drive.
env HOME="$WORK/home" "$BIN" -c "$WORK/ui.yaml" ui --headless --addr 127.0.0.1:$UI_PORT >"$WORK/ui.log" 2>&1 &
UI_PID=$!
for _ in $(seq 1 40); do grep -q 'token=' "$WORK/ui.log" && break; sleep 0.25; done
TOKEN=$(grep -o 'token=[a-f0-9]*' "$WORK/ui.log" | head -1 | cut -d= -f2)
[ -n "$TOKEN" ] && pass "the editor prints a tokenised url" || fail "no token in: $(cat "$WORK/ui.log")"

contains "the startup output says which url to open" "用浏览器打开下面这条地址" "$(cat "$WORK/ui.log")"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$UI_PORT/")
[ "$code" = "200" ] && pass "the editor page is served" || fail "index returned $code"
curl -s "http://127.0.0.1:$UI_PORT/" > "$WORK/page.html"
contains "the page explains the token to a visitor who lacks one" "这个界面需要命令行里那个 token" "$(cat "$WORK/page.html")"

# A port we cannot take must fail loudly. Printing a URL for a port somebody
# else owns would send the operator to the wrong server.
out=$("$BIN" -c "$WORK/ui.yaml" ui --headless --addr 127.0.0.1:$UI_PORT 2>&1); code=$?
check "a taken port is reported instead of printing a wrong url" 1 "$code"
contains "the bind failure is explicit" "无法监听" "$out"
grep -q "备注" <<<"$(cat "$WORK/page.html")" && pass "the page is the editor (and speaks Chinese)" || fail "the page looks wrong"
contains "the status badges are Chinese, not allow/readonly/deny" 'allow: "允许"' "$(cat "$WORK/page.html")"
contains "the auth labels are Chinese too" 'password: "密码"' "$(cat "$WORK/page.html")"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$UI_PORT/api/state")
[ "$code" = "401" ] && pass "the api refuses a request without the token" || fail "the api returned $code without a token"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-SSHA-Token: wrong" "http://127.0.0.1:$UI_PORT/api/state")
[ "$code" = "401" ] && pass "the api refuses a wrong token" || fail "the api returned $code for a wrong token"

out=$(curl -s -H "X-SSHA-Token: $TOKEN" "http://127.0.0.1:$UI_PORT/api/state")
contains "state lists the hosts" '"prod-web"' "$out"
contains "state reports the effective policy" '"effective_mode"' "$out"

# Creating a host from the editor: the file must survive with its comments.
before_comments=$(grep -c '^[[:space:]]*#' "$WORK/ui.yaml")
[ "$before_comments" -gt 50 ] && pass "the template starts with $before_comments commented lines" || fail "only $before_comments comments to start with"
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' -X POST "http://127.0.0.1:$UI_PORT/api/hosts" -d '{
  "name": "ui-made",
  "addr": "10.9.9.9",
  "user": "deploy",
  "description": "编辑器的测试机器。跑 billing-api。",
  "tags": ["ui"],
  "auth": {"type": "key", "key_path": "/tmp/k"}
}'); check "the editor creates a host" 0 $?
contains "creation is acknowledged" "ui-made" "$out"
contains "the host landed in the file" "name: ui-made" "$(cat "$WORK/ui.yaml")"
contains "its note landed too" "跑 billing-api" "$(cat "$WORK/ui.yaml")"
after_comments=$(grep -c '^[[:space:]]*#' "$WORK/ui.yaml")
[ "$before_comments" = "$after_comments" ] && pass "all $after_comments comments survived the edit" || fail "comments went from $before_comments to $after_comments"
contains "an untouched host kept its nested comments" "# 加密私钥的口令来源" "$(cat "$WORK/ui.yaml")"
if grep -qP '[ \t]+$' "$WORK/ui.yaml"; then fail "the editor left trailing whitespace"; else pass "no trailing whitespace was left behind"; fi

# Editing an existing host must not drop the fields the editor did not send.
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' -X POST "http://127.0.0.1:$UI_PORT/api/hosts" -d '{"name":"prod-web","addr":"10.0.0.10","user":"deploy","description":"edited","auth":{"type":"key","key_path":"~/.ssh/id_ed25519"},"policy":{"mode":"allow"}}')
contains "an existing host can be edited" "prod-web" "$out"
out=$("$BIN" -c "$WORK/ui.yaml" hosts show prod-web --json)
contains "the edit took effect" "edited" "$out"
contains "the policy override took effect" '"policy_mode": "allow"' "$out"
out=$("$BIN" -c "$WORK/ui.yaml" hosts find ui-made)
contains "a host created by the editor is searchable by its note" "ui-made" "$out"

# 接入 agent：装 skill、拿 MCP 配置
out=$(curl -s -H "X-SSHA-Token: $TOKEN" "http://127.0.0.1:$UI_PORT/api/skill")
contains "the skill api names the skill" '"ssha-agent"' "$out"
contains "it offers install locations" '"targets"' "$out"
contains "it offers an mcp snippet" 'mcpServers' "$out"
contains "the snippet uses an absolute binary path" "$BIN" "$out"

SKILLDIR="$WORK/home/.agents/skills"
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/skill/install" -d "{\"dir\":\"$SKILLDIR\"}")
check "installing the skill" 0 $?
contains "installation reports the path" "$SKILLDIR/ssha-agent/SKILL.md" "$out"
[ -f "$SKILLDIR/ssha-agent/SKILL.md" ] && pass "SKILL.md was written" || fail "SKILL.md missing"
contains "the installed skill has frontmatter" "name: ssh-agent" "$(cat "$SKILLDIR/ssha-agent/SKILL.md")"
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/skill/install" -d "{\"dir\":\"$SKILLDIR\"}")
contains "installing again is an update, not an error" '"existed":true' "$out"
out=$(curl -s -H "X-SSHA-Token: $TOKEN" "http://127.0.0.1:$UI_PORT/api/skill" \
  | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["targets"][0]))')
contains "the target now reports as installed" '"exists": true' "$out"
contains "and as up to date" '"up_to_date": true' "$out"

out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/skill/install" -d '{"dir":"/tmp/../etc"}')
contains "a .. path component is refused" ".." "$out"
if [ -f /etc/ssha-agent/SKILL.md ]; then fail "the editor wrote outside its directory"; else pass "nothing was written outside the directory"; fi

curl -s -D "$WORK/skill-headers" -o "$WORK/SKILL.md" -H "X-SSHA-Token: $TOKEN" \
  "http://127.0.0.1:$UI_PORT/api/skill/download"
contains "the download is served as markdown" "text/markdown" "$(cat "$WORK/skill-headers")"
contains "the download is an attachment" "attachment" "$(cat "$WORK/skill-headers")"
contains "the download is the real skill" "name: ssh-agent" "$(cat "$WORK/SKILL.md")"

# The rejected edit must not corrupt the file.
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' -X POST "http://127.0.0.1:$UI_PORT/api/hosts" -d '{"name":"broken","auth":{"type":"key"}}')
contains "an invalid host is rejected" "error" "$out"
if grep -q "name: broken" "$WORK/ui.yaml"; then fail "the rejected host was written anyway"; else pass "the rejected host was not written"; fi

out=$(curl -s -H "X-SSHA-Token: $TOKEN" "http://127.0.0.1:$UI_PORT/api/audit?limit=5")
contains "the audit panel has data" '"records"' "$out"

# Typing a password in the editor stores it beside the config, never in it.
pwfile="$WORK/secrets/ui-made.password"
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/secret" -d '{"host":"ui-made","kind":"password","value":"e2e-secret-pw"}')
check "the editor stores a password" 0 $?
contains "storing reports where it went" "password" "$out"
[ -f "$pwfile" ] && pass "the secret file was created next to the config" || fail "no secret file at $pwfile"
mode=$(stat -c '%a' "$pwfile" 2>/dev/null)
[ "$mode" = "600" ] && pass "the secret file is 0600" || fail "secret file mode is $mode"
contains "the config references the secret" "password_file" "$(cat "$WORK/ui.yaml")"
if grep -q "e2e-secret-pw" "$WORK/ui.yaml"; then fail "the password was written into the config"; else pass "the password is not in the config"; fi

out=$(curl -s -H "X-SSHA-Token: $TOKEN" "http://127.0.0.1:$UI_PORT/api/state")
ready=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(h["password_ready"] for h in d["hosts"] if h["name"]=="ui-made"))' <<<"$out")
[ "$ready" = "True" ] && pass "the state reports the password as ready" || fail "password_ready is $ready"
if printf '%s' "$out" | grep -q "e2e-secret-pw"; then fail "the password leaked into the state"; else pass "the password never appears in a response"; fi
contains "the state says where secrets live" "secrets_dir" "$out"

# Clearing removes the file and the reference together.
curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/secret" -d '{"host":"ui-made","kind":"password","value":""}' >/dev/null
if [ -f "$pwfile" ]; then fail "clearing did not delete the secret file"; else pass "clearing deletes the secret file"; fi
if python3 - "$WORK/ui.yaml" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
host = next((h for h in cfg["hosts"] if h["name"] == "ui-made"), {})
sys.exit(1 if (host.get("auth") or {}).get("password_file") else 0)
PY
then pass "clearing removes the reference"; else fail "clearing left the reference behind"; fi

# The whole point: a password typed into the editor is one the broker actually
# uses. Create a host for the test container, store the real password through the
# API, and connect.
out=$(curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' -X POST "http://127.0.0.1:$UI_PORT/api/hosts" -d "{
  \"name\": \"ui-pw\",
  \"addr\": \"127.0.0.1\",
  \"port\": $PORT,
  \"user\": \"root\",
  \"description\": \"password typed in the editor\",
  \"auth\": {\"type\": \"password\"},
  \"host_key\": {\"known_hosts\": \"$WORK/known_hosts\"}
}"); check "a password host can be created" 0 $?
curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/secret" -d '{"host":"ui-pw","kind":"password","value":"e2e-secret"}' >/dev/null
out=$("$BIN" -c "$WORK/ui.yaml" run ui-pw -- uname -s 2>&1); check "a password typed in the editor really connects" 0 $?
contains "and returns output" "Linux" "$out"

# A wrong password must fail, or the check above proves nothing.
curl -s -H "X-SSHA-Token: $TOKEN" -H 'Content-Type: application/json' \
  -X POST "http://127.0.0.1:$UI_PORT/api/secret" -d '{"host":"ui-pw","kind":"password","value":"wrong"}' >/dev/null
out=$("$BIN" -c "$WORK/ui.yaml" run ui-pw -- uname -s 2>&1); code=$?
check "a wrong stored password fails" 1 "$code"
contains "with an explanation" "password is probably wrong" "$out"

curl -s -H "X-SSHA-Token: $TOKEN" -X DELETE "http://127.0.0.1:$UI_PORT/api/hosts/ui-made" >/dev/null
if grep -q "name: ui-made" "$WORK/ui.yaml"; then fail "delete did not remove the host"; else pass "the editor deletes a host"; fi

kill $UI_PID 2>/dev/null
wait $UI_PID 2>/dev/null

out=$("$BIN" -c "$WORK/ui.yaml" ui --headless --addr 0.0.0.0:$(( BASE_PORT + 1 )) 2>&1); code=$?
check "the editor refuses a non-loopback address" 1 "$code"
contains "the refusal explains itself" "拒绝把界面绑到" "$out"

# A persisted token is what makes a bookmarked URL survive a service restart.
PERSIST_PORT=$(( BASE_PORT + 4 ))
TF="$WORK/ui.token"
"$BIN" -c "$WORK/ui.yaml" ui --headless --addr 127.0.0.1:$PERSIST_PORT --token-file "$TF" >"$WORK/ui2.log" 2>&1 &
UI2=$!
for _ in $(seq 1 40); do [ -s "$TF" ] && break; sleep 0.25; done
first_token=$(cat "$TF" 2>/dev/null)
[ -n "$first_token" ] && pass "the token file was created" || fail "no token file was written"
mode=$(stat -c '%a' "$TF" 2>/dev/null)
[ "$mode" = "600" ] && pass "the token file is 0600" || fail "token file mode is $mode"
kill $UI2 2>/dev/null; wait $UI2 2>/dev/null

"$BIN" -c "$WORK/ui.yaml" ui --headless --addr 127.0.0.1:$PERSIST_PORT --token-file "$TF" >"$WORK/ui3.log" 2>&1 &
UI3=$!
for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$PERSIST_PORT/" && break; sleep 0.25; done
second_token=$(cat "$TF")
[ "$first_token" = "$second_token" ] && pass "a persisted token survives a restart" || fail "the token changed: $first_token -> $second_token"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-SSHA-Token: $first_token" "http://127.0.0.1:$PERSIST_PORT/api/state")
[ "$code" = "200" ] && pass "the bookmarked token still works after the restart" || fail "the old token returned $code"
kill $UI3 2>/dev/null; wait $UI3 2>/dev/null

# ---------------------------------------------------------------------------
log "mcp over http"
"$BIN" mcp --http 127.0.0.1:$(( BASE_PORT + 2 )) >/dev/null 2>&1 &
MCP_PID=$!
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$(( BASE_PORT + 2 ))/healthz)
[ "$code" = "200" ] && pass "healthz responds" || fail "healthz returned $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$(( BASE_PORT + 2 ))/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}')
[ "$code" = "200" ] && pass "anonymous loopback MCP initializes" || fail "initialize returned $code"
kill "$MCP_PID" 2>/dev/null

# non-loopback without tokens must refuse to start
out=$("$BIN" mcp --http 0.0.0.0:$(( BASE_PORT + 3 )) 2>&1); code=$?
check "http without tokens refuses non-loopback" 1 "$code"
contains "refusal explains why" "without tokens" "$out"

# ---------------------------------------------------------------------------
if [ "$FAILED" = "0" ]; then
  printf '\n\033[1;32mALL E2E CHECKS PASSED\033[0m\n'
else
  printf '\n\033[1;31mE2E FAILURES\033[0m\n'
fi
exit "$FAILED"
