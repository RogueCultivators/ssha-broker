#!/usr/bin/env python3
"""Assert that the MCP surface never reveals a host's identity.

This is the path an agent actually uses, so it is the one that must hold the
line: the address, the user name and anything matching redact_patterns must be
absent from every tool result, while the audit log on disk keeps the original.

Expects /tmp/leak.txt on the target to contain the address, the user name and
the token; ``scripts/e2e.sh`` uploads it first. The point is that the *command*
(`cat /tmp/leak.txt`) is clean, so anything that leaks came from the output.

    ./scripts/mcp_privacy.py <config> [ssha-binary] [address]
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import Server  # noqa: E402

CONFIG = sys.argv[1] if len(sys.argv) > 1 else "ssha.yaml"
BIN = sys.argv[2] if len(sys.argv) > 2 else "ssha"
ADDR = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
EXTRA = sys.argv[4:]
HOST = "secret"

FORBIDDEN = [ADDR, "root@", "SECRET-ABC123"]
IDENTITY_KEYS = ["addr", "user", "auth", "proxy_jump", "work_dir"]

failures = []


def check(desc, ok, detail=""):
    if ok:
        print(f"  ok   {desc}")
    else:
        failures.append(desc)
        print(f"  FAIL {desc}{': ' + detail if detail else ''}")


def assert_clean(desc, blob):
    leaks = [needle for needle in FORBIDDEN if needle in blob]
    check(desc, not leaks, f"leaked {leaks}: {blob[:300]}")


server = Server(BIN, CONFIG, EXTRA)
try:
    server.initialize()

    # The inventory must not carry identity for a host whose disclosure hides it.
    hosts = server.structured("ssh_list_hosts", {})
    entry = next((h for h in hosts["hosts"] if h["name"] == HOST), None)
    check("the hidden host is still listed", entry is not None)
    if entry:
        for key in IDENTITY_KEYS:
            check(f"the {HOST} entry has no {key} field", key not in entry, json.dumps(entry))
        check("the policy is still described", entry.get("policy_mode") == "allow", json.dumps(entry))
        check("the tags are still there", entry.get("tags") == ["secret"], json.dumps(entry))
        assert_clean("the hidden host's entry is clean", json.dumps(entry))

    # Output must be scrubbed in both the text and the structured form. The
    # command carries no secrets: it only cats a file the agent cannot read any
    # other way.
    leak_cmd = "cat /tmp/leak.txt"
    text = server.text("ssh_exec", {"host": HOST, "command": leak_cmd})
    structured = server.structured("ssh_exec", {"host": HOST, "command": leak_cmd})
    assert_clean("ssh_exec text is clean", text)
    check("the host placeholder is used", "<host>" in text, text)
    check("the user placeholder is used", "<user>" in text, text)
    check("the custom pattern is replaced", "<redacted>" in text, text)
    assert_clean("ssh_exec structured content is clean", json.dumps(structured))
    check("the command still ran", structured["exit_code"] == 0, json.dumps(structured))

    # whoami is the obvious attempt to learn the account.
    whoami = server.text("ssh_exec", {"host": HOST, "command": "whoami"})
    assert_clean("whoami is scrubbed", whoami)
    check("whoami returns the placeholder", "<user>" in whoami, repr(whoami))

    # Policy reasons and errors must not leak either.
    denied = server.text("ssh_exec", {"host": HOST, "command": "mkfs.ext4 /dev/sda"})
    check("the denial is reported", "DENIED" in denied, denied)
    assert_clean("the denial reason is clean", denied)

    failed = server.text("ssh_exec", {"host": HOST, "command": "exit 3"})
    assert_clean("a failing command is clean", failed)

    # History must not become a side channel.
    audit = server.structured("ssh_audit", {"host": HOST, "limit": 20})
    assert_clean("ssh_audit is clean", json.dumps(audit))
    check("audit records came back", audit["count"] > 0, repr(audit["count"]))
finally:
    stderr = server.close()

if stderr.strip():
    print("\n=== server stderr ===")
    print(stderr[:1000])

if failures:
    print("\nMCP PRIVACY TEST FAILED: " + "; ".join(failures))
    sys.exit(1)
print("\nMCP PRIVACY TEST PASSED")
