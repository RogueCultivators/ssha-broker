#!/usr/bin/env python3
"""Smoke-test the ssha MCP stdio server by speaking raw JSON-RPC.

    ./scripts/mcp_smoke.py <config> [ssha-binary]
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import Server  # noqa: E402

CONFIG = sys.argv[1] if len(sys.argv) > 1 else "ssha.yaml"
BIN = sys.argv[2] if len(sys.argv) > 2 else "ssha"

server = Server(BIN, CONFIG)


def show(title, value):
    print(f"\n=== {title} ===")
    print(json.dumps(value, indent=2)[:2000])


init = server.initialize()
show(
    "initialize",
    {
        "serverInfo": init["serverInfo"],
        "instructions": init.get("instructions", "")[:120],
    },
)

names = server.tool_names()
print("\n=== tools/list ===")
print(names)

allowed = server.call("ssh_exec", {"host": "testbox", "command": "uname -sr"})
show("tools/call ssh_exec (allowed)", allowed)

denied = server.call("ssh_exec", {"host": "testbox", "command": "mkfs.ext4 /dev/sda"})
show("tools/call ssh_exec (denied)", denied)

hosts = server.structured("ssh_list_hosts", {})
show("tools/call ssh_list_hosts", hosts)

audit = server.structured("ssh_audit", {"limit": 3})
show("tools/call ssh_audit", audit["count"])

check = server.structured("ssh_policy_check", {"host": "testbox", "command": "ls /"})
show("tools/call ssh_policy_check", check)

stderr = server.close()
if stderr.strip():
    print("\n=== server stderr ===")
    print(stderr[:1000])

expected = {
    "ssh_list_hosts",
    "ssh_exec",
    "ssh_exec_many",
    "ssh_upload",
    "ssh_download",
    "ssh_policy_check",
    "ssh_audit",
}
assert set(names) == expected, names
assert allowed["structuredContent"]["exit_code"] == 0, allowed
assert "DENIED" in denied["content"][0]["text"], denied
assert check["allowed"] is True, check
print("\nMCP SMOKE TEST PASSED")
