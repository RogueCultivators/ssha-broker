#!/usr/bin/env python3
"""Smoke-test the ssha MCP stdio server by speaking raw JSON-RPC."""
import json
import subprocess
import sys
import os

CONFIG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sshatest/ssha.yaml"
BIN = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ssha"

proc = subprocess.Popen(
    [BIN, "-c", CONFIG, "mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

next_id = [0]


def send(method, params=None, notify=False):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not notify:
        next_id[0] += 1
        msg["id"] = next_id[0]
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    if notify:
        return None
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read()
        raise SystemExit(f"no response to {method}; stderr:\n{err}")
    return json.loads(line)


def show(title, resp):
    print(f"\n=== {title} ===")
    print(json.dumps(resp, indent=2)[:2000])


init = send(
    "initialize",
    {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "smoke", "version": "1"},
    },
)
show("initialize", {"serverInfo": init["result"]["serverInfo"], "instructions": init["result"].get("instructions", "")[:120]})
send("notifications/initialized", notify=True)

tools = send("tools/list")
names = [t["name"] for t in tools["result"]["tools"]]
print("\n=== tools/list ===")
print(names)

exec_resp = send(
    "tools/call",
    {"name": "ssh_exec", "arguments": {"host": "testbox", "command": "uname -sr"}},
)
show("tools/call ssh_exec (allowed)", exec_resp["result"])

deny_resp = send(
    "tools/call",
    {"name": "ssh_exec", "arguments": {"host": "testbox", "command": "mkfs.ext4 /dev/sda"}},
)
show("tools/call ssh_exec (denied)", deny_resp["result"])

list_resp = send("tools/call", {"name": "ssh_list_hosts", "arguments": {}})
show("tools/call ssh_list_hosts", list_resp["result"]["structuredContent"])

audit_resp = send("tools/call", {"name": "ssh_audit", "arguments": {"limit": 3}})
show("tools/call ssh_audit", audit_resp["result"]["structuredContent"]["count"])

check_resp = send(
    "tools/call",
    {"name": "ssh_policy_check", "arguments": {"host": "testbox", "command": "ls /"}},
)
show("tools/call ssh_policy_check", check_resp["result"]["structuredContent"])

proc.stdin.close()
proc.wait(timeout=10)
err = proc.stderr.read()
if err.strip():
    print("\n=== server stderr ===")
    print(err[:1000])

assert set(names) == {
    "ssh_list_hosts",
    "ssh_exec",
    "ssh_exec_many",
    "ssh_upload",
    "ssh_download",
    "ssh_policy_check",
    "ssh_audit",
}, names
assert exec_resp["result"]["structuredContent"]["exit_code"] == 0
assert "DENIED" in deny_resp["result"]["content"][0]["text"]
print("\nMCP SMOKE TEST PASSED")
