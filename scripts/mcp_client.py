"""Minimal JSON-RPC client for the ssha MCP stdio server.

Test helper only: it speaks the wire protocol directly so the tests do not
depend on a full MCP SDK being installed.
"""

import json
import subprocess


class ServerError(RuntimeError):
    pass


class Server:
    """Runs `ssha -c <config> mcp` and talks to it over stdin/stdout."""

    def __init__(self, binary, config, extra_args=()):
        self.proc = subprocess.Popen(
            [binary, "-c", config, "mcp", *extra_args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def _send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._next_id += 1
            msg["id"] = self._next_id
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        line = self.proc.stdout.readline()
        if not line:
            raise ServerError(f"no response to {method}; stderr:\n{self.proc.stderr.read()}")
        return json.loads(line)

    def initialize(self):
        resp = self._send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ssha-e2e", "version": "1"},
            },
        )
        self._send("notifications/initialized", notify=True)
        return resp["result"]

    def tool_names(self):
        return [t["name"] for t in self._send("tools/list")["result"]["tools"]]

    def call(self, name, arguments):
        """Call a tool and return its result, whether or not the tool errored."""
        return self._send("tools/call", {"name": name, "arguments": arguments})["result"]

    def text(self, name, arguments):
        """Call a tool and return just the model-facing text."""
        res = self.call(name, arguments)
        return "\n".join(part.get("text", "") for part in res.get("content", []))

    def structured(self, name, arguments):
        return self.call(name, arguments)["structuredContent"]

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return self.proc.stderr.read()
