---
name: ssh-agent
description: Run commands and transfer files on remote servers through the ssha SSH broker, which enforces per-host policy and writes a tamper-evident audit log. Use when the user asks to inspect, run commands on, debug, deploy to, or copy files to/from a remote host, VM, or production server that is configured in ssha.
license: MIT
---

# Remote servers via ssha

`ssha` is an SSH broker. The host inventory, the credentials and the policy live
in the ssha config; the CLI never exposes private keys. Every command, allowed
or denied, is appended to a hash-chained audit log and returns an `audit_id`.

## Before you start

- Confirm the tool exists: `ssha version`. If it is missing, tell the user — do
  not install software on your own.
- Never guess host names, and never work around ssha by calling `ssh` directly,
  reading `~/.ssh/config`, or using an SSH key. If ssha is present, it is the
  intended path.
- If `ssha version` fails, or no host exists for what the user asked, stop and
  report that instead of improvising.

## Core workflow

1. List hosts before anything else:

   ```bash
   ssha hosts list
   ssha hosts list --tag prod
   ```

2. Inspect a host when the policy matters (this shows the allow/deny rules):

   ```bash
   ssha hosts show web-1
   ```

3. Dry-run a command when you are unsure it is permitted. This executes nothing
   and writes no audit entry:

   ```bash
   ssha policy check web-1 -- systemctl restart nginx
   ```

4. Run the command. Always put `--` between the host and the remote command so
   the remote flags are not parsed locally:

   ```bash
   ssha run web-1 -- systemctl status nginx
   ssha run web-1 --cwd /srv/app -- tail -n 100 logs/app.log
   ssha run web-1 -e APP_ENV=staging -- env
   ```

5. Touch a fleet in one call:

   ```bash
   ssha multi --tag prod -- uptime
   ssha multi --host web-1 --host web-2 -- df -h
   ```

6. Move files:

   ```bash
   ssha upload web-1 ./local.conf /etc/app/app.conf --mode 0644
   ssha download web-1 /var/log/syslog ./syslog --max-bytes 200000
   echo "text" | ssha upload web-1 - /tmp/note.txt
   ssha download web-1 /etc/hosts -
   ```

## Use JSON when you need to branch on the result

Add `--json` to any command. This is strongly preferred over scraping text:

```bash
ssha run web-1 --json -- systemctl is-active nginx
```

```json
{
  "host": "web-1",
  "command": "systemctl is-active nginx",
  "exit_code": 0,
  "stdout": "active\n",
  "stderr": "",
  "truncated": false,
  "duration_ms": 41,
  "decision": "allowed",
  "audit_id": "20260101T120000.000000000Z-3fa1c2"
}
```

`ssha multi --json` returns `{"results": [...]}` with one entry per host.
`ssha hosts list --json` returns `{"hosts": [...], "count": N}`.

## Reading the outcome

| Signal | Meaning |
|---|---|
| exit code `0` | success |
| exit code `1` | local failure or a command that could not run (see `stderr`, `error`) |
| exit code `2` | you used the CLI incorrectly |
| exit code `77` | policy denied the command — `decision` is `"denied"` |
| non-zero `exit_code` in JSON | the remote command ran and failed; read `stderr` |
| `truncated: true` | output was capped; the full text is in the audit log |

## Rules

- Do not retry a denied command and do not try to disguise it (no `sh -c`
  wrappers, base64 payloads, or alternate spellings). A denial is an answer.
- Prefer read-only inspection before anything that mutates state. Ask the user
  before restarting services, deleting files, or changing config.
- Timeouts and output limits can only be shortened (`--timeout 30s`,
  `--max-output 65536`); the host policy sets the ceiling.
- When you report back, include the host and the `audit_id` of anything you
  changed, so the user can find it with `ssha audit show <id>`.

## Reviewing what happened

```bash
ssha audit ls --host web-1 --limit 20
ssha audit show <audit_id>
ssha audit verify          # confirms the log has not been tampered with
```

## When ssha is exposed over MCP

If the agent supports MCP, the same broker is available as a server (`ssha mcp`)
with the tools `ssh_list_hosts`, `ssh_exec`, `ssh_exec_many`, `ssh_upload`,
`ssh_download`, `ssh_policy_check` and `ssh_audit`. Prefer those tools when they
are present; otherwise use this CLI.
