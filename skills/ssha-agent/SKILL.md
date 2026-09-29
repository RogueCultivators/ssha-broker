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

1. List hosts, or better, search for the thing you were asked about:

   ```bash
   ssha hosts find payment        # the service, not the machine
   ssha hosts list
   ssha hosts list --tag prod
   ```

   Each host entry lists the **applications** it runs, with the systemd unit, ports,
   log files and runbook from the operator's config. That is how you go from "the
   checkout service is slow" to the right command without guessing or asking.

   ```bash
   ssha hosts show prod-web       # applications, units, log paths, policy
   ```

2. If a host is newly configured or something fails, self-test it. This checks the
   host key, the credentials and command execution in one call, and reports the
   host key fingerprint:

   ```bash
   ssha hosts test web-1
   ssha hosts test --tag prod
   ```

3. Inspect a host when the policy matters (this shows the allow/deny rules):

   ```bash
   ssha hosts show web-1
   ```

4. Dry-run a command when you are unsure it is permitted. This executes nothing
   and writes no audit entry:

   ```bash
   ssha policy check web-1 -- systemctl restart nginx
   ```

5. Run the command. Always put `--` between the host and the remote command so
   the remote flags are not parsed locally. When the work is for a specific
   application, name it with `--app`: the broker checks that the host really runs
   it, and the audit log then answers "what has been done to checkout-api"
   rather than only "which host was touched".

   ```bash
   ssha run web-1 -- systemctl status nginx
   ssha run web-1 --app checkout-api -- systemctl status checkout-api
   ssha run web-1 --cwd /srv/app -- tail -n 100 logs/app.log
   ssha run web-1 -e APP_ENV=staging -- env
   ```

   Passing an app the host does not run is refused and the error lists what it
   does run. Do not guess: use `hosts show` or `hosts find` first.

6. Touch a fleet in one call. Prefer selecting by what the host runs:

   ```bash
   ssha multi --app checkout-api -- systemctl restart checkout-api
   ssha multi --query checkout -- systemctl status checkout-api
   ssha multi --tag prod -- uptime
   ssha multi --host web-1 --host web-2 -- df -h
   ```

7. Move files:

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

## Hidden identity

A host may be configured to withhold its identity from you. When it is, the
address, the port, the user name and the proxy are simply absent from
tool results, and any that would have appeared in output, in an error message
or in the audit log are replaced:

| Placeholder | Stands for |
|---|---|
| `<host>` | the server's address or host name |
| `<user>` | the account the broker logs in as |
| `<redacted>` | something the operator listed in `redact_patterns` |

These are not missing data to be filled in. Do not try to discover the real
values: do not read `/etc/hosts`, run `hostname -I`, `ip a`, `curl ifconfig.me`
or similar, and do not ask the user to reveal them. If a task genuinely needs
the address, say so and let the operator decide.

## Rules

- Do not retry a denied command and do not try to disguise it (no `sh -c`
  wrappers, base64 payloads, or alternate spellings). A denial is an answer.
- Prefer read-only inspection before anything that mutates state. Ask the user
  before restarting services, deleting files, or changing config.
- Timeouts and output limits can only be shortened (`--timeout 30s`,
  `--max-output 65536`); the host policy sets the ceiling.
- When you report back, include the host and the `audit_id` of anything you
  changed, so the user can find it with `ssha audit show <id>`.
- Never create, edit or delete an ssh key, a `known_hosts` file, or the ssha
  config to work around a failure. Fix the config through the user, not by
  weakening it. `ssha host-key <addr> --write` is the only sanctioned way to
  pin a new host key, and it refuses to overwrite a conflicting one.
- `--reveal` switches off identity hiding and is for the operator, not for you.
  Do not add it.

## When a connection fails

- `no password source configured` / `environment variable X is empty`: the
  password lives outside ssha. Do not guess or hardcode it. Tell the user to
  set `password_env`/`password_file` for that host, or to run the command
  themselves in a terminal so ssha can prompt. ssha never prompts over MCP.
- `host key mismatch` / `unknown host key`: the server's key is not pinned. Do
  not disable verification. Report the fingerprints and let the user decide,
  then suggest `ssha host-key <host> --write`.
- `keyboard-interactive was refused: the password is probably wrong` or
  `the server rejected every credential offered`: the credentials are wrong.
  Stop and report; do not retry with variations.

## Reviewing what happened

```bash
ssha audit ls --host web-1 --limit 20
ssha audit ls --app checkout-api --limit 20
ssha audit show <audit_id>
ssha audit verify          # confirms the log has not been tampered with
```

## When ssha is exposed over MCP

If the agent supports MCP, the same broker is available as a server (`ssha mcp`)
with the tools `ssh_list_hosts`, `ssh_exec`, `ssh_exec_many`, `ssh_upload`,
`ssh_download`, `ssh_policy_check` and `ssh_audit`. Prefer those tools when they
are present; otherwise use this CLI.
