---
name: ssh-agent
description: Run commands and transfer files on remote servers through the ssha SSH broker, and push or fetch git remotes whose credentials stay on the broker. Use when the user asks to inspect, run commands on, debug, deploy to, or copy files to/from a remote host, or to clone, fetch, pull, or push a repository configured in ssha.
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

   Each host carries a free-text **note** ("备注") from the operator: what runs on
   it, the systemd unit names, the log paths, who owns it. That note is what you
   search, and it is how you go from "the checkout service is slow" to the right
   command without guessing or asking.

   ```bash
   ssha hosts show prod-web       # the note, in full, plus the policy
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
   the remote flags are not parsed locally.

   ```bash
   ssha run web-1 -- systemctl status nginx
   ssha run web-1 --cwd /srv/app -- tail -n 100 logs/app.log
   ssha run web-1 -e APP_ENV=staging -- env
   ```

6. Touch a fleet in one call. Prefer selecting by what the host runs:

   ```bash
   ssha multi --query checkout -- systemctl status checkout-api
   ssha multi --tag prod -- uptime
   ssha multi --host web-1 --host web-2 -- df -h
   ```

7. Move files:

   ```bash
   ssha upload web-1 ./local.conf /etc/app/app.conf --mode 0644
   ssha download web-1 /var/log/syslog ./syslog --max-bytes 200000
   ssha download web-1 /var/log/syslog ~/Downloads/syslog   # ~ expands on both platforms
   echo "text" | ssha upload web-1 - /tmp/note.txt
   ssha download web-1 /etc/hosts -
   ```

## Reaching a service through a host

There are two directions. Both print the actual loopback address and block
until Ctrl-C; both require the host's `mode: allow`, its `policy.allow_*`
list, and a loopback listener. A denial (exit 77) is final.

**Local** — a service that listens on the remote side, exposed on this
machine. Use it instead of copying credentials around:

```bash
ssha forward db-1 --listen 127.0.0.1:0 --to 10.0.0.12:5432
```

The destination must match `allow_forwards`; `deny_forwards` wins. It is
dialled from that host itself, not from its jump host: if the host is reached
through a jump and its sshd refuses TCP forwarding, target the jump host
instead when the service is only reachable from there.

**Remote (`--remote`)** — a service that listens on this machine, exposed on
the remote host's loopback. Use it when the remote host must call back to
something only you can reach (e.g. a local inference server):

```bash
ssha forward build-1 --remote --listen 127.0.0.1:18000 --to 127.0.0.1:8000
```

The destination must match `allow_remote_forwards`. `--listen` must be a
numeric loopback IP (`127.0.0.1` or `::1`); omit the port to let the remote
sshd allocate one. The remote sshd must allow TCP forwarding, and the remote
side of the tunnel sees traffic from the sshd, not from the caller — check
with the operator before relying on source-address rules.

Do not leave a forward running after the task, and never try to make either
listener reachable from another machine.

## Commands that need sudo

Use the SSH login for ordinary work. When an authorized task needs root, add
`sudo` to the call instead of writing `sudo` into the command:

```bash
ssha policy check web-1 --sudo -- systemctl restart nginx
ssha run web-1 --sudo -- systemctl restart nginx
```

Over MCP, pass `sudo: true` (and optionally `sudo_user`) to `ssh_exec`,
`ssh_exec_many` or `ssh_policy_check`:

```json
{"host":"web-1","command":"systemctl restart nginx","sudo":true}
```

ssha then runs the command as root, answering sudo's password prompt itself with
the account's own login password: sudo asks for the password of the user running
it, so nothing extra has to be configured. The password goes over ssh stdin: it
is not in the command line, not in the result, not in the audit log, and not
visible to you. sudoers still decides what the account may run, so a denial from
sudo is final.

- Policy is checked on the `sudo`-prefixed form, so a readonly host needs an
  allow rule that matches `sudo ...` as well. `ssha policy check --sudo` answers
  the same question the run will ask.
- Each execution is a new session, so `sudo -i` or `su` cannot leave root for
  later calls. Elevate each command that needs it.
- Do not write `sudo` into the command yourself when `sudo: true` is available;
  ssha would prefix it again. A host that logs in with a key has no password to
  give, so if the result says no sudo password is available, report it and let
  the user decide (a NOPASSWD rule is their call). Never add a NOPASSWD rule
  yourself, read a credential file, or pipe a password to `sudo -S`.
- Uploads and downloads run as the login user; sudo does not elevate SFTP. For
  an authorized write to a privileged path, upload into a private temporary
  directory, then run an explicitly permitted `install`/`mv` with sudo, and
  clean up. A denied destination stays denied.

## Git

Some remotes need an SSH key, others a username and token. Both live on the
broker. Do not call `git push`, `git fetch`, `git pull`, `git clone` or
`git ls-remote` yourself, and do not put a token in a URL.

```bash
ssha git accounts
ssha git which -C ~/src/app
ssha git push -C ~/src/app -- main
ssha git fetch -C ~/src/app
ssha git clone -C ~/src -- https://github.com/acme/app.git app
```

Put ssha flags first. Everything after `--` is passed to git. `--force` and a
refspec that starts with `+` are denied unless that account allows force push.
A denial is final: do not retry with `--force`.

Exit code `77` means the account or the policy refused it. A non-zero exit
below that is git's own result; read stderr. If `ssha git accounts` has no
match for the host, stop and tell the user. Do not create a key, a credential
helper, or a password file to work around it.

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
  weakening it. `ssha host-key <name> --pin` (into `host_key.fingerprints`) and
  `ssha host-key <addr> --write` (into known_hosts) are the sanctioned ways to
  pin a new key; both refuse to overwrite a conflicting one. Pinning changes
  trust, so let the operator decide.
- `--reveal` switches off identity hiding and is for the operator, not for you.
  Do not add it.

## When a connection fails

- `no password source configured` / `environment variable X is empty`: the
  password lives outside ssha. Do not guess or hardcode it. Tell the user to
  set `password_env`/`password_file` for that host, or to run the command
  themselves in a terminal so ssha can prompt. ssha never prompts over MCP.
- `host key mismatch` / `unknown host key`: the server's key is not pinned. A
  key already trusted for this host on port 22 is accepted on other ports
  automatically; this error means that did not apply. Do not disable
  verification. Report the fingerprints and let the user decide, then suggest
  `ssha host-key <host> --pin` for a configured host, or
  `ssha host-key <addr> --write` for a raw address.
- `keyboard-interactive was refused: the password is probably wrong` or
  `the server rejected every credential offered`: the credentials are wrong.
  Stop and report; do not retry with variations.
- A remote path arrives looking like a Windows path (`C:/Program Files/Git/data`
  instead of `/data`): ssha passes paths through unchanged, so the shell in front
  of it rewrote the argument. On Windows that is Git Bash/MSYS path conversion.
  Re-run with `MSYS_NO_PATHCONV=1` in the environment, or use a shell that does
  not translate arguments. Do not rewrite the path by hand.

## Reviewing what happened

```bash
ssha audit ls --host web-1 --limit 20
ssha audit show <audit_id>
ssha audit verify          # confirms the log has not been tampered with
```

## When ssha is exposed over MCP

If the agent supports MCP, the same broker is available as a server (`ssha mcp`)
with the tools `ssh_list_hosts`, `ssh_exec`, `ssh_exec_many`, `ssh_upload`,
`ssh_download`, `ssh_policy_check`, `ssh_audit`, `git_accounts` and `git`.
Prefer those tools when they are present; otherwise use this CLI. `git` takes
`op` (`fetch`, `pull`, `push`, `clone`, `ls-remote`), `dir`, and optionally
`remote`, `url` and `args`. Never put a password in `url`.
