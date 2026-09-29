/**
 * ssha - SSH broker tools for Pi
 *
 * Adds native `ssh_exec`, `ssh_list_hosts`, `ssh_policy_check` and `ssh_audit`
 * tools that shell out to the `ssha` CLI. Credentials and policy stay in the
 * ssha config; the model never sees a key.
 *
 * Usage:
 *   pi --extension ~/.pi/agent/extensions/ssha-agent.ts
 *
 * Or copy this file to ~/.pi/agent/extensions/ (or .pi/extensions/ in a
 * project) and Pi loads it automatically.
 *
 * Requires the `ssha` binary on PATH. Configure it with `ssha init`, then
 * `ssha hosts list` to check that it works. The skill in
 * skills/ssha-agent/SKILL.md teaches the model the same workflow through bash;
 * this extension is the structured alternative.
 */

import { execFile } from "node:child_process";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, truncateHead } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

const SSH_BIN = process.env.SSHA_BIN ?? "ssha";
const TIMEOUT_MS = Number(process.env.SSHA_TIMEOUT_MS ?? 120_000);

interface ExecResult {
  audit_id?: string;
  host: string;
  command: string;
  exit_code: number;
  stdout?: string;
  stderr?: string;
  truncated?: boolean;
  duration_ms?: number;
  decision: string;
  reason?: string;
  error?: string;
}

interface AuditRecord {
  id: string;
  time: string;
  host: string;
  type: string;
  decision: string;
  command?: string;
  path?: string;
  reason?: string;
  exit_code?: number;
}

/** run ssha with --json and parse the result. */
function ssha<T>(args: string[]): Promise<T> {
  return new Promise((resolve, reject) => {
    execFile(SSH_BIN, args, { timeout: TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      // ssha exits 77 for a policy denial and with the remote exit code
      // otherwise; both still print valid JSON, so parse stdout first.
      const text = stdout.trim();
      if (text) {
        try {
          const parsed = JSON.parse(text) as T & { error?: string };
          resolve(parsed);
          return;
        } catch {
          // fall through to the error below
        }
      }
      const detail = (stderr || (err as Error | null)?.message || "").trim();
      reject(new Error(detail || `ssha ${args[0]} failed`));
    });
  });
}

function renderExec(r: ExecResult): string {
  if (r.decision === "denied") {
    return `DENIED on ${r.host}: ${r.reason}\nDo not retry this command.`;
  }
  const parts = [`$ ${r.command}`, `(host ${r.host}, exit ${r.exit_code}, ${r.duration_ms ?? 0}ms)`];
  if (r.stdout) parts.push(r.stdout.replace(/\n$/, ""));
  if (r.stderr) parts.push(`--- stderr ---\n${r.stderr.replace(/\n$/, "")}`);
  if (r.error) parts.push(`--- error: ${r.error}`);
  if (!r.stdout && !r.stderr && !r.error) parts.push("(no output)");
  return parts.join("\n");
}

export default function sshaExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "ssh_exec",
    label: "SSH exec",
    description:
      "Run a shell command on a remote host through the ssha broker, which enforces per-host policy and audits every call. " +
      "Call ssh_list_hosts first to learn the host names. A denied command returns decision=denied; do not retry it.",
    parameters: Type.Object({
      host: Type.String({ description: "Host name from ssh_list_hosts." }),
      command: Type.String({ description: "Shell command to run on the remote host." }),
      cwd: Type.Optional(Type.String({ description: "Remote working directory." })),
      timeout_seconds: Type.Optional(
        Type.Number({ description: "Per-command timeout; can only shorten the host's policy limit." }),
      ),
    }),
    async execute(_id, params) {
      const args = ["run", "--json", params.host];
      if (params.cwd) args.push("--cwd", params.cwd);
      if (params.timeout_seconds) args.push("--timeout", `${params.timeout_seconds}s`);
      args.push("--", params.command);

      const result = await ssha<ExecResult>(args);
      const text = truncateHead(renderExec(result), {
        maxLines: DEFAULT_MAX_LINES,
        maxBytes: DEFAULT_MAX_BYTES,
      }).content;
      return { content: [{ type: "text", text }], details: result };
    },
  });

  pi.registerTool({
    name: "ssh_list_hosts",
    label: "SSH hosts",
    description: "List the SSH hosts the ssha broker can reach, with their tags and policy mode.",
    parameters: Type.Object({
      tag: Type.Optional(Type.String({ description: "Only return hosts carrying this tag." })),
    }),
    async execute(_id, params) {
      const args = ["hosts", "list", "--json"];
      if (params.tag) args.push("--tag", params.tag);
      const result = await ssha<{ hosts: Array<Record<string, unknown>>; count: number }>(args);
      const lines = result.hosts.map(
        (h) =>
          `- ${h.name} (${h.user}@${h.addr}) policy=${h.policy_mode}` +
          (Array.isArray(h.tags) && h.tags.length ? ` tags=${(h.tags as string[]).join(",")}` : "") +
          (h.description ? ` - ${h.description}` : ""),
      );
      return {
        content: [{ type: "text", text: `${result.count} host(s):\n${lines.join("\n")}` }],
        details: result,
      };
    },
  });

  pi.registerTool({
    name: "ssh_policy_check",
    label: "SSH policy check",
    description:
      "Check whether a command would be allowed on a host without running it. Use before a risky command to avoid a denied audit entry.",
    parameters: Type.Object({
      host: Type.String({ description: "Host name." }),
      command: Type.String({ description: "Command to test." }),
    }),
    async execute(_id, params) {
      const d = await ssha<{ allowed: boolean; mode: string; reason?: string }>([
        "policy",
        "check",
        params.host,
        "--",
        params.command,
      ]);
      const text = d.allowed ? `ALLOWED (mode=${d.mode})` : `DENIED (mode=${d.mode}): ${d.reason}`;
      return { content: [{ type: "text", text }], details: d };
    },
  });

  pi.registerTool({
    name: "ssh_audit",
    label: "SSH audit",
    description: "Query the ssha audit log of commands run or denied across all agents and sessions.",
    parameters: Type.Object({
      host: Type.Optional(Type.String({ description: "Filter by host." })),
      decision: Type.Optional(Type.String({ description: "Filter by decision: allowed or denied." })),
      limit: Type.Optional(Type.Number({ description: "Maximum records to return (default 20)." })),
    }),
    async execute(_id, params) {
      const args = ["audit", "ls", "--json", "--limit", String(params.limit ?? 20)];
      if (params.host) args.push("--host", params.host);
      if (params.decision) args.push("--decision", params.decision);
      const result = await ssha<{ records: AuditRecord[]; count: number }>(args);
      const lines = result.records.map(
        (r) =>
          `[${r.id}] ${r.host} ${r.decision} exit=${r.exit_code ?? 0}` +
          (r.command ? ` :: ${r.command}` : r.path ? ` :: ${r.path}` : ""),
      );
      return {
        content: [{ type: "text", text: lines.join("\n") || "No audit records match." }],
        details: result,
      };
    },
  });
}
