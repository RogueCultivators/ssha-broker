// Package mcpsrv exposes the ssha broker over the Model Context Protocol, so
// agents such as pi, Codex, Claude Code and Cursor can run remote commands
// without ever holding an SSH key.
package mcpsrv

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/config"
)

// Instructions are surfaced to the connecting agent at initialize time.
const Instructions = `ssha is an SSH broker. The hosts, their credentials and the policy live on the ssha server; you never receive an SSH key.

Workflow:
1. Call ssh_list_hosts to see what you can reach. Each host reports its policy mode.
2. If a command might be restricted, call ssh_policy_check before running it.
3. Call ssh_exec for one host, ssh_exec_many for several hosts at once.
4. Use ssh_upload / ssh_download to move files.

Rules and behavior:
- Policy modes: allow (deny list only), readonly (allow list only), deny (nothing runs).
- timeouts and output limits can only be shortened by your request, never extended.
- Every call, including denied ones, is written to a tamper-evident audit log and returns an audit_id.
- A non-zero exit_code is a normal result, not an error. Read stderr.
- When a result says "denied", do not retry the same command; choose an allowed approach or stop and report.
- Credentials live on the ssha server and are never sent to you. If a host reports a missing
  password source or a host key mismatch, report it to the user; do not attempt to change the
  ssha configuration or the ssh known_hosts file yourself.`

// New builds an MCP server bound to a backend.
func New(be Backend, name, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, &mcp.ServerOptions{
		Instructions: Instructions,
	})
	registerTools(s, be)
	return s
}

// RunStdio serves the MCP protocol over stdin/stdout.
func RunStdio(ctx context.Context, be Backend, name, version string) error {
	s := New(be, name, version)
	return s.Run(ctx, &mcp.StdioTransport{})
}

// RunHTTP serves the MCP streamable HTTP transport, authenticating each
// request with a bearer token from the configuration.
func RunHTTP(ctx context.Context, b *broker.Broker, name, version, addr string, tokens []config.Token) error {
	if addr == "" {
		addr = "127.0.0.1:8765"
	}
	if len(tokens) == 0 && !isLoopback(addr) {
		return fmt.Errorf("refusing to serve %s without tokens: configure server.tokens or bind to 127.0.0.1", addr)
	}

	type route struct {
		name    string
		token   string
		handler http.Handler
	}
	routes := make([]*route, 0, len(tokens))
	for i := range tokens {
		t := tokens[i]
		secret, err := t.Resolve()
		if err != nil {
			return err
		}
		var be Backend = b
		scope := "all hosts"
		if len(t.Hosts) > 0 || len(t.Tags) > 0 {
			be = &scoped{base: b, token: t.Name, hosts: t.Hosts, tags: t.Tags}
			scope = fmt.Sprintf("hosts=%v tags=%v", t.Hosts, t.Tags)
		}
		srv := New(be, name, version)
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		routes = append(routes, &route{name: t.Name, token: secret, handler: h})
		slog.Info("mcp token registered", "token", t.Name, "scope", scope)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	if len(routes) == 0 {
		// Anonymous mode, only reachable when bound to loopback.
		srv := New(b, name, version)
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		mux.Handle("/mcp", h)
	} else {
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
			got := bearerToken(r)
			for _, rt := range routes {
				if constEq(got, rt.token) {
					rt.handler.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssha"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("ssha mcp listening", "addr", addr, "tokens", len(routes))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if v := r.Header.Get("X-API-Key"); v != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

func constEq(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "localhost":
		return true
	}
	if ip := strings.Split(host, ".")[0]; ip == "127" {
		return true
	}
	return host == "::1"
}

// ---------------------------------------------------------------------------
// Tool input/output types
// ---------------------------------------------------------------------------

type listHostsInput struct {
	Tags            []string `json:"tags,omitempty" jsonschema:"Only return hosts carrying all of these tags."`
	NameGlob        []string `json:"name_glob,omitempty" jsonschema:"Only return hosts whose name matches one of these glob patterns, e.g. web-*."`
	IncludeDisabled bool     `json:"include_disabled,omitempty" jsonschema:"Also list hosts that are disabled in the ssha config."`
}

type listHostsOutput struct {
	Hosts []broker.HostInfo `json:"hosts"`
	Count int               `json:"count"`
}

type execInput struct {
	Host           string            `json:"host" jsonschema:"Target host name, exactly as returned by ssh_list_hosts."`
	Command        string            `json:"command" jsonschema:"Shell command to run on the remote host."`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"Working directory. Defaults to the host's configured work_dir, otherwise the login directory."`
	Env            map[string]string `json:"env,omitempty" jsonschema:"Extra environment variables to export before the command."`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"Per-command timeout. Can only shorten the host's policy limit. 0 means use the policy limit."`
	MaxOutputBytes int               `json:"max_output_bytes,omitempty" jsonschema:"Cap on captured stdout and stderr combined. Can only lower the host's policy limit."`
}

type execManyInput struct {
	Hosts          []string `json:"hosts,omitempty" jsonschema:"Explicit host names to run on."`
	Tags           []string `json:"tags,omitempty" jsonschema:"Select every host carrying all of these tags instead of naming hosts."`
	Command        string   `json:"command" jsonschema:"Shell command to run on each host."`
	Cwd            string   `json:"cwd,omitempty" jsonschema:"Working directory for each host."`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"Per-command timeout, capped by each host's policy."`
	Concurrency    int      `json:"concurrency,omitempty" jsonschema:"Maximum parallel connections. Defaults to 8."`
}

type execManyOutput struct {
	Results   []*broker.ExecResult `json:"results"`
	HostCount int                  `json:"host_count"`
	Denied    int                  `json:"denied_count"`
	Failed    int                  `json:"failed_count"`
}

type uploadInput struct {
	Host          string `json:"host" jsonschema:"Target host name."`
	Path          string `json:"path" jsonschema:"Absolute remote file path to write."`
	Content       string `json:"content,omitempty" jsonschema:"Text content to write (UTF-8). Use content_base64 for binary data."`
	ContentBase64 string `json:"content_base64,omitempty" jsonschema:"Base64-encoded content, for binary files."`
	Mode          string `json:"mode,omitempty" jsonschema:"Octal file mode, e.g. \"0644\". Defaults to 0644."`
}

type transferOutput struct {
	AuditID    string `json:"audit_id,omitempty"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	Encoding   string `json:"encoding,omitempty"`
	Content    string `json:"content,omitempty"`
}

type downloadInput struct {
	Host     string `json:"host" jsonschema:"Target host name."`
	Path     string `json:"path" jsonschema:"Absolute remote file path to read."`
	MaxBytes int64  `json:"max_bytes,omitempty" jsonschema:"Maximum bytes to read. Defaults to 1 MiB."`
}

type policyCheckInput struct {
	Host    string `json:"host" jsonschema:"Host name to evaluate against."`
	Command string `json:"command" jsonschema:"Command to test. Nothing is executed and nothing is audited."`
}

type auditInput struct {
	Host     string `json:"host,omitempty" jsonschema:"Only return records for this host."`
	Type     string `json:"type,omitempty" jsonschema:"Filter by operation: exec, upload or download."`
	Decision string `json:"decision,omitempty" jsonschema:"Filter by decision: allowed or denied."`
	Limit    int    `json:"limit,omitempty" jsonschema:"Maximum records to return, newest last. Defaults to 50."`
}

type auditOutput struct {
	AuditLog string         `json:"audit_log"`
	Records  []audit.Record `json:"records"`
	Count    int            `json:"count"`
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

func registerTools(s *mcp.Server, be Backend) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "ssh_list_hosts",
		Description: "List the SSH hosts this agent may reach, with tags, policy mode and limits. " +
			"Call this first: every other tool takes a host name returned here.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listHostsInput) (*mcp.CallToolResult, listHostsOutput, error) {
		hosts := be.Hosts(in.Tags, in.NameGlob, in.IncludeDisabled)
		out := listHostsOutput{Hosts: hosts, Count: len(hosts)}
		return textResult(renderHosts(hosts)), out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "ssh_exec",
		Description: "Run a shell command on one SSH host and return stdout, stderr and the exit code. " +
			"Blocked commands return decision=denied with a reason; do not retry those. " +
			"Every call is audited and returns an audit_id.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in execInput) (*mcp.CallToolResult, broker.ExecResult, error) {
		res, err := be.Exec(ctx, broker.ExecRequest{
			Host:           in.Host,
			Command:        in.Command,
			Cwd:            in.Cwd,
			Env:            in.Env,
			Timeout:        secondsToDuration(in.TimeoutSeconds),
			MaxOutputBytes: in.MaxOutputBytes,
		})
		if res == nil {
			return nil, broker.ExecResult{}, err
		}
		return textResult(renderExec(res)), *res, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "ssh_exec_many",
		Description: "Run the same command on several hosts in parallel, selected by explicit names or by tags. " +
			"Returns one result per host. Prefer this over repeated ssh_exec calls when touching a fleet.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in execManyInput) (*mcp.CallToolResult, execManyOutput, error) {
		results, err := be.ExecMany(ctx, broker.MultiExecRequest{
			Hosts:       in.Hosts,
			Tags:        in.Tags,
			Command:     in.Command,
			Cwd:         in.Cwd,
			Timeout:     secondsToDuration(in.TimeoutSeconds),
			Concurrency: in.Concurrency,
		})
		if err != nil {
			return nil, execManyOutput{}, err
		}
		out := execManyOutput{Results: results, HostCount: len(results)}
		for _, r := range results {
			if r.Decision == audit.DecisionDenied {
				out.Denied++
			} else if r.ExitCode != 0 || r.Error != "" {
				out.Failed++
			}
		}
		return textResult(renderExecMany(results)), out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ssh_upload",
		Description: "Write a file to a remote host over SFTP. Provide text in content, or binary data in content_base64. Parent directories are created.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in uploadInput) (*mcp.CallToolResult, transferOutput, error) {
		var content []byte
		switch {
		case in.ContentBase64 != "":
			b, err := base64.StdEncoding.DecodeString(in.ContentBase64)
			if err != nil {
				return nil, transferOutput{}, fmt.Errorf("content_base64: %w", err)
			}
			content = b
		case in.Content != "":
			content = []byte(in.Content)
		default:
			return nil, transferOutput{}, errors.New("either content or content_base64 is required")
		}
		mode, err := parseMode(in.Mode)
		if err != nil {
			return nil, transferOutput{}, err
		}
		res, err := be.Upload(ctx, broker.UploadRequest{
			Host:       in.Host,
			RemotePath: in.Path,
			Content:    content,
			Mode:       mode,
		})
		if res == nil {
			return nil, transferOutput{}, err
		}
		out := transferOutput{
			AuditID: res.AuditID, Host: res.Host, Path: res.Path, Bytes: res.Bytes,
			DurationMS: res.DurationMS, Decision: res.Decision, Reason: res.Reason,
		}
		if !decidedAllowed(res.Decision) {
			return textResult(fmt.Sprintf("DENIED: %s", res.Reason)), out, nil
		}
		if err != nil {
			return textResult(fmt.Sprintf("upload failed: %v", err)), out, nil
		}
		return textResult(fmt.Sprintf("uploaded %d bytes to %s:%s (audit %s)", res.Bytes, res.Host, res.Path, res.AuditID)), out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ssh_download",
		Description: "Read a file from a remote host over SFTP and return its content. Text is returned as UTF-8, binary as base64.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in downloadInput) (*mcp.CallToolResult, transferOutput, error) {
		res, err := be.Download(ctx, broker.DownloadRequest{
			Host:       in.Host,
			RemotePath: in.Path,
			MaxBytes:   in.MaxBytes,
		})
		if res == nil {
			return nil, transferOutput{}, err
		}
		out := transferOutput{
			AuditID: res.AuditID, Host: res.Host, Path: res.Path, Bytes: res.Bytes,
			Truncated: res.Truncated, DurationMS: res.DurationMS,
			Decision: res.Decision, Reason: res.Reason,
		}
		if !decidedAllowed(res.Decision) {
			return textResult(fmt.Sprintf("DENIED: %s", res.Reason)), out, nil
		}
		if err != nil {
			return textResult(fmt.Sprintf("download failed: %v", err)), out, nil
		}
		if utf8.Valid(res.Content) {
			out.Encoding = "utf8"
			out.Content = string(res.Content)
		} else {
			out.Encoding = "base64"
			out.Content = base64.StdEncoding.EncodeToString(res.Content)
		}
		notice := ""
		if res.Truncated {
			notice = "\n[file truncated at max_bytes]"
		}
		return textResult(fmt.Sprintf("read %d bytes from %s:%s%s", res.Bytes, res.Host, res.Path, notice)), out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ssh_policy_check",
		Description: "Check whether a command would be allowed on a host, without executing it. Use before a risky command to avoid a denied audit entry.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in policyCheckInput) (*mcp.CallToolResult, any, error) {
		d, err := be.PolicyCheck(in.Host, in.Command)
		if err != nil {
			return nil, nil, err
		}
		var text string
		if d.Allowed {
			text = fmt.Sprintf("ALLOWED (mode=%s)", d.Mode)
		} else {
			text = fmt.Sprintf("DENIED (mode=%s): %s", d.Mode, d.Reason)
		}
		return textResult(text), d, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ssh_audit",
		Description: "Query the tamper-evident audit log of every command this broker has run or denied, across agents and sessions.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in auditInput) (*mcp.CallToolResult, auditOutput, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = 50
		}
		records, err := be.AuditQuery(audit.Filter{
			Host:     in.Host,
			Type:     in.Type,
			Decision: in.Decision,
		}, limit)
		if err != nil {
			return nil, auditOutput{}, err
		}
		out := auditOutput{AuditLog: be.AuditPath(), Records: records, Count: len(records)}
		return textResult(renderAudit(records)), out, nil
	})
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

func textResult(s string) *mcp.CallToolResult {
	if s == "" {
		s = "(no output)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

const textLimit = 16 * 1024

func clip(s string) string {
	if len(s) <= textLimit {
		return s
	}
	return s[:textLimit] + fmt.Sprintf("\n...[%d more bytes; full output is in the audit log]", len(s)-textLimit)
}

func renderHosts(hosts []broker.HostInfo) string {
	if len(hosts) == 0 {
		return "No hosts match. Check the ssha config or your filter."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d host(s):\n", len(hosts))
	for _, h := range hosts {
		fmt.Fprintf(&b, "\n- %s  (%s@%s)\n", h.Name, h.User, h.Addr)
		if h.Description != "" {
			fmt.Fprintf(&b, "  %s\n", h.Description)
		}
		if len(h.Tags) > 0 {
			fmt.Fprintf(&b, "  tags: %s\n", strings.Join(h.Tags, ", "))
		}
		fmt.Fprintf(&b, "  policy: %s, timeout: %s, max output: %d bytes\n", h.PolicyMode, h.Timeout, h.MaxOutputSize)
		if len(h.Allow) > 0 {
			fmt.Fprintf(&b, "  allowed: %s\n", strings.Join(h.Allow, " | "))
		}
		if h.ProxyJump != "" {
			fmt.Fprintf(&b, "  via jump host: %s\n", h.ProxyJump)
		}
	}
	return b.String()
}

func renderExec(res *broker.ExecResult) string {
	var b strings.Builder
	if res.Decision == audit.DecisionDenied {
		fmt.Fprintf(&b, "DENIED on %s: %s\n", res.Host, res.Reason)
		fmt.Fprintf(&b, "Do not retry this command.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "$ %s\n(host %s, exit %d, %dms", res.Command, res.Host, res.ExitCode, res.DurationMS)
	if res.Truncated {
		b.WriteString(", output truncated")
	}
	b.WriteString(")\n")
	if res.Stdout != "" {
		b.WriteString(clip(res.Stdout))
		if !strings.HasSuffix(res.Stdout, "\n") {
			b.WriteString("\n")
		}
	}
	if res.Stderr != "" {
		b.WriteString("--- stderr ---\n")
		b.WriteString(clip(res.Stderr))
		if !strings.HasSuffix(res.Stderr, "\n") {
			b.WriteString("\n")
		}
	}
	if res.Error != "" {
		fmt.Fprintf(&b, "--- error: %s\n", res.Error)
	}
	if res.Stdout == "" && res.Stderr == "" && res.Error == "" {
		b.WriteString("(no output)\n")
	}
	return b.String()
}

func renderExecMany(results []*broker.ExecResult) string {
	var b strings.Builder
	ok, denied, failed := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Decision == audit.DecisionDenied:
			denied++
		case r.ExitCode != 0 || r.Error != "":
			failed++
		default:
			ok++
		}
	}
	fmt.Fprintf(&b, "%d host(s): %d ok, %d failed, %d denied\n", len(results), ok, failed, denied)
	for _, r := range results {
		b.WriteString("\n")
		b.WriteString(renderExec(r))
	}
	return b.String()
}

func renderAudit(records []audit.Record) string {
	if len(records) == 0 {
		return "No audit records match."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d record(s), oldest first:\n", len(records))
	for i := range records {
		r := &records[i]
		fmt.Fprintf(&b, "\n[%s] %s host=%s type=%s decision=%s",
			r.Time.Format(time.RFC3339), r.ID, r.Host, r.Type, r.Decision)
		if r.Agent != nil && r.Agent.Tool != "" {
			fmt.Fprintf(&b, " agent=%s", r.Agent.Tool)
		}
		if r.Command != "" {
			fmt.Fprintf(&b, "\n  cmd: %s", clip(strings.TrimSpace(r.Command)))
		}
		if r.Path != "" {
			fmt.Fprintf(&b, "\n  path: %s", r.Path)
		}
		if r.Reason != "" {
			fmt.Fprintf(&b, "\n  reason: %s", r.Reason)
		}
		if r.ExitCode != 0 {
			fmt.Fprintf(&b, "\n  exit: %d", r.ExitCode)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func decidedAllowed(d string) bool { return d != audit.DecisionDenied }

func secondsToDuration(s int) time.Duration {
	if s <= 0 {
		return 0
	}
	return time.Duration(s) * time.Second
}

func parseMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0o644, nil
	}
	s = strings.TrimPrefix(strings.ToLower(s), "0o")
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid mode %q: expected octal like 0644", s)
	}
	return os.FileMode(v), nil
}
