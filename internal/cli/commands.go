package cli

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/mcpsrv"
	"ssha/skills"
)

//go:embed template.yaml
var templateYAML string

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func (a *App) cmdInit(args []string) int {
	fs := a.newFlagSet("init")
	force := fs.Bool("force", false, "overwrite an existing config")
	out := fs.String("out", "ssha.yaml", "path to write")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	path := *out
	if !*force {
		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(a.Stderr, "ssha: %s already exists (use --force to overwrite)\n", path)
			return ExitFail
		}
	}
	if err := os.WriteFile(path, []byte(templateYAML), 0o600); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stdout, "wrote %s\n\nNext:\n  1. edit the hosts section\n  2. ssha hosts list\n  3. ssha skill install\n", path)
	return ExitOK
}

// ---------------------------------------------------------------------------
// hosts
// ---------------------------------------------------------------------------

func (a *App) cmdHosts(args []string) int {
	sub := "list"
	if len(args) > 0 && (args[0] == "list" || args[0] == "show") {
		sub = args[0]
		args = args[1:]
	}

	fs := a.newFlagSet("hosts")
	var tags, names multiFlag
	all := fs.Bool("all", false, "include disabled hosts")
	fs.Var(&tags, "tag", "filter by tag (repeatable)")
	fs.Var(&names, "name", "filter by name glob (repeatable)")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	rest := trimmedArgs(fs)

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	switch sub {
	case "show":
		if len(rest) != 1 {
			return a.usageErr("usage: ssha hosts show <name>")
		}
		info, err := b.DescribeHost(rest[0])
		if err != nil {
			return a.fail(err)
		}
		a.emit(info, func() string { return renderHostDetail(info) })
		return ExitOK
	default:
		hosts := b.Hosts(tags, names, *all)
		a.emit(map[string]any{"hosts": hosts, "count": len(hosts)}, func() string {
			return renderHostTable(hosts)
		})
		return ExitOK
	}
}

func renderHostTable(hosts []broker.HostInfo) string {
	if len(hosts) == 0 {
		return "no hosts match\n"
	}
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tUSER\tADDR\tPOLICY\tTAGS\tDESCRIPTION")
	for _, h := range hosts {
		name := h.Name
		if h.Disabled {
			name += " (disabled)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			name, h.User, h.Addr, h.PolicyMode, strings.Join(h.Tags, ","), h.Description)
	}
	tw.Flush()
	return sb.String()
}

func renderHostDetail(h broker.HostInfo) string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", k, v)
		}
	}
	row("name", h.Name)
	row("description", h.Description)
	row("address", fmt.Sprintf("%s@%s", h.User, h.Addr))
	row("tags", strings.Join(h.Tags, ", "))
	row("auth", h.Auth)
	row("via jump host", h.ProxyJump)
	row("work dir", h.WorkDir)
	row("policy mode", h.PolicyMode)
	row("timeout", h.Timeout)
	row("max output", fmt.Sprintf("%d bytes", h.MaxOutputSize))
	row("allowed (allowlist)", strings.Join(h.Allow, "\n  "))
	row("denied (denylist)", strings.Join(h.Deny, "\n  "))
	if h.Disabled {
		row("disabled", "true")
	}
	tw.Flush()
	return sb.String()
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

type runFlags struct {
	cwd     string
	cmd     string
	timeout time.Duration
	maxOut  int
	dryRun  bool
	env     kvFlag
	fs      *flag.FlagSet
}

func (a *App) addRunFlags(name string) *runFlags {
	r := &runFlags{fs: a.newFlagSet(name)}
	r.fs.StringVar(&r.cwd, "cwd", "", "remote working directory")
	r.fs.StringVar(&r.cmd, "cmd", "", "command as a single string (alternative to trailing args)")
	r.fs.DurationVar(&r.timeout, "timeout", 0, "per-command timeout; can only shorten the policy limit")
	r.fs.IntVar(&r.maxOut, "max-output", 0, "max captured output bytes; can only lower the policy limit")
	r.fs.Var(&r.env, "e", "extra environment variable KEY=VALUE (repeatable)")
	return r
}

func (a *App) cmdRun(args []string) int {
	r := a.addRunFlags("run")
	r.fs.BoolVar(&r.dryRun, "dry-run", false, "evaluate policy without executing")
	if code, ok := a.parse(r.fs, args); !ok {
		return code
	}
	host, tail, perr := splitHost(r.fs, args)
	if perr != nil {
		return a.usageErr(perr.Error())
	}
	if host == "" {
		return a.usageErr("usage: ssha run <host> [flags] [--] <command>")
	}
	command := r.cmd
	if command == "" {
		command = commandFrom(tail)
	}
	if command == "" {
		return a.usageErr("no command given (use `ssha run <host> -- <command>`)")
	}

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := b.Exec(ctx, broker.ExecRequest{
		Host:           host,
		Command:        command,
		Cwd:            r.cwd,
		Env:            r.env,
		Timeout:        r.timeout,
		MaxOutputBytes: r.maxOut,
		DryRun:         r.dryRun,
	})
	if res == nil {
		return a.fail(err)
	}
	if err != nil && res.Decision != audit.DecisionDenied && res.Error == "" {
		res.Error = err.Error()
	}

	a.emit(res, func() string { return renderRunText(res) })

	if res.Decision == audit.DecisionDenied {
		return ExitDenied
	}
	if res.ExitCode != 0 {
		return normalizeExit(res.ExitCode)
	}
	if res.Error != "" {
		return ExitFail
	}
	return ExitOK
}

func renderRunText(res *broker.ExecResult) string {
	if res.Decision == audit.DecisionDenied {
		var sb strings.Builder
		fmt.Fprintf(&sb, "DENIED: %s\n", res.Reason)
		if res.AuditID != "" {
			fmt.Fprintf(&sb, "audit: %s\n", res.AuditID)
		}
		return sb.String()
	}
	if res.DryRun {
		return fmt.Sprintf("allowed: %s\n", res.Reason)
	}
	var sb strings.Builder
	sb.WriteString(res.Stdout)
	if res.Stderr != "" {
		if sb.Len() > 0 && !strings.HasSuffix(sb.String(), "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString(res.Stderr)
	}
	if res.Error != "" {
		fmt.Fprintf(&sb, "ssha: %s\n", res.Error)
	}
	if res.Truncated {
		fmt.Fprintf(&sb, "ssha: output truncated; full output in audit log %s\n", res.AuditID)
	}
	return sb.String()
}

// normalizeExit clamps a remote exit status into a usable process code.
func normalizeExit(code int) int {
	if code <= 0 {
		return ExitFail
	}
	if code > 125 {
		return ExitFail
	}
	return code
}

// ---------------------------------------------------------------------------
// multi
// ---------------------------------------------------------------------------

func (a *App) cmdMulti(args []string) int {
	r := a.addRunFlags("multi")
	var hosts, tags multiFlag
	r.fs.Var(&hosts, "host", "host name (repeatable)")
	r.fs.Var(&tags, "tag", "host tag (repeatable)")
	concurrency := r.fs.Int("concurrency", 0, "maximum parallel connections")
	if code, ok := a.parse(r.fs, args); !ok {
		return code
	}
	rest := trimmedArgs(r.fs)
	command := r.cmd
	if command == "" {
		command = commandFrom(rest)
	}
	if command == "" {
		return a.usageErr("usage: ssha multi [--host H]... [--tag T]... [--] <command>")
	}
	if len(hosts) == 0 && len(tags) == 0 {
		return a.usageErr("select hosts with --host or --tag")
	}

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	results, err := b.ExecMany(context.Background(), broker.MultiExecRequest{
		Hosts:          hosts,
		Tags:           tags,
		Command:        command,
		Cwd:            r.cwd,
		Timeout:        r.timeout,
		MaxOutputBytes: r.maxOut,
		Concurrency:    *concurrency,
	})
	if err != nil {
		return a.fail(err)
	}

	a.emit(map[string]any{"results": results, "count": len(results)}, func() string {
		return renderMultiText(results)
	})

	code := ExitOK
	for _, res := range results {
		switch {
		case res.Decision == audit.DecisionDenied:
			return ExitDenied
		case res.ExitCode != 0 || res.Error != "":
			code = ExitFail
		}
	}
	return code
}

func renderMultiText(results []*broker.ExecResult) string {
	var sb strings.Builder
	for _, res := range results {
		status := "ok"
		switch {
		case res.Decision == audit.DecisionDenied:
			status = "DENIED"
		case res.ExitCode != 0 || res.Error != "":
			status = fmt.Sprintf("exit %d", res.ExitCode)
		}
		fmt.Fprintf(&sb, "=== %s [%s] ===\n", res.Host, status)
		if res.Decision == audit.DecisionDenied {
			fmt.Fprintf(&sb, "denied: %s\n\n", res.Reason)
			continue
		}
		sb.WriteString(res.Stdout)
		if res.Stderr != "" {
			sb.WriteString(res.Stderr)
		}
		if res.Error != "" {
			fmt.Fprintf(&sb, "ssha: %s\n", res.Error)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// upload / download
// ---------------------------------------------------------------------------

func (a *App) cmdUpload(args []string) int {
	fs := a.newFlagSet("upload")
	mode := fs.String("mode", "", "octal file mode, e.g. 0644")
	pos, err := positionals(fs, args, 3)
	if err != nil {
		return a.usageErr(err.Error())
	}
	if len(pos) != 3 {
		return a.usageErr("usage: ssha upload <host> <local|-> <remote> [--mode 0644]")
	}
	host, src, dst := pos[0], pos[1], pos[2]

	content, err := readLocal(src)
	if err != nil {
		return a.fail(err)
	}
	var fm os.FileMode
	if *mode != "" {
		v, err := parseOctalMode(*mode)
		if err != nil {
			return a.usageErr(err.Error())
		}
		fm = v
	}

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	res, err := b.Upload(context.Background(), broker.UploadRequest{
		Host:       host,
		RemotePath: dst,
		Content:    content,
		Mode:       fm,
	})
	if res == nil {
		return a.fail(err)
	}
	a.emit(res, func() string {
		if res.Decision == audit.DecisionDenied {
			return fmt.Sprintf("DENIED: %s\n", res.Reason)
		}
		if err != nil {
			return fmt.Sprintf("upload failed: %v\n", err)
		}
		return fmt.Sprintf("uploaded %d bytes to %s:%s (audit %s)\n", res.Bytes, res.Host, res.Path, res.AuditID)
	})
	if res.Decision == audit.DecisionDenied {
		return ExitDenied
	}
	if err != nil {
		return ExitFail
	}
	return ExitOK
}

func (a *App) cmdDownload(args []string) int {
	fs := a.newFlagSet("download")
	maxBytes := fs.Int64("max-bytes", 0, "maximum bytes to read (default 1 MiB)")
	pos, err := positionals(fs, args, 3)
	if err != nil {
		return a.usageErr(err.Error())
	}
	if len(pos) != 3 {
		return a.usageErr("usage: ssha download <host> <remote> <local|-> [--max-bytes N]")
	}
	host, remote, dst := pos[0], pos[1], pos[2]

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	res, err := b.Download(context.Background(), broker.DownloadRequest{
		Host:       host,
		RemotePath: remote,
		MaxBytes:   *maxBytes,
	})
	if res == nil {
		return a.fail(err)
	}
	if res.Decision == audit.DecisionDenied {
		a.emit(res, func() string { return fmt.Sprintf("DENIED: %s\n", res.Reason) })
		return ExitDenied
	}
	if err != nil {
		return a.fail(err)
	}
	if dst == "-" {
		if _, err := a.Stdout.Write(res.Content); err != nil {
			return a.fail(err)
		}
		return ExitOK
	}
	if err := os.WriteFile(dst, res.Content, 0o644); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.Stderr, "wrote %d bytes from %s:%s to %s (audit %s)\n", res.Bytes, res.Host, res.Path, dst, res.AuditID)
	return ExitOK
}

func readLocal(src string) ([]byte, error) {
	if src == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(src)
}

func parseOctalMode(s string) (os.FileMode, error) {
	var v uint64
	if _, err := fmt.Sscanf(strings.TrimPrefix(s, "0o"), "%o", &v); err != nil {
		return 0, fmt.Errorf("invalid mode %q: expected octal like 0644", s)
	}
	return os.FileMode(v), nil
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

func (a *App) cmdPolicy(args []string) int {
	fs := a.newFlagSet("policy")
	if len(args) == 0 || args[0] != "check" {
		return a.usageErr("usage: ssha policy check <host> [--] <command>")
	}
	host, tail, perr := splitHost(fs, args[1:])
	if perr != nil {
		return a.usageErr(perr.Error())
	}
	if host == "" || len(tail) == 0 {
		return a.usageErr("usage: ssha policy check <host> [--] <command>")
	}
	command := commandFrom(tail)

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	decision, err := b.PolicyCheck(host, command)
	if err != nil {
		return a.fail(err)
	}
	a.emit(decision, func() string {
		if decision.Allowed {
			return fmt.Sprintf("ALLOWED (mode=%s)\n", decision.Mode)
		}
		return fmt.Sprintf("DENIED (mode=%s): %s\n", decision.Mode, decision.Reason)
	})
	if !decision.Allowed {
		return ExitDenied
	}
	return ExitOK
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

func (a *App) cmdAudit(args []string) int {
	if len(args) == 0 {
		return a.usageErr("usage: ssha audit <ls|show|verify>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls", "list":
		return a.cmdAuditLs(rest)
	case "show":
		return a.cmdAuditShow(rest)
	case "verify":
		return a.cmdAuditVerify(rest)
	default:
		return a.usageErr(fmt.Sprintf("unknown audit subcommand %q", sub))
	}
}

func (a *App) cmdAuditLs(args []string) int {
	fs := a.newFlagSet("audit ls")
	var host, typ, decision string
	limit := fs.Int("limit", 50, "maximum records")
	since := fs.Duration("since", 0, "only records newer than this duration ago")
	fs.StringVar(&host, "host", "", "filter by host")
	fs.StringVar(&typ, "type", "", "filter by type: exec, upload, download")
	fs.StringVar(&decision, "decision", "", "filter by decision: allowed, denied")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	filter := audit.Filter{Host: host, Type: typ, Decision: decision}
	if *since > 0 {
		filter.Since = time.Now().Add(-*since)
	}
	records, err := b.AuditQuery(filter, *limit)
	if err != nil {
		return a.fail(err)
	}
	a.emit(map[string]any{"audit_log": b.AuditPath(), "records": records, "count": len(records)}, func() string {
		return renderAuditTable(records)
	})
	return ExitOK
}

func renderAuditTable(records []audit.Record) string {
	if len(records) == 0 {
		return "no audit records match\n"
	}
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tID\tHOST\tTYPE\tDECISION\tEXIT\tCOMMAND")
	for i := range records {
		r := &records[i]
		cmd := strings.ReplaceAll(strings.TrimSpace(r.Command), "\n", " ")
		if r.Path != "" {
			cmd = r.Path
		}
		if len(cmd) > 60 {
			cmd = cmd[:57] + "..."
		}
		agent := ""
		if r.Agent != nil && r.Agent.Tool != "" {
			agent = r.Agent.Tool
		}
		_ = agent
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			r.Time.Local().Format("2006-01-02 15:04:05"), r.ID, r.Host, r.Type, r.Decision, r.ExitCode, cmd)
	}
	tw.Flush()
	return sb.String()
}

func (a *App) cmdAuditShow(args []string) int {
	fs := a.newFlagSet("audit show")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	rest := trimmedArgs(fs)
	if len(rest) != 1 {
		return a.usageErr("usage: ssha audit show <id>")
	}
	path, err := a.auditPath()
	if err != nil {
		return a.fail(err)
	}
	rec, err := audit.Get(path, rest[0])
	if err != nil {
		return a.fail(err)
	}
	a.emit(rec, func() string { return renderAuditDetail(rec) })
	return ExitOK
}

func renderAuditDetail(r *audit.Record) string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s:\t%s\n", k, v)
		}
	}
	row("id", r.ID)
	row("time", r.Time.Local().Format(time.RFC3339))
	row("session", r.SessionID)
	row("actor", r.Actor)
	row("machine", r.Machine)
	if r.Agent != nil {
		row("agent tool", r.Agent.Tool)
		row("agent model", r.Agent.Model)
		row("agent session", r.Agent.SessionID)
	}
	row("type", r.Type)
	row("host", r.Host)
	row("command", r.Command)
	row("path", r.Path)
	row("cwd", r.Cwd)
	row("decision", r.Decision)
	row("reason", r.Reason)
	if r.ExitCode != 0 {
		row("exit code", fmt.Sprint(r.ExitCode))
	}
	if r.DurationMS != 0 {
		row("duration", fmt.Sprintf("%dms", r.DurationMS))
	}
	if r.Bytes != 0 {
		row("bytes", fmt.Sprint(r.Bytes))
	}
	if r.Truncated {
		row("truncated", "true")
	}
	row("stdout", r.Stdout)
	row("stderr", r.Stderr)
	row("prev hash", r.PrevHash)
	row("hash", r.Hash)
	tw.Flush()
	return sb.String()
}

func (a *App) cmdAuditVerify(args []string) int {
	fs := a.newFlagSet("audit verify")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	path, err := a.auditPath()
	if err != nil {
		return a.fail(err)
	}
	n, err := audit.Verify(path)
	if err != nil {
		fmt.Fprintf(a.Stderr, "ssha: audit verification FAILED after %d record(s): %v\n", n, err)
		return ExitFail
	}
	result := map[string]any{"ok": true, "records": n, "audit_log": path}
	a.emit(result, func() string {
		return fmt.Sprintf("ok: %d record(s) verified, chain intact (%s)\n", n, path)
	})
	return ExitOK
}

func (a *App) auditPath() (string, error) {
	b, err := a.open()
	if err != nil {
		return "", err
	}
	defer b.Close()
	return b.AuditPath(), nil
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

func (a *App) cmdMCP(args []string) int {
	fs := a.newFlagSet("mcp")
	httpAddr := fs.String("http", "", "serve streamable HTTP on this address instead of stdio")
	verbose := fs.Bool("verbose", false, "enable debug logging on stderr")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}

	level := slog.LevelError
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(a.Stderr, &slog.HandlerOptions{Level: level})))

	b, err := a.open()
	if err != nil {
		return a.fail(err)
	}
	defer b.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr != "" {
		err = mcpsrv.RunHTTP(ctx, b, "ssha", a.Version, *httpAddr, b.Config().Server.Tokens)
	} else {
		err = mcpsrv.RunStdio(ctx, b, "ssha", a.Version)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		return a.fail(err)
	}
	return ExitOK
}

// ---------------------------------------------------------------------------
// skill
// ---------------------------------------------------------------------------

func (a *App) cmdSkill(args []string) int {
	if len(args) == 0 {
		return a.usageErr("usage: ssha skill <install|print>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "print":
		fmt.Fprint(a.Stdout, skills.Content)
		return ExitOK
	case "install":
		fs := a.newFlagSet("skill install")
		dir := fs.String("dir", defaultSkillDir(), "skills directory")
		force := fs.Bool("force", false, "overwrite an existing skill")
		if code, ok := a.parse(fs, rest); !ok {
			return code
		}
		path := filepath.Join(*dir, skills.Name, "SKILL.md")
		if !*force {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(a.Stderr, "ssha: %s already exists (use --force to overwrite)\n", path)
				return ExitFail
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return a.fail(err)
		}
		if err := os.WriteFile(path, []byte(skills.Content), 0o644); err != nil {
			return a.fail(err)
		}
		fmt.Fprintf(a.Stdout, "installed skill %s to %s\n", skills.Name, path)
		return ExitOK
	default:
		return a.usageErr(fmt.Sprintf("unknown skill subcommand %q", sub))
	}
}

func defaultSkillDir() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".agents", "skills")
	}
	return ".agents/skills"
}
