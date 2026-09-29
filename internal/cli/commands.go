package cli

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssha/internal/audit"
	"ssha/internal/broker"
	"ssha/internal/config"
	"ssha/internal/mcpsrv"
	"ssha/internal/sshx"
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

// promptFunc returns a secret prompt, or nil when prompting is disabled or
// stdin is not a terminal. The MCP server never installs one, so a headless
// agent can never block waiting for a password.
func (a *App) promptFunc() sshx.PromptFunc {
	if a.NoPrompt || !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	return func(host, what string) (string, error) {
		fmt.Fprintf(a.Stderr, "ssha: %s for %s: ", what, host)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(a.Stderr)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", what, err)
		}
		if len(b) == 0 {
			return "", fmt.Errorf("no %s entered", what)
		}
		return string(b), nil
	}
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
	if len(args) > 0 && (args[0] == "list" || args[0] == "show" || args[0] == "test") {
		sub = args[0]
		args = args[1:]
	}

	fs := a.newFlagSet("hosts")
	var tags, names multiFlag
	all := fs.Bool("all", false, "include disabled hosts, or test every enabled host")
	probe := fs.String("probe", "", "command used by `hosts test` (default: true)")
	fs.Var(&tags, "tag", "filter by tag (repeatable)")
	fs.Var(&names, "name", "filter by name glob (repeatable)")
	rest, perr := positionals(fs, args, 0)
	if perr != nil {
		return a.usageErr(perr.Error())
	}

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
	case "test":
		return a.runHostTests(b, rest, tags, names, *all, *probe)
	default:
		hosts := b.Hosts(tags, names, *all)
		a.emit(map[string]any{"hosts": hosts, "count": len(hosts)}, func() string {
			return renderHostTable(hosts)
		})
		return ExitOK
	}
}

func (a *App) runHostTests(b *broker.Broker, positional, tags, globs []string, all bool, probe string) int {
	var targets []string
	switch {
	case len(positional) > 0:
		targets = positional
	case all || len(tags) > 0 || len(globs) > 0:
		for _, h := range b.Hosts(tags, globs, false) {
			targets = append(targets, h.Name)
		}
	default:
		return a.usageErr("usage: ssha hosts test <name>... | --tag T | --all")
	}
	if len(targets) == 0 {
		return a.fail(errors.New("no hosts matched"))
	}

	ctx := context.Background()
	results := make([]*broker.HostTest, 0, len(targets))
	failed := 0
	for _, name := range targets {
		res := b.Test(ctx, name, probe)
		if !res.OK {
			failed++
		}
		results = append(results, res)
	}

	a.emit(map[string]any{"results": results, "count": len(results), "failed": failed}, func() string {
		return renderHostTests(results)
	})
	if failed > 0 {
		return ExitFail
	}
	return ExitOK
}

func renderHostTests(results []*broker.HostTest) string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tRESULT\tAUTH\tVIA\tHOST KEY\tLATENCY\tDETAIL")
	for _, r := range results {
		result := "ok"
		if !r.OK {
			result = "FAIL"
		}
		hostKey := "-"
		if r.HostKeyFingerprint != "" {
			hostKey = fmt.Sprintf("%s (%s)", r.HostKeyFingerprint, r.HostKeyType)
		}
		via := r.Via
		if via == "" {
			via = "-"
		}
		detail := r.Error
		if r.OK {
			detail = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%dms\t%s\n",
			r.Host, result, r.Auth, via, hostKey, r.LatencyMS, detail)
	}
	tw.Flush()
	return sb.String()
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
// host-key
// ---------------------------------------------------------------------------

// hostKeyInfo is one scanned public host key.
type hostKeyInfo struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Line        string `json:"known_hosts_line"`
}

// cmdHostKey fetches a server's public host keys so the first connection can be
// pinned instead of trusted blindly.
func (a *App) cmdHostKey(args []string) int {
	fs := a.newFlagSet("host-key")
	port := fs.Int("port", 0, "SSH port, when the argument is not a configured host name")
	write := fs.Bool("write", false, "append the keys to the known_hosts file")
	knownHosts := fs.String("known-hosts", "", "known_hosts file to consider (default: from the host config, else ~/.ssh/known_hosts)")
	timeout := fs.Duration("timeout", 10*time.Second, "connection timeout")
	rest, perr := positionals(fs, args, 1)
	if perr != nil {
		return a.usageErr(perr.Error())
	}
	if len(rest) != 1 {
		return a.usageErr("usage: ssha host-key <name|addr>[:port] [--write] [--known-hosts PATH]")
	}
	spec := rest[0]

	// A configured host name supplies the address and the known_hosts location.
	addr := ""
	khPath := ""
	if b, err := a.open(); err == nil {
		if h, err := b.Config().Host(spec); err == nil {
			addr = h.AddrPort()
			khPath = h.HostKey.KnownHosts
		}
		b.Close()
	}
	if addr == "" {
		defaultPort := *port
		if defaultPort == 0 {
			defaultPort = 22
		}
		host, p, err := parseHostPort(spec, defaultPort)
		if err != nil {
			return a.usageErr(err.Error())
		}
		addr = net.JoinHostPort(host, strconv.Itoa(p))
	}
	if *knownHosts != "" {
		khPath = *knownHosts
	}
	if khPath == "" {
		khPath = config.DefaultKnownHosts()
	}
	khPath = config.ExpandHome(khPath)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+2*time.Second)
	defer cancel()
	keys, err := sshx.ScanHostKeys(ctx, addr, *timeout)
	if err != nil {
		return a.fail(fmt.Errorf("scan %s: %w", addr, err))
	}

	infos := make([]hostKeyInfo, 0, len(keys))
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		line := sshx.KnownHostsLine(addr, k)
		infos = append(infos, hostKeyInfo{Type: k.Type(), Fingerprint: ssh.FingerprintSHA256(k), Line: line})
		lines = append(lines, line)
	}

	result := map[string]any{
		"address":     addr,
		"known_hosts": khPath,
		"keys":        infos,
		"written":     false,
	}
	text := renderHostKeys(addr, khPath, infos, false, 0)

	if *write {
		added, conflicts, err := appendKnownHosts(khPath, lines)
		if err != nil {
			return a.fail(err)
		}
		result["written"] = true
		result["added"] = added
		result["conflicts"] = conflicts
		text = renderHostKeys(addr, khPath, infos, true, added)
		if len(conflicts) > 0 {
			fmt.Fprintf(a.Stderr, "ssha: WARNING: %s already pins a different key for: %s\n", khPath, strings.Join(conflicts, ", "))
			fmt.Fprintln(a.Stderr, "ssha: refusing to change it - verify the server out of band before editing known_hosts by hand")
		}
	}
	a.emit(result, func() string { return text })
	return ExitOK
}

func renderHostKeys(addr, khPath string, keys []hostKeyInfo, written bool, added int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "host keys for %s:\n\n", addr)
	for _, k := range keys {
		fmt.Fprintf(&sb, "  %-24s %s\n", k.Type, k.Fingerprint)
	}
	sb.WriteString("\nknown_hosts lines:\n\n")
	for _, k := range keys {
		sb.WriteString("  " + k.Line + "\n")
	}
	if written {
		fmt.Fprintf(&sb, "\nadded %d line(s) to %s\n", added, khPath)
	} else {
		fmt.Fprintf(&sb, "\nadd them with:  ssha host-key %s --write\n(target file: %s)\n", addr, khPath)
	}
	return sb.String()
}

// appendKnownHosts adds lines that are not already present. It returns the
// number of lines written and any host+key type pairs that are already pinned
// to a different key, which it refuses to overwrite.
func appendKnownHosts(path string, lines []string) (int, []string, error) {
	type pair struct{ host, keyType string }
	existing := map[pair]string{}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		for _, l := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(l)
			if len(fields) < 3 || strings.HasPrefix(l, "#") {
				continue
			}
			existing[pair{fields[0], fields[1]}] = fields[2]
		}
	case !os.IsNotExist(err):
		return 0, nil, err
	}

	var (
		toWrite   []string
		conflicts []string
	)
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 3 {
			continue
		}
		p := pair{fields[0], fields[1]}
		if have, ok := existing[p]; ok {
			if have != fields[2] {
				conflicts = append(conflicts, fields[0]+" "+fields[1])
			}
			continue
		}
		existing[p] = fields[2]
		toWrite = append(toWrite, l)
	}
	if len(toWrite) == 0 {
		return 0, conflicts, nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, conflicts, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, conflicts, err
	}
	defer f.Close()
	prefix := ""
	if len(raw) > 0 && !strings.HasSuffix(string(raw), "\n") {
		prefix = "\n"
	}
	if _, err := f.WriteString(prefix + strings.Join(toWrite, "\n") + "\n"); err != nil {
		return 0, conflicts, err
	}
	return len(toWrite), conflicts, nil
}

// parseHostPort splits "[user@]host[:port]" and "[v6addr]:port".
func parseHostPort(spec string, defaultPort int) (string, int, error) {
	spec = strings.TrimSpace(spec)
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		spec = spec[i+1:]
	}
	if spec == "" {
		return "", 0, errors.New("empty host")
	}
	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("invalid address %q: missing closing bracket", spec)
		}
		host := spec[1:end]
		rest := spec[end+1:]
		if rest == "" {
			return host, defaultPort, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("invalid address %q", spec)
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("invalid port in %q", spec)
		}
		return host, p, nil
	}
	// A single colon separates host from port; several colons mean a bare IPv6
	// literal, which has no port.
	if strings.Count(spec, ":") == 1 {
		host, portStr, _ := strings.Cut(spec, ":")
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("invalid port in %q", spec)
		}
		return host, p, nil
	}
	return spec, defaultPort, nil
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
	rest, perr := positionals(r.fs, args, 0)
	if perr != nil {
		return a.usageErr(perr.Error())
	}
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
	rest, perr := positionals(fs, args, 1)
	if perr != nil {
		return a.usageErr(perr.Error())
	}
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
