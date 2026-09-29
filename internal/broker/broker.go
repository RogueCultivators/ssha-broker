// Package broker is the core of ssha: it owns the host inventory, the policy
// engine, the audit log and the SSH connection pool. Both the CLI and the MCP
// server are thin adapters over this package, so they can never disagree about
// what is allowed or what gets recorded.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"ssha/internal/audit"
	"ssha/internal/config"
	"ssha/internal/policy"
	"ssha/internal/sshx"
)

// Defaults for output capture stored inside the audit log.
const (
	DefaultMaxFieldBytes = 64 * 1024
	DefaultConcurrency   = 8
)

// DeniedError is returned when policy blocks an operation. The accompanying
// result still carries the decision and reason for structured callers.
type DeniedError struct {
	Host    string
	Command string
	Reason  string
}

func (e *DeniedError) Error() string {
	if e.Command != "" {
		return fmt.Sprintf("denied on %s: %s", e.Host, e.Reason)
	}
	return fmt.Sprintf("denied on %s: %s", e.Host, e.Reason)
}

// Broker is the ssha core.
type Broker struct {
	cfg      *config.Config
	policies policy.Set
	auditor  *audit.Logger
	pool     *sshx.Pool
	prompt   sshx.PromptFunc

	// redactors holds one identity scrubber per host that enabled
	// redact_output. reveal is the operator override (--reveal).
	redactors map[string]*redactor
	reveal    bool

	sessionID string
	agent     *audit.Agent
	actor     string
	machine   string

	storeOutput   bool
	maxFieldBytes int
}

// Options tweaks how a broker is constructed.
type Options struct {
	// Prompt supplies secrets that are absent from the environment and from
	// files. The CLI sets it when stdin is a terminal; the MCP server leaves it
	// nil so a headless agent can never block on a password prompt.
	Prompt sshx.PromptFunc
	// AuditPath overrides config.Audit.Path when non-empty.
	AuditPath string
	// Reveal disables output redaction and host disclosure limits. It exists
	// for the operator at the CLI only; agent-facing surfaces never set it.
	Reveal bool
}

// Open loads the config, compiles policies and opens the audit log.
func Open(cfgPath string) (*Broker, error) {
	return OpenWithOptions(cfgPath, Options{})
}

// OpenWithOptions is Open with explicit options.
func OpenWithOptions(cfgPath string, opts Options) (*Broker, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	policies, err := policy.NewSet(cfg)
	if err != nil {
		return nil, err
	}
	auditPath := firstNonEmpty(opts.AuditPath, cfg.Audit.Path)
	if auditPath == "" {
		auditPath = config.DefaultAuditPath()
	}
	auditor, err := audit.Open(config.ExpandHome(auditPath))
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	maxField := cfg.Audit.MaxFieldBytes
	if maxField <= 0 {
		maxField = DefaultMaxFieldBytes
	}
	b := &Broker{
		cfg:           cfg,
		policies:      policies,
		auditor:       auditor,
		pool:          sshx.NewPool(5 * time.Minute),
		prompt:        opts.Prompt,
		reveal:        opts.Reveal,
		sessionID:     newSessionID(),
		agent:         audit.DetectAgent(),
		actor:         audit.Actor(),
		machine:       audit.Machine(),
		storeOutput:   cfg.Audit.StoreOutputEnabled(),
		maxFieldBytes: maxField,
	}
	b.buildRedactors()
	return b, nil
}

// Close flushes and releases resources.
func (b *Broker) Close() error {
	var err error
	if b.pool != nil {
		_ = b.pool.Close()
	}
	if b.auditor != nil {
		err = b.auditor.Close()
	}
	return err
}

// Config returns the loaded configuration.
func (b *Broker) Config() *config.Config { return b.cfg }

// SessionID is the audit session identifier for this process.
func (b *Broker) SessionID() string { return b.sessionID }

// AuditPath returns the audit log location.
func (b *Broker) AuditPath() string { return b.auditor.Path() }

func newSessionID() string {
	var r [4]byte
	_, _ = rand.Read(r[:])
	return "ssha-" + time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(r[:])
}

// HostInfo is a redacted view of a configured host, safe to hand to an agent.
// Fields that a host's disclosure policy withholds are omitted entirely rather
// than sent empty, so a caller can tell "hidden" from "not configured".
type HostInfo struct {
	Name          string       `json:"name"`
	Addr          string       `json:"addr,omitempty"`
	User          string       `json:"user,omitempty"`
	Tags          []string     `json:"tags,omitempty"`
	Description   string       `json:"description,omitempty"`
	Apps          []config.App `json:"apps,omitempty"`
	Auth          string       `json:"auth,omitempty"`
	ProxyJump     string       `json:"proxy_jump,omitempty"`
	WorkDir       string       `json:"work_dir,omitempty"`
	PolicyMode    string       `json:"policy_mode"`
	Allow         []string     `json:"allow_commands,omitempty"`
	Deny          []string     `json:"deny_commands,omitempty"`
	Timeout       string       `json:"timeout"`
	MaxOutputSize int          `json:"max_output_bytes"`
	Disabled      bool         `json:"disabled,omitempty"`
}

// disclosure returns the effective disclosure level for a host, honouring the
// operator's --reveal override.
func (b *Broker) disclosure(h *config.Host) string {
	if b.reveal {
		return config.DisclosureFull
	}
	return b.cfg.EffectivePolicy(h).Disclosure
}

func (b *Broker) hostInfo(h *config.Host) HostInfo {
	spec := b.cfg.EffectivePolicy(h)

	// Everything that is not identity is always visible: the agent needs the
	// name, the policy mode and the limits to work at all.
	info := HostInfo{
		Name:          h.Name,
		Tags:          h.Tags,
		Description:   h.Description,
		Apps:          h.Apps,
		PolicyMode:    spec.Mode,
		Allow:         spec.Allow,
		Deny:          spec.Deny,
		Timeout:       spec.Timeout.String(),
		MaxOutputSize: spec.MaxOutputBytes,
		Disabled:      h.Disabled,
	}
	switch level := b.disclosure(h); level {
	case config.DisclosureBlind:
		info.Tags = nil
		info.Description = ""
		info.Apps = nil
		info.Allow = nil
		info.Deny = nil
	case config.DisclosureAlias:
		// Name, tags, description and policy only: no identity.
	default:
		info.Addr = h.AddrPort()
		info.User = h.User
		info.Auth = h.AuthType()
		info.ProxyJump = h.ProxyJump
		info.WorkDir = h.WorkDir
	}
	return info
}

// HostQuery selects hosts for discovery.
type HostQuery struct {
	// Tags must all be present.
	Tags []string
	// Names are glob patterns matched against the host name.
	Names []string
	// Query is free text; every whitespace-separated word must appear in the
	// host's name, description, tags or one of its apps.
	Query string
	// IncludeDisabled also returns hosts marked disabled.
	IncludeDisabled bool
}

// FindHosts returns the hosts matching a discovery query, sorted by name and
// already filtered by each host's disclosure policy.
func (b *Broker) FindHosts(q HostQuery) []HostInfo {
	selected := b.cfg.Select(q.Tags, q.Names)
	out := make([]HostInfo, 0, len(selected))
	for _, h := range selected {
		if h.MatchQuery(q.Query) {
			out = append(out, b.hostInfo(h))
		}
	}
	if q.IncludeDisabled {
		for i := range b.cfg.Hosts {
			h := &b.cfg.Hosts[i]
			if !h.Disabled || !h.MatchQuery(q.Query) || !hasAllTags(h.Tags, q.Tags) || !matchesNames(q.Names, h.Name) {
				continue
			}
			out = append(out, b.hostInfo(h))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func hasAllTags(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func matchesNames(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Hosts lists configured hosts, filtered by tags and name globs.
func (b *Broker) Hosts(tags, patterns []string, includeDisabled bool) []HostInfo {
	return b.FindHosts(HostQuery{Tags: tags, Names: patterns, IncludeDisabled: includeDisabled})
}

// PolicyCheck evaluates a command without executing it or writing an audit
// record.
func (b *Broker) PolicyCheck(host, command string) (policy.Decision, error) {
	h, err := b.cfg.Host(host)
	if err != nil {
		return policy.Decision{}, err
	}
	return b.policies.For(h.Name).Decide(command), nil
}

// ExecRequest describes a remote command.
type ExecRequest struct {
	Host           string
	Command        string
	Cwd            string
	Env            map[string]string
	Timeout        time.Duration
	MaxOutputBytes int
	// App names the workload this command is for. When set, the host must
	// actually run it; that keeps "what has been done to checkout-api"
	// answerable from the audit log.
	App string
	// DryRun only evaluates policy; nothing is executed and nothing is audited.
	DryRun bool
}

// ExecResult is the outcome of a remote command, including the audit id that
// can be used to look up the full record later.
type ExecResult struct {
	AuditID    string `json:"audit_id,omitempty"`
	Host       string `json:"host"`
	App        string `json:"app,omitempty"`
	Command    string `json:"command"`
	Cwd        string `json:"cwd,omitempty"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Exec runs a command on a single host.
func (b *Broker) Exec(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	h, err := b.cfg.Host(req.Host)
	if err != nil {
		return nil, err
	}
	if err := checkApp(h, req.App); err != nil {
		return nil, err
	}
	spec := b.cfg.EffectivePolicy(h)
	compiled := b.policies.For(h.Name)

	res := &ExecResult{Host: h.Name, App: req.App, Command: req.Command, Decision: audit.DecisionAllowed}

	decision := compiled.Decide(req.Command)
	if !decision.Allowed {
		res.Decision = audit.DecisionDenied
		res.Reason = decision.Reason
		res.ExitCode = -1
		b.record(&audit.Record{
			Type:     audit.TypeExec,
			Host:     h.Name,
			App:      req.App,
			Command:  req.Command,
			Cwd:      req.Cwd,
			Decision: audit.DecisionDenied,
			Reason:   decision.Reason,
		})
		return res, &DeniedError{Host: h.Name, Command: req.Command, Reason: decision.Reason}
	}
	if req.DryRun {
		res.DryRun = true
		res.Reason = "dry run: policy allows execution"
		return res, nil
	}

	cwd := firstNonEmpty(req.Cwd, h.WorkDir)
	timeout := clampDuration(req.Timeout, spec.Timeout.D())
	maxBytes := clampInt(req.MaxOutputBytes, spec.MaxOutputBytes)
	env := mergeEnv(h.Env, req.Env)

	target, err := b.resolveTarget(h)
	if err != nil {
		return nil, err
	}
	runRes, runErr := b.runWithRetry(ctx, target, req.Command, cwd, env, timeout, maxBytes)

	rec := &audit.Record{
		Type:     audit.TypeExec,
		Host:     h.Name,
		App:      req.App,
		Command:  req.Command,
		Cwd:      cwd,
		Decision: audit.DecisionAllowed,
	}
	if runRes != nil {
		res.ExitCode = runRes.ExitCode
		res.Stdout = runRes.Stdout
		res.Stderr = runRes.Stderr
		res.Truncated = runRes.Truncated
		res.Bytes = runRes.Bytes
		res.DurationMS = runRes.Duration.Milliseconds()
		rec.ExitCode = runRes.ExitCode
		rec.DurationMS = res.DurationMS
		rec.Bytes = runRes.Bytes
		rec.Truncated = runRes.Truncated
		if b.storeOutput {
			rec.Stdout = truncate(runRes.Stdout, b.maxFieldBytes)
			rec.Stderr = truncate(runRes.Stderr, b.maxFieldBytes)
		}
	}
	if runErr != nil {
		res.Error = runErr.Error()
		res.ExitCode = -1
		rec.ExitCode = -1
		rec.Reason = runErr.Error()
		if res.Stderr == "" {
			res.Stderr = runErr.Error()
		}
	}
	rec.ID = b.record(rec)
	res.AuditID = rec.ID

	return b.redactExec(res), b.redactErr(h.Name, runErr)
}

// MultiExecRequest fans a command out over several hosts.
type MultiExecRequest struct {
	Hosts []string
	Tags  []string
	// Query selects hosts the same way ssh_list_hosts does, e.g. every host
	// running the payment-api app.
	Query string
	// App restricts the selection to hosts running this application and records
	// it against every command, so the audit log stays answerable per service.
	App            string
	Command        string
	Cwd            string
	Timeout        time.Duration
	MaxOutputBytes int
	Concurrency    int
}

// ExecMany runs the same command on every matching host, in parallel, and
// returns results in the order the hosts were selected.
func (b *Broker) ExecMany(ctx context.Context, req MultiExecRequest) ([]*ExecResult, error) {
	selected := b.FindHosts(HostQuery{Tags: req.Tags, Names: req.Hosts, Query: req.Query})
	if req.App != "" {
		kept := selected[:0]
		for _, h := range selected {
			hh, err := b.cfg.Host(h.Name)
			if err != nil {
				continue
			}
			if _, ok := hh.App(req.App); ok {
				kept = append(kept, h)
			}
		}
		selected = kept
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no hosts matched (names=%v tags=%v query=%q app=%q)", req.Hosts, req.Tags, req.Query, req.App)
	}
	hosts := make([]string, len(selected))
	for i, h := range selected {
		hosts[i] = h.Name
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(hosts) {
		concurrency = len(hosts)
	}

	results := make([]*ExecResult, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i, name := range hosts {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := b.Exec(ctx, ExecRequest{
				Host:           name,
				App:            req.App,
				Command:        req.Command,
				Cwd:            req.Cwd,
				Timeout:        req.Timeout,
				MaxOutputBytes: req.MaxOutputBytes,
			})
			if res == nil {
				res = &ExecResult{Host: name, App: req.App, Command: req.Command, ExitCode: -1, Decision: audit.DecisionDenied}
			}
			if err != nil && res.Error == "" {
				res.Error = err.Error()
			}
			results[i] = res
		}(i, name)
	}
	wg.Wait()
	return results, nil
}

// UploadRequest describes a file upload.
type UploadRequest struct {
	Host       string
	RemotePath string
	Content    []byte
	Mode       os.FileMode
}

// TransferResult is the outcome of an upload or download.
type TransferResult struct {
	AuditID    string `json:"audit_id,omitempty"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	Content    []byte `json:"-"`
}

// Upload writes content to a remote path.
func (b *Broker) Upload(ctx context.Context, req UploadRequest) (*TransferResult, error) {
	h, err := b.cfg.Host(req.Host)
	if err != nil {
		return nil, err
	}
	res := &TransferResult{Host: h.Name, Path: req.RemotePath, Decision: audit.DecisionAllowed}

	decision := b.policies.For(h.Name).DecidePath(req.RemotePath, true)
	if !decision.Allowed {
		res.Decision = audit.DecisionDenied
		res.Reason = decision.Reason
		b.record(&audit.Record{
			Type:     audit.TypeUpload,
			Host:     h.Name,
			Path:     req.RemotePath,
			Decision: audit.DecisionDenied,
			Reason:   decision.Reason,
		})
		return res, &DeniedError{Host: h.Name, Reason: decision.Reason}
	}

	target, err := b.resolveTarget(h)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	client, err := b.pool.Get(ctx, target)
	if err == nil {
		err = client.Upload(req.RemotePath, req.Content, req.Mode)
		if err != nil && sshx.IsConnError(err) {
			b.pool.Invalidate(target.Name)
			if c2, e2 := b.pool.Get(ctx, target); e2 == nil {
				err = c2.Upload(req.RemotePath, req.Content, req.Mode)
			}
		}
	}
	res.DurationMS = time.Since(start).Milliseconds()
	res.Bytes = int64(len(req.Content))

	rec := &audit.Record{
		Type:       audit.TypeUpload,
		Host:       h.Name,
		Path:       req.RemotePath,
		Decision:   audit.DecisionAllowed,
		Bytes:      res.Bytes,
		DurationMS: res.DurationMS,
	}
	if err != nil {
		res.Reason = err.Error()
		res.Decision = audit.DecisionDenied
		rec.Decision = audit.DecisionDenied
		rec.Reason = err.Error()
	}
	rec.ID = b.record(rec)
	res.AuditID = rec.ID
	return b.redactTransfer(res), b.redactErr(h.Name, err)
}

// DownloadRequest describes a file download.
type DownloadRequest struct {
	Host       string
	RemotePath string
	MaxBytes   int64
}

// Download reads a remote file.
func (b *Broker) Download(ctx context.Context, req DownloadRequest) (*TransferResult, error) {
	h, err := b.cfg.Host(req.Host)
	if err != nil {
		return nil, err
	}
	res := &TransferResult{Host: h.Name, Path: req.RemotePath, Decision: audit.DecisionAllowed}

	decision := b.policies.For(h.Name).DecidePath(req.RemotePath, false)
	if !decision.Allowed {
		res.Decision = audit.DecisionDenied
		res.Reason = decision.Reason
		b.record(&audit.Record{
			Type:     audit.TypeDownload,
			Host:     h.Name,
			Path:     req.RemotePath,
			Decision: audit.DecisionDenied,
			Reason:   decision.Reason,
		})
		return res, &DeniedError{Host: h.Name, Reason: decision.Reason}
	}

	maxBytes := req.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	target, err := b.resolveTarget(h)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	var content []byte
	var truncated bool
	client, err := b.pool.Get(ctx, target)
	if err == nil {
		content, truncated, err = client.Download(req.RemotePath, maxBytes)
		if err != nil && sshx.IsConnError(err) {
			b.pool.Invalidate(target.Name)
			if c2, e2 := b.pool.Get(ctx, target); e2 == nil {
				content, truncated, err = c2.Download(req.RemotePath, maxBytes)
			}
		}
	}
	res.DurationMS = time.Since(start).Milliseconds()
	res.Content = content
	res.Bytes = int64(len(content))
	res.Truncated = truncated

	rec := &audit.Record{
		Type:       audit.TypeDownload,
		Host:       h.Name,
		Path:       req.RemotePath,
		Decision:   audit.DecisionAllowed,
		Bytes:      res.Bytes,
		Truncated:  truncated,
		DurationMS: res.DurationMS,
	}
	if err != nil {
		res.Reason = err.Error()
		res.Decision = audit.DecisionDenied
		rec.Decision = audit.DecisionDenied
		rec.Reason = err.Error()
	}
	rec.ID = b.record(rec)
	res.AuditID = rec.ID
	return b.redactTransfer(res), b.redactErr(h.Name, err)
}

// AuditQuery returns recent audit records. The caller-facing copy of every
// record is scrubbed; the file on disk keeps the original for forensics.
func (b *Broker) AuditQuery(f audit.Filter, limit int) ([]audit.Record, error) {
	records, err := audit.Query(b.auditor.Path(), f, limit)
	if err != nil || b.reveal {
		return records, err
	}
	out := make([]audit.Record, len(records))
	copy(out, records)
	for i := range out {
		r := &out[i]
		red := b.redactors[r.Host]
		if red == nil {
			continue
		}
		r.Command = red.apply(r.Command)
		r.Path = red.apply(r.Path)
		r.Reason = red.apply(r.Reason)
		r.Stdout = red.apply(r.Stdout)
		r.Stderr = red.apply(r.Stderr)
	}
	return out, nil
}

// AuditVerify checks the hash chain of the audit log.
func (b *Broker) AuditVerify() (int, error) { return audit.Verify(b.auditor.Path()) }

// record appends an audit entry and returns its id.
func (b *Broker) record(r *audit.Record) string {
	if r == nil {
		return ""
	}
	r.SessionID = b.sessionID
	r.Actor = b.actor
	r.Machine = b.machine
	r.Agent = b.agent
	if err := b.auditor.Append(r); err != nil {
		fmt.Fprintf(os.Stderr, "ssha: warning: could not write audit record: %v\n", err)
		return ""
	}
	return r.ID
}

func (b *Broker) resolveTarget(h *config.Host) (sshx.Target, error) {
	t := sshx.Target{
		Name:    h.Name,
		Addr:    h.AddrPort(),
		User:    h.User,
		Auth:    h.Auth,
		HostKey: h.HostKey,
		Timeout: b.cfg.EffectivePolicy(h).Timeout.D(),
		Prompt:  b.prompt,
	}
	if h.ProxyJump == "" {
		return t, nil
	}
	jump, err := b.cfg.Host(h.ProxyJump)
	if err != nil {
		return t, err
	}
	proxy := sshx.Target{
		Name:    jump.Name,
		Addr:    jump.AddrPort(),
		User:    jump.User,
		Auth:    jump.Auth,
		HostKey: jump.HostKey,
		Timeout: b.cfg.EffectivePolicy(jump).Timeout.D(),
		Prompt:  b.prompt,
	}
	t.Proxy = &proxy
	return t, nil
}

// checkApp rejects a command that names an application the host does not run,
// so the audit log cannot claim a connection was about the payment service when
// it touched something else.
func checkApp(h *config.Host, app string) error {
	if app == "" {
		return nil
	}
	if _, ok := h.App(app); ok {
		return nil
	}
	names := make([]string, 0, len(h.Apps))
	for _, a := range h.Apps {
		names = append(names, a.Name)
	}
	if len(names) == 0 {
		return fmt.Errorf("host %q has no configured applications, so it cannot be named for %q", h.Name, app)
	}
	return fmt.Errorf("host %q does not run %q; it runs: %s", h.Name, app, strings.Join(names, ", "))
}

func (b *Broker) runWithRetry(ctx context.Context, t sshx.Target, command, cwd string, env map[string]string, timeout time.Duration, maxBytes int) (*sshx.RunResult, error) {
	client, err := b.pool.Get(ctx, t)
	if err != nil {
		return nil, err
	}
	res, err := client.Run(ctx, command, cwd, env, timeout, maxBytes)
	if err != nil && sshx.IsConnError(err) {
		b.pool.Invalidate(t.Name)
		client, err2 := b.pool.Get(ctx, t)
		if err2 != nil {
			return res, err
		}
		return client.Run(ctx, command, cwd, env, timeout, maxBytes)
	}
	return res, err
}

// clampDuration returns requested if it is positive and shorter than limit;
// otherwise it returns the policy limit. Agents may only shorten timeouts.
func clampDuration(requested, limit time.Duration) time.Duration {
	if requested <= 0 || (limit > 0 && requested > limit) {
		return limit
	}
	return requested
}

// clampInt works like clampDuration for output byte limits.
func clampInt(requested, limit int) int {
	if requested <= 0 || (limit > 0 && requested > limit) {
		return limit
	}
	return requested
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mergeEnv(base, over map[string]string) map[string]string {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	const marker = "\n...[truncated by ssha]"
	if max <= len(marker) {
		return s[:max]
	}
	return s[:max-len(marker)] + marker
}

// HostNames returns just the configured host names.
func (b *Broker) HostNames() []string {
	out := make([]string, 0, len(b.cfg.Hosts))
	for i := range b.cfg.Hosts {
		out = append(out, b.cfg.Hosts[i].Name)
	}
	sort.Strings(out)
	return out
}

// DescribeHost returns a single host's info.
func (b *Broker) DescribeHost(name string) (HostInfo, error) {
	h, err := b.cfg.Host(name)
	if err != nil {
		return HostInfo{}, err
	}
	return b.hostInfo(h), nil
}

// HostTest is the outcome of a connection self-test. Identity fields are
// omitted for hosts whose disclosure policy withholds them.
type HostTest struct {
	Host               string `json:"host"`
	OK                 bool   `json:"ok"`
	Addr               string `json:"addr,omitempty"`
	User               string `json:"user,omitempty"`
	Auth               string `json:"auth,omitempty"`
	PolicyMode         string `json:"policy_mode"`
	Via                string `json:"via,omitempty"`
	HostKeyType        string `json:"host_key_type,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	LatencyMS          int64  `json:"latency_ms"`
	Error              string `json:"error,omitempty"`
}

// Test connects to a host, verifies the host key and the credentials, and runs
// probe (default "true") to prove that command execution works. It writes no
// audit record: it is a diagnostic, not an operation on the target.
func (b *Broker) Test(ctx context.Context, name, probe string) *HostTest {
	if probe == "" {
		probe = "true"
	}
	h, err := b.cfg.Host(name)
	if err != nil {
		return &HostTest{Host: name, Error: err.Error()}
	}
	res := &HostTest{
		Host:       h.Name,
		Addr:       h.AddrPort(),
		User:       h.User,
		Auth:       h.AuthType(),
		PolicyMode: b.cfg.EffectivePolicy(h).Mode,
		Via:        h.ProxyJump,
	}

	// An agent may run the self-test too, so identity must not escape on any
	// path - including a failed dial, which is exactly when it is easy to
	// forget - and the error text must be scrubbed.
	if b.disclosure(h) != config.DisclosureFull {
		defer func() {
			res.Addr, res.User, res.Auth, res.Via = "", "", "", ""
			res.HostKeyType, res.HostKeyFingerprint = "", ""
		}()
	}
	defer func() { res.Error = b.redact(name, res.Error) }()

	target, err := b.resolveTarget(h)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	start := time.Now()
	client, err := sshx.Dial(ctx, target)
	if err != nil {
		res.LatencyMS = time.Since(start).Milliseconds()
		res.Error = err.Error()
		return res
	}
	defer client.Close()

	run, err := client.Run(ctx, probe, "", nil, 15*time.Second, 4096)
	res.LatencyMS = time.Since(start).Milliseconds()
	res.HostKeyType = client.HostKeyType()
	res.HostKeyFingerprint = client.HostKeyFingerprint()
	switch {
	case err != nil:
		res.Error = err.Error()
	case run.ExitCode != 0:
		res.Error = fmt.Sprintf("probe %q exited %d: %s", probe, run.ExitCode, firstNonEmpty(strings.TrimSpace(run.Stderr), strings.TrimSpace(run.Stdout)))
	default:
		res.OK = true
	}
	return res
}

// Tags returns the sorted set of tags in use.
func (b *Broker) Tags() []string {
	set := map[string]struct{}{}
	for i := range b.cfg.Hosts {
		for _, t := range b.cfg.Hosts[i].Tags {
			set[t] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ErrNoConfig is returned when no configuration file can be located.
var ErrNoConfig = errors.New("no configuration")

// OpenDefault locates a config file and opens the broker.
func OpenDefault(explicit string) (*Broker, error) {
	return OpenDefaultWithOptions(explicit, Options{})
}

// OpenDefaultWithOptions is OpenDefault with explicit options.
func OpenDefaultWithOptions(explicit string, opts Options) (*Broker, error) {
	path := explicit
	if path == "" {
		p, err := config.Discover()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoConfig, err)
		}
		path = p
	}
	return OpenWithOptions(path, opts)
}
