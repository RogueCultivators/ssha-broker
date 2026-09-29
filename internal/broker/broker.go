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
	"sort"
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

	sessionID string
	agent     *audit.Agent
	actor     string
	machine   string

	storeOutput   bool
	maxFieldBytes int
}

// Open loads the config, compiles policies and opens the audit log.
func Open(cfgPath string) (*Broker, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	policies, err := policy.NewSet(cfg)
	if err != nil {
		return nil, err
	}
	auditPath := cfg.Audit.Path
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
		sessionID:     newSessionID(),
		agent:         audit.DetectAgent(),
		actor:         audit.Actor(),
		machine:       audit.Machine(),
		storeOutput:   cfg.Audit.StoreOutputEnabled(),
		maxFieldBytes: maxField,
	}
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
type HostInfo struct {
	Name          string   `json:"name"`
	Addr          string   `json:"addr"`
	User          string   `json:"user"`
	Tags          []string `json:"tags,omitempty"`
	Description   string   `json:"description,omitempty"`
	Auth          string   `json:"auth"`
	ProxyJump     string   `json:"proxy_jump,omitempty"`
	WorkDir       string   `json:"work_dir,omitempty"`
	PolicyMode    string   `json:"policy_mode"`
	Allow         []string `json:"allow_commands,omitempty"`
	Deny          []string `json:"deny_commands,omitempty"`
	Timeout       string   `json:"timeout"`
	MaxOutputSize int      `json:"max_output_bytes"`
	Disabled      bool     `json:"disabled,omitempty"`
}

func (b *Broker) hostInfo(h *config.Host) HostInfo {
	spec := b.cfg.EffectivePolicy(h)
	return HostInfo{
		Name:          h.Name,
		Addr:          h.AddrPort(),
		User:          h.User,
		Tags:          h.Tags,
		Description:   h.Description,
		Auth:          h.AuthType(),
		ProxyJump:     h.ProxyJump,
		WorkDir:       h.WorkDir,
		PolicyMode:    spec.Mode,
		Allow:         spec.Allow,
		Deny:          spec.Deny,
		Timeout:       spec.Timeout.String(),
		MaxOutputSize: spec.MaxOutputBytes,
		Disabled:      h.Disabled,
	}
}

// Hosts lists configured hosts, filtered by tags and name globs.
func (b *Broker) Hosts(tags, patterns []string, includeDisabled bool) []HostInfo {
	hosts := b.cfg.Select(tags, patterns)
	out := make([]HostInfo, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, b.hostInfo(h))
	}
	if includeDisabled {
		for i := range b.cfg.Hosts {
			h := &b.cfg.Hosts[i]
			if !h.Disabled {
				continue
			}
			out = append(out, b.hostInfo(h))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
	// DryRun only evaluates policy; nothing is executed and nothing is audited.
	DryRun bool
}

// ExecResult is the outcome of a remote command, including the audit id that
// can be used to look up the full record later.
type ExecResult struct {
	AuditID    string `json:"audit_id,omitempty"`
	Host       string `json:"host"`
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
	spec := b.cfg.EffectivePolicy(h)
	compiled := b.policies.For(h.Name)

	res := &ExecResult{Host: h.Name, Command: req.Command, Decision: audit.DecisionAllowed}

	decision := compiled.Decide(req.Command)
	if !decision.Allowed {
		res.Decision = audit.DecisionDenied
		res.Reason = decision.Reason
		res.ExitCode = -1
		b.record(&audit.Record{
			Type:     audit.TypeExec,
			Host:     h.Name,
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

	return res, runErr
}

// MultiExecRequest fans a command out over several hosts.
type MultiExecRequest struct {
	Hosts          []string
	Tags           []string
	Command        string
	Cwd            string
	Timeout        time.Duration
	MaxOutputBytes int
	Concurrency    int
}

// ExecMany runs the same command on every matching host, in parallel, and
// returns results in the order the hosts were selected.
func (b *Broker) ExecMany(ctx context.Context, req MultiExecRequest) ([]*ExecResult, error) {
	hosts := b.cfg.Select(req.Tags, req.Hosts)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts matched (names=%v tags=%v)", req.Hosts, req.Tags)
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
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := b.Exec(ctx, ExecRequest{
				Host:           name,
				Command:        req.Command,
				Cwd:            req.Cwd,
				Timeout:        req.Timeout,
				MaxOutputBytes: req.MaxOutputBytes,
			})
			if res == nil {
				res = &ExecResult{Host: name, Command: req.Command, ExitCode: -1, Decision: audit.DecisionDenied}
			}
			if err != nil && res.Error == "" {
				res.Error = err.Error()
			}
			results[i] = res
		}(i, h.Name)
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
	return res, err
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
	return res, err
}

// AuditQuery returns recent audit records.
func (b *Broker) AuditQuery(f audit.Filter, limit int) ([]audit.Record, error) {
	return audit.Query(b.auditor.Path(), f, limit)
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
	}
	t.Proxy = &proxy
	return t, nil
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
	path := explicit
	if path == "" {
		p, err := config.Discover()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoConfig, err)
		}
		path = p
	}
	return Open(path)
}
