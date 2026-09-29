package broker

import (
	"errors"
	"regexp"

	"ssha/internal/config"
)

// Placeholders substituted into text that is handed to an agent. They are
// deliberately stable so a model can reason about "the same host" without ever
// learning what it is.
const (
	PlaceholderHost     = "<host>"
	PlaceholderUser     = "<user>"
	PlaceholderRedacted = "<redacted>"
)

type redactRule struct {
	re   *regexp.Regexp
	with string
}

// redactor scrubs one host's identity out of the copy of a result that goes to
// the caller. The audit log on disk keeps the original text; only the copy the
// agent sees is rewritten.
type redactor struct {
	rules []redactRule
}

// apply rewrites every match. A nil redactor is a no-op, so callers do not need
// to check whether redaction is enabled for a host.
func (r *redactor) apply(s string) string {
	if r == nil || s == "" {
		return s
	}
	for _, rule := range r.rules {
		s = rule.re.ReplaceAllString(s, rule.with)
	}
	return s
}

// redacted reports whether anything actually changed, which lets callers keep
// the original error value (and its errors.Is/As behaviour) when possible.
func (r *redactor) changed(before, after string) bool { return before != after }

// newRedactor builds the substitution rules for a host. Order matters: longer
// forms are replaced first so that "10.0.0.10:22" does not decay to
// "<host>:22".
func newRedactor(h *config.Host, jump *config.Host, extra []*regexp.Regexp) *redactor {
	var rules []redactRule

	// Deliberately not using regexp.MustCompile: a pattern that fails to
	// compile must not take the process down at runtime.
	addRE := func(re *regexp.Regexp, with string) {
		if re != nil {
			rules = append(rules, redactRule{re: re, with: with})
		}
	}
	addLiteral := func(literal, with string) {
		if literal == "" {
			return
		}
		re, err := regexp.Compile(regexp.QuoteMeta(literal))
		if err != nil {
			return
		}
		rules = append(rules, redactRule{re: re, with: with})
	}

	addHost := func(host *config.Host) {
		if host == nil {
			return
		}
		// The host name is the alias the agent is given, so it is never
		// scrubbed. Only a real address that differs from the alias is secret.
		if host.Addr != "" && host.Addr != host.Name {
			addrPort := host.AddrPort()
			addLiteral(addrPort, PlaceholderHost)
			if host.Addr != addrPort {
				addLiteral(host.Addr, PlaceholderHost)
			}
		}
		if host.User != "" {
			if re, err := regexp.Compile(`\b` + regexp.QuoteMeta(host.User) + `\b`); err == nil {
				addRE(re, PlaceholderUser)
			}
		}
	}
	addHost(h)
	addHost(jump)

	for _, re := range extra {
		addRE(re, PlaceholderRedacted)
	}
	if len(rules) == 0 {
		return nil
	}
	return &redactor{rules: rules}
}

// buildRedactors prepares one redactor per host that opted in.
func (b *Broker) buildRedactors() {
	b.redactors = make(map[string]*redactor, len(b.cfg.Hosts))
	for i := range b.cfg.Hosts {
		h := &b.cfg.Hosts[i]
		spec := b.cfg.EffectivePolicy(h)
		if !spec.RedactOutput {
			continue
		}
		var jump *config.Host
		if h.ProxyJump != "" {
			if j, err := b.cfg.Host(h.ProxyJump); err == nil {
				jump = j
			}
		}
		if r := newRedactor(h, jump, b.policies.For(h.Name).RedactPatterns()); r != nil {
			b.redactors[h.Name] = r
		}
	}
}

// redact rewrites a string for the caller. The operator's --reveal bypasses it.
func (b *Broker) redact(host, s string) string {
	if b.reveal {
		return s
	}
	return b.redactors[host].apply(s)
}

// redactErr rewrites an error message, preserving the original error when
// nothing needed hiding.
func (b *Broker) redactErr(host string, err error) error {
	if err == nil || b.reveal {
		return err
	}
	red := b.redactors[host]
	if red == nil {
		return err
	}
	before := err.Error()
	after := red.apply(before)
	if !red.changed(before, after) {
		return err
	}
	return errors.New(after)
}

// redactExec rewrites the caller-facing copy of a command result.
func (b *Broker) redactExec(res *ExecResult) *ExecResult {
	if res == nil || b.reveal {
		return res
	}
	red := b.redactors[res.Host]
	if red == nil {
		return res
	}
	res.Stdout = red.apply(res.Stdout)
	res.Stderr = red.apply(res.Stderr)
	res.Error = red.apply(res.Error)
	res.Reason = red.apply(res.Reason)
	res.Cwd = red.apply(res.Cwd)
	return res
}

// redactTransfer rewrites the caller-facing copy of an upload or download.
func (b *Broker) redactTransfer(res *TransferResult) *TransferResult {
	if res == nil || b.reveal {
		return res
	}
	red := b.redactors[res.Host]
	if red == nil {
		return res
	}
	res.Path = red.apply(res.Path)
	res.Reason = red.apply(res.Reason)
	return res
}
