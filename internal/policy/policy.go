// Package policy decides whether a command or file transfer is permitted.
//
// Evaluation order for every command:
//
//  1. mode=deny          -> denied
//  2. baseline deny list -> denied (unless disabled)
//  3. user deny list     -> denied
//  4. mode=readonly      -> allowed only if it matches the allow list
//  5. mode=allow         -> allowed
//
// Deny always wins. The engine does not attempt to parse shell syntax: a
// command is a raw string. For untrusted agents prefer mode=readonly with a
// tight allow list over a deny list, because deny lists are trivially
// bypassable (`r”m -rf /`).
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"ssha/internal/config"
)

// baselineDeny is applied to every host. These are commands that no
// agent-driven workflow should ever execute by accident.
var baselineDeny = []string{
	`:\(\)\s*\{.*\}\s*;\s*:`, // fork bomb
	`\bmkfs(\.[a-z0-9]+)?\b`, // format a filesystem
	`\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd|vd|disk|mmcblk)`,
	`>\s*/dev/(sd|nvme|hd|vd|disk|mmcblk)`,
	`\brm\s+(-[a-zA-Z]+\s+)*/(\s|$)`, // rm -rf /
	`\brm\s+(-[a-zA-Z]+\s+)*/\*`,     // rm -rf /*
	`\brm\s+(-[a-zA-Z]+\s+)*/(etc|boot|usr|var|home)\b`,
	`\b(shutdown|reboot|halt|poweroff)\b`,
	`\binit\s+0\b`,
	`>\s*/etc/(passwd|shadow|sudoers)`,
	`\b(userdel|groupdel)\b`,
	`\bwipefs\b`,
	`\bchmod\s+-R\s+777\s+/\s*$`,
}

// shellMetachars matches the characters that let one command smuggle in
// another. An allow list matched against the whole string cannot stop
// `ls; rm -rf /tmp` from resembling `ls`, so readonly mode rejects these
// unless the operator opts in.
var shellMetachars = regexp.MustCompile("[;&|<>`\r\n]|\\$\\(")

// Compiled is a policy spec with its regular expressions compiled.
type Compiled struct {
	Spec      config.Spec
	deny      []*regexp.Regexp
	allow     []*regexp.Regexp
	denyPaths []*regexp.Regexp
	redact    []*regexp.Regexp
}

// Decision is the outcome of a policy check.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Mode    string `json:"mode"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func compileAll(patterns []string, anchor bool) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		expr := "(?s)" + p
		if anchor {
			expr = "(?s)^(?:" + p + ")"
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Compile prepares a spec for evaluation.
func Compile(spec config.Spec) (*Compiled, error) {
	spec = spec.WithDefaults()
	c := &Compiled{Spec: spec}

	deny := append([]string{}, spec.Deny...)
	if !spec.DisableBaseline {
		deny = append(baselineDeny, deny...)
	}
	var err error
	if c.deny, err = compileAll(deny, false); err != nil {
		return nil, err
	}
	if c.allow, err = compileAll(spec.Allow, true); err != nil {
		return nil, err
	}
	if c.denyPaths, err = compileAll(spec.DenyPaths, false); err != nil {
		return nil, err
	}
	if c.redact, err = compileAll(spec.RedactPatterns, false); err != nil {
		return nil, err
	}
	return c, nil
}

// Decide evaluates a raw command string.
func (c *Compiled) Decide(command string) Decision {
	d := Decision{Mode: c.Spec.Mode}
	switch c.Spec.Mode {
	case config.ModeDeny:
		d.Allowed = false
		d.Reason = "host policy mode is deny"
		return d
	case config.ModeReadonly, config.ModeAllow:
	default:
		d.Allowed = false
		d.Reason = fmt.Sprintf("unknown policy mode %q", c.Spec.Mode)
		return d
	}

	for _, re := range c.deny {
		if re.MatchString(command) {
			d.Allowed = false
			d.Rule = re.String()
			d.Reason = fmt.Sprintf("command matches deny rule %s", trimExpr(re.String()))
			return d
		}
	}

	if c.Spec.Mode == config.ModeReadonly {
		if !c.Spec.AllowShellMetachars && shellMetachars.MatchString(command) {
			d.Allowed = false
			d.Reason = "readonly policy: shell metacharacters (; | & < > backticks, newlines, $()) are not permitted; " +
				"run one command per call, or set policy.allow_shell_metacharacters"
			return d
		}
		for _, re := range c.allow {
			if re.MatchString(command) {
				d.Allowed = true
				d.Rule = re.String()
				return d
			}
		}
		d.Allowed = false
		d.Reason = "readonly policy: command is not in the allow list"
		return d
	}

	d.Allowed = true
	return d
}

// DecidePath evaluates a remote path for a transfer. write must be true for
// uploads and false for downloads: a readonly host may be read from but never
// written to.
func (c *Compiled) DecidePath(path string, write bool) Decision {
	d := Decision{Mode: c.Spec.Mode, Allowed: true}
	switch c.Spec.Mode {
	case config.ModeDeny:
		d.Allowed = false
		d.Reason = "host policy mode is deny"
		return d
	case config.ModeReadonly:
		if write {
			d.Allowed = false
			d.Reason = "readonly policy: file writes are not permitted, use ssh_exec instead"
			return d
		}
	case config.ModeAllow:
	default:
		d.Allowed = false
		d.Reason = fmt.Sprintf("unknown policy mode %q", c.Spec.Mode)
		return d
	}
	for _, re := range c.denyPaths {
		if re.MatchString(path) {
			d.Allowed = false
			d.Rule = re.String()
			d.Reason = fmt.Sprintf("path matches deny_paths rule %s", trimExpr(re.String()))
			return d
		}
	}
	return d
}

// RedactPatterns returns the operator-supplied expressions whose matches are
// scrubbed from command output before it reaches the caller.
func (c *Compiled) RedactPatterns() []*regexp.Regexp { return c.redact }

// Timeout returns the effective per-command timeout.
func (c *Compiled) MaxOutputBytes() int { return c.Spec.MaxOutputBytes }

func trimExpr(s string) string {
	s = strings.TrimPrefix(s, "(?s)")
	s = strings.TrimPrefix(s, "^(?:")
	s = strings.TrimSuffix(s, ")")
	return s
}

// Set maps host names to compiled policies.
type Set map[string]*Compiled

// NewSet compiles a policy for every host in the config.
func NewSet(cfg *config.Config) (Set, error) {
	set := make(Set, len(cfg.Hosts))
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		c, err := Compile(cfg.EffectivePolicy(h))
		if err != nil {
			return nil, fmt.Errorf("host %q: %w", h.Name, err)
		}
		set[h.Name] = c
	}
	return set, nil
}

// For returns the compiled policy for a host, falling back to a deny-all
// policy if the host is unknown.
func (s Set) For(host string) *Compiled {
	if c, ok := s[host]; ok {
		return c
	}
	c, _ := Compile(config.Spec{Mode: config.ModeDeny})
	return c
}
