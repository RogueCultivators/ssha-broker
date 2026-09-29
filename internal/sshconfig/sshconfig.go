// Package sshconfig reads OpenSSH client configuration well enough to import
// reality into ssha: aliases, addresses, users, ports, keys and jump hosts.
//
// It deliberately implements a useful subset. Runtime-conditional constructs
// (Match blocks, ProxyCommand) cannot be represented in the ssha config, so they
// are reported as warnings instead of being silently dropped.
package sshconfig

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ssha/internal/config"
)

// HostEntry is one concrete Host block from an ssh config file.
type HostEntry struct {
	// Alias is the name the user types (`ssh <alias>`), and becomes the ssha
	// host name.
	Alias string
	// HostName, User and Port are the resolved connection facts.
	HostName string
	User     string
	Port     int
	// IdentityFile keeps every path in order; the first is used.
	IdentityFile []string
	// ProxyJump is the raw value, e.g. "bastion" or "jump@10.0.0.1:22".
	ProxyJump string
	// ProxyCommand cannot be expressed in the ssha config.
	ProxyCommand string
	// Source is "file:line" where the block started.
	Source string
}

// Result is what a parse found.
type Result struct {
	Hosts    []HostEntry
	Warnings []string
}

// DefaultPath returns ~/.ssh/config.
func DefaultPath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".ssh", "config")
	}
	return ""
}

// Parse reads path and everything it Includes.
func Parse(path string) (*Result, error) {
	res := &Result{}
	defaults := &HostEntry{}
	if err := parseFile(path, res, defaults, map[string]bool{}, 0); err != nil {
		return nil, err
	}
	for i := range res.Hosts {
		inherit(&res.Hosts[i], defaults)
	}
	return res, nil
}

// inherit fills the fields a wildcard block (usually `Host *`) supplied. OpenSSH
// takes the first value it finds, so a concrete block always wins.
func inherit(e *HostEntry, d *HostEntry) {
	if e.User == "" {
		e.User = d.User
	}
	if e.Port == 0 {
		e.Port = d.Port
	}
	if len(e.IdentityFile) == 0 {
		e.IdentityFile = d.IdentityFile
	}
	if e.ProxyJump == "" {
		e.ProxyJump = d.ProxyJump
	}
	if e.ProxyCommand == "" {
		e.ProxyCommand = d.ProxyCommand
	}
}

func parseFile(path string, res *Result, defaults *HostEntry, seen map[string]bool, depth int) error {
	if depth > 8 {
		return fmt.Errorf("%s: Include is nested too deeply", path)
	}
	if abs, err := filepath.Abs(path); err == nil {
		if seen[abs] {
			return nil
		}
		seen[abs] = true
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var (
		// targets are indices into res.Hosts, not pointers: appending another
		// Host block can reallocate the slice and invalidate pointers.
		targets  []int
		isGlobal bool
		lineNo   int
		sc       = bufio.NewScanner(f)
	)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		key, value := splitKeyValue(line)
		switch strings.ToLower(key) {
		case "host":
			targets, isGlobal = nil, false
			var patterns []string
			for _, pattern := range strings.Fields(value) {
				if isPattern(pattern) {
					// "*" matches everything, so its block can act as defaults.
					// Any other pattern depends on matching we do not implement.
					if pattern == "*" {
						isGlobal = true
					} else {
						patterns = append(patterns, pattern)
					}
					continue
				}
				targets = append(targets, res.entryIndex(pattern, path, lineNo))
			}
			if len(targets) == 0 && !isGlobal {
				res.warn("%s:%d: `Host %s` relies on pattern matching, which ssha does not have; those hosts were not imported",
					path, lineNo, strings.Join(patterns, " "))
			}
		case "match":
			// Depends on the invoking user, host and address; not importable.
			targets, isGlobal = nil, false
			res.warn("%s:%d: a Match block was skipped: it depends on runtime conditions", path, lineNo)
		case "include":
			for _, inc := range expandInclude(path, value) {
				if err := parseFile(inc, res, defaults, seen, depth+1); err != nil {
					res.warn("%s: could not read Include %s: %v", path, inc, err)
				}
			}
		default:
			switch {
			case len(targets) > 0:
				for _, i := range targets {
					apply(&res.Hosts[i], key, value)
				}
			case isGlobal:
				apply(defaults, key, value)
			}
		}
	}
	return sc.Err()
}

// entryIndex returns the index of the entry for alias, creating it in the order
// the file first mentions it.
func (r *Result) entryIndex(alias, path string, line int) int {
	for i := range r.Hosts {
		if r.Hosts[i].Alias == alias {
			return i
		}
	}
	r.Hosts = append(r.Hosts, HostEntry{Alias: alias, Source: fmt.Sprintf("%s:%d", path, line)})
	return len(r.Hosts) - 1
}

func (r *Result) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// apply records a directive. OpenSSH keeps the first value it sees, so a field
// that already has one is left alone.
func apply(e *HostEntry, key, value string) {
	switch strings.ToLower(key) {
	case "hostname":
		if e.HostName == "" {
			e.HostName = unquote(value)
		}
	case "user":
		if e.User == "" {
			e.User = unquote(value)
		}
	case "port":
		if e.Port == 0 {
			if p, err := strconv.Atoi(unquote(value)); err == nil {
				e.Port = p
			}
		}
	case "identityfile":
		e.IdentityFile = append(e.IdentityFile, unquote(value))
	case "proxyjump":
		if e.ProxyJump == "" {
			e.ProxyJump = unquote(value)
		}
	case "proxycommand":
		if e.ProxyCommand == "" {
			e.ProxyCommand = unquote(value)
		}
	}
}

// stripComment removes an unquoted # comment.
func stripComment(line string) string {
	var quote rune
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			return line[:i]
		}
	}
	return line
}

// splitKeyValue handles both "Key value" and "Key=value".
func splitKeyValue(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		return line[:i], strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	}
	return line, ""
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isPattern(s string) bool {
	return strings.ContainsAny(s, "*?!")
}

// expandInclude resolves Include patterns relative to the including file, as
// OpenSSH does.
func expandInclude(from, value string) []string {
	base := filepath.Dir(from)
	var out []string
	for _, pattern := range strings.Fields(unquote(value)) {
		pattern = config.ExpandHome(pattern)
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(base, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		out = append(out, matches...)
	}
	return out
}

// ---------------------------------------------------------------------------
// conversion
// ---------------------------------------------------------------------------

// ReadOnlyAllow is the conservative allow list seeded for hosts imported as
// readonly: enough to look at a machine, nothing that changes it.
var ReadOnlyAllow = []string{
	`^ls\b`, `^cat\b`, `^tail\b`, `^head\b`, `^grep\b`, `^zgrep\b`, `^find\b`,
	`^df\b`, `^du\b`, `^free\b`, `^uptime\b`, `^ps\b`, `^top\b -b`,
	`^systemctl\s+status\b`, `^systemctl\s+list-units\b`,
	`^journalctl\b`, `^dmesg\b`,
	`^uname\b`, `^whoami\b`, `^id\b`, `^hostname\b`, `^pwd\b`,
	`^docker\s+(ps|logs|inspect|stats)\b`,
	`^ss\b`, `^netstat\b`,
}

// ConvertOptions controls how ssh config entries become ssha hosts.
type ConvertOptions struct {
	// PolicyMode is deny, readonly or allow. An empty value means deny: an
	// imported host should be visible before it is usable.
	PolicyMode string
	// Tags are added to every imported host, on top of "imported".
	Tags []string
}

// Converted is one ssh config entry turned into an ssha host, together with
// everything about that entry the operator should look at.
type Converted struct {
	Host     config.Host
	Source   string
	Warnings []string
}

// Convert maps entries to ssha hosts.
//
// Nothing is granted by default: a mode of deny (or unset) imports the host so
// an operator can see it, and leaves the decision about what an agent may run
// to the person who knows the machine. readonly seeds a read-only allow list.
func Convert(entries []HostEntry, opts ConvertOptions) []Converted {
	mode := opts.PolicyMode
	if mode == "" {
		mode = config.ModeDeny
	}
	byAlias := make(map[string]bool, len(entries))
	for _, e := range entries {
		byAlias[e.Alias] = true
	}

	out := make([]Converted, 0, len(entries))
	for _, e := range entries {
		var warnings []string
		h := config.Host{
			Name:        e.Alias,
			Addr:        e.HostName,
			User:        e.User,
			Port:        e.Port,
			Tags:        append([]string{"imported"}, opts.Tags...),
			Description: fmt.Sprintf("imported from %s", e.Source),
			Policy:      &config.Spec{Mode: mode},
		}
		if h.Addr == "" {
			h.Addr = e.Alias
		}
		if mode == config.ModeReadonly {
			h.Policy.Allow = append([]string{}, ReadOnlyAllow...)
		}

		switch {
		case len(e.IdentityFile) > 0:
			h.Auth = config.Auth{Type: "key", KeyPath: e.IdentityFile[0]}
			if len(e.IdentityFile) > 1 {
				warnings = append(warnings, fmt.Sprintf("%s: %s lists %d keys; ssha uses the first (%s)",
					e.Source, e.Alias, len(e.IdentityFile), e.IdentityFile[0]))
			}
		default:
			// OpenSSH would fall back to the agent and the default key names.
			h.Auth = config.Auth{Type: "agent"}
			warnings = append(warnings, fmt.Sprintf("%s: %s has no IdentityFile; imported as auth.type=agent (needs SSH_AUTH_SOCK)",
				e.Source, e.Alias))
		}

		if strings.Contains(h.Addr, "%") {
			warnings = append(warnings, fmt.Sprintf("%s: %s uses a %% token in HostName (%s); ssha does not expand tokens, so fix addr before using this host",
				e.Source, e.Alias, h.Addr))
		}

		if e.ProxyCommand != "" {
			warnings = append(warnings, fmt.Sprintf("%s: %s uses ProxyCommand, which ssha cannot express; the host was imported without a jump host",
				e.Source, e.Alias))
		}
		if jump := proxyJumpAlias(e.ProxyJump); jump != "" {
			if byAlias[jump] {
				h.ProxyJump = jump
			} else {
				warnings = append(warnings, fmt.Sprintf("%s: %s jumps through %q, which is not among the imported aliases; import it too, or set proxy_jump by hand",
					e.Source, e.Alias, jump))
			}
		}

		out = append(out, Converted{Host: h, Source: e.Source, Warnings: warnings})
	}
	return out
}

// proxyJumpAlias reduces "user@host:port,second" to the first hop's host.
func proxyJumpAlias(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	if i := strings.LastIndexByte(value, '@'); i >= 0 {
		value = value[i+1:]
	}
	if host, _, err := splitHostPort(value); err == nil {
		return host
	}
	return value
}

func splitHostPort(s string) (string, int, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("missing ]")
		}
		host := s[1:end]
		rest := strings.TrimPrefix(s[end+1:], ":")
		if rest == "" {
			return host, 0, nil
		}
		p, err := strconv.Atoi(rest)
		return host, p, err
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[:i], ":") {
		p, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return "", 0, err
		}
		return s[:i], p, nil
	}
	return s, 0, nil
}
