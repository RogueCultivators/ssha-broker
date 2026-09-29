// Package config loads and validates the ssha configuration file.
//
// The configuration is intentionally file-based and human-editable: a host
// inventory, per-host credentials, and the policy/audit settings that govern
// what an agent is allowed to do.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy modes.
const (
	// ModeAllow permits every command except those matching Deny.
	ModeAllow = "allow"
	// ModeReadonly permits only commands matching Allow.
	ModeReadonly = "readonly"
	// ModeDeny blocks every command on the host.
	ModeDeny = "deny"
)

// Disclosure levels control how much of a host's identity the caller (in
// practice, an AI agent) is allowed to see. Credentials are never disclosed at
// any level.
const (
	// DisclosureFull shows name, address, port, user and auth type. Default.
	DisclosureFull = "full"
	// DisclosureAlias shows the name, tags, description and policy, but hides
	// the address, port, user, proxy and working directory.
	DisclosureAlias = "alias"
	// DisclosureBlind shows the name, policy mode and limits only.
	DisclosureBlind = "blind"
)

// Duration is a YAML-friendly time.Duration ("60s", "5m").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML parses a human-readable duration string.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Spec is a policy specification. It is defined here (rather than in the
// policy package) so that config has no dependency on the engine that
// evaluates it.
type Spec struct {
	// Mode is one of allow, readonly or deny.
	Mode string `yaml:"mode"`
	// Allow is the allowlist used when Mode is readonly. Entries are regular
	// expressions anchored at the start of the command.
	Allow []string `yaml:"allow_commands"`
	// Deny is checked first, in every mode. Entries are regular expressions
	// matched against the raw command string.
	Deny []string `yaml:"deny_commands"`
	// DenyPaths blocks file transfers whose remote path matches.
	DenyPaths []string `yaml:"deny_paths"`
	// MaxOutputBytes caps the captured stdout+stderr per command.
	MaxOutputBytes int `yaml:"max_output_bytes"`
	// Timeout caps a single command's wall-clock time.
	Timeout Duration `yaml:"timeout"`
	// DisableBaseline turns off the built-in destructive-command baseline
	// deny list. Not recommended.
	DisableBaseline bool `yaml:"disable_baseline"`
	// AllowShellMetachars permits ; | & < > backticks, newlines and $( in
	// readonly mode. It is off by default because an allow list over a raw
	// shell string cannot otherwise stop `ls; rm -rf /tmp` from matching a
	// `^ls` rule.
	AllowShellMetachars bool `yaml:"allow_shell_metacharacters"`
	// Disclosure is full, alias or blind. It limits what an agent learns about
	// a host's identity: at alias and blind the address, port, user and proxy
	// are omitted from every tool result. Credentials are never disclosed.
	Disclosure string `yaml:"disclosure"`
	// RedactOutput replaces the host address, the user name and every
	// RedactPatterns match in command output before it is returned. The audit
	// log on disk keeps the original.
	RedactOutput bool `yaml:"redact_output"`
	// RedactPatterns are extra regular expressions replaced with <redacted>.
	RedactPatterns []string `yaml:"redact_patterns"`
}

// Defaults applied when neither the global nor the host spec sets a value.
const (
	DefaultTimeout        = 60 * time.Second
	DefaultMaxOutputBytes = 256 * 1024
	// HardMaxOutputBytes is the absolute ceiling, regardless of config.
	HardMaxOutputBytes = 8 * 1024 * 1024
)

// WithDefaults fills unset numeric fields.
func (s Spec) WithDefaults() Spec {
	if s.Timeout <= 0 {
		s.Timeout = Duration(DefaultTimeout)
	}
	if s.MaxOutputBytes <= 0 {
		s.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if s.MaxOutputBytes > HardMaxOutputBytes {
		s.MaxOutputBytes = HardMaxOutputBytes
	}
	if s.Mode == "" {
		s.Mode = ModeAllow
	}
	if s.Disclosure == "" {
		s.Disclosure = DisclosureFull
	}
	return s
}

// Merge overlays non-empty fields of over onto base.
func Merge(base Spec, over *Spec) Spec {
	out := base
	if over == nil {
		return out.WithDefaults()
	}
	if over.Mode != "" {
		out.Mode = over.Mode
	}
	if over.Allow != nil {
		out.Allow = over.Allow
	}
	if over.Deny != nil {
		out.Deny = over.Deny
	}
	if over.DenyPaths != nil {
		out.DenyPaths = over.DenyPaths
	}
	if over.MaxOutputBytes > 0 {
		out.MaxOutputBytes = over.MaxOutputBytes
	}
	if over.Timeout > 0 {
		out.Timeout = over.Timeout
	}
	if over.DisableBaseline {
		out.DisableBaseline = true
	}
	if over.AllowShellMetachars {
		out.AllowShellMetachars = true
	}
	if over.RedactOutput {
		out.RedactOutput = true
	}
	if over.RedactPatterns != nil {
		out.RedactPatterns = over.RedactPatterns
	}
	if over.Disclosure != "" {
		out.Disclosure = over.Disclosure
	}
	return out.WithDefaults()
}

// Auth describes how to authenticate a host.
//
// Every secret can come from an environment variable, a file, or - from the
// CLI only - an interactive prompt. Environment variables win, then files,
// then the prompt.
type Auth struct {
	// Type is one of key, agent, password.
	Type string `yaml:"type"`
	// KeyPath is the private key file for Type=key.
	KeyPath string `yaml:"key_path"`
	// KeyEnv holds a PEM private key inline (for Type=key with no file).
	KeyEnv string `yaml:"key_env"`
	// PassphraseEnv and PassphraseFile hold the passphrase for an encrypted key.
	PassphraseEnv  string `yaml:"passphrase_env"`
	PassphraseFile string `yaml:"passphrase_file"`
	// PasswordEnv and PasswordFile hold the password for Type=password.
	PasswordEnv  string `yaml:"password_env"`
	PasswordFile string `yaml:"password_file"`
}

// HostKey describes how the remote host key is verified.
type HostKey struct {
	// KnownHosts is a known_hosts file. Defaults to ~/.ssh/known_hosts.
	KnownHosts string `yaml:"known_hosts"`
	// Fingerprints accepts specific SHA256 fingerprints (e.g. "SHA256:abc...").
	Fingerprints []string `yaml:"fingerprints"`
	// Insecure disables host key verification. Never use in production.
	Insecure bool `yaml:"insecure"`
}

// Host is a single SSH target.
type Host struct {
	Name        string            `yaml:"name"`
	Addr        string            `yaml:"addr"`
	Port        int               `yaml:"port"`
	User        string            `yaml:"user"`
	Tags        []string          `yaml:"tags"`
	Description string            `yaml:"description"`
	Auth        Auth              `yaml:"auth"`
	HostKey     HostKey           `yaml:"host_key"`
	ProxyJump   string            `yaml:"proxy_jump"`
	WorkDir     string            `yaml:"work_dir"`
	Env         map[string]string `yaml:"env"`
	Policy      *Spec             `yaml:"policy"`
	Disabled    bool              `yaml:"disabled"`
}

// AuthType returns the effective auth type, defaulting to key.
func (h Host) AuthType() string {
	if h.Auth.Type == "" {
		return "key"
	}
	return h.Auth.Type
}

// AddrPort returns host:port with the default SSH port applied.
func (h Host) AddrPort() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	addr := h.Addr
	if addr == "" {
		addr = h.Name
	}
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return addr // already host:port (or an IPv6 without brackets)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// AuditConfig controls the append-only audit log.
type AuditConfig struct {
	// Path is the JSONL audit file. Defaults to ~/.local/share/ssha/audit.jsonl.
	Path string `yaml:"path"`
	// StoreOutput stores stdout/stderr in the audit record.
	StoreOutput *bool `yaml:"store_output"`
	// MaxFieldBytes truncates stored stdout/stderr.
	MaxFieldBytes int `yaml:"max_field_bytes"`
}

// StoreOutputEnabled reports whether output capture is enabled (default true).
func (a AuditConfig) StoreOutputEnabled() bool {
	return a.StoreOutput == nil || *a.StoreOutput
}

// Token scopes an HTTP MCP client to a subset of hosts.
type Token struct {
	Name     string   `yaml:"name"`
	Value    string   `yaml:"value"`
	ValueEnv string   `yaml:"value_env"`
	Hosts    []string `yaml:"hosts"` // glob patterns, empty means all
	Tags     []string `yaml:"tags"`
}

// Resolve returns the token secret, reading from the environment if needed.
func (t Token) Resolve() (string, error) {
	if t.Value != "" {
		return t.Value, nil
	}
	if t.ValueEnv != "" {
		v := os.Getenv(t.ValueEnv)
		if v == "" {
			return "", fmt.Errorf("token %q: environment variable %s is empty", t.Name, t.ValueEnv)
		}
		return v, nil
	}
	return "", fmt.Errorf("token %q: neither value nor value_env is set", t.Name)
}

// ServerConfig configures the HTTP MCP transport.
type ServerConfig struct {
	// HTTPAddr is the listen address for `ssha mcp --http`. Host 127.0.0.1 by
	// default; exposing it beyond localhost requires tokens.
	HTTPAddr string  `yaml:"http_addr"`
	Tokens   []Token `yaml:"tokens"`
}

// Config is the root document.
type Config struct {
	Version  int          `yaml:"version"`
	Defaults Spec         `yaml:"defaults"`
	Policy   Spec         `yaml:"policy"`
	Audit    AuditConfig  `yaml:"audit"`
	Server   ServerConfig `yaml:"server"`
	Hosts    []Host       `yaml:"hosts"`

	// path is the file this config was loaded from.
	path string
	// byName indexes Hosts.
	byName map[string]*Host
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }

// GlobalPolicy returns the effective default policy.
func (c *Config) GlobalPolicy() Spec { return Merge(c.Defaults, &c.Policy) }

// EffectivePolicy returns the policy for a host, layering global then host.
func (c *Config) EffectivePolicy(h *Host) Spec {
	return Merge(c.GlobalPolicy(), h.Policy)
}

// Host returns a host by name.
func (c *Config) Host(name string) (*Host, error) {
	if h, ok := c.byName[name]; ok {
		return h, nil
	}
	names := make([]string, 0, len(c.Hosts))
	for i := range c.Hosts {
		names = append(names, c.Hosts[i].Name)
	}
	return nil, fmt.Errorf("unknown host %q (configured: %s)", name, strings.Join(names, ", "))
}

// Select returns hosts matching the given tags and/or glob name patterns.
// Tags are ANDed together. Disabled hosts are always excluded.
func (c *Config) Select(tags, patterns []string) []*Host {
	var out []*Host
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.Disabled {
			continue
		}
		if len(tags) > 0 && !hasAllTags(h.Tags, tags) {
			continue
		}
		if len(patterns) > 0 && !matchAny(patterns, h.Name) {
			continue
		}
		out = append(out, h)
	}
	return out
}

func hasAllTags(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, t := range have {
		set[t] = struct{}{}
	}
	for _, t := range want {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Validate checks structural invariants and normalizes defaults.
func (c *Config) Validate() error {
	if len(c.Hosts) == 0 {
		return errors.New("config: no hosts defined")
	}
	c.byName = make(map[string]*Host, len(c.Hosts))
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.Name == "" {
			return fmt.Errorf("config: host #%d has no name", i+1)
		}
		if _, dup := c.byName[h.Name]; dup {
			return fmt.Errorf("config: duplicate host name %q", h.Name)
		}
		if h.Addr == "" {
			h.Addr = h.Name
		}
		if h.Port == 0 {
			h.Port = 22
		}
		switch h.AuthType() {
		case "key":
			if h.Auth.KeyPath == "" && h.Auth.KeyEnv == "" {
				return fmt.Errorf("config: host %q: auth.type=key requires key_path or key_env", h.Name)
			}
		case "password":
			// No source is required here: the CLI can prompt for the password.
			// A headless MCP server reports a clear error at connect time.
		case "agent":
		default:
			return fmt.Errorf("config: host %q: unknown auth.type %q", h.Name, h.Auth.Type)
		}
		spec := c.EffectivePolicy(h)
		switch spec.Mode {
		case ModeAllow, ModeReadonly, ModeDeny:
		default:
			return fmt.Errorf("config: host %q: unknown policy mode %q", h.Name, spec.Mode)
		}
		switch spec.Disclosure {
		case DisclosureFull, DisclosureAlias, DisclosureBlind:
		default:
			return fmt.Errorf("config: host %q: unknown policy disclosure %q (want full, alias or blind)", h.Name, spec.Disclosure)
		}
		if spec.Mode == ModeReadonly && len(spec.Allow) == 0 {
			return fmt.Errorf("config: host %q: policy mode readonly requires at least one allow_commands entry", h.Name)
		}
		c.byName[h.Name] = h
	}
	for i, h := range c.Hosts {
		if h.ProxyJump == "" {
			continue
		}
		if _, err := c.Host(h.ProxyJump); err != nil {
			return fmt.Errorf("config: host %q: proxy_jump: %w", c.Hosts[i].Name, err)
		}
	}
	return nil
}

// Load reads, parses and validates a config file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	cfg := &Config{Version: 1}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Common search locations, in precedence order.
//
//	--config flag, $SSHA_CONFIG, ./ssha.yaml, ./ssha.yml,
//	~/.config/ssha/config.yaml, /etc/ssha/config.yaml
func Candidates() []string {
	var out []string
	if v := os.Getenv("SSHA_CONFIG"); v != "" {
		out = append(out, ExpandHome(v))
	}
	out = append(out, "ssha.yaml", "ssha.yml")
	out = append(out, ExpandHome("~/.config/ssha/config.yaml"))
	out = append(out, "/etc/ssha/config.yaml")
	return out
}

// Discover returns the first existing candidate path.
func Discover() (string, error) {
	for _, p := range Candidates() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("no config file found; run `ssha init` or pass --config")
}

// ExpandHome expands a leading ~ and applies environment expansion.
func ExpandHome(p string) string {
	if p == "" {
		return p
	}
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
		}
	}
	return p
}

// DefaultAuditPath is used when audit.path is unset.
func DefaultAuditPath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".local", "share", "ssha", "audit.jsonl")
	}
	return "ssha-audit.jsonl"
}

// DefaultKnownHosts returns ~/.ssh/known_hosts.
func DefaultKnownHosts() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".ssh", "known_hosts")
	}
	return ""
}
