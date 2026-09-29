// Package config loads and validates the ssha configuration file.
//
// The configuration is intentionally file-based and human-editable: a host
// inventory, per-host credentials, and the policy/audit settings that govern
// what an agent is allowed to do.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// MarshalJSON renders the duration as "30s" rather than a nanosecond count.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON accepts a duration string ("30s", "5m") or a plain number of
// seconds, which is what an editor form naturally sends.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		*d = 0
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		v, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", str, err)
		}
		*d = Duration(v)
		return nil
	}
	secs, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid duration %s: expected a string like \"30s\" or a number of seconds", s)
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// Spec is a policy specification. It is defined here (rather than in the
// policy package) so that config has no dependency on the engine that
// evaluates it.
type Spec struct {
	// Mode is one of allow, readonly or deny.
	Mode string `yaml:"mode" json:"mode"`
	// Allow is the allowlist used when Mode is readonly. Entries are regular
	// expressions anchored at the start of the command.
	Allow []string `yaml:"allow_commands,omitempty" json:"allow_commands,omitempty"`
	// Deny is checked first, in every mode. Entries are regular expressions
	// matched against the raw command string.
	Deny []string `yaml:"deny_commands,omitempty" json:"deny_commands,omitempty"`
	// DenyPaths blocks file transfers whose remote path matches.
	DenyPaths []string `yaml:"deny_paths,omitempty" json:"deny_paths,omitempty"`
	// MaxOutputBytes caps the captured stdout+stderr per command.
	MaxOutputBytes int `yaml:"max_output_bytes,omitempty" json:"max_output_bytes,omitempty"`
	// Timeout caps a single command's wall-clock time.
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// DisableBaseline turns off the built-in destructive-command baseline
	// deny list. Not recommended.
	DisableBaseline bool `yaml:"disable_baseline,omitempty" json:"disable_baseline,omitempty"`
	// AllowShellMetachars permits ; | & < > backticks, newlines and $( in
	// readonly mode. It is off by default because an allow list over a raw
	// shell string cannot otherwise stop `ls; rm -rf /tmp` from matching a
	// `^ls` rule.
	AllowShellMetachars bool `yaml:"allow_shell_metacharacters,omitempty" json:"allow_shell_metacharacters,omitempty"`
	// Disclosure is full, alias or blind. It limits what an agent learns about
	// a host's identity: at alias and blind the address, port, user and proxy
	// are omitted from every tool result. Credentials are never disclosed.
	Disclosure string `yaml:"disclosure,omitempty" json:"disclosure,omitempty"`
	// RedactOutput replaces the host address, the user name and every
	// RedactPatterns match in command output before it is returned. The audit
	// log on disk keeps the original.
	RedactOutput bool `yaml:"redact_output,omitempty" json:"redact_output,omitempty"`
	// RedactPatterns are extra regular expressions replaced with <redacted>.
	RedactPatterns []string `yaml:"redact_patterns,omitempty" json:"redact_patterns,omitempty"`
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
	Type string `yaml:"type" json:"type"`
	// KeyPath is the private key file for Type=key.
	KeyPath string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	// KeyEnv holds a PEM private key inline (for Type=key with no file).
	KeyEnv string `yaml:"key_env,omitempty" json:"key_env,omitempty"`
	// PassphraseEnv and PassphraseFile hold the passphrase for an encrypted key.
	PassphraseEnv  string `yaml:"passphrase_env,omitempty" json:"passphrase_env,omitempty"`
	PassphraseFile string `yaml:"passphrase_file,omitempty" json:"passphrase_file,omitempty"`
	// PasswordEnv and PasswordFile hold the password for Type=password.
	PasswordEnv  string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordFile string `yaml:"password_file,omitempty" json:"password_file,omitempty"`
}

// HostKey describes how the remote host key is verified.
type HostKey struct {
	// KnownHosts is a known_hosts file. Defaults to ~/.ssh/known_hosts.
	KnownHosts string `yaml:"known_hosts,omitempty" json:"known_hosts,omitempty"`
	// Fingerprints accepts specific SHA256 fingerprints (e.g. "SHA256:abc...").
	Fingerprints []string `yaml:"fingerprints,omitempty" json:"fingerprints,omitempty"`
	// Insecure disables host key verification. Never use in production.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
}

// Host is a single SSH target.
type Host struct {
	Name string   `yaml:"name" json:"name"`
	Addr string   `yaml:"addr,omitempty" json:"addr,omitempty"`
	Port int      `yaml:"port,omitempty" json:"port,omitempty"`
	User string   `yaml:"user,omitempty" json:"user,omitempty"`
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Description is the operator's note about this machine: what runs on it,
	// what it is for, anything an agent should know. It is what discovery
	// searches, so a good note is how an agent finds the right host without
	// being told an address.
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Auth        Auth              `yaml:"auth" json:"auth"`
	HostKey     HostKey           `yaml:"host_key" json:"host_key"`
	ProxyJump   string            `yaml:"proxy_jump,omitempty" json:"proxy_jump,omitempty"`
	WorkDir     string            `yaml:"work_dir,omitempty" json:"work_dir,omitempty"`
	Env         map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Policy      *Spec             `yaml:"policy,omitempty" json:"policy,omitempty"`
	Disabled    bool              `yaml:"disabled,omitempty" json:"disabled,omitempty"`
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
	Path string `yaml:"path" json:"path"`
	// StoreOutput stores stdout/stderr in the audit record.
	StoreOutput *bool `yaml:"store_output" json:"store_output"`
	// MaxFieldBytes truncates stored stdout/stderr.
	MaxFieldBytes int `yaml:"max_field_bytes" json:"max_field_bytes"`
}

// StoreOutputEnabled reports whether output capture is enabled (default true).
func (a AuditConfig) StoreOutputEnabled() bool {
	return a.StoreOutput == nil || *a.StoreOutput
}

// Token scopes an HTTP MCP client to a subset of hosts.
type Token struct {
	Name     string   `yaml:"name" json:"name"`
	Value    string   `yaml:"value" json:"value"`
	ValueEnv string   `yaml:"value_env" json:"value_env"`
	Hosts    []string `yaml:"hosts" json:"hosts"` // glob patterns, empty means all
	Tags     []string `yaml:"tags,omitempty" json:"tags,omitempty"`
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
	HTTPAddr string  `yaml:"http_addr" json:"http_addr"`
	Tokens   []Token `yaml:"tokens" json:"tokens"`
}

// Config is the root document.
type Config struct {
	Version  int          `yaml:"version" json:"version"`
	Defaults Spec         `yaml:"defaults" json:"defaults"`
	Policy   Spec         `yaml:"policy" json:"policy"`
	Audit    AuditConfig  `yaml:"audit" json:"audit"`
	Server   ServerConfig `yaml:"server" json:"server"`
	Hosts    []Host       `yaml:"hosts" json:"hosts"`

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

// searchText is everything a discovery query matches against: the host name,
// the operator's note and the tags.
func (h *Host) searchText() string {
	parts := append([]string{h.Name}, h.Description)
	parts = append(parts, h.Tags...)
	return strings.ToLower(strings.Join(parts, " "))
}

// MatchQuery reports whether every whitespace-separated word in query appears
// somewhere in the host's searchable text. An empty query matches everything.
func (h *Host) MatchQuery(query string) bool {
	for _, word := range strings.Fields(strings.ToLower(query)) {
		if !strings.Contains(h.searchText(), word) {
			return false
		}
	}
	return true
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

// migrationHint turns a removed-field complaint into instructions, because
// strict parsing is only friendly if it says what to do instead.
func migrationHint(err error) string {
	switch {
	case strings.Contains(err.Error(), "field apps not found"):
		return "\n\nhint: the per-host `apps` list was removed. Put what runs on the\n" +
			"host in its `description` (the note) instead - agents search that text,\n" +
			"so unit names, ports and log paths belong there in your own words."
	default:
		return ""
	}
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
		return nil, fmt.Errorf("%s: %w%s", path, err, migrationHint(err))
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
