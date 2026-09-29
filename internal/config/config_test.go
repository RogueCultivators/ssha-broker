package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationParsing(t *testing.T) {
	type wrapper struct {
		D Duration `yaml:"d"`
	}
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"", 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			var w wrapper
			if err := yaml.Unmarshal([]byte("d: "+quote(tc.in)), &w); err != nil {
				t.Fatalf("unmarshal %q: %v", tc.in, err)
			}
			if w.D.D() != tc.want {
				t.Errorf("D() = %v, want %v", w.D.D(), tc.want)
			}
		})
	}

	var w wrapper
	if err := yaml.Unmarshal([]byte("d: nonsense"), &w); err == nil {
		t.Fatal("expected an error for an unparseable duration")
	}
}

func quote(s string) string { return `"` + s + `"` }

func TestMerge(t *testing.T) {
	base := Spec{Mode: ModeAllow, Timeout: Duration(10 * time.Second), MaxOutputBytes: 1000, Deny: []string{"a"}}
	tests := []struct {
		name string
		over *Spec
		want func(Spec) bool
		desc string
	}{
		{
			name: "nil override keeps the base",
			over: nil,
			want: func(s Spec) bool { return s.Mode == ModeAllow && s.Timeout.D() == 10*time.Second && len(s.Deny) == 1 },
			desc: "mode, timeout and deny preserved",
		},
		{
			name: "mode override wins",
			over: &Spec{Mode: ModeReadonly},
			want: func(s Spec) bool { return s.Mode == ModeReadonly && s.Timeout.D() == 10*time.Second },
			desc: "mode replaced, timeout kept",
		},
		{
			name: "zero values do not clobber",
			over: &Spec{Mode: ""},
			want: func(s Spec) bool { return s.Mode == ModeAllow },
			desc: "empty mode keeps the base",
		},
		{
			name: "allow list override replaces rather than appends",
			over: &Spec{Allow: []string{"x", "y"}},
			want: func(s Spec) bool { return len(s.Allow) == 2 },
			desc: "allow list replaced",
		},
		{
			name: "timeout override wins",
			over: &Spec{Timeout: Duration(time.Minute)},
			want: func(s Spec) bool { return s.Timeout.D() == time.Minute },
			desc: "timeout replaced",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(base, tc.over)
			if !tc.want(got) {
				t.Errorf("Merge produced %+v; want %s", got, tc.desc)
			}
		})
	}
}

func TestWithDefaults(t *testing.T) {
	got := Spec{}.WithDefaults()
	if got.Mode != ModeAllow {
		t.Errorf("Mode = %q, want allow", got.Mode)
	}
	if got.Timeout.D() != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", got.Timeout.D(), DefaultTimeout)
	}
	if got.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Errorf("MaxOutputBytes = %d, want %d", got.MaxOutputBytes, DefaultMaxOutputBytes)
	}

	capped := Spec{MaxOutputBytes: HardMaxOutputBytes * 10}.WithDefaults()
	if capped.MaxOutputBytes != HardMaxOutputBytes {
		t.Errorf("MaxOutputBytes = %d, want it capped at %d", capped.MaxOutputBytes, HardMaxOutputBytes)
	}
}

func TestAddrPort(t *testing.T) {
	tests := []struct {
		host Host
		want string
	}{
		{Host{Addr: "10.0.0.1"}, "10.0.0.1:22"},
		{Host{Addr: "10.0.0.1", Port: 2222}, "10.0.0.1:2222"},
		{Host{Name: "web"}, "web:22"},
		{Host{Addr: "10.0.0.1:2200"}, "10.0.0.1:2200"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.host.AddrPort(); got != tc.want {
				t.Errorf("AddrPort() = %q, want %q", got, tc.want)
			}
		})
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimalHost = `
hosts:
  - name: web
    addr: 10.0.0.1
    user: deploy
    auth: {type: key, key_path: /tmp/key}
`

func TestLoadMinimal(t *testing.T) {
	cfg, err := Load(writeConfig(t, "version: 1\n"+minimalHost))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(cfg.Hosts))
	}
	if cfg.Hosts[0].Port != 22 {
		t.Errorf("Port = %d, want the default 22", cfg.Hosts[0].Port)
	}
	if got := cfg.EffectivePolicy(&cfg.Hosts[0]).Mode; got != ModeAllow {
		t.Errorf("default mode = %q, want allow", got)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(writeConfig(t, "version: 1\nnonsense: true\n"+minimalHost))
	if err == nil {
		t.Fatal("expected an error for an unknown top-level key")
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "no hosts",
			body: "version: 1\n",
			want: "no hosts",
		},
		{
			name: "duplicate names",
			body: minimalHost + "  - name: web\n    auth: {type: key, key_path: /tmp/key}\n",
			want: "duplicate",
		},
		{
			name: "key auth without a key",
			body: "hosts:\n  - name: web\n    auth: {type: key}\n",
			want: "key_path or key_env",
		},
		{
			name: "unknown auth type",
			body: "hosts:\n  - name: web\n    auth: {type: telepathy}\n",
			want: "unknown auth.type",
		},
		{
			name: "readonly without an allow list",
			body: "hosts:\n  - name: web\n    auth: {type: key, key_path: /tmp/key}\n    policy: {mode: readonly}\n",
			want: "readonly requires at least one allow_commands",
		},
		{
			name: "unknown policy mode",
			body: "hosts:\n  - name: web\n    auth: {type: key, key_path: /tmp/key}\n    policy: {mode: yolo}\n",
			want: "unknown policy mode",
		},
		{
			name: "dangling proxy_jump",
			body: minimalHost + "    proxy_jump: ghost\n",
			want: "unknown host",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestPasswordAuthWithoutASourceIsAllowed(t *testing.T) {
	// The CLI can prompt for the password, so a missing source is not a config
	// error; a headless MCP server reports it when it tries to connect.
	cfg, err := Load(writeConfig(t, "hosts:\n  - name: web\n    auth: {type: password}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Hosts[0].AuthType(); got != "password" {
		t.Errorf("AuthType() = %q, want password", got)
	}
}

func TestEffectivePolicyLayers(t *testing.T) {
	body := `
policy:
  mode: allow
  deny_commands: ['\bmkfs\b']
  timeout: 60s
hosts:
  - name: ro
    auth: {type: key, key_path: /tmp/key}
    policy:
      mode: readonly
      allow_commands: ['^ls\b']
      timeout: 15s
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	spec := cfg.EffectivePolicy(&cfg.Hosts[0])
	if spec.Mode != ModeReadonly {
		t.Errorf("Mode = %q, want readonly", spec.Mode)
	}
	if spec.Timeout.D() != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", spec.Timeout.D())
	}
	if len(spec.Deny) != 1 {
		t.Errorf("global deny list was not inherited: %+v", spec.Deny)
	}
	if len(spec.Allow) != 1 {
		t.Errorf("Allow = %+v, want the host allow list", spec.Allow)
	}
}

func TestDisclosureDefaultsToFull(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalHost))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.EffectivePolicy(&cfg.Hosts[0]).Disclosure; got != DisclosureFull {
		t.Errorf("Disclosure = %q, want %q", got, DisclosureFull)
	}
}

func TestValidateRejectsUnknownDisclosure(t *testing.T) {
	body := "hosts:\n  - name: web\n    auth: {type: key, key_path: /tmp/key}\n    policy: {disclosure: sometimes}\n"
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("expected an error for an unknown disclosure level")
	}
	if !strings.Contains(err.Error(), "disclosure") {
		t.Errorf("error = %v, want it to mention disclosure", err)
	}
}

func TestMergeDisclosureAndRedaction(t *testing.T) {
	base := Spec{Mode: ModeAllow, Disclosure: DisclosureAlias, RedactOutput: true}
	tests := []struct {
		name         string
		over         *Spec
		wantDisclose string
		wantRedact   bool
	}{
		{"inherits when unset", &Spec{}, DisclosureAlias, true},
		{"host can tighten to blind", &Spec{Disclosure: DisclosureBlind}, DisclosureBlind, true},
		{"host can loosen back to full", &Spec{Disclosure: DisclosureFull}, DisclosureFull, true},
		{"redaction can only be enabled", &Spec{RedactOutput: false}, DisclosureAlias, true},
		{"redaction can be enabled per host", &Spec{RedactOutput: true}, DisclosureAlias, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(base, tc.over)
			if got.Disclosure != tc.wantDisclose {
				t.Errorf("Disclosure = %q, want %q", got.Disclosure, tc.wantDisclose)
			}
			if got.RedactOutput != tc.wantRedact {
				t.Errorf("RedactOutput = %v, want %v", got.RedactOutput, tc.wantRedact)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	body := `
hosts:
  - name: web-1
    tags: [prod, web]
    auth: {type: key, key_path: /tmp/key}
  - name: web-2
    tags: [staging, web]
    auth: {type: key, key_path: /tmp/key}
  - name: db-1
    tags: [prod, db]
    auth: {type: key, key_path: /tmp/key}
  - name: retired
    disabled: true
    tags: [prod]
    auth: {type: key, key_path: /tmp/key}
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		tags     []string
		patterns []string
		want     []string
	}{
		{"no filter returns all enabled hosts", nil, nil, []string{"web-1", "web-2", "db-1"}},
		{"single tag", []string{"prod"}, nil, []string{"web-1", "db-1"}},
		{"tags are ANDed", []string{"prod", "web"}, nil, []string{"web-1"}},
		{"name glob", nil, []string{"web-*"}, []string{"web-1", "web-2"}},
		{"tag and glob", []string{"web"}, []string{"*-1"}, []string{"web-1"}},
		{"disabled hosts are excluded", []string{"prod"}, []string{"retired"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cfg.Select(tc.tags, tc.patterns)
			var names []string
			for _, h := range got {
				names = append(names, h.Name)
			}
			if len(names) != len(tc.want) {
				t.Fatalf("got %v, want %v", names, tc.want)
			}
			for i := range names {
				if names[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", names, tc.want)
				}
			}
		})
	}
}

func TestAuditDefaults(t *testing.T) {
	if (&AuditConfig{}).StoreOutputEnabled() != true {
		t.Error("store_output should default to true")
	}
	no := false
	if (&AuditConfig{StoreOutput: &no}).StoreOutputEnabled() != false {
		t.Error("store_output: false should be honoured")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got, want := ExpandHome("~/x"), filepath.Join(home, "x"); got != want {
		t.Errorf("ExpandHome(~/x) = %q, want %q", got, want)
	}
	if got := ExpandHome("/absolute/path"); got != "/absolute/path" {
		t.Errorf("ExpandHome left an absolute path alone but got %q", got)
	}
	t.Setenv("SSHA_TEST_VAR", "value")
	if got := ExpandHome("$SSHA_TEST_VAR/x"); got != "value/x" {
		t.Errorf("ExpandHome did not expand the environment: %q", got)
	}
}
