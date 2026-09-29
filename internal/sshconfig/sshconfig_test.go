package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"ssha/internal/config"
)

// marshalConfig renders hosts the way ssha init would, for the validator test.
func marshalConfig(hosts []config.Host) ([]byte, error) {
	return yaml.Marshal(struct {
		Hosts []config.Host `yaml:"hosts"`
	}{Hosts: hosts})
}

// writeConfig writes files into a temp dir and returns the main config path.
// Keys are filenames relative to that dir.
func writeConfig(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "config")
}

func entryFor(t *testing.T, entries []HostEntry, alias string) HostEntry {
	t.Helper()
	for _, e := range entries {
		if e.Alias == alias {
			return e
		}
	}
	t.Fatalf("no entry for %q in %+v", alias, entries)
	return HostEntry{}
}

func TestParseBasics(t *testing.T) {
	path := writeConfig(t, map[string]string{"config": `
# a leading comment
Host *
    ServerAliveInterval 60
    User deploy

Host bastion
    HostName bastion.example.com
    User jump
    IdentityFile ~/.ssh/id_ed25519

Host web-1 web-2
    HostName 10.0.0.1
    Port 2222
    ProxyJump bastion
    IdentityFile "~/.ssh/work key"

host db-1
    HOSTNAME db.example.com
`})

	res, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Hosts) != 4 {
		t.Fatalf("got %d entries, want 4: %+v", len(res.Hosts), res.Hosts)
	}

	// `Host web-1 web-2` must configure both, not just the last one.
	web1 := entryFor(t, res.Hosts, "web-1")
	web2 := entryFor(t, res.Hosts, "web-2")
	if web1.HostName != "10.0.0.1" || web2.HostName != "10.0.0.1" {
		t.Errorf("both aliases on one Host line should get HostName, got %q and %q", web1.HostName, web2.HostName)
	}
	if web1.Port != 2222 || web2.Port != 2222 {
		t.Errorf("Port = %d and %d, want 2222", web1.Port, web2.Port)
	}
	if web1.ProxyJump != "bastion" {
		t.Errorf("ProxyJump = %q, want bastion", web1.ProxyJump)
	}
	if web1.User != "deploy" {
		t.Errorf("User = %q, want the value inherited from `Host *`", web1.User)
	}
	if len(web1.IdentityFile) != 1 || web1.IdentityFile[0] != "~/.ssh/work key" {
		t.Errorf("quoted IdentityFile not unquoted: %+v", web1.IdentityFile)
	}

	// A concrete block wins over the wildcard one.
	if got := entryFor(t, res.Hosts, "bastion").User; got != "jump" {
		t.Errorf("bastion User = %q, want jump", got)
	}
	// Keys are case insensitive.
	if got := entryFor(t, res.Hosts, "db-1").HostName; got != "db.example.com" {
		t.Errorf("db-1 HostName = %q", got)
	}
}

func TestParseSkipsPatternBlocks(t *testing.T) {
	path := writeConfig(t, map[string]string{"config": `
Host *
    User deploy

Host *.internal
    User someone
    IdentityFile ~/.ssh/internal

Host web-1
    HostName 10.0.0.1
`})

	res, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("got %d entries, want only web-1: %+v", len(res.Hosts), res.Hosts)
	}
	// `*.internal` must not leak into the global defaults.
	if got := res.Hosts[0].User; got != "deploy" {
		t.Errorf("User = %q, want deploy from `Host *`, not from `*.internal`", got)
	}
	if len(res.Hosts[0].IdentityFile) != 0 {
		t.Errorf("IdentityFile leaked from a pattern block: %+v", res.Hosts[0].IdentityFile)
	}
	var found bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "*.internal") && strings.Contains(w, "pattern matching") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about the pattern block, got %v", res.Warnings)
	}
}

func TestParseIncludeAndCycle(t *testing.T) {
	path := writeConfig(t, map[string]string{
		"config":       "Host main\n    HostName 10.0.0.1\nInclude conf.d/*\nInclude config\n",
		"conf.d/extra": "Host extra-1\n    HostName 10.1.0.1\n",
	})

	res, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Hosts) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(res.Hosts), res.Hosts)
	}
	if got := entryFor(t, res.Hosts, "extra-1").HostName; got != "10.1.0.1" {
		t.Errorf("included host not parsed: %q", got)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("a self-include should be silently ignored, got %v", res.Warnings)
	}
}

func TestStripCommentRespectsQuotes(t *testing.T) {
	got := stripComment(`IdentityFile "/home/me/key #2" # the second key`)
	if !strings.Contains(got, "#2") {
		t.Errorf("a # inside quotes was treated as a comment: %q", got)
	}
	if strings.Contains(got, "the second key") {
		t.Errorf("a trailing comment survived: %q", got)
	}
}

func TestConvertPolicyModes(t *testing.T) {
	entries := []HostEntry{{Alias: "web-1", HostName: "10.0.0.1", IdentityFile: []string{"~/.ssh/id"}}}

	tests := []struct {
		mode      string
		wantMode  string
		wantAllow bool
	}{
		{"", config.ModeDeny, false},
		{config.ModeDeny, config.ModeDeny, false},
		{config.ModeReadonly, config.ModeReadonly, true},
		{config.ModeAllow, config.ModeAllow, false},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			got := Convert(entries, ConvertOptions{PolicyMode: tc.mode})
			if len(got) != 1 {
				t.Fatalf("got %d results", len(got))
			}
			p := got[0].Host.Policy
			if p == nil || p.Mode != tc.wantMode {
				t.Fatalf("policy = %+v, want mode %q", p, tc.wantMode)
			}
			if tc.wantAllow && len(p.Allow) == 0 {
				t.Error("readonly should seed an allow list")
			}
			if !tc.wantAllow && len(p.Allow) != 0 {
				t.Errorf("mode %q should not seed an allow list: %v", tc.wantMode, p.Allow)
			}
		})
	}
}

func TestConvertAuthAndTags(t *testing.T) {
	tests := []struct {
		name     string
		entry    HostEntry
		wantAuth string
		wantKey  string
	}{
		{"key file", HostEntry{Alias: "a", IdentityFile: []string{"~/.ssh/id"}}, "key", "~/.ssh/id"},
		{"no key falls back to the agent", HostEntry{Alias: "b"}, "agent", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Convert([]HostEntry{tc.entry}, ConvertOptions{Tags: []string{"work"}})
			h := got[0].Host
			if h.Auth.Type != tc.wantAuth || h.Auth.KeyPath != tc.wantKey {
				t.Errorf("auth = %+v, want type %q key %q", h.Auth, tc.wantAuth, tc.wantKey)
			}
			if len(h.Tags) != 2 || h.Tags[0] != "imported" || h.Tags[1] != "work" {
				t.Errorf("tags = %v, want [imported work]", h.Tags)
			}
		})
	}
}

func TestConvertProxyJump(t *testing.T) {
	entries := []HostEntry{
		{Alias: "bastion", HostName: "bastion.example.com"},
		{Alias: "web-1", HostName: "10.0.0.1", ProxyJump: "jump@bastion:22"},
		{Alias: "web-2", HostName: "10.0.0.2", ProxyJump: "10.9.9.9"},
	}
	got := Convert(entries, ConvertOptions{})
	byAlias := map[string]Converted{}
	for _, c := range got {
		byAlias[c.Host.Name] = c
	}
	if jump := byAlias["web-1"].Host.ProxyJump; jump != "bastion" {
		t.Errorf("web-1 proxy_jump = %q, want bastion (user and port stripped)", jump)
	}
	if jump := byAlias["web-2"].Host.ProxyJump; jump != "" {
		t.Errorf("web-2 proxy_jump = %q, want it left empty", jump)
	}
	if len(byAlias["web-2"].Warnings) == 0 {
		t.Error("an unresolvable jump host should warn")
	}
}

func TestConvertWarnsAboutWhatItCannotExpress(t *testing.T) {
	got := Convert([]HostEntry{{
		Alias:        "cmd-host",
		HostName:     "10.0.0.40",
		ProxyCommand: "nc %h %p",
	}}, ConvertOptions{})

	if got[0].Host.ProxyJump != "" {
		t.Error("ProxyCommand should not become a jump host")
	}
	joined := strings.Join(got[0].Warnings, "\n")
	if !strings.Contains(joined, "ProxyCommand") {
		t.Errorf("expected a ProxyCommand warning, got %v", got[0].Warnings)
	}

	token := Convert([]HostEntry{{Alias: "tok", HostName: "10.0.0.%h"}}, ConvertOptions{})
	if !strings.Contains(strings.Join(token[0].Warnings, "\n"), "% token") {
		t.Errorf("expected a token warning, got %v", token[0].Warnings)
	}
}

func TestConvertFallsBackToTheAlias(t *testing.T) {
	got := Convert([]HostEntry{{Alias: "web-1"}}, ConvertOptions{})
	if got[0].Host.Addr != "web-1" {
		t.Errorf("Addr = %q, want the alias when there is no HostName", got[0].Host.Addr)
	}
}

// The converted hosts must satisfy the config validator for every mode.
func TestConvertProducesValidHosts(t *testing.T) {
	entries := []HostEntry{
		{Alias: "web-1", HostName: "10.0.0.1", IdentityFile: []string{"~/.ssh/id"}},
		{Alias: "db-1", HostName: "10.0.0.2", Port: 2222},
	}
	for _, mode := range []string{config.ModeDeny, config.ModeReadonly, config.ModeAllow, ""} {
		t.Run(mode, func(t *testing.T) {
			converted := Convert(entries, ConvertOptions{PolicyMode: mode})
			hosts := make([]config.Host, 0, len(converted))
			for _, c := range converted {
				hosts = append(hosts, c.Host)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "ssha.yaml")
			body, err := marshalConfig(hosts)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path); err != nil {
				t.Fatalf("imported hosts do not validate: %v\n%s", err, body)
			}
		})
	}
}
