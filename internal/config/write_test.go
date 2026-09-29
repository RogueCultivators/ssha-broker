package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commentedConfig = `version: 1

# Everything below is hand written and must survive an edit from the UI.
hosts:
  # The web tier.
  - name: web-1
    addr: 10.0.0.10
    user: deploy
    # Keep this list sorted.
    tags: [prod, web]
    auth:
      type: key
      # rotate every 90 days
      key_path: ~/.ssh/id_ed25519
    policy:
      mode: readonly
      allow_commands: ['^ls\b']

  # The database. Do not touch.
  - name: db-1
    addr: 10.0.0.20
    user: dba
    auth:
      type: password
      password_env: DB_PW
    policy:
      mode: deny
`

func tempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpsertHostPreservesComments(t *testing.T) {
	path := tempConfig(t, commentedConfig)

	updated := Host{
		Name:    "web-1",
		Addr:    "10.0.0.10",
		User:    "deploy",
		Tags:    []string{"prod", "web"},
		WorkDir: "/srv/app",
		Auth:    Auth{Type: "key", KeyPath: "~/.ssh/id_ed25519"},
		Policy:  &Spec{Mode: ModeReadonly, Allow: []string{`^ls\b`}},
	}
	if err := UpsertHost(path, updated); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	got := readFile(t, path)

	for _, want := range []string{
		"# Everything below is hand written and must survive an edit from the UI.",
		"# The web tier.",
		"# Keep this list sorted.",
		"# rotate every 90 days",
		"# The database. Do not touch.",
		"work_dir: /srv/app",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comment or field lost: %q\n---\n%s", want, got)
		}
	}

	// The other host must be untouched, byte for byte.
	dbStart := strings.Index(got, "# The database.")
	if dbStart < 0 {
		t.Fatal("db-1 disappeared")
	}
	if tail := got[dbStart:]; !strings.HasSuffix(strings.TrimRight(commentedConfig, "\n"), strings.TrimRight(tail, "\n")) {
		t.Errorf("db-1 was rewritten:\n%s", tail)
	}
}

func TestUpsertHostUpdatesAndClearsFields(t *testing.T) {
	path := tempConfig(t, commentedConfig)

	h := Host{
		Name: "web-1", Addr: "10.0.0.11", User: "ops",
		Auth:   Auth{Type: "agent"},
		Policy: &Spec{Mode: ModeAllow},
	}
	if err := UpsertHost(path, h); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	web, err := cfg.Host("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if web.Addr != "10.0.0.11" || web.User != "ops" {
		t.Errorf("basic fields not updated: %+v", web)
	}
	if web.Auth.Type != "agent" || web.Auth.KeyPath != "" {
		t.Errorf("auth not replaced cleanly: %+v", web.Auth)
	}
	if len(web.Tags) != 0 {
		t.Errorf("cleared tags came back: %v", web.Tags)
	}
	if got := cfg.EffectivePolicy(web); got.Mode != ModeAllow || len(got.Allow) != 0 {
		t.Errorf("policy not replaced cleanly: %+v", got)
	}
}

func TestUpsertHostAddsAndKeepsOthers(t *testing.T) {
	path := tempConfig(t, commentedConfig)

	app := Host{
		Name: "api-1", Addr: "10.0.0.30", User: "deploy",
		Description: "api tier",
		Tags:        []string{"prod"},
		Apps: []App{{
			Name:        "payment-api",
			Description: "handles payments",
			Kind:        "api",
			Unit:        "payment-api.service",
			Ports:       []int{8080},
			Logs:        []string{"/var/log/payment/api.log"},
		}},
		Auth:   Auth{Type: "key", KeyPath: "~/.ssh/id_ed25519"},
		Policy: &Spec{Mode: ModeAllow},
	}
	if err := UpsertHost(path, app); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(cfg.Hosts))
	}
	got, err := cfg.Host("api-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 || got.Apps[0].Name != "payment-api" {
		t.Fatalf("app did not round-trip: %+v", got.Apps)
	}
	if got.Apps[0].Unit != "payment-api.service" || got.Apps[0].Ports[0] != 8080 {
		t.Errorf("app details lost: %+v", got.Apps[0])
	}
	if !strings.Contains(readFile(t, path), "# The database. Do not touch.") {
		t.Error("existing comments were lost when appending a host")
	}
}

func TestUpsertHostRejectsInvalidAndRollsBack(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	before := readFile(t, path)

	// readonly with no allow list is rejected by Validate.
	bad := Host{
		Name:   "web-1",
		Addr:   "10.0.0.10",
		User:   "deploy",
		Auth:   Auth{Type: "key", KeyPath: "/tmp/k"},
		Policy: &Spec{Mode: ModeReadonly},
	}
	err := UpsertHost(path, bad)
	if err == nil {
		t.Fatal("expected the invalid policy to be rejected")
	}
	if !strings.Contains(err.Error(), "readonly") {
		t.Errorf("error = %v, want it to explain the readonly problem", err)
	}
	if got := readFile(t, path); got != before {
		t.Errorf("the file was not rolled back:\n--- want ---\n%s\n--- got ---\n%s", before, got)
	}

	// An invalid auth block is rejected as well.
	bad2 := Host{Name: "web-1", Auth: Auth{Type: "key"}}
	if err := UpsertHost(path, bad2); err == nil {
		t.Error("expected a key host with no key to be rejected")
	}
	if got := readFile(t, path); got != before {
		t.Error("the file was not rolled back after the second failure")
	}
}

func TestDeleteHost(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	if err := DeleteHost(path, "web-1"); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Name != "db-1" {
		t.Fatalf("got %+v, want only db-1", cfg.Hosts)
	}
	if !strings.Contains(readFile(t, path), "# The database. Do not touch.") {
		t.Error("comments on the remaining host were lost")
	}
	if err := DeleteHost(path, "ghost"); err == nil {
		t.Error("expected an error for an unknown host")
	}
}

func TestUpsertHostWritesABackup(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	h := Host{Name: "web-1", Addr: "10.0.0.10", User: "deploy", Auth: Auth{Type: "key", KeyPath: "/tmp/k"}}
	if err := UpsertHost(path, h); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path+".bak"); got != commentedConfig {
		t.Errorf("backup does not match the previous content:\n%s", got)
	}
}
