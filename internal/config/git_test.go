package config

import (
	"strings"
	"testing"
)

func TestMatchGitPrefersLongerPrefix(t *testing.T) {
	cfg := &Config{Git: GitConfig{Accounts: []GitAccount{
		{Name: "all", Hosts: []string{"github.com"}, Auth: GitAuth{Type: "https", Username: "a"}},
		{Name: "org", Hosts: []string{"github.com"}, PathPrefix: "acme", Auth: GitAuth{Type: "ssh", KeyPath: "/tmp/k"}},
	}}}
	if err := cfg.validateGit(); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.MatchGit("GitHub.com", "acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "org" {
		t.Fatalf("match = %s, want org", got.Name)
	}
	other, err := cfg.MatchGit("github.com", "other/app.git")
	if err != nil {
		t.Fatal(err)
	}
	if other.Name != "all" {
		t.Fatalf("match = %s, want all", other.Name)
	}
}

func TestMatchGitAmbiguous(t *testing.T) {
	cfg := &Config{Git: GitConfig{Accounts: []GitAccount{
		{Name: "one", Hosts: []string{"gitlab.com"}, Auth: GitAuth{Type: "ssh", KeyPath: "/tmp/k"}},
		{Name: "two", Hosts: []string{"gitlab.com"}, Auth: GitAuth{Type: "https", Username: "a"}},
	}}}
	if _, err := cfg.MatchGit("gitlab.com", "group/app"); err == nil {
		t.Fatal("expected ambiguous match")
	}
}

func TestNormalizeGitHostRejectsURL(t *testing.T) {
	if _, err := NormalizeGitHost("https://github.com/org/repo"); err == nil {
		t.Fatal("expected a URL to be rejected")
	}
	got, err := NormalizeGitHost("GitHub.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "github.com" {
		t.Fatalf("host = %s", got)
	}
}

func TestGitOnlyConfigLoads(t *testing.T) {
	path := tempConfig(t, "version: 1\ngit:\n  accounts:\n    - name: gh\n      hosts: [github.com]\n      auth: {type: https, username: octo}\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Git.Accounts) != 1 || cfg.Git.Accounts[0].Hosts[0] != "github.com" {
		t.Fatalf("accounts = %+v", cfg.Git.Accounts)
	}
}

func TestUpsertGitAccountPreservesHosts(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	err := UpsertGitAccount(path, GitAccount{
		Name:  "github",
		Hosts: []string{"github.com"},
		Auth:  GitAuth{Type: "https", Username: "octo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if !containsAll(body, "name: web-1", "# The database. Do not touch.", "github.com") {
		t.Fatalf("hosts or account missing:\n%s", body)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Host("web-1"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Git.Accounts) != 1 {
		t.Fatalf("accounts = %d", len(cfg.Git.Accounts))
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
