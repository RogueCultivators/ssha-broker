package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndReadSecret(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")

	path, err := WriteSecret(cfgPath, "prod-web", SecretPassword, "hunter2")
	if err != nil {
		t.Fatalf("WriteSecret: %v", err)
	}
	if want := filepath.Join(dir, "secrets", "prod-web.password"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the secret file was not written: %v", err)
	}
	if strings.TrimSpace(string(b)) != "hunter2" {
		t.Errorf("content = %q", b)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", st.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", parent.Mode().Perm())
	}
	if !HasStoredSecret(cfgPath, "prod-web", SecretPassword) {
		t.Error("HasStoredSecret should be true")
	}

	// Overwriting replaces, it does not append.
	if _, err := WriteSecret(cfgPath, "prod-web", SecretPassword, "newer"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.TrimSpace(string(b)) != "newer" {
		t.Errorf("content after overwrite = %q", b)
	}

	if err := DeleteSecret(cfgPath, "prod-web", SecretPassword); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if HasStoredSecret(cfgPath, "prod-web", SecretPassword) {
		t.Error("the secret should be gone")
	}
	// Deleting twice is fine.
	if err := DeleteSecret(cfgPath, "prod-web", SecretPassword); err != nil {
		t.Errorf("deleting a missing secret should not fail: %v", err)
	}
}

func TestWriteSecretRefusesEmpty(t *testing.T) {
	path, err := WriteSecret(filepath.Join(t.TempDir(), "ssha.yaml"), "web", SecretPassword, "  \n")
	if err == nil {
		t.Fatalf("expected an error, wrote %q", path)
	}
}

func TestSecretNamesCannotEscapeTheDirectory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	tests := []struct{ host, want string }{
		{"prod-web", "prod-web"},
		{"web.example.com", "web.example.com"},
		{"../../etc/passwd", "_.._etc_passwd"},
		{"a/b", "a_b"},
		{"...", "host"},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			path, err := WriteSecret(cfgPath, tc.host, SecretPassword, "x")
			if err != nil {
				t.Fatal(err)
			}
			if got := filepath.Base(path); got != tc.want+".password" {
				t.Errorf("base name = %q, want %q", got, tc.want+".password")
			}
			if rel, err := filepath.Rel(SecretsDir(cfgPath), path); err != nil || strings.HasPrefix(rel, "..") {
				t.Errorf("secret escaped its directory: %q", path)
			}
		})
	}
}

func TestHasSecret(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"empty path", "", false},
		{"missing file", filepath.Join(dir, "nope"), false},
		{"whitespace only", empty, false},
		{"a real secret", filepath.Join(dir, "ok"), true},
	}
	if err := os.WriteFile(filepath.Join(dir, "ok"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasSecret(tc.path); got != tc.want {
				t.Errorf("HasSecret(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// The path a host's password_file points at is the one the editor writes, so a
// stored secret is picked up without touching the host's config beyond one line.
func TestStoredSecretIsWhatTheHostWouldReference(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	path, err := WriteSecret(cfgPath, "web-1", SecretPassword, "pw")
	if err != nil {
		t.Fatal(err)
	}
	body := "hosts:\n  - name: web-1\n    auth: {type: password, password_file: " + path + "}\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Hosts[0].Auth.PasswordFile; got != path {
		t.Fatalf("PasswordFile = %q, want %q", got, path)
	}
	if !HasSecret(cfg.Hosts[0].Auth.PasswordFile) {
		t.Error("the referenced secret was not found")
	}
}
