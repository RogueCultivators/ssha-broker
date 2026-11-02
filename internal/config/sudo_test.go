package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSudoPasswordPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nhosts:\n  - name: web\n    auth: {type: agent}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &cfg.Hosts[0]

	if _, err := cfg.SudoPassword(h); !errors.Is(err, ErrNoSudoPassword) {
		t.Fatalf("nothing configured: err = %v, want ErrNoSudoPassword", err)
	}

	// The sealed secret the editor writes is the fallback.
	if _, err := WriteSecret(path, h.Name, SecretSudo, "stored-pw"); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.SudoPassword(h)
	if err != nil {
		t.Fatal(err)
	}
	if got != "stored-pw" {
		t.Fatalf("stored secret = %q", got)
	}

	// A file replaces the stored secret.
	file := filepath.Join(dir, "sudo.pass")
	if err := os.WriteFile(file, []byte("file-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.Sudo.PasswordFile = file
	if got, err := cfg.SudoPassword(h); err != nil || got != "file-pw" {
		t.Fatalf("file = (%q, %v)", got, err)
	}

	// And the environment wins over both, because that is where a secret
	// manager puts it.
	t.Setenv("SSHA_TEST_SUDO", "env-pw")
	h.Sudo.PasswordEnv = "SSHA_TEST_SUDO"
	if got, err := cfg.SudoPassword(h); err != nil || got != "env-pw" {
		t.Fatalf("env = (%q, %v)", got, err)
	}

	// An empty environment variable is a misconfiguration, not a fallback: it
	// would otherwise silently run -n and report the wrong reason.
	t.Setenv("SSHA_TEST_SUDO", "")
	if _, err := cfg.SudoPassword(h); err == nil || errors.Is(err, ErrNoSudoPassword) {
		t.Fatalf("empty env var: err = %v, want a real error", err)
	}
}

func TestSudoUserDefaultsToRoot(t *testing.T) {
	if got := (Sudo{}).TargetUser(); got != "root" {
		t.Fatalf("TargetUser() = %q, want root", got)
	}
	if got := (Sudo{User: "postgres"}).TargetUser(); got != "postgres" {
		t.Fatalf("TargetUser() = %q", got)
	}
}

func TestSudoPasswordFileIsAnchored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	body := "version: 1\nhosts:\n  - name: web\n    auth: {type: agent}\n    sudo:\n      password_file: secrets/sudo.pass\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "secrets", "sudo.pass"); cfg.Hosts[0].Sudo.PasswordFile != want {
		t.Fatalf("password_file = %q, want %q", cfg.Hosts[0].Sudo.PasswordFile, want)
	}
}

// sudo asks for the password of the user who runs it, so a host that logs in
// with a password already has what sudo wants. Making the operator configure it
// twice was the wrong default.
func TestSudoDefaultsToTheLoginPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	body := `version: 1
hosts:
  - name: box
    auth: {type: password, password_env: SSHA_TEST_LOGIN}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &cfg.Hosts[0]

	if _, err := cfg.SudoPassword(h); !errors.Is(err, ErrNoSudoPassword) {
		t.Fatalf("an explicit sudo password appeared from nowhere: %v", err)
	}
	t.Setenv("SSHA_TEST_LOGIN", "login-pw")
	got, err := cfg.LoginPassword(h)
	if err != nil || got != "login-pw" {
		t.Fatalf("LoginPassword = (%q, %v)", got, err)
	}
	if src := cfg.SudoPasswordSource(h); src != "the login password" {
		t.Fatalf("source = %q", src)
	}

	// A key-authenticated host has no login password to reuse.
	h.Auth = Auth{Type: "key", KeyPath: "/tmp/k"}
	if _, err := cfg.LoginPassword(h); !errors.Is(err, ErrNoSudoPassword) {
		t.Fatalf("a key host reported a login password: %v", err)
	}
}
