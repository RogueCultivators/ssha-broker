package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveSecretPrefersTheEnvironment(t *testing.T) {
	t.Setenv("SSHA_TEST_SECRET", "from-env")
	file := writeSecret(t, "from-file\n")

	got, err := resolveSecret(Target{Name: "web"}, "SSHA_TEST_SECRET", file, "password")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want the environment value", got)
	}
}

func TestResolveSecretFromFileTrimsNewline(t *testing.T) {
	file := writeSecret(t, "hunter2\n")

	got, err := resolveSecret(Target{Name: "web"}, "", file, "password")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestResolveSecretErrorCases(t *testing.T) {
	empty := writeSecret(t, "")
	tests := []struct {
		name    string
		target  Target
		envVar  string
		file    string
		wantErr string
	}{
		{
			name:    "declared env var is empty",
			target:  Target{Name: "web"},
			envVar:  "SSHA_TEST_UNSET",
			wantErr: "SSHA_TEST_UNSET is empty",
		},
		{
			name:    "file does not exist",
			target:  Target{Name: "web"},
			file:    filepath.Join(t.TempDir(), "missing"),
			wantErr: "read",
		},
		{
			name:    "file is empty",
			target:  Target{Name: "web"},
			file:    empty,
			wantErr: "is empty",
		},
		{
			name:    "no source and no prompt",
			target:  Target{Name: "web"},
			wantErr: "no password source configured",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveSecret(tc.target, tc.envVar, tc.file, "password")
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.target.Name) {
				t.Errorf("error = %v, want it to name the host", err)
			}
		})
	}
}

func TestResolveSecretFallsBackToThePrompt(t *testing.T) {
	var gotHost, gotWhat string
	target := Target{
		Name: "db-1",
		Prompt: func(host, what string) (string, error) {
			gotHost, gotWhat = host, what
			return "typed-at-the-prompt", nil
		},
	}
	got, err := resolveSecret(target, "", "", "password")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if got != "typed-at-the-prompt" {
		t.Errorf("got %q, want the prompted value", got)
	}
	if gotHost != "db-1" || gotWhat != "password" {
		t.Errorf("prompt called with (%q, %q), want (db-1, password)", gotHost, gotWhat)
	}
}

func TestResolveSecretPromptError(t *testing.T) {
	target := Target{
		Name:   "db-1",
		Prompt: func(string, string) (string, error) { return "", os.ErrClosed },
	}
	if _, err := resolveSecret(target, "", "", "password"); err == nil {
		t.Fatal("expected the prompt error to propagate")
	}
}

func TestKnownHostsLineBracketsNonDefaultPorts(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"10.0.0.1:22", "10.0.0.1"},
		{"10.0.0.1:2222", "[10.0.0.1]:2222"},
		{"example.com:2200", "[example.com]:2200"},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			key := testPublicKey(t)
			line := KnownHostsLine(tc.addr, key)
			if !strings.HasPrefix(line, tc.want+" ") {
				t.Errorf("KnownHostsLine(%q) = %q, want the host prefix %q", tc.addr, line, tc.want)
			}
		})
	}
}
