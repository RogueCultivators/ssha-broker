package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Elevation is part of the command the policy sees. A readonly host that allows
// `systemctl status` must not thereby allow `sudo systemctl status`, because
// that is a different privilege level.
func TestSudoIsPartOfThePolicyDecision(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	body := `version: 1
audit:
  path: ` + filepath.Join(dir, "audit.jsonl") + `
policy:
  mode: readonly
  allow_commands: ['^systemctl status']
hosts:
  - name: web
    addr: 127.0.0.1
    port: 1
    auth: {type: agent}
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	plain, err := b.Exec(context.Background(), ExecRequest{Host: "web", Command: "systemctl status nginx", DryRun: true})
	if err != nil {
		t.Fatalf("plain command: %v", err)
	}
	if plain.Decision != "allowed" {
		t.Fatalf("plain command was %s: %s", plain.Decision, plain.Reason)
	}

	elevated, err := b.Exec(context.Background(), ExecRequest{Host: "web", Command: "systemctl status nginx", Sudo: true, DryRun: true})
	if err == nil || elevated == nil {
		t.Fatal("the sudo form was allowed by an allow list that does not mention sudo")
	}
	if elevated.Decision != "denied" || !strings.Contains(elevated.Reason, "not in the allow list") {
		t.Fatalf("decision = %s, reason = %q", elevated.Decision, elevated.Reason)
	}

	// And it is allowed once the allow list covers the elevated form.
	body = strings.Replace(body, `allow_commands: ['^systemctl status']`, `allow_commands: ['^sudo systemctl status']`, 1)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	b = b2
	elevated, err = b.Exec(context.Background(), ExecRequest{Host: "web", Command: "systemctl status nginx", Sudo: true, DryRun: true})
	if err != nil {
		t.Fatalf("elevated command with a matching allow rule: %v", err)
	}
	if elevated.Decision != "allowed" || !elevated.Sudo {
		t.Fatalf("decision = %s, sudo = %v", elevated.Decision, elevated.Sudo)
	}
	if elevated.SudoUser != "root" {
		t.Fatalf("sudo user = %q, want root", elevated.SudoUser)
	}
}

// An already-sudo command is not prefixed twice: that would change what
// sudoers matches against, and look like a different command in the audit.
func TestSudoDoesNotDoublePrefix(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	body := `version: 1
audit:
  path: ` + filepath.Join(dir, "audit.jsonl") + `
policy:
  mode: readonly
  allow_commands: ['^sudo -n -- /usr/bin/id']
hosts:
  - name: web
    addr: 127.0.0.1
    port: 1
    auth: {type: agent}
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Open(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	res, err := b.Exec(context.Background(), ExecRequest{
		Host: "web", Command: "sudo -n -- /usr/bin/id", Sudo: true, DryRun: true,
	})
	if err != nil {
		t.Fatalf("a command that already spells out sudo was refused: %v", err)
	}
	if res.Decision != "allowed" {
		t.Fatalf("decision = %s: %s", res.Decision, res.Reason)
	}
}

func TestNeedsSudoPassword(t *testing.T) {
	cases := []struct {
		stderr, errText string
		want            bool
	}{
		{"sudo: a password is required\n", "", true},
		{"", "sudo: a password is required", true},
		{"sudo: a terminal is required to read the password", "", true},
		{"sudo: no tty present and no askpass program specified", "", true},
		{"sudo: user is not in the sudoers file", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		if got := needsSudoPassword(tc.stderr, tc.errText); got != tc.want {
			t.Errorf("needsSudoPassword(%q, %q) = %v, want %v", tc.stderr, tc.errText, got, tc.want)
		}
	}
}

// A transfer path is never rewritten, so a Windows-looking one is reported with
// the reason instead of being silently "fixed".
func TestRemotePathHint(t *testing.T) {
	base := errors.New("open /data/x: no such file")

	if got := remotePathHint("/data/x", base); got != base.Error() {
		t.Errorf("a POSIX path got a hint: %q", got)
	}
	for _, p := range []string{`\data\x`, `C:\data\x`, `C:/data/x`} {
		got := remotePathHint(p, base)
		if !strings.Contains(got, "remote paths are sent exactly as written") {
			t.Errorf("%q did not get the hint: %q", p, got)
		}
		if !strings.Contains(got, "MSYS_NO_PATHCONV") {
			t.Errorf("%q hint does not say how to check the shell: %q", p, got)
		}
	}
	if !looksLikeWindowsPath(`D:/x`) || looksLikeWindowsPath("/data/x") || looksLikeWindowsPath("1:/x") {
		t.Error("looksLikeWindowsPath is wrong")
	}
}
