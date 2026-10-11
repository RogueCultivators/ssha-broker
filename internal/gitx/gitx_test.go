package gitx

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssha/internal/config"
)

func TestParseRemote(t *testing.T) {
	tests := []struct {
		in     string
		scheme string
		host   string
		path   string
		fail   bool
	}{
		{in: "git@github.com:acme/app.git", scheme: "ssh", host: "github.com", path: "acme/app.git"},
		{in: "ssh://git@github.com:22/acme/app.git", scheme: "ssh", host: "github.com", path: "acme/app.git"},
		{in: "https://github.com/acme/app.git", scheme: "https", host: "github.com", path: "acme/app.git"},
		{in: "https://octo@github.com/acme/app.git", scheme: "https", host: "github.com", path: "acme/app.git"},
		{in: "https://octo:secret@github.com/acme/app.git", fail: true},
		{in: "/tmp/repo", fail: true},
	}
	for _, tt := range tests {
		got, err := ParseRemote(tt.in)
		if tt.fail {
			if err == nil {
				t.Errorf("ParseRemote(%q) succeeded", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRemote(%q): %v", tt.in, err)
			continue
		}
		if got.Scheme != tt.scheme || got.Host != tt.host || got.Path != tt.path {
			t.Errorf("ParseRemote(%q) = %+v", tt.in, got)
		}
	}
}

func TestCredentialRejectsOtherHost(t *testing.T) {
	g := Grant{Auth: "https", Host: "github.com", Path: "acme/app.git", Username: "octo", Secret: "s3cret-token"}
	out, err := Credential("get", strings.NewReader("protocol=https\nhost=gitlab.com\n\n"), g)
	if err == nil || out != "" {
		t.Fatalf("other host: out=%q err=%v", out, err)
	}
	if strings.Contains(out, "s3cret-token") {
		t.Fatal("secret leaked on refusal")
	}
	got, err := Credential("get", strings.NewReader("protocol=https\nhost=github.com\npath=acme/app.git\n\n"), g)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "password=s3cret-token\n") || !strings.Contains(got, "username=octo\n") {
		t.Fatalf("fill = %q", got)
	}
	stored, err := Credential("store", strings.NewReader("password=s3cret-token\n\n"), g)
	if err != nil || stored != "" {
		t.Fatalf("store = %q %v", stored, err)
	}
}

func TestCredentialRejectsNewline(t *testing.T) {
	g := Grant{Auth: "https", Host: "github.com", Path: "acme/app.git", Username: "octo", Secret: "tok\nen"}
	_, err := Credential("get", strings.NewReader("protocol=https\nhost=github.com\npath=acme/app.git\n\n"), g)
	if err == nil {
		t.Fatal("newline in the token was accepted")
	}
}

func TestKeyBytesEncrypted(t *testing.T) {
	if !keyBytesEncrypted([]byte("Proc-Type: 4,ENCRYPTED\n")) {
		t.Fatal("PEM marker not detected")
	}
	if keyBytesEncrypted(opensshKey("none")) {
		t.Fatal("unencrypted OpenSSH key looked encrypted")
	}
	if !keyBytesEncrypted(opensshKey("aes256-ctr")) {
		t.Fatal("encrypted OpenSSH key was not detected")
	}
}

func opensshKey(cipher string) []byte {
	var b strings.Builder
	b.WriteString("openssh-key-v1\x00")
	var n [4]byte
	n[3] = byte(len(cipher))
	b.Write(n[:])
	b.WriteString(cipher)
	return []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		base64.StdEncoding.EncodeToString([]byte(b.String())) +
		"\n-----END OPENSSH PRIVATE KEY-----\n")
}

func TestAskPassRefusesHostKeyPrompt(t *testing.T) {
	g := Grant{Auth: "ssh", Secret: "phrase"}
	if _, err := AskPassAnswer("The authenticity of host 'x' can't be established. Are you sure you want to continue connecting (yes/no)?", g); err == nil {
		t.Fatal("host key prompt was answered")
	}
	got, err := AskPassAnswer("Enter passphrase for key '/tmp/id': ", g)
	if err != nil || got != "phrase" {
		t.Fatalf("passphrase = %q %v", got, err)
	}
}

func TestSSHArgsRejectsOtherHost(t *testing.T) {
	g := Grant{Auth: "ssh", Host: "github.com", KeyPath: "/tmp/id"}
	if _, err := SSHArgs(g, []string{"-o", "SendEnv=GIT_PROTOCOL", "git@gitlab.com", "git-upload-pack", "x"}); err == nil {
		t.Fatal("expected host refusal")
	}
	args, err := SSHArgs(g, []string{"-p", "22", "git@github.com", "git-receive-pack", "acme/app.git"})
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "-i" || args[1] != "/tmp/id" || !contains(args, "IdentitiesOnly=yes") || !contains(args, "BatchMode=yes") {
		t.Fatalf("args = %q", args)
	}
}

func TestRunDoesNotLeakSecret(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "git")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > " + shellQuote(out) + "\nprintf '\\n' >> " + shellQuote(out) + "\nenv >> " + shellQuote(out) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHA_TEST_GIT_TOKEN", "super-secret-token")
	cfg := testConfig("https")
	cfg.Git.Accounts[0].Auth.PasswordEnv = "SSHA_TEST_GIT_TOKEN"
	r := &Runner{
		Config: cfg,
		Git:    script,
		Self:   "/usr/bin/ssha",
		LookupRemote: func(string, string) (string, error) {
			return "https://github.com/acme/app.git", nil
		},
	}
	res, err := r.Run(context.Background(), Request{Op: "push", Dir: dir, Args: []string{"main"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "allowed" || res.ExitCode != 0 {
		t.Fatalf("result = %+v", res)
	}
	seen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(seen), "super-secret-token") {
		t.Fatalf("secret leaked to git:\n%s", seen)
	}
	if !strings.Contains(string(seen), "credential.helper=") || !strings.Contains(string(seen), "git-credential") {
		t.Fatalf("helper not installed:\n%s", seen)
	}
	if !strings.Contains(string(seen), "SSHA_GIT_GRANT=") {
		t.Fatalf("grant env missing:\n%s", seen)
	}
}

func TestRunRewritesHTTPSRemoteToSSH(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "git")
	body := "#!/bin/sh\nprintf '%s\n' \"$*\" > " + shellQuote(out) + "\nenv >> " + shellQuote(out) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "id")
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("ssh")
	cfg.Git.Accounts[0].Auth.KeyPath = key
	r := &Runner{
		Config: cfg,
		Git:    script,
		Self:   "/usr/bin/ssha",
		LookupRemote: func(string, string) (string, error) {
			return "https://github.com/acme/app.git", nil
		},
	}
	res, err := r.Run(context.Background(), Request{Op: "fetch", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "allowed" {
		t.Fatalf("result = %+v", res)
	}
	seen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(seen)
	if !strings.Contains(text, "url.ssh://git@github.com/acme/app.git.insteadof=https://github.com/acme/app.git") {
		t.Fatalf("remote was not rewritten:\n%s", text)
	}
	if !strings.Contains(text, "GIT_SSH_COMMAND=") || strings.Contains(text, "credential.helper=!") {
		t.Fatalf("ssh wrapper not selected:\n%s", text)
	}
}

func TestRunDeniesForceWithoutInvokingGit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "git")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho invoked > "+shellQuote(filepath.Join(dir, "invoked"))+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig("https")
	r := &Runner{Config: cfg, Git: script, LookupRemote: func(string, string) (string, error) {
		return "https://github.com/acme/app.git", nil
	}}
	res, err := r.Run(context.Background(), Request{Op: "push", Dir: dir, Args: []string{"--force", "main"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != "denied" {
		t.Fatalf("decision = %s", res.Decision)
	}
	if _, err := os.Stat(filepath.Join(dir, "invoked")); err == nil {
		t.Fatal("git was invoked for a denied force push")
	}
}

func testConfig(auth string) *config.Config {
	a := config.GitAccount{
		Name:  "github",
		Hosts: []string{"github.com"},
		Auth:  config.GitAuth{Type: auth, Username: "octo"},
	}
	if auth == "ssh" {
		a.Auth = config.GitAuth{Type: "ssh", KeyPath: "/tmp/id"}
	}
	return &config.Config{Git: config.GitConfig{Accounts: []config.GitAccount{a}}}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
