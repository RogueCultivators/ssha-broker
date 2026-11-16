package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssha/internal/config"
	"ssha/skills"
)

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		def     int
		wantH   string
		wantP   int
		wantErr bool
	}{
		{name: "bare host", spec: "example.com", def: 22, wantH: "example.com", wantP: 22},
		{name: "host and port", spec: "example.com:2222", def: 22, wantH: "example.com", wantP: 2222},
		{name: "user is stripped", spec: "deploy@example.com:2222", def: 22, wantH: "example.com", wantP: 2222},
		{name: "ipv4", spec: "10.0.0.1", def: 22, wantH: "10.0.0.1", wantP: 22},
		{name: "bracketed ipv6", spec: "[2001:db8::1]", def: 22, wantH: "2001:db8::1", wantP: 22},
		{name: "bracketed ipv6 with port", spec: "[2001:db8::1]:2222", def: 22, wantH: "2001:db8::1", wantP: 2222},
		{name: "bare ipv6 has no port", spec: "2001:db8::1", def: 22, wantH: "2001:db8::1", wantP: 22},
		{name: "default port is honoured", spec: "example.com", def: 2022, wantH: "example.com", wantP: 2022},
		{name: "port is validated", spec: "example.com:99999", def: 22, wantErr: true},
		{name: "non numeric port", spec: "example.com:abc", def: 22, wantErr: true},
		{name: "unclosed bracket", spec: "[2001:db8::1", def: 22, wantErr: true},
		{name: "empty host", spec: "", def: 22, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseHostPort(tc.spec, tc.def)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHostPort(%q): %v", tc.spec, err)
			}
			if host != tc.wantH || port != tc.wantP {
				t.Errorf("parseHostPort(%q) = (%q, %d), want (%q, %d)", tc.spec, host, port, tc.wantH, tc.wantP)
			}
		})
	}
}

func TestAppendKnownHosts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "known_hosts")
	keyA := "AAAAB3NzaC1yc2EAAAADAQABAAABgQ"
	keyB := "AAAAB3NzaC1yc2EAAAADAQABAAABgR"
	line1 := "10.0.0.1 ssh-rsa " + keyA
	line2 := "10.0.0.1 ssh-ed25519 " + keyB

	added, conflicts, err := appendKnownHosts(path, []string{line1, line2})
	if err != nil {
		t.Fatalf("appendKnownHosts: %v", err)
	}
	if added != 2 || len(conflicts) != 0 {
		t.Fatalf("added=%d conflicts=%v, want 2 and none", added, conflicts)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the file was not created: %v", err)
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Fatalf("file has %d lines, want 2:\n%s", strings.Count(string(data), "\n"), data)
	}
	if st, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}

	t.Run("re-adding the same lines is a no-op", func(t *testing.T) {
		added, conflicts, err := appendKnownHosts(path, []string{line1, line2})
		if err != nil {
			t.Fatal(err)
		}
		if added != 0 || len(conflicts) != 0 {
			t.Fatalf("added=%d conflicts=%v, want 0 and none", added, conflicts)
		}
	})

	t.Run("a different key for the same host and type is a conflict", func(t *testing.T) {
		added, conflicts, err := appendKnownHosts(path, []string{"10.0.0.1 ssh-rsa AAAAchanged"})
		if err != nil {
			t.Fatal(err)
		}
		if added != 0 {
			t.Errorf("added = %d, want the conflicting line to be skipped", added)
		}
		if len(conflicts) != 1 {
			t.Fatalf("conflicts = %v, want one entry", conflicts)
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "AAAAchanged") {
			t.Error("the conflicting key was written to known_hosts")
		}
	})

	t.Run("a new key type for the same host is appended", func(t *testing.T) {
		added, conflicts, err := appendKnownHosts(path, []string{"10.0.0.1 ecdsa-sha2-nistp256 AAAAz"})
		if err != nil {
			t.Fatal(err)
		}
		if added != 1 || len(conflicts) != 0 {
			t.Fatalf("added=%d conflicts=%v, want 1 and none", added, conflicts)
		}
	})
}

func TestPinFingerprints(t *testing.T) {
	const fpA = "SHA256:aaaaaaaa"
	const fpB = "SHA256:bbbbbbbb"
	const fpC = "SHA256:cccccccc"

	t.Run("empty pins take the scan", func(t *testing.T) {
		h := &config.Host{Name: "web"}
		if err := pinFingerprints(h, []string{fpA, fpB}); err != nil {
			t.Fatal(err)
		}
		if strings.Join(h.HostKey.Fingerprints, ",") != fpA+","+fpB {
			t.Fatalf("pins = %v", h.HostKey.Fingerprints)
		}
	})

	t.Run("overlap allows a refresh", func(t *testing.T) {
		h := &config.Host{Name: "web", HostKey: config.HostKey{Fingerprints: []string{fpA, fpC}}}
		if err := pinFingerprints(h, []string{fpA, fpB}); err != nil {
			t.Fatal(err)
		}
		if strings.Join(h.HostKey.Fingerprints, ",") != fpA+","+fpB {
			t.Fatalf("pins = %v", h.HostKey.Fingerprints)
		}
	})

	t.Run("bare values match their SHA256 form", func(t *testing.T) {
		h := &config.Host{Name: "web", HostKey: config.HostKey{Fingerprints: []string{"bbbbbbbb"}}}
		if err := pinFingerprints(h, []string{fpB}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a contradiction is refused and kept", func(t *testing.T) {
		h := &config.Host{Name: "web", HostKey: config.HostKey{Fingerprints: []string{fpC}}}
		err := pinFingerprints(h, []string{fpA})
		if err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("got %v, want a refusal", err)
		}
		if len(h.HostKey.Fingerprints) != 1 || h.HostKey.Fingerprints[0] != fpC {
			t.Fatalf("the old pin changed: %v", h.HostKey.Fingerprints)
		}
	})

	t.Run("insecure is refused", func(t *testing.T) {
		h := &config.Host{Name: "web", HostKey: config.HostKey{Insecure: true}}
		if err := pinFingerprints(h, []string{fpA}); err == nil {
			t.Fatal("pinning while insecure must be refused")
		}
	})
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
	}
	for _, tc := range tests {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A forward without a destination is a usage error and must not open the
// broker, which would prompt for a password on a terminal.
func TestForwardRequiresDestination(t *testing.T) {
	var out, errs strings.Builder
	a := &App{Stdout: &out, Stderr: &errs}
	if code := a.cmdForward([]string{"web"}); code != ExitUsage {
		t.Fatalf("cmdForward = %d, want %d; stderr=%s", code, ExitUsage, errs.String())
	}
	if !strings.Contains(errs.String(), "--to") {
		t.Fatalf("unhelpful error: %q", errs.String())
	}
}

func TestParseOctalMode(t *testing.T) {
	tests := []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{in: "0644", want: 0o644},
		{in: "600", want: 0o600},
		{in: "0o755", want: 0o755},
		{in: "not-a-mode", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseOctalMode(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("parseOctalMode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeExit(t *testing.T) {
	tests := []struct {
		in   int
		want int
	}{
		{0, ExitFail},
		{1, 1},
		{7, 7},
		{125, 125},
		{126, ExitFail},
		{255, ExitFail},
		{-1, ExitFail},
	}
	for _, tc := range tests {
		if got := normalizeExit(tc.in); got != tc.want {
			t.Errorf("normalizeExit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// The skill ships inside the binary, so an installed copy that predates an
// upgrade must be refreshed rather than left behind: it would disagree with
// `ssha skill print` and with what the editor writes.
func TestSkillInstallRefreshesAStaleCopy(t *testing.T) {
	dir := t.TempDir()
	run := func() (int, string) {
		var out, errs strings.Builder
		a := &App{Stdout: &out, Stderr: &errs}
		code := a.cmdSkill([]string{"install", "--dir", dir})
		return code, out.String() + errs.String()
	}
	path := filepath.Join(dir, skills.Name, "SKILL.md")

	code, out := run()
	if code != ExitOK || !strings.Contains(out, "installed skill") {
		t.Fatalf("first install: code=%d out=%q", code, out)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != skills.Content {
		t.Fatal("the installed skill does not match the embedded one")
	}

	code, out = run()
	if code != ExitOK || !strings.Contains(out, "up to date") {
		t.Fatalf("second install: code=%d out=%q", code, out)
	}

	// An older build's copy, or a hand edit: install replaces it.
	if err := os.WriteFile(path, []byte("---\nname: ssh-agent\n---\nold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out = run()
	if code != ExitOK || !strings.Contains(out, "updated skill") {
		t.Fatalf("refresh: code=%d out=%q", code, out)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != skills.Content {
		t.Fatalf("the stale copy was not refreshed (err=%v)", err)
	}
}

// `ssha init` writes a file the operator then edits, so it must keep refusing
// to replace one. The skill above is the opposite case.
func TestInitRefusesToOverwriteAConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	var out, errs strings.Builder
	a := &App{Stdout: &out, Stderr: &errs}
	if code := a.cmdInit([]string{"--out", path}); code != ExitOK {
		t.Fatalf("first init: code=%d err=%s", code, errs.String())
	}
	errs.Reset()
	if code := a.cmdInit([]string{"--out", path}); code != ExitFail {
		t.Fatalf("second init: code=%d, want a refusal", code)
	}
	if !strings.Contains(errs.String(), "already exists") {
		t.Fatalf("unhelpful refusal: %q", errs.String())
	}
}
