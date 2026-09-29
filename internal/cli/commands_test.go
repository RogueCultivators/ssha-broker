package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
