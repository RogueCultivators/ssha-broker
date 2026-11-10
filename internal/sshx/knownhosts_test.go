package sshx

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKnownHostsHasHost(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJc7FkLY/hM+6quChfLIs+9YOTGOl2CuX3HGrln3FyxT"

	tests := []struct {
		name  string
		lines []string
		addr  string
		want  bool
	}{
		{
			name:  "plain entry on the default port",
			lines: []string{"example.com " + key},
			addr:  "example.com:22",
			want:  true,
		},
		{
			name:  "plain entry with an explicit port",
			lines: []string{"[example.com]:2222 " + key},
			addr:  "example.com:2222",
			want:  true,
		},
		{
			name:  "explicit :22 pattern",
			lines: []string{"example.com:22 " + key},
			addr:  "example.com:22",
			want:  true,
		},
		{
			name:  "port-22 entry covers another port",
			lines: []string{"example.com " + key},
			addr:  "example.com:2222",
			want:  true,
		},
		{
			name:  "hashed entry on the default port",
			lines: []string{knownhosts.HashHostname("example.com") + " " + key},
			addr:  "example.com:22",
			want:  true,
		},
		{
			name:  "hashed entry on a custom port",
			lines: []string{knownhosts.HashHostname("[example.com]:2222") + " " + key},
			addr:  "example.com:2222",
			want:  true,
		},
		{
			name:  "wildcard",
			lines: []string{"*.example.com " + key},
			addr:  "web.example.com:22",
			want:  true,
		},
		{
			name:  "wildcard with a port",
			lines: []string{"[*.example.com]:2222 " + key},
			addr:  "web.example.com:2222",
			want:  true,
		},
		{
			name:  "negated name",
			lines: []string{"!bad.example.com,*.example.com " + key},
			addr:  "bad.example.com:22",
			want:  false,
		},
		{
			name:  "positive pattern next to a negation",
			lines: []string{"!bad.example.com,*.example.com " + key},
			addr:  "web.example.com:22",
			want:  true,
		},
		{
			name:  "different host",
			lines: []string{"other.example.com " + key},
			addr:  "example.com:22",
			want:  false,
		},
		{
			name:  "comment and revoked marker are ignored",
			lines: []string{"# example.com " + key, "@revoked * " + key},
			addr:  "example.com:22",
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeKnownHosts(t, tc.lines...)
			if got := KnownHostsHasHost(path, tc.addr); got != tc.want {
				t.Fatalf("KnownHostsHasHost(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestKnownHostsKeyMismatches(t *testing.T) {
	key, other := testPublicKey(t), testPublicKey(t)
	path := writeKnownHosts(t, knownhosts.Line([]string{"example.com"}, key))

	if got := KnownHostsKeyMismatches(path, "example.com:22", []ssh.PublicKey{key}); len(got) != 0 {
		t.Fatalf("a matching key is not a conflict: %v", got)
	}
	if got := KnownHostsKeyMismatches(path, "example.com:22", []ssh.PublicKey{other}); len(got) != 1 {
		t.Fatalf("a different key must conflict, got %v", got)
	}
	// The port-22 record is the fallback for another port, exactly like the
	// connection callback; a different key there is a conflict too.
	if got := KnownHostsKeyMismatches(path, "example.com:2222", []ssh.PublicKey{other}); len(got) != 1 {
		t.Fatalf("the port-22 fallback must report the conflict, got %v", got)
	}
	if got := KnownHostsKeyMismatches(path, "example.com:2222", []ssh.PublicKey{key}); len(got) != 0 {
		t.Fatalf("the same key on the default port is accepted, got %v", got)
	}
	if got := KnownHostsKeyMismatches(path, "elsewhere:22", []ssh.PublicKey{other}); len(got) != 0 {
		t.Fatalf("an unknown host is not a conflict: %v", got)
	}
	if got := KnownHostsKeyMismatches(filepath.Join(t.TempDir(), "nope"), "example.com:22", []ssh.PublicKey{other}); len(got) != 0 {
		t.Fatalf("a missing file is not a conflict: %v", got)
	}
}

func TestKnownHostsHasHostMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope")
	if KnownHostsHasHost(path, "example.com:22") {
		t.Fatal("a missing known_hosts file must not count as trusted")
	}
}

func TestKnownHostsHasHostBadAddress(t *testing.T) {
	path := writeKnownHosts(t, "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJc7FkLY/hM+6quChfLIs+9YOTGOl2CuX3HGrln3FyxT")
	if KnownHostsHasHost(path, "example.com") {
		t.Fatal("an address without a port must not count as trusted")
	}
}
