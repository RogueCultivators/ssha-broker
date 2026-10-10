package sshx

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssha/internal/config"
)

func callbackFrom(t *testing.T, lines ...string) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := hostKeyCallback(Target{HostKey: config.HostKey{KnownHosts: path}})
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func hashedHostLine(normalized string, key ssh.PublicKey) string {
	return knownhosts.HashHostname(normalized) + " " + key.Type() + " " +
		base64.StdEncoding.EncodeToString(key.Marshal())
}

func TestHostKeyAcceptsPort22RecordForOtherPort(t *testing.T) {
	key := testPublicKey(t)
	other := testPublicKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.8"), Port: 10222}

	t.Run("plain port 22 entry", func(t *testing.T) {
		cb := callbackFrom(t, knownhosts.Line([]string{"10.0.0.8"}, key))
		if err := cb("10.0.0.8:10222", remote, key); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("hashed port 22 entry", func(t *testing.T) {
		cb := callbackFrom(t, hashedHostLine("10.0.0.8", key))
		if err := cb("10.0.0.8:10222", remote, key); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("different key stays unknown", func(t *testing.T) {
		cb := callbackFrom(t, knownhosts.Line([]string{"10.0.0.8"}, other))
		err := cb("10.0.0.8:10222", remote, key)
		if err == nil || !strings.Contains(err.Error(), "unknown host key") {
			t.Fatalf("got %v, want unknown host key", err)
		}
	})

	t.Run("exact port mismatch is not papered over", func(t *testing.T) {
		cb := callbackFrom(t,
			knownhosts.Line([]string{"10.0.0.8"}, key),
			knownhosts.Line([]string{"10.0.0.8:10222"}, other),
		)
		err := cb("10.0.0.8:10222", remote, key)
		if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
			t.Fatalf("got %v, want host key mismatch", err)
		}
	})

	t.Run("unknown host stays unknown", func(t *testing.T) {
		cb := callbackFrom(t, knownhosts.Line([]string{"10.9.9.9"}, key))
		err := cb("10.0.0.8:10222", remote, key)
		if err == nil || !strings.Contains(err.Error(), "unknown host key") {
			t.Fatalf("got %v, want unknown host key", err)
		}
	})

	t.Run("port 22 still matches itself", func(t *testing.T) {
		cb := callbackFrom(t, knownhosts.Line([]string{"10.0.0.8"}, key))
		r22 := &net.TCPAddr{IP: net.ParseIP("10.0.0.8"), Port: 22}
		if err := cb("10.0.0.8:22", r22, key); err != nil {
			t.Fatal(err)
		}
	})
}
