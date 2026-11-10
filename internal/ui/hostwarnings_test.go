package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssha/internal/config"
)

// The editor must not ask for a scan when ~/.ssh/known_hosts already trusts the
// host: that warning would come back on every visit and the scan would change
// nothing.
func TestHostWarningsRespectsDefaultKnownHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	h := &config.Host{
		Name: "nas",
		Addr: "192.0.2.10",
		Auth: config.Auth{Type: "key", KeyPath: "/tmp/id_ed25519"},
	}
	spec := config.Spec{Mode: config.ModeAllow}

	// No known_hosts entry yet: the warning is the point.
	if warnings := hostWarnings(h, spec); !hasHostKeyWarning(warnings) {
		t.Fatalf("an unpinned host must warn, got %v", warnings)
	}

	// A plain entry, as ssha host-key --write produces.
	line := "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJc7FkLY/hM+6quChfLIs+9YOTGOl2CuX3HGrln3FyxT\n"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if warnings := hostWarnings(h, spec); hasHostKeyWarning(warnings) {
		t.Fatalf("a host already in known_hosts must not warn, got %v", warnings)
	}
}

// accept_new is an explicit decision to trust the first key, so the "scan
// first" warning must give way, but the trade-off still has to be visible.
func TestHostWarningsAcceptNew(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	h := &config.Host{
		Name: "nas", Addr: "192.0.2.10",
		Auth:    config.Auth{Type: "key", KeyPath: "/tmp/id_ed25519"},
		HostKey: config.HostKey{AcceptNew: true},
	}
	warnings := hostWarnings(h, config.Spec{Mode: config.ModeAllow})
	if hasHostKeyWarning(warnings) {
		t.Fatalf("accept_new must not also ask for a scan, got %v", warnings)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "accept_new") {
			found = true
		}
	}
	if !found {
		t.Fatalf("accept_new must be called out, got %v", warnings)
	}
}

func hasHostKeyWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "没有钉主机密钥") {
			return true
		}
	}
	return false
}
