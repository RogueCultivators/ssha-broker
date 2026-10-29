package config

import (
	"os"
	"path/filepath"
	"testing"
)

// work_dir names a directory on the remote machine, not on this one. Loading a
// config must not "help" by making it absolute, cleaning it or changing its
// separators: ssha may run on Windows and still manage Linux servers.
func TestWorkDirIsNeverRewritten(t *testing.T) {
	body := `version: 1
hosts:
  - name: web
    addr: 10.0.0.1
    user: deploy
    work_dir: /data
    auth: {type: agent}
    policy: {mode: allow}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Hosts[0].WorkDir; got != "/data" {
		t.Fatalf("work_dir = %q, want %q", got, "/data")
	}
}
