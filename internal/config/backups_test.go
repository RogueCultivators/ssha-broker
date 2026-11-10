package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupIsWrittenAndRestorable(t *testing.T) {
	path := tempConfig(t, commentedConfig)

	// A save that changes the file keeps the version before it.
	updated := Host{
		Name: "nas",
		Addr: "10.0.0.30",
		Auth: Auth{Type: "key", KeyPath: "~/.ssh/id_ed25519"},
	}
	if err := UpsertHost(path, updated); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	list, err := Backups(path)
	if err != nil {
		t.Fatalf("Backups: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d backups, want 1", len(list))
	}
	if strings.Contains(readFile(t, path), "name: nas") != true {
		t.Fatal("the save did not land")
	}

	saved, err := RestoreBackup(path, list[0].Name)
	if err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if saved == "" {
		t.Fatal("restore must keep the file it replaced")
	}
	restored := readFile(t, path)
	if strings.Contains(restored, "name: nas") {
		t.Fatal("the restored file still has the newer host")
	}
	if !strings.Contains(restored, "name: web-1") {
		t.Fatal("the restored file is not the previous config")
	}
	after, err := Backups(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range after {
		if b.Name == saved {
			found = true
		}
	}
	if !found {
		t.Fatal("the pre-restore file must be in the rotation")
	}
}

func TestSavingUnchangedFileAddsNoBackup(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	h := Host{Name: "web-1", Addr: "10.0.0.10", User: "deploy",
		Tags: []string{"prod", "web"}, Auth: Auth{Type: "key", KeyPath: "~/.ssh/id_ed25519"},
		Policy: &Spec{Mode: ModeReadonly, Allow: []string{`^ls\b`}}}
	if err := UpsertHost(path, h); err != nil {
		t.Fatal(err)
	}
	before, err := Backups(path)
	if err != nil {
		t.Fatal(err)
	}
	// The second save produces the same document, so it must not push the
	// useful copy out of the rotation.
	if err := UpsertHost(path, h); err != nil {
		t.Fatal(err)
	}
	after, err := Backups(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("identical save added a backup: %d -> %d", len(before), len(after))
	}
}

func TestBackupsKeepNewest(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	for i := 0; i < backupKeep+3; i++ {
		h := Host{Name: "web-1", Addr: "10.0.0.10", WorkDir: filepath.Join("/tmp", string(rune('a'+i))),
			Auth: Auth{Type: "key", KeyPath: "~/.ssh/id_ed25519"}}
		if err := UpsertHost(path, h); err != nil {
			t.Fatal(err)
		}
	}
	list, err := Backups(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != backupKeep {
		t.Fatalf("got %d backups, want %d", len(list), backupKeep)
	}
}

func TestRestoreRejectsNamesOutsideTheRotation(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	if _, err := RestoreBackup(path, "../config.yaml"); err == nil {
		t.Fatal("path traversal must be refused")
	}
	if _, err := RestoreBackup(path, filepath.Base(path)+".bak-20990101-000000.000000000"); err == nil {
		t.Fatal("a missing backup must be refused")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a refused restore must not touch the config: %v", err)
	}
}

func TestRestoreValidatesTheBackup(t *testing.T) {
	path := tempConfig(t, commentedConfig)
	bad := path + backupPrefix + "20990101-000000.000000000"
	if err := os.WriteFile(bad, []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(path, filepath.Base(bad)); err == nil {
		t.Fatal("an unparseable backup must be refused")
	}
	if !strings.Contains(readFile(t, path), "name: web-1") {
		t.Fatal("a refused restore must leave the config alone")
	}
}
