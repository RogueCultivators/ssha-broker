package ui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "ui.token")

	first, err := loadToken(path)
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if len(first) != 48 {
		t.Errorf("token = %q (%d chars), want 24 random bytes as hex", first, len(first))
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the token file was not created: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if parent, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if parent.Mode().Perm() != 0o700 {
		t.Errorf("parent dir mode = %v, want 0700", parent.Mode().Perm())
	}

	// The whole point: a restart keeps a bookmarked URL working.
	second, err := loadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("token changed across calls: %q then %q", first, second)
	}
}

func TestLoadTokenWithoutAFileIsEphemeral(t *testing.T) {
	a, err := loadToken("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadToken("")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("without a token file each run should get a fresh token")
	}
}

func TestLoadTokenReplacesAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui.token")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 48 {
		t.Errorf("token = %q, want a generated one", got)
	}
}
