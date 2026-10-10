package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecretFileKeepsHandWrittenPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prod.pass")
	if err := os.WriteFile(path, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Errorf("ReadSecretFile = %q, want hunter2", got)
	}
	if SecretSealed(path) {
		t.Error("a hand-written file should not look sealed")
	}
}

func TestSealExistingSecretsLeavesForeignFilesAlone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	secrets := SecretsDir(cfgPath)
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(secrets, "web-1.password")
	if err := os.WriteFile(plain, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(secrets, "note.txt")
	if err := os.WriteFile(note, []byte("leave me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.password")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SealExistingSecrets(cfgPath); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecretFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Errorf("migrated secret = %q, want s3cret", got)
	}
	b, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cret") {
		t.Fatalf("migration left the password in plaintext: %q", b)
	}
	if !SecretSealed(plain) {
		t.Error("migrated file should be sealed")
	}

	// A second pass is a no-op, not a second encryption of the ciphertext.
	if err := SealExistingSecrets(cfgPath); err != nil {
		t.Fatal(err)
	}
	got, err = ReadSecretFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Errorf("after second migration = %q, want s3cret", got)
	}

	for _, path := range []string{note, outside} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "SSHA1:") {
			t.Errorf("%s was sealed and should not have been: %q", path, b)
		}
	}
}

func TestSealedSecretRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	path, err := WriteSecret(cfgPath, "web", SecretPassword, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext, not the prefix.
	if len(b) < len(secretPrefix)+8 {
		t.Fatalf("sealed file is unexpectedly short: %q", b)
	}
	b[len(secretPrefix)+4] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ReadSecretFile(path)
	if err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaked the secret: %v", err)
	}
}

func TestSealedSecretRejectsAReplacedKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssha.yaml")
	path, err := WriteSecret(cfgPath, "web", SecretPassword, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(SecretsDir(cfgPath), sealKeyName)
	other := make([]byte, sealKeyLen)
	for i := range other {
		other[i] = 0xab
	}
	if err := os.WriteFile(keyPath, other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = ReadSecretFile(path)
	if err == nil {
		t.Fatal("a replaced key still decrypted the secret")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaked the secret: %v", err)
	}
}

func TestSealKeyIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteSecret(filepath.Join(dir, "ssha.yaml"), "web", SecretPassword, "x"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "secrets", sealKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("seal key mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestSealExistingSecretsWithoutADirectory(t *testing.T) {
	if err := SealExistingSecrets(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
}
