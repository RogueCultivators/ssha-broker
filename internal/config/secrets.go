package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecretKind names what a stored secret is for.
type SecretKind string

const (
	// SecretPassword is an SSH login password.
	SecretPassword SecretKind = "password"
	// SecretPassphrase unlocks an encrypted private key.
	SecretPassphrase SecretKind = "passphrase"
)

// SecretsDir is where secrets belonging to a config file live: a `secrets`
// directory next to it. Keeping them together means deleting the config's
// directory deletes its secrets too, rather than leaving them somewhere the
// operator forgets about.
func SecretsDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "secrets")
}

// SecretPath is where a host's secret of this kind is stored.
func SecretPath(configPath, host string, kind SecretKind) string {
	return filepath.Join(SecretsDir(configPath), secretName(host)+"."+string(kind))
}

// secretName makes a host name safe to use as a file name. Host names come from
// the config, so this is about not letting `../` or a slash escape the directory.
func secretName(host string) string {
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		name = "host"
	}
	return name
}

// WriteSecret stores a secret with mode 0600, creating the directory 0700, and
// returns the path written. The value must not be empty: clearing a secret is
// DeleteSecret's job.
func WriteSecret(configPath, host string, kind SecretKind, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("refusing to store an empty %s", kind)
	}
	dir := SecretsDir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := SecretPath(configPath, host, kind)
	// Write then rename, so a crash cannot leave a half-written secret behind.
	tmp, err := os.CreateTemp(dir, "."+secretName(host)+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// DeleteSecret removes a stored secret. A missing file is not an error: the
// caller's intent ("this host has no stored secret") is already satisfied.
func DeleteSecret(configPath, host string, kind SecretKind) error {
	err := os.Remove(SecretPath(configPath, host, kind))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// HasSecret reports whether path holds a non-empty secret. A permission error is
// reported as "not readable" rather than crashing the caller.
func HasSecret(path string) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(ExpandHome(path))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) != ""
}

// HasStoredSecret reports whether the secret this config would store for a host
// is present on disk.
func HasStoredSecret(configPath, host string, kind SecretKind) bool {
	return HasSecret(SecretPath(configPath, host, kind))
}
