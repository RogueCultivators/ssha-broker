package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// sealKeyName is the data key for secrets this config owns. It sits next to
	// those files so CLI and MCP can decrypt without a separate unlock step.
	sealKeyName = ".seal-key"
	// secretPrefix marks a file written by WriteSecret. A file without it is
	// plaintext, which is how a hand-written password file keeps working.
	secretPrefix = "SSHA1:"
	sealKeyLen   = 32
)

// sealMu serializes writers in this process. The file lock covers other processes.
var sealMu sync.Mutex

// ReadSecretFile returns the secret stored at path. Files written by WriteSecret
// are sealed and decrypted with the key beside them. A file without the seal
// prefix is returned as plaintext.
func ReadSecretFile(path string) (string, error) {
	path = ExpandHome(path)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(b), "\r\n")
	if text == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	if !strings.HasPrefix(text, secretPrefix) {
		return text, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("sealed secret %s is corrupt", path)
	}
	key, err := readSealKey(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("sealed secret %s: %w", path, err)
	}
	plain, err := openSeal(key, raw)
	if err != nil {
		return "", fmt.Errorf("sealed secret %s cannot be decrypted", path)
	}
	return string(plain), nil
}

// SecretSealed reports whether path holds a sealed secret. A missing or
// unreadable file is not sealed.
func SecretSealed(path string) bool {
	if path == "" {
		return false
	}
	sealed, err := fileIsSealed(ExpandHome(path))
	return err == nil && sealed
}

// SealExistingSecrets encrypts plaintext password and passphrase files that
// this config owns. Already-sealed files, empty files and anything that is not
// a stored secret are left alone. Hand-written files outside the secrets
// directory are not touched.
func SealExistingSecrets(configPath string) error {
	dir := SecretsDir(configPath)
	if st, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("secrets path %s is not a directory", dir)
	}
	return withSealLock(dir, func() error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		var pending []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, "."+string(SecretPassword)) && !strings.HasSuffix(name, "."+string(SecretPassphrase)) {
				continue
			}
			path := filepath.Join(dir, name)
			sealed, err := fileIsSealed(path)
			if err != nil {
				return err
			}
			if sealed {
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.TrimRight(string(b), "\r\n") == "" {
				continue
			}
			pending = append(pending, path)
		}
		if len(pending) == 0 {
			return nil
		}
		key, err := loadOrCreateSealKey(dir)
		if err != nil {
			return err
		}
		for _, path := range pending {
			if err := sealPlainFile(dir, path, key); err != nil {
				return err
			}
		}
		return nil
	})
}

func sealPlainFile(dir, path string, key []byte) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := strings.TrimRight(string(b), "\r\n")
	if text == "" || strings.HasPrefix(text, secretPrefix) {
		return nil
	}
	sealed, err := seal(key, []byte(text))
	if err != nil {
		return err
	}
	return writePrivate(dir, path, []byte(sealed+"\n"))
}

func fileIsSealed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, len(secretPrefix))
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	return string(buf[:n]) == secretPrefix, nil
}

func readSealKey(dir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, sealKeyName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("seal key is missing")
		}
		return nil, err
	}
	if len(b) != sealKeyLen {
		return nil, errors.New("seal key is corrupt")
	}
	return b, nil
}

// loadOrCreateSealKey returns the data key, creating it on first use. The
// caller must hold the seal lock so two processes cannot each invent a key.
func loadOrCreateSealKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, sealKeyName)
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != sealKeyLen {
			return nil, fmt.Errorf("seal key %s is corrupt", path)
		}
		return b, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, sealKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate seal key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return loadOrCreateSealKey(dir)
		}
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func seal(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// The prefix is additional data so a blob sealed for something else cannot
	// be pasted in and still open.
	out := gcm.Seal(nonce, nonce, plaintext, []byte(secretPrefix))
	return secretPrefix + base64.StdEncoding.EncodeToString(out), nil
}

func openSeal(key, raw []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, []byte(secretPrefix))
}

func withSealLock(dir string, fn func() error) error {
	sealMu.Lock()
	defer sealMu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".seal.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer unlockFile(f)
	return fn()
}

// writePrivate replaces path with data, mode 0600, via a temp file in dir.
func writePrivate(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
