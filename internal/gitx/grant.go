package gitx

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	grantFile = "grant.json"
	grantEnv  = "SSHA_GIT_GRANT"
	tokenEnv  = "SSHA_GIT_TOKEN"
	// grantLifetime is a backstop. The parent deletes the directory when git
	// returns; this only matters if that process dies first.
	grantLifetime = 2 * time.Hour
)

// Grant is the one-time capsule a helper may read. It lives in a 0700 directory
// for the duration of one git command and is not the config.
//
// The secret is in the file, not in argv, so `ps` does not show it. A same-user
// process can still read the file; that is the same boundary as the seal key.
type Grant struct {
	Token    string    `json:"token"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Auth     string    `json:"auth"`
	Username string    `json:"username,omitempty"`
	Secret   string    `json:"secret,omitempty"`
	KeyPath  string    `json:"key_path,omitempty"`
	Expires  time.Time `json:"expires"`
}

// WriteGrant stores g and returns the directory and the token the child must
// present. The token is generated here and is not secret material.
func WriteGrant(g Grant) (dir, token string, err error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", err
	}
	g.Token = hex.EncodeToString(buf[:])
	if g.Expires.IsZero() {
		g.Expires = time.Now().Add(grantLifetime)
	}
	dir, err = os.MkdirTemp("", "ssha-git-")
	if err != nil {
		return "", "", err
	}
	body, err := json.Marshal(g)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(dir, grantFile), body, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	return dir, g.Token, nil
}

// LoadGrant reads the grant named by the environment. A missing or mismatched
// token is a refusal, not an empty password: the helper must not guess.
func LoadGrant() (Grant, error) {
	dir := os.Getenv(grantEnv)
	token := os.Getenv(tokenEnv)
	if dir == "" || token == "" {
		return Grant{}, fmt.Errorf("no git grant")
	}
	body, err := os.ReadFile(filepath.Join(dir, grantFile))
	if err != nil {
		return Grant{}, fmt.Errorf("read git grant: %w", err)
	}
	var g Grant
	if err := json.Unmarshal(body, &g); err != nil {
		return Grant{}, fmt.Errorf("git grant is corrupt")
	}
	if subtle.ConstantTimeCompare([]byte(g.Token), []byte(token)) != 1 {
		return Grant{}, fmt.Errorf("git grant token does not match")
	}
	if !g.Expires.IsZero() && time.Now().After(g.Expires) {
		return Grant{}, fmt.Errorf("git grant expired")
	}
	return g, nil
}

// RemoveGrant deletes the directory. A missing directory is not an error.
func RemoveGrant(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}
