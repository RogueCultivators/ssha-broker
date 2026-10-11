package ui

import (
	"strings"
	"testing"
)

func TestGitSaveDoesNotReturnThePassword(t *testing.T) {
	s := testServer(t, "version: 1\naudit:\n  path: %s\nhosts:\n  - name: web\n    addr: 127.0.0.1\n    auth: {type: agent}\n")
	body := `{
		"name": "github",
		"hosts": ["github.com"],
		"auth": {"type": "https", "username": "octo"},
		"password": "super-secret-token"
	}`
	code, resp := do(t, s, "POST", "/api/git", body)
	if code != 200 {
		t.Fatalf("save: %d %s", code, resp)
	}
	if strings.Contains(resp, "super-secret-token") {
		t.Fatalf("password returned: %s", resp)
	}
	code, state := do(t, s, "GET", "/api/state", "")
	if code != 200 {
		t.Fatalf("state: %d %s", code, state)
	}
	if strings.Contains(state, "super-secret-token") {
		t.Fatalf("password leaked in state: %s", state)
	}
	if !strings.Contains(state, `"password_ready":true`) || !strings.Contains(state, `"password_sealed":true`) {
		t.Fatalf("state missing sealed flag: %s", state)
	}
	cfg := read(t, s)
	if strings.Contains(cfg, "super-secret-token") {
		t.Fatalf("password written into config:\n%s", cfg)
	}
	if !strings.Contains(cfg, "password_file:") {
		t.Fatalf("password file not recorded:\n%s", cfg)
	}
}
