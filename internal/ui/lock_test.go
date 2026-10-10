package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func doRaw(t *testing.T, s *Server, method, target, body, session string) (int, string) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	if rdr != nil {
		req = httptest.NewRequest(method, target, rdr)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("X-SSHA-Token", s.Token())
	if session != "" {
		req.Header.Set("X-SSHA-Session", session)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func cheapKDF(s *Server) {
	s.kdf = kdfParams{time: 1, memory: 64, threads: 1}
}

func TestAdminPasswordGatesTheAPI(t *testing.T) {
	s := testServer(t, editorConfig)
	cheapKDF(s)
	s.clearSessions()

	code, body := doRaw(t, s, "GET", "/api/state", "", "")
	if code != http.StatusUnauthorized || !strings.Contains(body, `"locked":true`) {
		t.Fatalf("state without session: %d %s", code, body)
	}

	code, body = doRaw(t, s, "GET", "/api/session", "", "")
	if code != 200 || !strings.Contains(body, `"configured":false`) {
		t.Fatalf("status: %d %s", code, body)
	}

	code, body = doRaw(t, s, "POST", "/api/session", `{"password":"short","confirm":"short"}`, "")
	if code != http.StatusBadRequest || !strings.Contains(body, "至少 8") {
		t.Fatalf("short password: %d %s", code, body)
	}

	code, body = doRaw(t, s, "POST", "/api/session", `{"password":"correct horse","confirm":"nope"}`, "")
	if code != http.StatusBadRequest || !strings.Contains(body, "不一致") {
		t.Fatalf("mismatch: %d %s", code, body)
	}

	code, body = doRaw(t, s, "POST", "/api/session", `{"password":"correct horse","confirm":"correct horse"}`, "")
	if code != 200 || !strings.Contains(body, `"session"`) {
		t.Fatalf("setup: %d %s", code, body)
	}
	var resp struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Session == "" {
		t.Fatal("setup did not return a session")
	}

	authPath := uiAuthPath(s.ConfigPath())
	st, err := os.Stat(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("ui-auth mode = %v, want 0600", st.Mode().Perm())
	}
	stored, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "correct horse") {
		t.Fatalf("password stored in the auth file: %s", stored)
	}

	code, body = doRaw(t, s, "GET", "/api/state", "", resp.Session)
	if code != 200 {
		t.Fatalf("unlocked state: %d %s", code, body)
	}

	code, body = doRaw(t, s, "POST", "/api/session", `{"password":"wrong password"}`, "")
	if code != http.StatusUnauthorized || !strings.Contains(body, "不对") || strings.Contains(body, `"locked":true`) {
		t.Fatalf("wrong password: %d %s", code, body)
	}

	code, body = doRaw(t, s, "POST", "/api/session/password", `{"old":"correct horse","password":"another secret","confirm":"another secret"}`, resp.Session)
	if code != 200 {
		t.Fatalf("change: %d %s", code, body)
	}
	var changed struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal([]byte(body), &changed); err != nil {
		t.Fatal(err)
	}
	code, _ = doRaw(t, s, "GET", "/api/state", "", resp.Session)
	if code != http.StatusUnauthorized {
		t.Fatalf("old session still worked: %d", code)
	}
	code, body = doRaw(t, s, "GET", "/api/state", "", changed.Session)
	if code != 200 {
		t.Fatalf("new session: %d %s", code, body)
	}

	code, _ = doRaw(t, s, "POST", "/api/session/lock", "", changed.Session)
	if code != 200 {
		t.Fatalf("lock: %d", code)
	}
	code, _ = doRaw(t, s, "GET", "/api/state", "", changed.Session)
	if code != http.StatusUnauthorized {
		t.Fatalf("session survived lock: %d", code)
	}
}

func TestExpiredSessionIsLocked(t *testing.T) {
	s := testServer(t, editorConfig)
	id, err := s.issueSession()
	if err != nil {
		t.Fatal(err)
	}
	s.sessMu.Lock()
	s.sessions[id] = time.Now().Add(-time.Second)
	s.sessMu.Unlock()

	code, body := doRaw(t, s, "GET", "/api/state", "", id)
	if code != http.StatusUnauthorized || !strings.Contains(body, `"locked":true`) {
		t.Fatalf("expired session: %d %s", code, body)
	}
}

func TestLoginBackoff(t *testing.T) {
	s := testServer(t, editorConfig)
	cheapKDF(s)
	if code, body := doRaw(t, s, "POST", "/api/session", `{"password":"correct horse","confirm":"correct horse"}`, ""); code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	s.sessMu.Lock()
	s.guard.fails = 8
	s.guard.until = time.Now().Add(time.Minute)
	s.sessMu.Unlock()

	code, body := doRaw(t, s, "POST", "/api/session", `{"password":"correct horse"}`, "")
	if code != http.StatusTooManyRequests || !strings.Contains(body, "稍后再试") {
		t.Fatalf("backoff: %d %s", code, body)
	}
}
