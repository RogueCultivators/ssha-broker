package ui

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// ---------------------------------------------------------------------------
// the settings endpoint
// ---------------------------------------------------------------------------

const editorConfig = `version: 1

policy:
  timeout: 30s
  deny_commands: ['rm -rf /']
  allow_commands: ['^ls\b']

audit:
  path: %s

hosts:
  - name: web-1
    addr: 10.0.0.10
    auth: {type: agent}
`

func testServer(t *testing.T, body string) *Server {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	cfg := fmt.Sprintf(body, filepath.Join(dir, "audit.jsonl"))
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path, "test", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func do(t *testing.T, s *Server, method, target, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("X-SSHA-Token", s.Token())
	sid, err := s.issueSession()
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-SSHA-Session", sid)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func read(t *testing.T, s *Server) string {
	t.Helper()
	b, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSettingsSavesAndReloads(t *testing.T) {
	s := testServer(t, editorConfig)

	code, body := do(t, s, "POST", "/api/settings", `{
		"policy": {"mode": "readonly", "disclosure": "blind", "redact_output": true, "timeout": "2m"},
		"audit": {"store_output": false, "max_field_bytes": 4096}
	}`)
	if code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}

	got := read(t, s)
	for _, want := range []string{"mode: readonly", "disclosure: blind", "redact_output: true",
		"timeout: 2m", "store_output: false", "max_field_bytes: 4096"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// The lists the form does not own are still there.
	for _, want := range []string{"deny_commands:", "allow_commands:"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from\n%s", want, got)
		}
	}

	// And the running server picked the change up, which is what makes the
	// settings page useful rather than a YAML editor with extra steps.
	code, body = do(t, s, "GET", "/api/state", "")
	if code != 200 {
		t.Fatalf("state: %d %s", code, body)
	}
	if !strings.Contains(body, `"effective_mode":"readonly"`) {
		t.Errorf("the effective policy did not follow the edit: %s", body)
	}
	if !strings.Contains(body, `"store_output":false`) {
		t.Errorf("audit settings did not follow the edit: %s", body)
	}
}

// Clearing a field means "inherit the built-in default", not "pin it to zero".
func TestSettingsClearsFields(t *testing.T) {
	s := testServer(t, editorConfig)
	if code, body := do(t, s, "POST", "/api/settings", `{"policy": {}, "audit": {}}`); code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}
	got := read(t, s)
	for _, unwanted := range []string{"timeout:", "mode:", "disclosure:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q should have been removed from\n%s", unwanted, got)
		}
	}
}

func TestSettingsRejectsWhatTheLoaderRejects(t *testing.T) {
	s := testServer(t, editorConfig)
	before := read(t, s)
	code, body := do(t, s, "POST", "/api/settings", `{"policy": {"mode": "sometimes"}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("code = %d, want 422: %s", code, body)
	}
	if !strings.Contains(body, "unknown policy mode") {
		t.Errorf("error should say what is wrong: %s", body)
	}
	if after := read(t, s); after != before {
		t.Error("the file changed despite the rejection")
	}
}

func TestSettingsNeedsTheToken(t *testing.T) {
	s := testServer(t, editorConfig)
	req := httptest.NewRequest("POST", "/api/settings", strings.NewReader(`{"policy":{}}`))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// the audit endpoint
// ---------------------------------------------------------------------------

func auditLog(t *testing.T, s *Server) {
	t.Helper()
	records := []string{
		`{"id":"a1","time":"2026-01-01T10:00:00Z","seq":1,"session_id":"s1","type":"exec","host":"web-1","command":"systemctl status nginx","decision":"allowed","exit_code":0}`,
		`{"id":"a2","time":"2026-01-01T10:05:00Z","seq":2,"session_id":"s1","type":"exec","host":"web-1","command":"rm -rf /var/log","decision":"denied","reason":"baseline deny list"}`,
		`{"id":"a3","time":"2026-01-01T10:09:00Z","seq":3,"session_id":"s2","type":"download","host":"web-1","path":"/etc/nginx/nginx.conf","decision":"allowed","bytes":1200}`,
	}
	path := s.broker().AuditPath()
	if err := os.WriteFile(path, []byte(strings.Join(records, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditFilters(t *testing.T) {
	s := testServer(t, editorConfig)
	auditLog(t, s)

	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"a1", "a2", "a3"}},
		{"?decision=denied", []string{"a2"}},
		{"?q=nginx", []string{"a1", "a3"}}, // the command, and the path it names
		{"?q=baseline", []string{"a2"}},    // the policy's own reason
		{"?q=SYSTEMCTL", []string{"a1"}},   // case does not matter
		{"?type=download", []string{"a3"}},
		{"?since=1h", nil}, // everything in the fixture is in the past
	}
	for _, tc := range cases {
		code, body := do(t, s, "GET", "/api/audit"+tc.query, "")
		if code != 200 {
			t.Fatalf("%s: %d %s", tc.query, code, body)
		}
		for _, id := range []string{"a1", "a2", "a3"} {
			want := slices.Contains(tc.want, id)
			if got := strings.Contains(body, `"id":"`+id+`"`); got != want {
				t.Errorf("%s: record %s present = %v, want %v", tc.query, id, got, want)
			}
		}
	}
}

func TestAuditSummaryCountsTheLog(t *testing.T) {
	s := testServer(t, editorConfig)
	auditLog(t, s)

	code, body := do(t, s, "GET", "/api/audit/summary", "")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	for _, want := range []string{`"total":3`, `"denied":1`, `"download":1`, `"web-1":3`} {
		if !strings.Contains(body, want) {
			t.Errorf("summary missing %s: %s", want, body)
		}
	}
	// Counts are not the records. A command from the log must not come back here.
	if strings.Contains(body, "systemctl") || strings.Contains(body, "nginx.conf") {
		t.Errorf("summary leaked a command or path: %s", body)
	}

	code, body = do(t, s, "GET", "/api/audit/summary?today=yesterday", "")
	if code != http.StatusBadRequest {
		t.Fatalf("bad today: %d %s", code, body)
	}
}

func TestAuditRejectsAnUnreadableSince(t *testing.T) {
	s := testServer(t, editorConfig)
	code, body := do(t, s, "GET", "/api/audit?since=last+tuesday", "")
	if code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", code)
	}
	if !strings.Contains(body, "7d") {
		t.Errorf("the error should say what a valid value looks like: %s", body)
	}
}

func TestParseSince(t *testing.T) {
	if _, err := parseSince("7d"); err != nil {
		t.Errorf("7d: %v", err)
	}
	if _, err := parseSince("90m"); err != nil {
		t.Errorf("90m: %v", err)
	}
	if _, err := parseSince("2026-01-01T00:00:00Z"); err != nil {
		t.Errorf("rfc3339: %v", err)
	}
	if _, err := parseSince("yesterday"); err == nil {
		t.Error("expected an error for nonsense")
	}
	got, err := parseSince("7d")
	if err != nil {
		t.Fatal(err)
	}
	if days := time.Since(got).Hours() / 24; days < 6.9 || days > 7.1 {
		t.Errorf("7d resolved to %v days ago", days)
	}
}
