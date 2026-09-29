package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssha/internal/audit"
	"ssha/internal/config"
)

// openTestBroker is a fully wired broker over a temp config and audit log, so
// the execution and audit paths can be exercised, not just the policy checks.
func openTestBroker(t *testing.T, body string) *Broker {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ssha.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenWithOptions(path, Options{AuditPath: filepath.Join(dir, "audit.jsonl")})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestCheckApp(t *testing.T) {
	h := &config.Host{Name: "app-1", Apps: []config.App{{Name: "checkout-api"}, {Name: "nginx"}}}

	tests := []struct {
		name    string
		host    *config.Host
		app     string
		wantErr string
	}{
		{"no app named is always fine", h, "", ""},
		{"an app the host runs", h, "checkout-api", ""},
		{"case insensitive", h, "CHECKOUT-API", ""},
		{"an app it does not run", h, "payment", "does not run"},
		{"a host with no apps", &config.Host{Name: "bare"}, "payment", "no configured applications"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkApp(tc.host, tc.app)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkApp: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	// The message should list what the host actually runs, so the caller can
	// correct itself without another round trip.
	err := checkApp(h, "payment")
	for _, want := range []string{"checkout-api", "nginx"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

const appConfig = `
hosts:
  - name: app-1
    addr: 127.0.0.1
    port: 1
    user: deploy
    auth: {type: key, key_path: /tmp/key}
    host_key: {insecure: true}
    apps:
      - name: checkout-api
      - name: nginx
    policy: {mode: allow, timeout: 500ms}
`

func TestExecRefusesToMislabelApp(t *testing.T) {
	b := openTestBroker(t, appConfig)

	res, err := b.Exec(context.Background(), ExecRequest{
		Host:    "app-1",
		App:     "payment",
		Command: "ls",
	})
	if err == nil {
		t.Fatal("expected the unknown app to be refused")
	}
	if res != nil {
		t.Errorf("no result should be returned, got %+v", res)
	}
	if !strings.Contains(err.Error(), "does not run") {
		t.Errorf("error = %v, want it to explain the app mismatch", err)
	}
}

func TestExecAcceptsAKnownApp(t *testing.T) {
	b := openTestBroker(t, appConfig)

	// The command answers policy but the dial fails, which is not our concern:
	// what matters is that the app was accepted and recorded.
	res, err := b.Exec(context.Background(), ExecRequest{
		Host:    "app-1",
		App:     "checkout-api",
		Command: "ls",
	})
	if err != nil && strings.Contains(err.Error(), "does not run") {
		t.Fatalf("a known app was refused: %v", err)
	}
	if res == nil {
		t.Fatal("expected a result even when the connection fails")
	}
	if res.App != "checkout-api" {
		t.Errorf("App = %q, want it echoed on the result", res.App)
	}
}

func TestDeniedExecRecordsTheApp(t *testing.T) {
	b := openTestBroker(t, appConfig)

	res, err := b.Exec(context.Background(), ExecRequest{
		Host:    "app-1",
		App:     "nginx",
		Command: "mkfs.ext4 /dev/sda", // baseline deny
	})
	if res == nil {
		t.Fatalf("expected a result, got err %v", err)
	}
	if res.Decision != "denied" {
		t.Fatalf("Decision = %q, want denied", res.Decision)
	}

	records, qerr := b.AuditQuery(audit.Filter{App: "nginx"}, 10)
	if qerr != nil {
		t.Fatalf("AuditQuery: %v", qerr)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want the denial", len(records))
	}
	if records[0].App != "nginx" {
		t.Errorf("recorded app = %q, want nginx", records[0].App)
	}
	if records[0].Decision != "denied" {
		t.Errorf("recorded decision = %q, want denied", records[0].Decision)
	}
}
