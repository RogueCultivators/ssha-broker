package audit

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempLog(t *testing.T) (*Logger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func appendExec(t *testing.T, l *Logger, host, cmd string) *Record {
	t.Helper()
	r := &Record{Type: TypeExec, Host: host, Command: cmd, Decision: DecisionAllowed}
	if err := l.Append(r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return r
}

func TestAppendAssignsChainFields(t *testing.T) {
	l, path := tempLog(t)

	first := appendExec(t, l, "web-1", "uname -a")
	if first.ID == "" {
		t.Fatal("expected an id")
	}
	if first.Seq != 1 {
		t.Errorf("first record Seq = %d, want 1", first.Seq)
	}
	if first.PrevHash != "" {
		t.Errorf("first record PrevHash = %q, want empty", first.PrevHash)
	}
	if !strings.HasPrefix(first.Hash, "sha256:") {
		t.Errorf("Hash = %q, want a sha256: prefix", first.Hash)
	}

	second := appendExec(t, l, "web-1", "uptime")
	if second.Seq != 2 {
		t.Errorf("second record Seq = %d, want 2", second.Seq)
	}
	if second.PrevHash != first.Hash {
		t.Errorf("second PrevHash = %q, want %q", second.PrevHash, first.Hash)
	}

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 2 {
		t.Errorf("Verify counted %d records, want 2", n)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	l, path := tempLog(t)
	appendExec(t, l, "web-1", "ls")
	appendExec(t, l, "web-1", "rm -rf /tmp/x")
	appendExec(t, l, "web-1", "uptime")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	// Rewrite the middle record's command, leaving its hash untouched.
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	rec["command"] = "ls"
	patched, _ := json.Marshal(rec)
	lines[1] = string(patched)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := Verify(path)
	if err == nil {
		t.Fatal("expected Verify to fail on a modified record")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error = %v, want a hash mismatch", err)
	}
	if n != 1 {
		t.Errorf("verified %d records before the failure, want 1", n)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	l, path := tempLog(t)
	appendExec(t, l, "web-1", "a")
	appendExec(t, l, "web-1", "b")
	appendExec(t, l, "web-1", "c")

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Drop the middle record: the chain no longer links up.
	kept := []string{lines[0], lines[2]}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path); err == nil {
		t.Fatal("expected Verify to fail after a record was removed")
	}
}

func TestQueryFiltersAndLimits(t *testing.T) {
	l, path := tempLog(t)
	appendExec(t, l, "web-1", "ls")
	appendExec(t, l, "web-1", "uptime")
	l.Append(&Record{Type: TypeExec, Host: "web-2", Command: "ls", Decision: DecisionDenied, Reason: "readonly"})
	l.Append(&Record{Type: TypeUpload, Host: "web-2", Path: "/tmp/x", Decision: DecisionAllowed})

	tests := []struct {
		name   string
		filter Filter
		limit  int
		want   int
	}{
		{"no filter", Filter{}, 0, 4},
		{"by host", Filter{Host: "web-2"}, 0, 2},
		{"by decision", Filter{Decision: DecisionDenied}, 0, 1},
		{"by type", Filter{Type: TypeUpload}, 0, 1},
		{"limit keeps the newest", Filter{}, 2, 2},
		{"limit over the total", Filter{}, 99, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Query(path, tc.filter, tc.limit)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d records, want %d", len(got), tc.want)
			}
			if tc.limit > 0 && len(got) > 1 {
				if !got[0].Time.Before(got[len(got)-1].Time) && got[0].Time != got[len(got)-1].Time {
					t.Error("records are not in chronological order")
				}
			}
		})
	}
}

func TestQueryBySince(t *testing.T) {
	l, path := tempLog(t)
	old := &Record{Type: TypeExec, Host: "h", Command: "old", Decision: DecisionAllowed, Time: time.Now().Add(-2 * time.Hour)}
	if err := l.Append(old); err != nil {
		t.Fatal(err)
	}
	appendExec(t, l, "h", "new")

	got, err := Query(path, Filter{Since: time.Now().Add(-time.Hour)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Command != "new" {
		t.Fatalf("got %+v, want only the recent record", got)
	}
}

// TestLastLineAcrossChunks makes the final record larger than the read chunk so
// the tail scanner has to walk backwards to find the previous line.
func TestLastLineAcrossChunks(t *testing.T) {
	l, path := tempLog(t)
	appendExec(t, l, "h", "small")

	// A record larger than the 64 KiB tail-scan chunk, so the scanner has to
	// walk backwards past it to find the previous line.
	bigRec := &Record{
		Type: TypeExec, Host: "h", Command: "big", Decision: DecisionAllowed,
		Stdout: strings.Repeat("x", 200*1024),
	}
	if err := l.Append(bigRec); err != nil {
		t.Fatalf("Append big record: %v", err)
	}
	third := appendExec(t, l, "h", "after-big")

	if third.PrevHash != bigRec.Hash {
		t.Errorf("PrevHash after a >64KiB record = %q, want %q", third.PrevHash, bigRec.Hash)
	}
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 3 {
		t.Errorf("verified %d records, want 3", n)
	}
}

// TestConcurrentAppendsKeepChain exercises the cross-instance file lock: two
// Logger values in one process do not share the in-process mutex.
func TestConcurrentAppendsKeepChain(t *testing.T) {
	_, path := tempLog(t)
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	const perWriter = 25
	var wg sync.WaitGroup
	for _, l := range []*Logger{a, b} {
		wg.Add(1)
		go func(l *Logger) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if err := l.Append(&Record{Type: TypeExec, Host: "h", Command: "x", Decision: DecisionAllowed}); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}(l)
	}
	wg.Wait()

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify after concurrent appends: %v", err)
	}
	if want := 2 * perWriter; n != want {
		t.Errorf("verified %d records, want %d", n, want)
	}
}

func TestVerifyOnMissingFile(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Fatal("expected an error for a missing audit log")
	}
}

func TestGet(t *testing.T) {
	l, path := tempLog(t)
	want := appendExec(t, l, "web-1", "ls")
	got, err := Get(path, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Command != "ls" {
		t.Errorf("Command = %q, want ls", got.Command)
	}
	if _, err := Get(path, "does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown id")
	}
}

// TestRecordWithoutAnAppHashesLikeItAlwaysDid guards the compatibility promise
// of the hash chain: an audit file written before Record gained the App field
// must still verify, because verification re-marshals each record and compares
// hashes. A record with no app has to serialise to exactly the bytes it was
// hashed from, which means the new field must stay omitempty and must not
// shuffle the fields around it.
func TestRecordWithoutAnAppHashesLikeItAlwaysDid(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	// The shape of Record before the App field existed.
	type recordV1 struct {
		ID         string    `json:"id"`
		Time       time.Time `json:"time"`
		PrevHash   string    `json:"prev_hash"`
		Hash       string    `json:"hash,omitempty"`
		SessionID  string    `json:"session_id"`
		Seq        int       `json:"seq"`
		Actor      string    `json:"actor,omitempty"`
		Machine    string    `json:"machine,omitempty"`
		Agent      *Agent    `json:"agent,omitempty"`
		Type       string    `json:"type"`
		Host       string    `json:"host"`
		Command    string    `json:"command,omitempty"`
		Path       string    `json:"path,omitempty"`
		Cwd        string    `json:"cwd,omitempty"`
		Decision   string    `json:"decision"`
		Reason     string    `json:"reason,omitempty"`
		ExitCode   int       `json:"exit_code,omitempty"`
		DurationMS int64     `json:"duration_ms,omitempty"`
		Bytes      int64     `json:"bytes,omitempty"`
		Truncated  bool      `json:"truncated,omitempty"`
		Stdout     string    `json:"stdout,omitempty"`
		Stderr     string    `json:"stderr,omitempty"`
	}

	old := recordV1{
		ID: "20260304T050607.000000000Z-abcdef", Time: now, PrevHash: "sha256:prev",
		SessionID: "ssha-1", Seq: 7, Actor: "ch", Machine: "box",
		Agent: &Agent{Tool: "pi", Model: "m"}, Type: TypeExec, Host: "web-1",
		Command: "systemctl status nginx", Cwd: "/srv", Decision: DecisionAllowed,
		ExitCode: 0, DurationMS: 12, Bytes: 10, Stdout: "active\n",
	}
	// The same record as the current code would write it: no app.
	current := Record{
		ID: old.ID, Time: old.Time, PrevHash: old.PrevHash, Hash: old.Hash,
		SessionID: old.SessionID, Seq: old.Seq, Actor: old.Actor, Machine: old.Machine,
		Agent: old.Agent, Type: old.Type, Host: old.Host, Command: old.Command,
		Path: old.Path, Cwd: old.Cwd, Decision: old.Decision, Reason: old.Reason,
		ExitCode: old.ExitCode, DurationMS: old.DurationMS, Bytes: old.Bytes,
		Truncated: old.Truncated, Stdout: old.Stdout, Stderr: old.Stderr,
	}

	oldJSON, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	newJSON, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldJSON) != string(newJSON) {
		t.Fatalf("a record without an app no longer serialises the same, so old audit logs would stop verifying.\nold: %s\nnew: %s", oldJSON, newJSON)
	}
	// The chain is built over the JSON, so identical bytes mean an identical
	// hash; compare that directly rather than through the Record type.
	sumOld := sha256.Sum256(append([]byte("sha256:prev\n"), oldJSON...))
	sumNew := sha256.Sum256(append([]byte("sha256:prev\n"), newJSON...))
	if sumOld != sumNew {
		t.Error("the hash of an app-less record changed")
	}
}
