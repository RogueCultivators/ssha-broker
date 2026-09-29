// Package audit implements the append-only, tamper-evident command log.
//
// Every record is a single JSON line. Records are chained: each record stores
// the hash of the previous record, and its own hash covers the previous hash
// plus its canonical JSON. Any edit, reorder or deletion breaks the chain,
// which `ssha audit verify` detects.
//
// JSON Lines (rather than a database) is deliberate: it is append-only,
// crash-safe, inspectable with tail/jq, and trivially shipped off-host.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Record kinds.
const (
	TypeExec     = "exec"
	TypeUpload   = "upload"
	TypeDownload = "download"
)

// Decisions.
const (
	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
)

// Agent identifies the automated client that issued a command.
type Agent struct {
	// Tool is the agent runtime: pi, codex, claude, cli, or mcp.
	Tool string `json:"tool,omitempty"`
	// Model is the model identifier, when known.
	Model string `json:"model,omitempty"`
	// SessionID is the agent's own session id, when known.
	SessionID string `json:"session_id,omitempty"`
}

// Record is one audited operation.
type Record struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash,omitempty"`
	SessionID string    `json:"session_id"`
	Seq       int       `json:"seq"`

	Actor   string `json:"actor,omitempty"`
	Machine string `json:"machine,omitempty"`
	Agent   *Agent `json:"agent,omitempty"`

	Type string `json:"type"`
	Host string `json:"host"`
	// App is the workload the caller said it was operating on. It is checked
	// against the host's apps before the command runs, so the log answers
	// "what has been done to the checkout service?" and not just "on which host".
	App     string `json:"app,omitempty"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Cwd     string `json:"cwd,omitempty"`

	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`

	ExitCode   int   `json:"exit_code,omitempty"`
	DurationMS int64 `json:"duration_ms,omitempty"`
	Bytes      int64 `json:"bytes,omitempty"`
	Truncated  bool  `json:"truncated,omitempty"`

	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

func hashRecord(r Record, prevHash string) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{'\n'})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func newID(t time.Time) string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return t.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:])
}

// Logger appends records to a JSONL audit file.
type Logger struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

// Open opens (creating if needed) the audit log at path.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{path: path, f: f}, nil
}

// Path returns the audit file path.
func (l *Logger) Path() string { return l.path }

// Close releases the file handle.
func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Append writes a record, filling in id, time, sequence and hashes.
func (l *Logger) Append(r *Record) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := lockFile(l.f); err != nil {
		return err
	}
	defer func() { _ = unlockFile(l.f) }()

	prevHash, prevSeq, err := lastState(l.f)
	if err != nil {
		return err
	}
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	} else {
		r.Time = r.Time.UTC()
	}
	if r.ID == "" {
		r.ID = newID(r.Time)
	}
	r.PrevHash = prevHash
	r.Seq = prevSeq + 1
	r.Hash = hashRecord(*r, prevHash)

	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return err
	}
	return l.f.Sync()
}

// lastState returns the hash and sequence of the final record in f.
func lastState(f *os.File) (string, int, error) {
	line, err := lastLine(f)
	if err != nil || len(line) == 0 {
		return "", 0, err
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return "", 0, fmt.Errorf("audit: corrupt trailing record: %w", err)
	}
	return r.Hash, r.Seq, nil
}

// lastLine reads the final non-empty line of f without loading the whole file.
func lastLine(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}
	const chunk = 64 * 1024
	var buf []byte
	off := size
	for off > 0 {
		n := int64(chunk)
		if off < n {
			n = off
		}
		off -= n
		tmp := make([]byte, n)
		if _, err := f.ReadAt(tmp, off); err != nil {
			return nil, err
		}
		buf = append(tmp, buf...)
		trimmed := bytes.TrimRight(buf, "\r\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if off == 0 {
			return trimmed, nil
		}
	}
	return nil, nil
}

// Filter selects records for Query.
type Filter struct {
	Host      string
	App       string
	Type      string
	Decision  string
	SessionID string
	Since     time.Time
}

func (f Filter) match(r *Record) bool {
	if f.Host != "" && r.Host != f.Host {
		return false
	}
	if f.App != "" && !strings.EqualFold(r.App, f.App) {
		return false
	}
	if f.Type != "" && r.Type != f.Type {
		return false
	}
	if f.Decision != "" && r.Decision != f.Decision {
		return false
	}
	if f.SessionID != "" && r.SessionID != f.SessionID {
		return false
	}
	if !f.Since.IsZero() && r.Time.Before(f.Since) {
		return false
	}
	return true
}

// Query returns up to limit matching records, in chronological order.
// A limit <= 0 returns every match.
func Query(path string, f Filter, limit int) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var out []Record
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			continue // tolerate a partially written trailing line
		}
		if !f.match(&r) {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// Get returns a single record by id.
func Get(path, id string) (*Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.ID == id {
			return &r, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("audit record %q not found", id)
}

// Verify recomputes the hash chain and returns the number of verified records.
func Verify(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	prev := ""
	n := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		n++
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return n - 1, fmt.Errorf("record #%d: invalid JSON: %w", n, err)
		}
		if r.PrevHash != prev {
			return n - 1, fmt.Errorf("record #%d (%s): broken chain: prev_hash %s, expected %s", n, r.ID, r.PrevHash, prev)
		}
		if want := hashRecord(r, prev); r.Hash != want {
			return n - 1, fmt.Errorf("record #%d (%s): hash mismatch, record was modified", n, r.ID)
		}
		prev = r.Hash
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

// DetectAgent inspects the environment for a known agent runtime.
func DetectAgent() *Agent {
	a := &Agent{
		Tool:      detectTool(),
		Model:     firstEnv("PI_MODEL", "ANTHROPIC_MODEL", "OPENAI_MODEL", "CODEX_MODEL"),
		SessionID: firstEnv("PI_SESSION_ID", "CLAUDE_SESSION_ID", "CODEX_SESSION_ID", "SSHA_AGENT_SESSION"),
	}
	if a.Tool == "" && a.Model == "" && a.SessionID == "" {
		return nil
	}
	return a
}

func detectTool() string {
	switch {
	case os.Getenv("PI_CODING_AGENT") != "":
		return "pi"
	case firstEnv("CODEX_SANDBOX", "CODEX_HOME", "CODEX_SESSION_ID") != "":
		return "codex"
	case firstEnv("CLAUDE_CODE_ENTRYPOINT", "CLAUDECODE", "CLAUDE_SESSION_ID") != "":
		return "claude"
	}
	return ""
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// Actor returns a stable identifier for the local OS user.
func Actor() string {
	u := firstEnv("USER", "USERNAME", "LOGNAME")
	if u == "" {
		u = "uid:" + strconv.Itoa(os.Getuid())
	}
	return u
}

// Machine returns the local hostname.
func Machine() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
