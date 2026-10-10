package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSummarizeBuckets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	today := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	lines := []summaryLine{
		{Time: now.Add(-time.Hour), Type: TypeExec, Host: "web", Decision: DecisionAllowed},
		{Time: now.Add(-30 * time.Hour), Type: TypeUpload, Host: "db", Decision: DecisionDenied},
		{Time: now.AddDate(0, 0, -10), Type: TypeDownload, Host: "web", Decision: DecisionAllowed},
		{Time: now.AddDate(0, 0, -40), Type: TypeExec, Host: "web", Decision: DecisionAllowed},
	}
	var b strings.Builder
	for _, r := range lines {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	// A half-written line must not fail the count or hide the records around it.
	b.WriteString("not json\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Summarize(path, now, today)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 4 {
		t.Errorf("total = %d, want 4", got.Total)
	}
	if got.Today != 1 || got.Last24h != 1 || got.Last7d != 2 || got.Last30d != 3 {
		t.Errorf("windows today/24h/7d/30d = %d/%d/%d/%d, want 1/1/2/3", got.Today, got.Last24h, got.Last7d, got.Last30d)
	}
	if got.Decision[DecisionDenied] != 1 || got.Type[TypeUpload] != 1 || got.Host["web"] != 3 || got.Host["db"] != 1 {
		t.Errorf("counts = %+v", got)
	}
}

func TestSummarizeMissingFile(t *testing.T) {
	got, err := Summarize(filepath.Join(t.TempDir(), "missing.jsonl"), time.Now(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 0 || got.Decision == nil || got.Host == nil {
		t.Errorf("missing file should be an empty summary, got %+v", got)
	}
}
