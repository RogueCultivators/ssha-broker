package audit

import "testing"

func TestComputeStats(t *testing.T) {
	records := []Record{
		{Type: TypeExec, Host: "web-1", Decision: DecisionAllowed, ExitCode: 0, Command: "uptime"},
		{Type: TypeExec, Host: "web-1", Decision: DecisionAllowed, ExitCode: 1, Command: "grep x /nope"},
		{Type: TypeExec, Host: "db-1", Decision: DecisionAllowed, ExitCode: 1, Command: "grep x /nope"},
		{Type: TypeExec, Host: "db-1", Decision: DecisionAllowed, ExitCode: -1,
			Command: "sleep 99", Reason: "command exceeded timeout 60s"},
		{Type: TypeExec, Host: "db-1", Decision: DecisionDenied, Reason: "denied by policy"},
		{Type: TypeUpload, Host: "web-1", Decision: DecisionAllowed, Path: "/tmp/a"},
	}
	s := ComputeStats(records)
	if s.Total != 6 || s.Allowed != 5 || s.Denied != 1 {
		t.Fatalf("counts = %+v", s)
	}
	if s.Failed != 3 || s.Timeouts != 1 {
		t.Fatalf("failed/timeouts = %d/%d, want 3/1", s.Failed, s.Timeouts)
	}
	if s.ExitCodes["1"] != 2 || s.ExitCodes["-1"] != 1 {
		t.Fatalf("exit codes = %v", s.ExitCodes)
	}
	if s.FailedByHost["db-1"] != 2 || s.FailedByHost["web-1"] != 1 {
		t.Fatalf("failed hosts = %v", s.FailedByHost)
	}
	if s.FailedCommands["grep x /nope"] != 2 {
		t.Fatalf("failed commands = %v", s.FailedCommands)
	}
}

func TestTopFailuresIsStable(t *testing.T) {
	rows := TopFailures(map[string]int{"b": 1, "a": 1, "c": 3}, 2)
	if len(rows) != 2 || rows[0].Key != "c" || rows[1].Key != "a" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestFilterFailedAndExit(t *testing.T) {
	ok := Record{Decision: DecisionAllowed, ExitCode: 0}
	failed := Record{Decision: DecisionAllowed, ExitCode: 2}
	denied := Record{Decision: DecisionDenied}
	for _, tc := range []struct {
		name string
		f    Filter
		r    Record
		want bool
	}{
		{"failed keeps non-zero", Filter{Failed: true}, failed, true},
		{"failed drops zero", Filter{Failed: true}, ok, false},
		{"failed drops denials", Filter{Failed: true}, denied, false},
		{"exact exit", Filter{ExitCode: intp(2)}, failed, true},
		{"other exit", Filter{ExitCode: intp(1)}, failed, false},
	} {
		if got := tc.f.match(&tc.r); got != tc.want {
			t.Errorf("%s: match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func intp(v int) *int { return &v }
