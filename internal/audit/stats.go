package audit

import (
	"sort"
	"strconv"
	"strings"
)

// Stats is the "what went wrong" view of a set of records. It counts only
// commands that ran (decision allowed): a denied command never produced an
// exit code, and mixing the two would make a policy doing its job look like a
// broken host.
type Stats struct {
	Total     int            `json:"total"`
	Allowed   int            `json:"allowed"`
	Denied    int            `json:"denied"`
	Failed    int            `json:"failed"`
	Timeouts  int            `json:"timeouts"`
	ExitCodes map[string]int `json:"exit_codes"`
	// FailedByHost and FailedCommands are sorted by count when rendered, but
	// kept as maps here so JSON callers can consume them directly.
	FailedByHost   map[string]int `json:"failed_by_host"`
	FailedCommands map[string]int `json:"failed_commands"`
}

// ComputeStats counts records. The caller has already applied its filter
// (host, since, type), so this package does not need to know about it.
func ComputeStats(records []Record) Stats {
	out := Stats{
		ExitCodes:      map[string]int{},
		FailedByHost:   map[string]int{},
		FailedCommands: map[string]int{},
	}
	for i := range records {
		r := &records[i]
		out.Total++
		switch r.Decision {
		case DecisionDenied:
			out.Denied++
			continue
		case DecisionAllowed:
			out.Allowed++
		default:
			continue
		}
		if strings.Contains(r.Reason, "exceeded timeout") {
			out.Timeouts++
		}
		if r.ExitCode == 0 {
			continue
		}
		out.Failed++
		out.ExitCodes[strconv.Itoa(r.ExitCode)]++
		if r.Host != "" {
			out.FailedByHost[r.Host]++
		}
		if cmd := failureKey(r); cmd != "" {
			out.FailedCommands[cmd]++
		}
	}
	return out
}

// failureKey is what an operator would paste to reproduce the failure: the
// command, or the path for transfers, flattened to one line.
func failureKey(r *Record) string {
	s := r.Command
	if s == "" {
		s = r.Path
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// TopFailures returns the n most frequent failure keys, highest first, with
// ties ordered by key so repeated runs print the same table.
func TopFailures(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Count is one row of a ranked map.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}
