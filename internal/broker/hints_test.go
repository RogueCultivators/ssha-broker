package broker

import "testing"

func TestShellQuotingHint(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		exit     int
		stderr   string
		wantHint bool
	}{
		{"unquoted template split by the shell", "docker ps --format table {{.Names}}", 127,
			"bash: {{.Names}}: command not found", true},
		{"quoted template that still failed", `docker ps --format '{{.Names}}'`, 127,
			"bash: docker: command not found", false},
		{"template tool usage error", "docker ps --format table {{.Names}}", 64,
			"template parsing error", true},
		{"ordinary failure", "grep x /nope", 1, "", false},
		{"failure with no template", "systemctl restart nginx", 127,
			"bash: systemctl: command not found", false},
	}
	for _, tc := range tests {
		got := shellQuotingHint(tc.command, tc.exit, tc.stderr)
		if (got != "") != tc.wantHint {
			t.Errorf("%s: hint = %q, want hint=%v", tc.name, got, tc.wantHint)
		}
	}
}
