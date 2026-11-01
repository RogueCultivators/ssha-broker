package sshx

import (
	"strings"
	"testing"
)

// Remote paths belong to the remote host. ssha runs from Windows too, so the
// script it sends must keep a POSIX cwd exactly as written: no local path
// cleaning, and no separator conversion.
func TestBuildScriptKeepsTheRemotePath(t *testing.T) {
	tests := []struct {
		name string
		cwd  string
		want string
	}{
		{"posix cwd", "/data", "set -e\ncd '/data'\nset +e\nls /data"},
		{"nested posix cwd", "/srv/app/current", "set -e\ncd '/srv/app/current'\nset +e\nls /data"},
		{"cwd with a space", "/srv/my app", "set -e\ncd '/srv/my app'\nset +e\nls /data"},
		// Nothing is rewritten even when the value looks like a Windows path:
		// the host may genuinely be Windows, and deciding that here would be a
		// guess about a machine ssha has not connected to yet.
		{"windows-looking cwd is not converted", `C:\data`, `set -e` + "\n" + `cd 'C:\data'` + "\nset +e\nls /data"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := buildScript("ls /data", RunOptions{Cwd: tc.cwd})
			if got != tc.want {
				t.Fatalf("buildScript() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildScriptQuotesEnvValues(t *testing.T) {
	got, _ := buildScript("env", RunOptions{Cwd: "/data", Env: map[string]string{"A": "x y", "B": "it's"}})
	want := "set -e\ncd '/data'\nexport A='x y'\nexport B='it'\\''s'\nset +e\nenv"
	if got != want {
		t.Fatalf("buildScript() = %q, want %q", got, want)
	}
}

// A sudo password must reach sudo through stdin. Putting it on the command line
// would expose it in the remote process table and in the audit record.
func TestBuildScriptSudo(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		opts       RunOptions
		wantScript string
		wantStdin  string
	}{
		{
			name:       "nopasswd uses -n",
			command:    "systemctl restart nginx",
			opts:       RunOptions{Sudo: &SudoRun{}},
			wantScript: "set -e\nset +e\nsudo -n -p '' -- sh -c 'systemctl restart nginx'",
		},
		{
			name:       "a password goes to stdin with -S",
			command:    "systemctl restart nginx",
			opts:       RunOptions{Sudo: &SudoRun{Password: "s3cret"}},
			wantScript: "set -e\nset +e\nsudo -S -p '' -- sh -c 'systemctl restart nginx'",
			wantStdin:  "s3cret\n",
		},
		{
			name:       "user and cwd are preserved",
			command:    "id",
			opts:       RunOptions{Cwd: "/data", Sudo: &SudoRun{User: "postgres", Password: "pw"}},
			wantScript: "set -e\ncd '/data'\nset +e\nsudo -S -p '' --user 'postgres' -- sh -c 'id'",
			wantStdin:  "pw\n",
		},
		{
			// sudo resets the environment, so exports have to be inside the shell
			// sudo starts.
			name:       "env is exported inside the sudo shell",
			command:    "env",
			opts:       RunOptions{Env: map[string]string{"A": "1"}, Sudo: &SudoRun{}},
			wantScript: "set -e\nset +e\nsudo -n -p '' -- sh -c 'export A='\\''1'\\''\nenv'",
		},
		{
			name:       "the password never appears in the script",
			command:    "id",
			opts:       RunOptions{Sudo: &SudoRun{Password: "s3cret"}},
			wantScript: "set -e\nset +e\nsudo -S -p '' -- sh -c 'id'",
			wantStdin:  "s3cret\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script, stdin := buildScript(tc.command, tc.opts)
			if script != tc.wantScript {
				t.Fatalf("script = %q, want %q", script, tc.wantScript)
			}
			if stdin != tc.wantStdin {
				t.Fatalf("stdin = %q, want %q", stdin, tc.wantStdin)
			}
			if tc.opts.Sudo != nil && tc.opts.Sudo.Password != "" && strings.Contains(script, tc.opts.Sudo.Password) {
				t.Fatalf("the sudo password leaked into the command line: %q", script)
			}
		})
	}
}
