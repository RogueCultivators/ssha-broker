package sshx

import "testing"

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
			if got := buildScript("ls /data", tc.cwd, nil); got != tc.want {
				t.Fatalf("buildScript() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildScriptQuotesEnvValues(t *testing.T) {
	got := buildScript("env", "/data", map[string]string{"A": "x y", "B": "it's"})
	want := "set -e\ncd '/data'\nexport A='x y'\nexport B='it'\\''s'\nset +e\nenv"
	if got != want {
		t.Fatalf("buildScript() = %q, want %q", got, want)
	}
}
