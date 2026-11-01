package cli

import (
	"os"
	"path/filepath"
	"testing"

	"ssha/internal/config"
)

// Every other path in ssha expands ~. The transfer commands did not, which on
// Windows matters because no shell expands it there: "~\Downloads\x" reached
// os.WriteFile literally and failed with "the system cannot find the path".
func TestLocalPathExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	tests := []struct{ in, want string }{
		{"-", "-"},
		{"relative/file", "relative/file"},
		{"~/Downloads/x", filepath.Join(home, "Downloads", "x")},
	}
	for _, tc := range tests {
		if got := localPath(tc.in); got != tc.want {
			t.Errorf("localPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := localPath("~/nested/dir/file"); got != filepath.Join(home, "nested/dir/file") {
		t.Errorf("nested home path = %q", got)
	}
}

// The hint for a Windows-looking path must not change the path itself.
func TestLocalPathDoesNotRewriteWindowsPaths(t *testing.T) {
	for _, p := range []string{`C:\out\x`, `\\server\share\x`, `..\up\x`} {
		if got := localPath(p); got != config.ExpandHome(p) {
			t.Errorf("localPath(%q) = %q, want it unchanged", p, got)
		}
	}
}
