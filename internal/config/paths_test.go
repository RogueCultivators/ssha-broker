package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Windows branches are exercised from any platform: the separator is a
// parameter rather than runtime.GOOS, so a path bug shows up in CI on Linux
// instead of on the one machine nobody can test.

func TestExpandHomePath(t *testing.T) {
	unixHome := "/home/me"
	winHome := `C:\Users\me`
	tests := []struct {
		name string
		p    string
		home string
		sep  rune
		want string
	}{
		{"posix tilde", "~/.ssh/id_ed25519", unixHome, '/', filepath.Join(unixHome, ".ssh/id_ed25519")},
		{"posix bare tilde", "~", unixHome, '/', unixHome},
		{"posix trailing slash", "~/", unixHome, '/', unixHome},
		{"posix absolute is untouched", "/etc/k", unixHome, '/', "/etc/k"},
		{"posix tilde-user is left alone", "~deploy/.ssh", unixHome, '/', "~deploy/.ssh"},
		{"posix backslash is not a separator", `~\.ssh`, unixHome, '/', `~\.ssh`},

		{"windows forward slashes", "~/.ssh/id_rsa", winHome, '\\', `C:\Users\me\.ssh\id_rsa`},
		{"windows backslashes", `~\.ssh\id_rsa`, winHome, '\\', `C:\Users\me\.ssh\id_rsa`},
		{"windows bare tilde", "~", winHome, '\\', winHome},
		{"windows tilde-user is left alone", `~deploy\k`, winHome, '\\', `~deploy\k`},
		{"empty home is a no-op", "~/x", "", '/', "~/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandHomePath(tc.p, tc.home, tc.sep); got != tc.want {
				t.Fatalf("expandHomePath(%q) = %q, want %q", tc.p, got, tc.want)
			}
		})
	}
}

func TestExpandPercent(t *testing.T) {
	t.Setenv("SSHA_TEST_DIR", `C:\Users\me`)
	tests := []struct {
		in   string
		want string
	}{
		{`%SSHA_TEST_DIR%\.ssh\id_rsa`, `C:\Users\me\.ssh\id_rsa`},
		{`%SSHA_TEST_DIR%/mixed/path`, `C:\Users\me/mixed/path`},
		{`%SSHA_TEST_UNKNOWN%\x`, `%SSHA_TEST_UNKNOWN%\x`},
		{`100% done`, `100% done`},
		{`%a b%`, `%a b%`},
		{`no percent`, `no percent`},
		{`%SSHA_TEST_DIR%,%SSHA_TEST_DIR%`, `C:\Users\me,C:\Users\me`},
		{`50%`, `50%`},
	}
	for _, tc := range tests {
		if got := expandPercent(tc.in); got != tc.want {
			t.Errorf("expandPercent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandEnvsLeavesPercentAloneOffWindows(t *testing.T) {
	t.Setenv("SSHA_TEST_DIR", "/home/me")
	if got := expandEnvs("%SSHA_TEST_DIR%/x", '/'); got != "%SSHA_TEST_DIR%/x" {
		t.Fatalf("a POSIX path had its percent signs expanded: %q", got)
	}
	if got := expandEnvs("$SSHA_TEST_DIR/x", '/'); got != "/home/me/x" {
		t.Fatalf("$VAR was not expanded: %q", got)
	}
	if got := expandEnvs("%SSHA_TEST_DIR%\\x", '\\'); !strings.HasPrefix(got, "/home/me") {
		t.Fatalf("percent variable was not expanded on Windows: %q", got)
	}
}

func TestIsRootedPath(t *testing.T) {
	tests := []struct {
		p    string
		sep  rune
		want bool
	}{
		{"/etc/ssha/config.yaml", '/', true},
		{"relative/key", '/', false},
		{"", '/', false},

		{`C:\Users\me\key`, '\\', true},
		{"C:/Users/me/key", '\\', true},
		{`\\server\share\key`, '\\', true},
		{`/etc/ssha/config.yaml`, '\\', true},
		{`\ProgramData\x`, '\\', true},
		{`relative\key`, '\\', false},
		{".ssh/id_rsa", '\\', false},
		{"1:\\not-a-drive", '\\', false},
	}
	for _, tc := range tests {
		if got := isRootedPath(tc.p, tc.sep); got != tc.want {
			t.Errorf("isRootedPath(%q, %q) = %v, want %v", tc.p, tc.sep, got, tc.want)
		}
	}
}

// anchorPath is what turns `password_file: secrets/web.pass` into a path that
// does not depend on the working directory, while leaving anything the operator
// wrote as an absolute path alone - including the Windows forms that
// filepath.IsAbs does not recognise.
func TestAnchorPathWindows(t *testing.T) {
	dir := `C:\Users\me\.config\ssha`
	home := `C:\Users\me`
	t.Setenv("SSHA_TEST_KEY_DIR", `D:\keys`)
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"relative is anchored", "secrets/web.pass", `C:\Users\me\.config\ssha\secrets/web.pass`},
		{"windows relative is anchored", `secrets\web.pass`, `C:\Users\me\.config\ssha\secrets\web.pass`},
		{"drive path is left alone", `D:\keys\id_rsa`, `D:\keys\id_rsa`},
		{"unc path is left alone", `\\server\share\id_rsa`, `\\server\share\id_rsa`},
		{"posix-style root is left alone", "/etc/key.pem", "/etc/key.pem"},
		{"tilde is expanded first", `~\.ssh\id_rsa`, `C:\Users\me\.ssh\id_rsa`},
		{"percent variable is expanded first", `%SSHA_TEST_KEY_DIR%\id_rsa`, `D:\keys\id_rsa`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := anchorPathOn(dir, tc.in, '\\', home); got != tc.want {
				t.Fatalf("anchorPathOn(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAnchorPathKeepsRootedPaths(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"/etc/key.pem", "/var/lib/k"} {
		if got := anchorPath(dir, p); got != p {
			t.Errorf("anchorPath joined a rooted path: %q -> %q", p, got)
		}
	}
}

func TestCandidatesIncludesAppDataOnWindows(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)
	found := ""
	for _, c := range Candidates() {
		if strings.HasPrefix(c, appData) {
			found = c
		}
	}
	if want := filepath.Join(appData, "ssha", "config.yaml"); found != want {
		t.Fatalf("APPDATA config candidate = %q, want %q", found, want)
	}

	t.Setenv("APPDATA", "")
	for _, c := range Candidates() {
		if strings.Contains(c, "AppData") {
			t.Fatalf("a Windows-only candidate appeared without APPDATA: %q", c)
		}
	}
}

func TestDefaultAuditPathUsesLocalAppData(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	if got, want := DefaultAuditPath(), filepath.Join(local, "ssha", "audit.jsonl"); got != want {
		t.Fatalf("DefaultAuditPath() = %q, want %q", got, want)
	}

	t.Setenv("LOCALAPPDATA", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got, want := DefaultAuditPath(), filepath.Join(home, ".local", "share", "ssha", "audit.jsonl"); got != want {
		t.Fatalf("DefaultAuditPath() = %q, want the XDG path %q", got, want)
	}
}
