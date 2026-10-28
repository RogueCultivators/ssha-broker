package gitx

import (
	"strings"
	"testing"
)

// git runs the credential helper and GIT_SSH_COMMAND through sh on Windows too,
// where an unquoted backslash is an escape. A path without spaces used to be
// emitted bare, so `C:\Users\me\ssha.exe` reached sh as `C:Usersmessha.exe`.
func TestShQuoteWindows(t *testing.T) {
	tests := []struct{ in, want string }{
		{`C:\Users\me\ssha.exe`, `'C:/Users/me/ssha.exe'`},
		{`C:\Program Files\ssha\ssha.exe`, `'C:/Program Files/ssha/ssha.exe'`},
		{`C:\Users\o'brien\ssha.exe`, `'C:/Users/o'\''brien/ssha.exe'`},
	}
	for _, tc := range tests {
		if got := shQuote(tc.in, true); got != tc.want {
			t.Errorf("shQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShQuotePosix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/usr/local/bin/ssha", `'/usr/local/bin/ssha'`},
		{"/opt/my ssha/ssha", `'/opt/my ssha/ssha'`},
		// A backslash is a legal character in a POSIX file name, so it must
		// survive: only the Windows branch rewrites separators.
		{`/opt/back\slash/ssha`, `'/opt/back\slash/ssha'`},
	}
	for _, tc := range tests {
		if got := shQuote(tc.in, false); got != tc.want {
			t.Errorf("shQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The two-quote helper is the shape git parses: one word, no stray quoting.
func TestShQuoteWindowsIsOneShellWord(t *testing.T) {
	got := shQuote(`C:\Program Files\ssha\ssha.exe`, true)
	if len(got) < 2 || got[0] != '\'' || got[len(got)-1] != '\'' {
		t.Fatalf("not a single quoted word: %s", got)
	}
	for _, bad := range []string{`\\`, `\"`} {
		if strings.Contains(got, bad) {
			t.Errorf("quote output contains %q: %s", bad, got)
		}
	}
}
