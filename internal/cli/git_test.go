package cli

import "testing"

func TestGitHelpersSkipFlagParsing(t *testing.T) {
	// git appends ssh options after the helper name. Those must not be parsed
	// as ssha flags, and a missing grant must not dump the general usage.
	code := Run([]string{"git-ssh", "-o", "BatchMode=yes", "git@example.com"}, "test")
	if code == ExitUsage {
		t.Fatal("git-ssh arguments were parsed as ssha flags")
	}
	if code != ExitFail {
		t.Fatalf("git-ssh exit = %d, want %d", code, ExitFail)
	}
	code = Run([]string{"git-credential", "get"}, "test")
	if code != ExitFail {
		t.Fatalf("git-credential exit = %d, want %d", code, ExitFail)
	}
}
