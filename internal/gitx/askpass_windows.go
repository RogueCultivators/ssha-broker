//go:build windows

package gitx

import (
	"os"
	"path/filepath"
	"strings"
)

func writeAskpass(dir, self string) (string, error) {
	path := filepath.Join(dir, "askpass.cmd")
	body := "@echo off\r\n" + cmdQuote(self) + " git-askpass %*\r\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func shellQuote(s string) string {
	return cmdQuote(s)
}

func cmdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
