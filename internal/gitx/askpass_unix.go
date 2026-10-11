//go:build !windows

package gitx

import (
	"os"
	"path/filepath"
	"strings"
)

func writeAskpass(dir, self string) (string, error) {
	path := filepath.Join(dir, "askpass")
	body := "#!/bin/sh\nexec " + shellQuote(self) + " git-askpass \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
