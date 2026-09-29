//go:build ignore

// Command genrc turns ssha.rc.in into a .rc that windres can compile.
//
// It exists because neither of the two obvious approaches works. Passing the
// version as a -D define needs layers of quoting (the value is a comma list in
// one place and a quoted string in the other) that differ per shell, and a
// Windows path inside a .rc string is a minefield, because a backslash starts an
// escape sequence there.
//
// Run with: go run packaging/windows/genrc.go -version 1.2.3 -icon <path> -out <path>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ssha/internal/version"
)

func main() {
	v := flag.String("version", "0.0.0", "version string, e.g. 1.2.3 or a git describe output")
	icon := flag.String("icon", "packaging/icons/ssha.ico", "path to the .ico, slashes are fine")
	out := flag.String("out", "packaging/windows/ssha.rc", "where to write the .rc")
	flag.Parse()

	in := filepath.Join(filepath.Dir(*out), "ssha.rc.in")
	if _, err := os.Stat(in); err != nil {
		in = "packaging/windows/ssha.rc.in"
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		fail(err)
	}

	// A slash path cannot be mistaken for an escape, and windres accepts it.
	iconPath, err := filepath.Abs(*icon)
	if err != nil {
		fail(err)
	}
	repl := strings.NewReplacer(
		"@ICON@", filepath.ToSlash(iconPath),
		"@VERSION_COMMA@", version.Comma(*v),
		"@VERSION_STR@", version.Display(*v),
	)
	if err := os.WriteFile(*out, []byte(repl.Replace(string(raw))), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("%s: %s (%s)\n", *out, version.Display(*v), version.Comma(*v))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "genrc: %v\n", err)
	os.Exit(1)
}
