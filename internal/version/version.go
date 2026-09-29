// Package version turns what git describe prints into the shapes the rest of the
// build needs.
//
// git describe --tags --always falls back to a bare commit hash when no tag
// exists, and a hash can start with digits: 1726c7e is not version 1726.0.0.
// Getting that wrong is quiet, and shows up as a nonsense version in a Windows
// properties tab or in a Debian package name, so the rule lives here with a
// test.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Numbers returns the three numbers a version starts with. Anything that is not
// a version gives zeroes.
func Numbers(v string) [3]int {
	var out [3]int
	if !IsVersion(v) {
		return out
	}
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// 1.2.3-4-gabcdef describes a release, the part after the dash does not.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		// The digits we find, not a rejection: 1.2rc3 is version 1.2, not
		// version 0.0.
		if n, err := strconv.Atoi(leadingDigits(part)); err == nil {
			out[i] = n
		}
	}
	return out
}

// Display renders the human readable form, which has to look like a version:
// Windows shows it in the properties tab, and a Debian version has to begin
// with a digit.
func Display(v string) string {
	n := Numbers(v)
	return fmt.Sprintf("%d.%d.%d", n[0], n[1], n[2])
}

// IsVersion reports whether v looks like a version rather than a commit hash.
//
// The scripts/version.sh rule, in Go: a v prefix means someone tagged a release
// and is trusted, while a bare string that starts with digits is only a version
// if it has dots, because 1726c7e is a commit.
func IsVersion(v string) bool {
	v = strings.TrimSpace(v)
	tagged := len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9'
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	return (tagged || strings.Contains(v, ".")) && leadingDigits(v) != ""
}

// Comma renders the four numbers a Windows VERSIONINFO wants.
func Comma(v string) string {
	n := Numbers(v)
	return fmt.Sprintf("%d,%d,%d,0", n[0], n[1], n[2])
}

func leadingDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
