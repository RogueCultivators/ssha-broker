package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Path handling that has to work the same way when a config written on one
// platform is read on another. The Windows branches are pure functions so they
// can be tested from any host: the separator is a parameter, not runtime.GOOS.

// expandHomePath replaces a leading ~ with home. "~" alone is the home
// directory; "~/" and, on Windows, "~\" start a path below it. "~user" is not
// supported and is left alone rather than silently mangled.
func expandHomePath(p, home string, sep rune) string {
	if home == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	if len(p) == 1 {
		return home
	}
	if p[1] != '/' && !(sep == '\\' && p[1] == '\\') {
		return p
	}
	rest := strings.TrimLeft(p[1:], "/\\")
	if rest == "" {
		return home
	}
	if sep == '\\' {
		// Rewrite the separators too, so a "~/a/b" written on Windows comes out
		// fully backslashed rather than half and half.
		rest = strings.ReplaceAll(rest, "/", `\`)
	}
	return joinPath(sep, home, rest)
}

// joinPath joins with an explicit separator, so the Windows rules produce the
// same result when tested from Linux.
func joinPath(sep rune, elems ...string) string {
	out := ""
	for _, e := range elems {
		if e == "" {
			continue
		}
		if out == "" {
			out = e
			continue
		}
		out = strings.TrimRight(out, "/\\") + string(sep) + strings.TrimLeft(e, "/\\")
	}
	if sep == rune(filepath.Separator) {
		// Clean resolves "." and ".." with the platform's rules. It is skipped
		// for a separator that is not this host's, where Clean would read the
		// separators as ordinary characters and mangle the path.
		return filepath.Clean(out)
	}
	return out
}

// expandEnvs expands $VAR everywhere and %VAR% on Windows, where that is the
// form the platform's own tools use. An unknown variable is left as written, so
// a literal % in a file name survives.
func expandEnvs(p string, sep rune) string {
	p = os.ExpandEnv(p)
	if sep != '\\' || !strings.ContainsRune(p, '%') {
		return p
	}
	return expandPercent(p)
}

func expandPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		j := strings.IndexByte(s[i:], '%')
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		b.WriteString(s[i:j])
		k := strings.IndexByte(s[j+1:], '%')
		if k < 0 {
			b.WriteString(s[j:])
			break
		}
		k += j + 1
		name := s[j+1 : k]
		value, ok := os.LookupEnv(name)
		switch {
		case name == "" || strings.ContainsAny(name, `\/ `):
			// Not a variable reference: "% done %" and "50%" stay as they are.
			b.WriteString(s[j : k+1])
		case ok:
			b.WriteString(value)
		default:
			b.WriteString(s[j : k+1])
		}
		i = k + 1
	}
	return b.String()
}

// isRootedPath reports whether p names a location from a root rather than one
// relative to the config file. filepath.IsAbs alone is not enough: on Windows
// "/etc/ssha/config.yaml" and "\srv\share" are rooted at the current drive, and
// joining them onto the config's directory would invent a path that does not
// exist.
func isRootedPath(p string, sep rune) bool {
	if p == "" {
		return false
	}
	if sep != '\\' {
		return p[0] == '/'
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return p[0] == '/' || p[0] == '\\'
}

// appDataPath returns a directory under %APPDATA%, or "" where that variable
// does not exist. Windows tools keep configuration there rather than under
// ~/.config, which is an XDG convention.
func appDataPath(elem ...string) string {
	base := os.Getenv("APPDATA")
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base, "ssha"}, elem...)...)
}

// localAppDataPath is the non-roaming counterpart, used for state such as the
// audit log.
func localAppDataPath(elem ...string) string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base, "ssha"}, elem...)...)
}
