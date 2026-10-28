package gitx

import "strings"

// shQuote quotes a path for the shell git uses to run a helper.
//
// git runs credential.helper and GIT_SSH_COMMAND through sh on every platform,
// including Windows. There a bare backslash is an escape, so
// `C:\Users\me\ssha.exe` would arrive as `C:Usersmessha.exe`; forward slashes
// mean the same thing to Windows and are inert to sh. Single quotes then keep
// spaces in `C:/Program Files/ssha/ssha.exe` together.
//
// This is not cmd quoting: the askpass .cmd file is written by cmdQuote, which
// runs under cmd.exe instead.
func shQuote(p string, windows bool) string {
	if windows {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}
