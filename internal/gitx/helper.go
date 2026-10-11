package gitx

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// Credential answers one git-credential action from the grant.
//
// store and erase are ignored. Git must not write the password into
// ~/.git-credentials, and the helper must not delete the account's secret
// because git asked it to.
func Credential(action string, in io.Reader, g Grant) (string, error) {
	switch action {
	case "get":
	case "store", "erase", "":
		return "", nil
	default:
		return "", fmt.Errorf("unknown credential action %q", action)
	}
	if g.Auth != "https" {
		return "", fmt.Errorf("git grant is not an https account")
	}
	attrs := parseCredential(in)
	host := attrs["host"]
	if host == "" || !strings.EqualFold(host, g.Host) {
		return "", fmt.Errorf("credential request for %q does not match the granted host", host)
	}
	if g.Path != "" {
		path := strings.Trim(attrs["path"], "/")
		if path != g.Path && !strings.HasPrefix(path, g.Path+"/") {
			return "", fmt.Errorf("credential request path %q is outside the grant", path)
		}
	}
	if g.Secret == "" || g.Username == "" {
		return "", fmt.Errorf("git grant has no https credential")
	}
	for _, v := range []string{g.Username, g.Secret, host, attrs["path"], attrs["protocol"]} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return "", fmt.Errorf("refusing a credential attribute that contains a newline")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "protocol=%s\n", firstNonEmpty(attrs["protocol"], "https"))
	fmt.Fprintf(&b, "host=%s\n", host)
	if path := attrs["path"]; path != "" {
		fmt.Fprintf(&b, "path=%s\n", path)
	}
	fmt.Fprintf(&b, "username=%s\n", g.Username)
	fmt.Fprintf(&b, "password=%s\n", g.Secret)
	b.WriteByte('\n')
	return b.String(), nil
}

func parseCredential(in io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[key] = val
	}
	return out
}

// sshTakesArg lists OpenSSH options that consume the next argv element.
var sshTakesArg = map[string]bool{
	"-o": true, "-p": true, "-l": true, "-i": true, "-F": true,
	"-c": true, "-E": true, "-b": true, "-D": true, "-e": true,
	"-I": true, "-L": true, "-R": true, "-W": true, "-w": true,
	"-S": true, "-J": true, "-Q": true, "-B": true, "-m": true,
}

// SSHArgs builds the argv for the real ssh binary.
//
// The host git asked for must be the granted host. IdentitiesOnly stops ssh
// from offering whatever else is in the agent, which would make the account's
// key optional and the audit a lie.
func SSHArgs(g Grant, gitArgs []string) ([]string, error) {
	if g.Auth != "ssh" {
		return nil, fmt.Errorf("git grant is not an ssh account")
	}
	if g.KeyPath == "" {
		return nil, fmt.Errorf("git grant has no key")
	}
	host, err := sshHost(gitArgs)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(host, g.Host) {
		return nil, fmt.Errorf("ssh to %s is not the granted host %s", host, g.Host)
	}
	args := []string{"-i", g.KeyPath, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"}
	if g.Secret == "" {
		args = append(args, "-o", "BatchMode=yes")
	}
	return append(args, gitArgs...), nil
}

func sshHost(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return hostOf(args[i+1]), nil
			}
			break
		}
		if a == "" || a[0] != '-' {
			return hostOf(a), nil
		}
		if sshTakesArg[a] {
			i++
			continue
		}
		if len(a) > 2 && sshTakesArg[a[:2]] {
			continue
		}
	}
	return "", fmt.Errorf("ssh command has no host")
}

func hostOf(s string) string {
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// AskPassAnswer is what the askpass helper prints, or an error if the prompt
// is not a passphrase request.
//
// ssh also uses askpass to confirm a host key. Answering that with the
// passphrase would accept an unknown server, so anything that is not a
// passphrase prompt is refused.
func AskPassAnswer(prompt string, g Grant) (string, error) {
	if g.Auth != "ssh" || g.Secret == "" {
		return "", fmt.Errorf("no passphrase for this git account")
	}
	if strings.ContainsAny(g.Secret, "\r\n\x00") {
		return "", fmt.Errorf("passphrase contains a newline")
	}
	lower := strings.ToLower(prompt)
	switch {
	case strings.Contains(lower, "authenticity"),
		strings.Contains(lower, "fingerprint"),
		strings.Contains(lower, "yes/no"),
		strings.Contains(lower, "password for"):
		return "", fmt.Errorf("refusing askpass prompt %q", prompt)
	}
	return g.Secret, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
