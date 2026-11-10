package sshx

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// KnownHostsHasHost reports whether path already records a key for addr. It
// applies the matching rules the SSH client itself uses: plain and hashed host
// names, wildcards and negation, and the port-22 entry that also covers other
// ports.
//
// It exists to keep an operator warning honest, never to decide whether a
// connection is allowed: it cannot see the server's key. Anything it cannot
// parse counts as "not found", which only keeps the warning visible.
func KnownHostsHasHost(path, addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || path == "" {
		return false
	}
	candidates := []knownHost{{host: host, port: port}}
	if port != "22" {
		// host_key_callback accepts a key trusted for the bare host on 22 when
		// the configured port is different.
		candidates = append(candidates, knownHost{host: host, port: "22"})
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], "@") {
			// Comments, blank lines, and @revoked / @cert-authority markers.
			continue
		}
		if hostFieldMatches(fields[0], candidates) {
			return true
		}
	}
	return false
}

// appendKnownHost records one key. The caller has already established that the
// file does not pin a different key for this address; a duplicate line is
// harmless and keeps two concurrent first connections from needing a lock.
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// KnownHostsKeyMismatches reports the keys path already pins for addr when the
// scanned keys contradict them. A key that is merely absent is not a conflict;
// that is what accept_new and a first scan are for. The port-22 fallback is
// checked too, because hostKeyCallback accepts it on other ports.
func KnownHostsKeyMismatches(path, addr string, keys []ssh.PublicKey) []string {
	if path == "" {
		return nil
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil
	}
	addresses := []string{addr}
	if host, port, err := net.SplitHostPort(addr); err == nil && port != "22" {
		addresses = append(addresses, net.JoinHostPort(host, "22"))
	}

	var out []string
	seen := map[string]bool{}
	add := func(conflicts []knownhosts.KnownKey) {
		for _, c := range conflicts {
			fp := c.Key.Type() + " " + ssh.FingerprintSHA256(c.Key)
			if !seen[fp] {
				seen[fp] = true
				out = append(out, fp)
			}
		}
	}
	for _, key := range keys {
		err := cb(addresses[0], staticAddr(addresses[0]), key)
		if err == nil {
			continue
		}
		var ke *knownhosts.KeyError
		unknown := errors.As(err, &ke) && len(ke.Want) == 0
		if unknown && len(addresses) > 1 {
			// The real callback consults port 22 only when the exact port is
			// unknown; a mismatch on the exact port is never papered over.
			err = cb(addresses[1], staticAddr(addresses[1]), key)
			if err == nil {
				continue
			}
			unknown = errors.As(err, &ke) && len(ke.Want) == 0
		}
		var revoked *knownhosts.RevokedError
		switch {
		case errors.As(err, &ke) && len(ke.Want) > 0:
			add(ke.Want)
		case errors.As(err, &revoked):
			add([]knownhosts.KnownKey{revoked.Revoked})
		case !unknown:
			// Parse or I/O trouble: not a conflict this helper can prove.
		}
	}
	return out
}

// staticAddr satisfies net.Addr for knownhosts' check, which calls String()
// before it looks at the address argument.
type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }

type knownHost struct {
	host, port string
}

// String renders the address the way the knownhosts package does before it
// hashes or matches: IPv6 hosts are bracketed and the port is always present.
func (a knownHost) String() string {
	h := a.host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + a.port
}

func hostFieldMatches(field string, candidates []knownHost) bool {
	if strings.HasPrefix(field, "|") {
		return hashedHostMatches(field, candidates)
	}
	matched := false
	for _, pattern := range strings.Split(field, ",") {
		if pattern == "" {
			continue
		}
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = pattern[1:]
		}
		p, ok := parseHostPattern(pattern)
		if !ok {
			continue
		}
		for _, c := range candidates {
			if p.port != c.port || !wildcardHostMatch(p.host, c.host) {
				continue
			}
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

// parseHostPattern mirrors knownhosts' newHostnameMatcher: a bare name implies
// port 22, and only a bracketed name carries an explicit port.
func parseHostPattern(p string) (knownHost, bool) {
	if p == "" {
		return knownHost{}, false
	}
	if strings.HasPrefix(p, "[") {
		host, port, err := net.SplitHostPort(p)
		if err != nil {
			return knownHost{}, false
		}
		return knownHost{host: host, port: port}, true
	}
	if host, port, err := net.SplitHostPort(p); err == nil {
		return knownHost{host: host, port: port}, true
	}
	return knownHost{host: p, port: "22"}, true
}

func hashedHostMatches(field string, candidates []knownHost) bool {
	parts := strings.Split(field, "|")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	for _, c := range candidates {
		mac := hmac.New(sha1.New, salt)
		mac.Write([]byte(knownhosts.Normalize(c.String())))
		if hmac.Equal(mac.Sum(nil), want) {
			return true
		}
	}
	return false
}

// wildcardHostMatch is OpenSSH's host glob: * spans any run, ? matches one
// byte, and separators are not special.
func wildcardHostMatch(pattern, name string) bool {
	pat, str := []byte(pattern), []byte(name)
	for {
		if len(pat) == 0 {
			return len(str) == 0
		}
		if len(str) == 0 {
			return false
		}
		if pat[0] == '*' {
			if len(pat) == 1 {
				return true
			}
			for i := range str {
				if wildcardHostMatch(string(pat[1:]), string(str[i:])) {
					return true
				}
			}
			return false
		}
		if pat[0] == '?' || pat[0] == str[0] {
			pat, str = pat[1:], str[1:]
			continue
		}
		return false
	}
}
