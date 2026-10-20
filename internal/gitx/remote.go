package gitx

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"ssha/internal/config"
)

// Remote is a parsed git URL with any password already rejected.
type Remote struct {
	Scheme string
	User   string
	Host   string
	Port   string
	Path   string
	Raw    string
}

// ParseRemote parses an https, ssh, or scp-style git remote.
//
// A password embedded in the URL is refused. The agent must not carry the
// secret in the remote string; the account holds it.
func ParseRemote(raw string) (Remote, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Remote{}, fmt.Errorf("empty git remote")
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".") || strings.HasPrefix(raw, "~") {
		return Remote{}, fmt.Errorf("remote %q is a local path", raw)
	}
	if strings.Contains(raw, "://") {
		return parseURLRemote(raw)
	}
	return parseSCPRemote(raw)
}

func parseURLRemote(raw string) (Remote, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Remote{}, fmt.Errorf("parse git remote: %w", err)
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			return Remote{}, fmt.Errorf("remote for %s contains a password; save it on the git account instead", u.Hostname())
		}
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "ssh", "https", "http", "git":
	default:
		return Remote{}, fmt.Errorf("unsupported git remote scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Remote{}, fmt.Errorf("git remote %q has no host", raw)
	}
	user := ""
	if u.User != nil {
		user = u.User.Username()
	}
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return Remote{}, fmt.Errorf("git remote %q has no repository path", raw)
	}
	return Remote{
		Scheme: scheme,
		User:   user,
		Host:   host,
		Port:   u.Port(),
		Path:   path,
		Raw:    raw,
	}, nil
}

func parseSCPRemote(raw string) (Remote, error) {
	i := strings.Index(raw, ":")
	if i <= 0 || strings.Contains(raw[:i], "/") {
		return Remote{}, fmt.Errorf("cannot parse git remote %q", raw)
	}
	left, path := raw[:i], strings.Trim(raw[i+1:], "/")
	if path == "" {
		return Remote{}, fmt.Errorf("git remote %q has no repository path", raw)
	}
	user, host := "", left
	if at := strings.LastIndex(left, "@"); at >= 0 {
		user = left[:at]
		host = left[at+1:]
	}
	if host == "" || strings.Contains(host, " ") {
		return Remote{}, fmt.Errorf("cannot parse git remote %q", raw)
	}
	return Remote{Scheme: "ssh", User: user, Host: host, Path: path, Raw: raw}, nil
}

// Transport is the credential kind this remote needs: ssh or https.
func (r Remote) Transport() string {
	if r.Scheme == "ssh" {
		return "ssh"
	}
	return "https"
}

// EffectivePort is the port the remote actually connects to, with the scheme
// default filled in. Account matching needs it: a remote written without a port
// still uses 22 over ssh, so an account that names "host:22" should match it.
func (r Remote) EffectivePort() string {
	if r.Port != "" {
		return r.Port
	}
	switch r.Scheme {
	case "ssh":
		return "22"
	case "https":
		return "443"
	case "http":
		return "80"
	case "git":
		return "9418"
	}
	return ""
}

// Sanitized is the remote with userinfo removed, safe to log and to show an agent.
func (r Remote) Sanitized() string {
	if r.Raw != "" && !strings.Contains(r.Raw, "://") {
		return r.Raw
	}
	return r.Rewritten(r.Transport(), r.User)
}

// Rewritten builds the URL the account's auth type can actually use.
//
// The repository's remote is left untouched. This URL is only for the one
// command, so an https checkout can be pushed with an SSH key, or the reverse,
// without the agent rewriting remotes.
func (r Remote) Rewritten(auth, username string) string {
	path := strings.Trim(r.Path, "/")
	switch auth {
	case "ssh":
		user := username
		if user == "" {
			user = r.User
		}
		if user == "" {
			user = "git"
		}
		host := r.Host
		if r.Port != "" && r.Port != "22" {
			host = net.JoinHostPort(r.Host, r.Port)
		}
		return fmt.Sprintf("ssh://%s@%s/%s", user, host, path)
	default:
		host := r.Host
		if r.Port != "" && r.Port != "443" {
			host = net.JoinHostPort(r.Host, r.Port)
		}
		return "https://" + host + "/" + path
	}
}

// SameTransport reports whether the remote already speaks the account's auth.
func (r Remote) SameTransport(account config.GitAccount) bool {
	return r.Transport() == account.Auth.Type
}
