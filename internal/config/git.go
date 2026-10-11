package config

import (
	"fmt"
	"strings"
)

// Git operations ssha will run. Anything else (commit, reset, rebase) does not
// need a credential, and is not this broker's job.
const (
	GitFetch    = "fetch"
	GitPull     = "pull"
	GitPush     = "push"
	GitClone    = "clone"
	GitLsRemote = "ls-remote"
)

// DefaultGitOps is what an account may do when its allow list is empty.
func DefaultGitOps() []string {
	return []string{GitFetch, GitPull, GitPush, GitClone, GitLsRemote}
}

// GitConfig is the git-account block. It is optional.
type GitConfig struct {
	Accounts []GitAccount `yaml:"accounts,omitempty" json:"accounts,omitempty"`
}

// GitAccount is one credential for a set of git hosts.
//
// A host is a hostname such as github.com, not a repository URL. SSH and HTTPS
// are both expressed here so the agent does not have to know which one a push
// needs, and never sees the key or the password.
type GitAccount struct {
	Name        string    `yaml:"name" json:"name"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Hosts       []string  `yaml:"hosts" json:"hosts"`
	PathPrefix  string    `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	Auth        GitAuth   `yaml:"auth" json:"auth"`
	Policy      GitPolicy `yaml:"policy,omitempty" json:"policy,omitempty"`
	Disabled    bool      `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// GitAuth is how that account authenticates. Secrets stay in env or a file,
// never in this struct's YAML as a raw password.
type GitAuth struct {
	// Type is ssh or https.
	Type           string `yaml:"type" json:"type"`
	KeyPath        string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	KeyEnv         string `yaml:"key_env,omitempty" json:"key_env,omitempty"`
	PassphraseEnv  string `yaml:"passphrase_env,omitempty" json:"passphrase_env,omitempty"`
	PassphraseFile string `yaml:"passphrase_file,omitempty" json:"passphrase_file,omitempty"`
	Username       string `yaml:"username,omitempty" json:"username,omitempty"`
	PasswordEnv    string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordFile   string `yaml:"password_file,omitempty" json:"password_file,omitempty"`
}

// GitPolicy limits what an agent may do with the account. Force push is off
// unless the operator turns it on: a model that "fixes" a rejected push by
// adding --force is the failure this exists to stop.
type GitPolicy struct {
	Allow      []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	AllowForce bool     `yaml:"allow_force,omitempty" json:"allow_force,omitempty"`
}

// GitPublic is the account as an agent may see it. Paths to keys and password
// files are omitted; those are operator details, not something a model needs
// in order to push.
type GitPublic struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Hosts         []string `json:"hosts"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
	Auth          string   `json:"auth"`
	Username      string   `json:"username,omitempty"`
	PasswordReady bool     `json:"password_ready"`
	KeyConfigured bool     `json:"key_configured"`
	AllowForce    bool     `json:"allow_force"`
	Allow         []string `json:"allow,omitempty"`
	Disabled      bool     `json:"disabled,omitempty"`
}

// Operations returns the operations this account permits.
func (a GitAccount) Operations() []string {
	if len(a.Policy.Allow) == 0 {
		return DefaultGitOps()
	}
	out := make([]string, len(a.Policy.Allow))
	for i, op := range a.Policy.Allow {
		out[i] = strings.ToLower(op)
	}
	return out
}

// Allows reports whether op is permitted. op is one of the Git* constants.
func (a GitAccount) Allows(op string) bool {
	op = strings.ToLower(op)
	for _, have := range a.Operations() {
		if have == op {
			return true
		}
	}
	return false
}

// Public is the agent-facing view. It never includes a key path or a password.
func (a GitAccount) Public() GitPublic {
	ready := a.Auth.PasswordEnv != "" || HasSecret(a.Auth.PasswordFile)
	return GitPublic{
		Name:          a.Name,
		Description:   a.Description,
		Hosts:         append([]string(nil), a.Hosts...),
		PathPrefix:    a.PathPrefix,
		Auth:          a.Auth.Type,
		Username:      a.Auth.Username,
		PasswordReady: a.Auth.Type == "https" && ready,
		KeyConfigured: a.Auth.Type == "ssh" && (a.Auth.KeyPath != "" || a.Auth.KeyEnv != ""),
		AllowForce:    a.Policy.AllowForce,
		Allow:         a.Operations(),
		Disabled:      a.Disabled,
	}
}

func (c *Config) validateGit() error {
	seen := make(map[string]struct{}, len(c.Git.Accounts))
	for i := range c.Git.Accounts {
		a := &c.Git.Accounts[i]
		if err := a.Normalize(); err != nil {
			return err
		}
		if _, dup := seen[a.Name]; dup {
			return fmt.Errorf("config: duplicate git account %q", a.Name)
		}
		seen[a.Name] = struct{}{}
	}
	return nil
}

// Normalize cleans one account and reports a problem that would make it
// unusable. Duplicate names are not its job; that needs the rest of the file.
func (a *GitAccount) Normalize() error {
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" {
		return fmt.Errorf("config: git account has no name")
	}
	if strings.ContainsAny(a.Name, " /\\") {
		return fmt.Errorf("config: git account name %q must not contain spaces or slashes", a.Name)
	}
	if len(a.Hosts) == 0 {
		return fmt.Errorf("config: git account %q: no hosts", a.Name)
	}
	for j, h := range a.Hosts {
		norm, err := NormalizeGitHost(h)
		if err != nil {
			return fmt.Errorf("config: git account %q: %w", a.Name, err)
		}
		a.Hosts[j] = norm
	}
	a.PathPrefix = strings.Trim(strings.TrimSpace(a.PathPrefix), "/")
	if strings.Contains(a.PathPrefix, "..") {
		return fmt.Errorf("config: git account %q: path_prefix must not contain ..", a.Name)
	}
	switch a.Auth.Type {
	case "ssh":
		if a.Auth.KeyPath == "" && a.Auth.KeyEnv == "" {
			return fmt.Errorf("config: git account %q: auth.type=ssh requires key_path or key_env", a.Name)
		}
	case "https":
		if strings.TrimSpace(a.Auth.Username) == "" {
			return fmt.Errorf("config: git account %q: auth.type=https requires username", a.Name)
		}
		a.Auth.Username = strings.TrimSpace(a.Auth.Username)
	default:
		return fmt.Errorf("config: git account %q: unknown auth.type %q (want ssh or https)", a.Name, a.Auth.Type)
	}
	for _, op := range a.Policy.Allow {
		if !knownGitOp(op) {
			return fmt.Errorf("config: git account %q: unknown operation %q", a.Name, op)
		}
	}
	return nil
}

func knownGitOp(op string) bool {
	switch strings.ToLower(op) {
	case GitFetch, GitPull, GitPush, GitClone, GitLsRemote:
		return true
	default:
		return false
	}
}

// NormalizeGitHost accepts a hostname and rejects a URL or a path. Operators
// paste full clone URLs into the host field; the error tells them what to keep.
func NormalizeGitHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	lower := strings.ToLower(h)
	for _, prefix := range []string{"https://", "http://", "ssh://", "git://"} {
		if strings.HasPrefix(lower, prefix) {
			return "", fmt.Errorf("host %q should be a hostname such as github.com, not a URL", h)
		}
	}
	h = strings.Trim(h, "/")
	if h == "" || strings.ContainsAny(h, " /@") || strings.Contains(h, ":") {
		return "", fmt.Errorf("host %q is not a hostname", h)
	}
	return strings.ToLower(h), nil
}

// MatchGit finds the account for a remote host and repository path.
//
// A longer path_prefix wins, so one account can cover github.com while another
// covers github.com/myorg. Two accounts that match equally are an error: picking
// one silently would authenticate with the wrong key.
func (c *Config) MatchGit(host, path string) (*GitAccount, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.Trim(path, "/")
	var best *GitAccount
	bestLen := -1
	var tied []string
	for i := range c.Git.Accounts {
		a := &c.Git.Accounts[i]
		if a.Disabled || !a.matchesHost(host) {
			continue
		}
		if a.PathPrefix != "" && path != a.PathPrefix && !strings.HasPrefix(path, a.PathPrefix+"/") {
			continue
		}
		n := len(a.PathPrefix)
		if n > bestLen {
			best = a
			bestLen = n
			tied = []string{a.Name}
			continue
		}
		if n == bestLen {
			tied = append(tied, a.Name)
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no git account matches %s", host)
	}
	if len(tied) > 1 {
		return nil, fmt.Errorf("git remote %s matches more than one account (%s)", host, strings.Join(tied, ", "))
	}
	return best, nil
}

func (a GitAccount) matchesHost(host string) bool {
	for _, h := range a.Hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
