package gitx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"ssha/internal/config"
)

// MaxOutputBytes caps what a git command may return to the agent and the audit
// log. Push errors are short; a clone's progress is not worth keeping in full.
const MaxOutputBytes = 256 * 1024

// PromptFunc asks the operator for a secret the config does not have. MCP
// leaves it nil, so a headless agent cannot block on a password prompt.
type PromptFunc func(account, what string) (string, error)

// Request is one git operation. Args are passed to git after the operation;
// they are not a free-form git command.
type Request struct {
	Op     string
	Dir    string
	Remote string
	URL    string
	Args   []string
	Prompt PromptFunc
}

// Result is what the caller audits and returns. It never contains a secret.
type Result struct {
	AuditID    string `json:"audit_id,omitempty"`
	Account    string `json:"account,omitempty"`
	Auth       string `json:"auth,omitempty"`
	Host       string `json:"host,omitempty"`
	URL        string `json:"url,omitempty"`
	Op         string `json:"op"`
	Command    string `json:"command"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// Runner executes git with credentials the caller does not see.
type Runner struct {
	Config *config.Config
	Git    string
	Self   string
	// LookupRemote resolves a remote name in a repository. Tests replace it.
	LookupRemote func(dir, name string) (string, error)
}

// Run authenticates one git operation. A policy refusal is a Result with
// Decision denied and a nil error; the caller decides the exit code. A broken
// config or a git that cannot be started is an error.
func (r *Runner) Run(ctx context.Context, req Request) (*Result, error) {
	if r.Config == nil {
		return nil, fmt.Errorf("git: no config")
	}
	op := strings.ToLower(strings.TrimSpace(req.Op))
	if !knownOp(op) {
		return denied("", op, strings.Join(append([]string{op}, req.Args...), " "), "", fmt.Sprintf("git operation %q is not allowed", req.Op)), nil
	}
	if err := rejectUnsafeArgs(req.Args); err != nil {
		return nil, err
	}
	if req.Dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		req.Dir = wd
	}
	if req.Remote == "" {
		req.Remote = "origin"
	}

	rawURL := req.URL
	if rawURL == "" {
		rawURL = remoteInArgs(req.Args)
	}
	if rawURL == "" && op != config.GitClone {
		lookup := r.LookupRemote
		if lookup == nil {
			lookup = r.defaultLookup
		}
		got, err := lookup(req.Dir, req.Remote)
		if err != nil {
			return nil, err
		}
		rawURL = got
	}
	if req.URL != "" {
		if other := remoteInArgs(req.Args); other != "" && other != req.URL {
			return nil, fmt.Errorf("git %s: URL and arguments name different remotes", op)
		}
	}
	if rawURL == "" {
		return nil, fmt.Errorf("git %s: no remote URL", op)
	}
	remote, err := ParseRemote(rawURL)
	if err != nil {
		return nil, err
	}
	account, err := r.Config.MatchGit(remote.Host, remote.EffectivePort(), remote.Path)
	if err != nil {
		res := denied("", op, commandLine(op, req.Args), remote.Sanitized(), err.Error())
		res.Host = remote.Host
		return res, nil
	}
	if !account.Allows(op) {
		return denied(account.Name, op, commandLine(op, req.Args), remote.Sanitized(),
			fmt.Sprintf("account %q does not allow %s", account.Name, op)), nil
	}
	if op == config.GitPush && forcePush(req.Args) && !account.Policy.AllowForce {
		return denied(account.Name, op, commandLine(op, req.Args), remote.Sanitized(),
			fmt.Sprintf("force push is not allowed for account %q", account.Name)), nil
	}

	res := &Result{
		Account:  account.Name,
		Auth:     account.Auth.Type,
		Host:     remote.Host,
		URL:      remote.Sanitized(),
		Op:       op,
		Command:  commandLine(op, req.Args),
		Decision: "allowed",
	}

	secret, keyPath, cleanup, err := r.materialize(account, req.Prompt)
	if cleanup == nil {
		cleanup = func() {}
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	defer cleanup()
	if account.Auth.Type == "ssh" && secret == "" && keyLooksEncrypted(keyPath) {
		return nil, fmt.Errorf("git account %s: key is encrypted and no passphrase is configured", account.Name)
	}
	grant := Grant{
		Host:     remote.Host,
		Path:     remote.Path,
		Auth:     account.Auth.Type,
		Username: account.Auth.Username,
		Secret:   secret,
		KeyPath:  keyPath,
	}
	if account.Auth.Type == "ssh" && grant.Username == "" {
		grant.Username = "git"
	}
	dir, token, err := WriteGrant(grant)
	if err != nil {
		return nil, err
	}
	defer RemoveGrant(dir)

	gitBin := r.Git
	if gitBin == "" {
		gitBin, err = exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("git is not installed or not on PATH")
		}
	}
	self := r.Self
	if self == "" {
		self, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("find ssha binary: %w", err)
		}
	}

	args := []string{"-C", req.Dir, "-c", "credential.helper=", "-c", "credential.useHttpPath=true"}
	gitArgs := append([]string(nil), req.Args...)
	rewritten := remote.Rewritten(account.Auth.Type, account.Auth.Username)
	switch {
	case replaceRemoteArg(gitArgs, rawURL):
		gitArgs = replaceRemoteArgValue(gitArgs, rawURL, rewritten)
	case op == config.GitClone:
		// clone has no repository remote to rewrite. The URL has to be an argument.
		gitArgs = append(gitArgs, rewritten)
	default:
		if remote.SameTransport(*account) && rewritten == remote.Raw {
			break
		}
		if strings.ContainsAny(rewritten, "=\n") || strings.ContainsAny(rawURL, "=\n") {
			return nil, fmt.Errorf("git remote contains a character ssha will not pass to git config")
		}
		args = append(args, "-c", "url."+rewritten+".insteadof="+rawURL)
	}
	if account.Auth.Type == "https" {
		args = append(args, "-c", "credential.helper=!"+shellQuote(self)+" git-credential")
	}
	args = append(args, op)
	args = append(args, gitArgs...)

	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Dir = req.Dir
	cmd.Env, err = commandEnv(dir, token, account.Auth.Type, self, account.Auth.PasswordEnv, account.Auth.PassphraseEnv, account.Auth.KeyEnv)
	if err != nil {
		return nil, err
	}
	if account.Auth.Type == "ssh" && secret != "" {
		askpass, err := writeAskpass(dir, self)
		if err != nil {
			return nil, err
		}
		cmd.Env = append(cmd.Env, "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force")
		if os.Getenv("DISPLAY") == "" {
			cmd.Env = append(cmd.Env, "DISPLAY=:0")
		}
	}

	var stdout, stderr limited
	stdout.limit = MaxOutputBytes
	stderr.limit = MaxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	runErr := cmd.Run()
	res.DurationMS = time.Since(start).Milliseconds()
	res.Stdout = redact(stdout.String(), secret)
	res.Stderr = redact(stderr.String(), secret)
	res.Truncated = stdout.truncated || stderr.truncated
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		res.ExitCode = -1
		res.Reason = redact(runErr.Error(), secret)
		return res, fmt.Errorf("git %s: %w", op, errors.New(res.Reason))
	}
	return res, nil
}

func (r *Runner) defaultLookup(dir, name string) (string, error) {
	gitBin := r.Git
	var err error
	if gitBin == "" {
		gitBin, err = exec.LookPath("git")
		if err != nil {
			return "", fmt.Errorf("git is not installed or not on PATH")
		}
	}
	cmd := exec.Command(gitBin, "-C", dir, "remote", "get-url", name)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git remote get-url %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Runner) materialize(account *config.GitAccount, prompt PromptFunc) (secret, keyPath string, cleanup func(), err error) {
	nop := func() {}
	switch account.Auth.Type {
	case "https":
		secret, err = resolveSecret(account.Name, account.Auth.PasswordEnv, account.Auth.PasswordFile, "password", prompt)
		return secret, "", nop, err
	case "ssh":
		keyPath = account.Auth.KeyPath
		if account.Auth.KeyEnv != "" {
			pem := os.Getenv(account.Auth.KeyEnv)
			if pem == "" {
				return "", "", nop, fmt.Errorf("git account %s: environment variable %s is empty", account.Name, account.Auth.KeyEnv)
			}
			f, err := os.CreateTemp("", "ssha-git-key-")
			if err != nil {
				return "", "", nop, err
			}
			keyPath = f.Name()
			cleanup = func() { _ = os.Remove(keyPath) }
			if err := f.Chmod(0o600); err != nil {
				_ = f.Close()
				cleanup()
				return "", "", nop, err
			}
			if _, err := f.WriteString(pem); err != nil {
				_ = f.Close()
				cleanup()
				return "", "", nop, err
			}
			if err := f.Close(); err != nil {
				cleanup()
				return "", "", nop, err
			}
		}
		if cleanup == nil {
			cleanup = nop
		}
		if keyPath == "" {
			return "", "", cleanup, fmt.Errorf("git account %s: no key", account.Name)
		}
		switch {
		case account.Auth.PassphraseEnv != "" || account.Auth.PassphraseFile != "":
			secret, err = resolveSecret(account.Name, account.Auth.PassphraseEnv, account.Auth.PassphraseFile, "passphrase", prompt)
			if err != nil {
				return "", "", cleanup, err
			}
		case prompt != nil && keyLooksEncrypted(keyPath):
			secret, err = prompt(account.Name, "passphrase")
			if err != nil {
				return "", "", cleanup, err
			}
		}
		return secret, keyPath, cleanup, nil
	default:
		return "", "", nop, fmt.Errorf("git account %s: unknown auth %q", account.Name, account.Auth.Type)
	}
}

func keyLooksEncrypted(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return keyBytesEncrypted(b)
}

// keyBytesEncrypted recognises both the old PEM marker and the current
// OpenSSH format, whose encrypted keys do not contain the word ENCRYPTED.
func keyBytesEncrypted(b []byte) bool {
	if strings.Contains(string(b), "ENCRYPTED") {
		return true
	}
	raw := b
	if strings.Contains(string(b), "OPENSSH PRIVATE KEY") {
		var body strings.Builder
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "-----") {
				continue
			}
			body.WriteString(line)
		}
		decoded, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			return false
		}
		raw = decoded
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return false
	}
	cipher, _, ok := readSSHString(raw[len(magic):])
	if !ok {
		return false
	}
	return string(cipher) != "none"
}

func readSSHString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n < 0 || len(b) < 4+n {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func resolveSecret(account, envVar, file, what string, prompt PromptFunc) (string, error) {
	if envVar != "" {
		v := os.Getenv(envVar)
		if v == "" {
			return "", fmt.Errorf("git account %s: environment variable %s is empty", account, envVar)
		}
		return v, nil
	}
	if file != "" {
		v, err := config.ReadSecretFile(file)
		if err != nil {
			return "", fmt.Errorf("git account %s: read %s: %w", account, what, err)
		}
		if v == "" {
			return "", fmt.Errorf("git account %s: %s is empty", account, what)
		}
		return v, nil
	}
	if prompt != nil {
		return prompt(account, what)
	}
	return "", fmt.Errorf("git account %s: no %s source configured; set it in ssha ui or the config", account, what)
}

func commandEnv(dir, token, auth, self string, dropAlso ...string) ([]string, error) {
	drop := map[string]bool{
		"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_ASKPASS": true,
		"SSH_ASKPASS": true, "SSH_ASKPASS_REQUIRE": true,
		"GIT_TRACE": true, "GIT_TRACE_PACKET": true, "GIT_TRACE_PERFORMANCE": true,
		"GIT_TRACE_SETUP": true, "GIT_TRACE_CURL": true, "GIT_CURL_VERBOSE": true,
		"GIT_CONFIG_PARAMETERS": true, "GIT_CONFIG_COUNT": true,
		grantEnv: true, tokenEnv: true,
	}
	for _, key := range dropAlso {
		if key != "" {
			drop[key] = true
		}
	}
	var env []string
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if drop[key] || strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") {
			continue
		}
		env = append(env, e)
	}
	env = append(env,
		grantEnv+"="+dir,
		tokenEnv+"="+token,
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
	)
	if auth == "ssh" {
		env = append(env, "GIT_SSH_COMMAND="+shellQuote(self)+" git-ssh")
	}
	return env, nil
}

func denied(account, op, command, rawURL, reason string) *Result {
	return &Result{
		Account:  account,
		Op:       op,
		Command:  command,
		URL:      rawURL,
		Decision: "denied",
		Reason:   reason,
		ExitCode: -1,
	}
}

func knownOp(op string) bool {
	switch op {
	case config.GitFetch, config.GitPull, config.GitPush, config.GitClone, config.GitLsRemote:
		return true
	default:
		return false
	}
}

func rejectUnsafeArgs(args []string) error {
	for _, a := range args {
		if strings.ContainsAny(a, "\n\r") {
			return fmt.Errorf("git argument contains a newline")
		}
		switch {
		case a == "-c" || a == "--config" || strings.HasPrefix(a, "--config="):
			return fmt.Errorf("git config overrides are not allowed through ssha")
		case a == "--exec-path" || strings.HasPrefix(a, "--exec-path="):
			return fmt.Errorf("git --exec-path is not allowed through ssha")
		case a == "--all" || a == "--mirror":
			return fmt.Errorf("ssha git authenticates one remote; do not pass %s", a)
		}
	}
	return nil
}

func forcePush(args []string) bool {
	for _, a := range args {
		switch {
		case a == "-f" || a == "--force" || a == "--force-with-lease" || a == "--force-if-includes":
			return true
		case strings.HasPrefix(a, "--force"):
			return true
		case strings.HasPrefix(a, "+") && !strings.HasPrefix(a, "++"):
			return true
		}
	}
	return false
}

func commandLine(op string, args []string) string {
	if len(args) == 0 {
		return op
	}
	return op + " " + strings.Join(args, " ")
}

func remoteInArgs(args []string) string {
	for _, a := range args {
		if looksLikeRemote(a) {
			return a
		}
	}
	return ""
}

func looksLikeRemote(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "refs/") || strings.HasPrefix(s, "HEAD") {
		return false
	}
	if strings.Contains(s, "://") {
		return true
	}
	if strings.Contains(s, "@") && strings.Contains(s, ":") {
		return true
	}
	i := strings.Index(s, ":")
	if i > 0 && strings.Contains(s[:i], ".") && strings.Contains(s[i+1:], "/") && !strings.ContainsAny(s, " ") {
		return true
	}
	return false
}

func replaceRemoteArg(args []string, raw string) bool {
	for _, a := range args {
		if a == raw {
			return true
		}
	}
	return false
}

func replaceRemoteArgValue(args []string, raw, rewritten string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == raw {
			out[i] = rewritten
		}
	}
	return out
}

func redact(s, secret string) string {
	if secret == "" || s == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<redacted>")
}

type limited struct {
	buf       bytes.Buffer
	n         int
	limit     int
	truncated bool
}

func (l *limited) Write(p []byte) (int, error) {
	if l.limit <= 0 {
		l.limit = MaxOutputBytes
	}
	remain := l.limit - l.n
	if remain > 0 {
		take := p
		if len(take) > remain {
			take = take[:remain]
			l.truncated = true
		}
		_, _ = l.buf.Write(take)
		l.n += len(take)
	} else {
		l.truncated = true
	}
	return len(p), nil
}

func (l *limited) String() string { return l.buf.String() }

// Keep io imported for the limited writer documentation; Write implements it.
var _ io.Writer = (*limited)(nil)
