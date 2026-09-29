// Package sshx wraps golang.org/x/crypto/ssh into the small set of operations
// ssha needs: run a command, upload and download files, and reuse connections.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssha/internal/config"
)

// Target is a fully resolved connection target.
type Target struct {
	Name    string
	Addr    string // host:port
	User    string
	Auth    config.Auth
	HostKey config.HostKey
	Timeout time.Duration
	// Proxy, when set, is the jump host used to reach Addr.
	Proxy *Target
}

// Client is a pooled SSH connection to one target.
type Client struct {
	Name string

	ssh *ssh.Client
	// proxy keeps the jump-host connection alive for as long as the tunnel.
	proxy *ssh.Client

	mu       sync.Mutex
	sftp     *sftp.Client
	lastUsed time.Time
}

// RunResult is the outcome of a remote command.
type RunResult struct {
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	ExitCode  int           `json:"exit_code"`
	Truncated bool          `json:"truncated"`
	Bytes     int64         `json:"bytes"`
	Duration  time.Duration `json:"duration"`
}

// Dial establishes a new connection to t.
func Dial(ctx context.Context, t Target) (*Client, error) {
	cfg, err := clientConfig(t)
	if err != nil {
		return nil, err
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}

	var (
		conn  net.Conn
		proxy *ssh.Client
	)
	if t.Proxy == nil {
		conn, err = dialer.DialContext(ctx, "tcp", t.Addr)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", t.Addr, err)
		}
	} else {
		proxy, err = dialProxy(ctx, *t.Proxy, dialer)
		if err != nil {
			return nil, err
		}
		conn, err = proxy.Dial("tcp", t.Addr)
		if err != nil {
			proxy.Close()
			return nil, fmt.Errorf("dial %s via jump host %s: %w", t.Addr, t.Proxy.Name, err)
		}
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		conn.Close()
		if proxy != nil {
			proxy.Close()
		}
		return nil, fmt.Errorf("ssh handshake with %s: %w", t.Addr, err)
	}
	return &Client{
		Name:     t.Name,
		ssh:      ssh.NewClient(sshConn, chans, reqs),
		proxy:    proxy,
		lastUsed: time.Now(),
	}, nil
}

func dialProxy(ctx context.Context, t Target, dialer *net.Dialer) (*ssh.Client, error) {
	cfg, err := clientConfig(t)
	if err != nil {
		return nil, fmt.Errorf("jump host %s: %w", t.Name, err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial jump host %s: %w", t.Addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake with jump host %s: %w", t.Addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func clientConfig(t Target) (*ssh.ClientConfig, error) {
	methods, err := authMethods(t)
	if err != nil {
		return nil, err
	}
	cb, err := hostKeyCallback(t)
	if err != nil {
		return nil, err
	}
	user := t.User
	if user == "" {
		user = os.Getenv("USER")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: cb,
		Timeout:         timeout,
	}, nil
}

func authMethods(t Target) ([]ssh.AuthMethod, error) {
	switch t.Auth.Type {
	case "", "key":
		signer, err := keySigner(t)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case "agent":
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("auth.type=agent requires SSH_AUTH_SOCK")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("connect to ssh-agent: %w", err)
		}
		ac := agent.NewClient(conn)
		return []ssh.AuthMethod{ssh.PublicKeysCallback(ac.Signers)}, nil
	case "password":
		pw := os.Getenv(t.Auth.PasswordEnv)
		if pw == "" {
			return nil, fmt.Errorf("environment variable %s is empty", t.Auth.PasswordEnv)
		}
		return []ssh.AuthMethod{ssh.Password(pw), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			})}, nil
	default:
		return nil, fmt.Errorf("unknown auth.type %q", t.Auth.Type)
	}
}

func keySigner(t Target) (ssh.Signer, error) {
	var pem []byte
	var err error
	source := ""
	switch {
	case t.Auth.KeyEnv != "":
		pem = []byte(os.Getenv(t.Auth.KeyEnv))
		source = "environment variable " + t.Auth.KeyEnv
		if len(pem) == 0 {
			return nil, fmt.Errorf("environment variable %s is empty", t.Auth.KeyEnv)
		}
	default:
		p := config.ExpandHome(t.Auth.KeyPath)
		pem, err = os.ReadFile(p)
		source = p
		if err != nil {
			return nil, fmt.Errorf("read private key %s: %w", p, err)
		}
	}

	if t.Auth.PassphraseEnv != "" {
		pass := os.Getenv(t.Auth.PassphraseEnv)
		if pass == "" {
			return nil, fmt.Errorf("environment variable %s is empty", t.Auth.PassphraseEnv)
		}
		signer, err := ssh.ParsePrivateKeyWithPassphrase(pem, []byte(pass))
		if err != nil {
			return nil, fmt.Errorf("parse private key from %s: %w", source, err)
		}
		return signer, nil
	}

	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, fmt.Errorf("private key %s is encrypted; set auth.passphrase_env", source)
		}
		return nil, fmt.Errorf("parse private key from %s: %w", source, err)
	}
	return signer, nil
}

func hostKeyCallback(t Target) (ssh.HostKeyCallback, error) {
	if t.HostKey.Insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if len(t.HostKey.Fingerprints) > 0 {
		want := make(map[string]struct{}, len(t.HostKey.Fingerprints))
		for _, fp := range t.HostKey.Fingerprints {
			want[normalizeFP(fp)] = struct{}{}
		}
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := normalizeFP(ssh.FingerprintSHA256(key))
			if _, ok := want[got]; ok {
				return nil
			}
			return fmt.Errorf("host key %s is not in the configured fingerprints", got)
		}, nil
	}

	p := t.HostKey.KnownHosts
	if p == "" {
		p = config.DefaultKnownHosts()
	}
	p = config.ExpandHome(p)
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("known_hosts file %s not found: set host_key.known_hosts, host_key.fingerprints, or host_key.insecure", p)
	}
	inner, err := knownhosts.New(p)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts %s: %w", p, err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := inner(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) {
			got := ssh.FingerprintSHA256(key)
			if len(ke.Want) == 0 {
				return fmt.Errorf("unknown host key for %s (%s %s); add it to %s or set host_key.fingerprints",
					hostname, key.Type(), got, p)
			}
			want := make([]string, 0, len(ke.Want))
			for _, w := range ke.Want {
				want = append(want, w.Key.Type()+" "+ssh.FingerprintSHA256(w.Key))
			}
			return fmt.Errorf("host key mismatch for %s: server offered %s %s, but %s has %s; verify the server or refresh %s",
				hostname, key.Type(), got, p, strings.Join(want, ", "), p)
		}
		return err
	}, nil
}

func normalizeFP(fp string) string {
	fp = strings.TrimSpace(fp)
	if !strings.HasPrefix(fp, "SHA256:") {
		return "SHA256:" + fp
	}
	return fp
}

// Close releases the connection.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.sftp != nil {
		_ = c.sftp.Close()
		c.sftp = nil
	}
	c.mu.Unlock()
	if c.ssh != nil {
		_ = c.ssh.Close()
	}
	if c.proxy != nil {
		_ = c.proxy.Close()
	}
	return nil
}

// Run executes command, optionally changing directory and exporting env vars.
//
// A non-zero remote exit status is reported through RunResult.ExitCode with a
// nil error; a non-nil error means the command could not be run at all.
func (c *Client) Run(ctx context.Context, command, cwd string, env map[string]string, timeout time.Duration, maxBytes int) (*RunResult, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	stdout := newLimitedBuffer(maxBytes)
	stderr := newLimitedBuffer(maxBytes)
	sess.Stdout = stdout
	sess.Stderr = stderr

	script := buildScript(command, cwd, env)
	start := time.Now()

	if err := sess.Start(script); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	var timer <-chan time.Time
	if timeout > 0 {
		tm := time.NewTimer(timeout)
		defer tm.Stop()
		timer = tm.C
	}

	res := &RunResult{}
	select {
	case err := <-done:
		res.ExitCode = exitCode(err)
		if err != nil && res.ExitCode < 0 {
			return nil, fmt.Errorf("run command: %w", err)
		}
	case <-ctx.Done():
		killSession(sess)
		<-done
		res.ExitCode = -1
		res.Stderr = stderr.String()
		res.Duration = time.Since(start)
		return res, ctx.Err()
	case <-timer:
		killSession(sess)
		<-done
		res.ExitCode = -1
		_, _ = io.WriteString(stderr, fmt.Sprintf("\n[ssha] command exceeded timeout %s and was killed\n", timeout))
		res.Stdout = stdout.String()
		res.Stderr = stderr.String()
		res.Bytes = stdout.Bytes() + stderr.Bytes()
		res.Truncated = stdout.Truncated() || stderr.Truncated()
		res.Duration = time.Since(start)
		return res, fmt.Errorf("command exceeded timeout %s", timeout)
	}

	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	res.Bytes = stdout.Bytes() + stderr.Bytes()
	res.Truncated = stdout.Truncated() || stderr.Truncated()
	res.Duration = time.Since(start)
	return res, nil
}

func killSession(sess *ssh.Session) {
	_ = sess.Signal(ssh.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	_ = sess.Signal(ssh.SIGKILL)
	_ = sess.Close()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus()
	}
	return -1
}

// buildScript composes the shell snippet executed on the remote host.
func buildScript(command, cwd string, env map[string]string) string {
	if cwd == "" && len(env) == 0 {
		return command
	}
	var b strings.Builder
	b.WriteString("set -e\n")
	if cwd != "" {
		b.WriteString("cd " + shellQuote(cwd) + "\n")
	}
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString("export " + k + "=" + shellQuote(env[k]) + "\n")
		}
	}
	b.WriteString("set +e\n")
	b.WriteString(command)
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (c *Client) sftpClient() (*sftp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sftp != nil {
		return c.sftp, nil
	}
	sc, err := sftp.NewClient(c.ssh)
	if err != nil {
		return nil, fmt.Errorf("start sftp subsystem: %w", err)
	}
	c.sftp = sc
	return sc, nil
}

// Upload writes content to remotePath, creating parent directories.
func (c *Client) Upload(remotePath string, content []byte, mode os.FileMode) error {
	sc, err := c.sftpClient()
	if err != nil {
		return err
	}
	if dir := path.Dir(remotePath); dir != "" && dir != "." && dir != "/" {
		if err := sc.MkdirAll(dir); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	f, err := sc.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open %s: %w", remotePath, err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", remotePath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", remotePath, err)
	}
	if mode != 0 {
		if err := sc.Chmod(remotePath, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", remotePath, err)
		}
	}
	return nil
}

// Download reads at most maxBytes from remotePath. The second return value
// reports whether the file was larger than maxBytes.
func (c *Client) Download(remotePath string, maxBytes int64) ([]byte, bool, error) {
	sc, err := c.sftpClient()
	if err != nil {
		return nil, false, err
	}
	f, err := sc.Open(remotePath)
	if err != nil {
		return nil, false, fmt.Errorf("open %s: %w", remotePath, err)
	}
	defer f.Close()

	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", remotePath, err)
	}
	if n > maxBytes {
		return buf.Bytes()[:maxBytes], true, nil
	}
	return buf.Bytes(), false, nil
}

// limitedBuffer captures up to limit bytes and counts the rest.
type limitedBuffer struct {
	buf     bytes.Buffer
	limit   int
	dropped int64
}

func newLimitedBuffer(limit int) *limitedBuffer {
	if limit <= 0 {
		limit = config.DefaultMaxOutputBytes
	}
	if limit > config.HardMaxOutputBytes {
		limit = config.HardMaxOutputBytes
	}
	return &limitedBuffer{limit: limit}
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := w.limit - w.buf.Len()
	switch {
	case remain <= 0:
		w.dropped += int64(n)
	case n > remain:
		w.buf.Write(p[:remain])
		w.dropped += int64(n - remain)
	default:
		w.buf.Write(p)
	}
	return n, nil
}

func (w *limitedBuffer) String() string { return w.buf.String() }
func (w *limitedBuffer) Bytes() int64   { return int64(w.buf.Len()) + w.dropped }
func (w *limitedBuffer) Truncated() bool {
	return w.dropped > 0
}

// IsConnError reports whether err suggests the connection is no longer usable.
func IsConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "EOF")
}
