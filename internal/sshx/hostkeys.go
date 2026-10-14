package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyAlgorithms are probed in turn: one handshake only yields the single
// algorithm the client and server agree on, so getting every key the server
// offers takes several attempts.
var hostKeyAlgorithms = []string{
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"rsa-sha2-512",
	"rsa-sha2-256",
	"ssh-rsa",
}

// errHostKeyCaptured ends a scan handshake as soon as the host key is in hand.
// It is used when there is no account to scan as, so the client never offers a
// username: sshd records an unknown name as "Invalid user".
var errHostKeyCaptured = errors.New("host key captured")

// ScanHostKeys connects to t.Addr and returns every distinct host key the
// server offers. It never authenticates on its own account: the key is
// presented during the key exchange that precedes authentication, so a wrong
// credential still yields the key.
//
// It scans as the account in t, not as an invented name. sshd records an
// unknown name as "Invalid user" and an unrecognized login as a failure;
// fail2ban counts both, and a handful of scans is enough to ban the operator's
// address. Scanning with the configured account and its public key keeps the
// log to a normal "Accepted publickey". When t has no user, the connection is
// closed before a username is offered.
func ScanHostKeys(ctx context.Context, t Target, timeout time.Duration) ([]ssh.PublicKey, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	methods, closeAgent := scanAuthMethods(t)
	defer closeAgent()

	var (
		out     []ssh.PublicKey
		seen    = map[string]bool{}
		lastErr error
	)
	for _, alg := range hostKeyAlgorithms {
		key, err := scanOneHostKey(ctx, t, methods, alg, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		fp := ssh.FingerprintSHA256(key)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, key)
	}
	if len(out) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("%s offered no usable host key", t.Addr)
		}
		return nil, lastErr
	}
	return out, nil
}

func scanOneHostKey(ctx context.Context, t Target, methods []ssh.AuthMethod, alg string, timeout time.Duration) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              methods,
		HostKeyAlgorithms: []string{alg},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			if t.User == "" {
				// There is no account to scan as. Stop before the client
				// offers a name, so the server never sees an invalid user.
				return errHostKeyCaptured
			}
			return nil
		},
		Timeout: timeout,
	}

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Authentication is not needed: the key was captured during the key
	// exchange above. A failure here is expected when no credential is set,
	// and is ignored.
	if c, _, _, err := ssh.NewClientConn(conn, t.Addr, cfg); c != nil {
		_ = c.Close()
	} else if err == nil {
		return nil, errors.New("ssh: handshake produced no client and no error")
	}
	if captured == nil {
		return nil, fmt.Errorf("%s did not offer a %s host key", t.Addr, alg)
	}
	return captured, nil
}

// scanAuthMethods offers only public-key methods, and never a password. A wrong
// password is logged as "Failed password", which fail2ban counts, and the scan
// does not need to authenticate to read the host key. The prompt is dropped so
// a scan never stops to ask for a passphrase.
func scanAuthMethods(t Target) ([]ssh.AuthMethod, func()) {
	t.Prompt = nil
	switch t.Auth.Type {
	case "", "key":
		signer, err := keySigner(t)
		if err != nil {
			return nil, func() {}
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, func() {}
	case "agent":
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, func() {}
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, func() {}
		}
		ac := agent.NewClient(conn)
		return []ssh.AuthMethod{ssh.PublicKeysCallback(ac.Signers)}, func() { _ = conn.Close() }
	default:
		return nil, func() {}
	}
}

// KnownHostsLine renders a host key the way ssh-keyscan would, with the port
// bracketed when it is not 22.
func KnownHostsLine(addr string, key ssh.PublicKey) string {
	return knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
}
