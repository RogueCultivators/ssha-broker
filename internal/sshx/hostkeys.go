package sshx

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
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

// ScanHostKeys connects to addr and returns every distinct host key the server
// offers. It deliberately does not authenticate: the key is presented during
// key exchange, before any credentials are involved.
func ScanHostKeys(ctx context.Context, addr string, timeout time.Duration) ([]ssh.PublicKey, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var (
		out     []ssh.PublicKey
		seen    = map[string]bool{}
		lastErr error
	)
	for _, alg := range hostKeyAlgorithms {
		key, err := scanOneHostKey(ctx, addr, alg, timeout)
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
			lastErr = fmt.Errorf("%s offered no usable host key", addr)
		}
		return nil, lastErr
	}
	return out, nil
}

func scanOneHostKey(ctx context.Context, addr, alg string, timeout time.Duration) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "ssha-host-key-scan",
		Auth:              []ssh.AuthMethod{ssh.Password("")},
		HostKeyAlgorithms: []string{alg},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return nil
		},
		Timeout: timeout,
	}

	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Authentication is expected to fail; the host key is captured during the
	// key exchange that precedes it.
	_, _, _, _ = ssh.NewClientConn(conn, addr, cfg)
	if captured == nil {
		return nil, fmt.Errorf("%s did not offer a %s host key", addr, alg)
	}
	return captured, nil
}

// KnownHostsLine renders a host key the way ssh-keyscan would, with the port
// bracketed when it is not 22.
func KnownHostsLine(addr string, key ssh.PublicKey) string {
	return knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
}
