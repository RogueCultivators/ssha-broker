package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"ssha/internal/config"
)

// scanServer is a throwaway SSH server that records the username each client
// offers. It is enough to prove which account a scan authenticates as.
type scanServer struct {
	addr  string
	users []string
	mu    sync.Mutex
}

func (s *scanServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.users...)
}

func (s *scanServer) add(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = append(s.users, user)
}

func startScanServer(t *testing.T) *scanServer {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := &scanServer{}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			srv.add(conn.User())
			return nil, errors.New("rejected by the test server")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv.addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.UnknownChannelType, "")
				}
			}()
		}
	}()
	return srv
}

func writeKeyEnv(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	const name = "SSHA_TEST_SCAN_KEY"
	t.Setenv(name, string(pem.EncodeToMemory(block)))
	return name
}

func TestScanHostKeysUsesTheConfiguredUser(t *testing.T) {
	srv := startScanServer(t)
	target := Target{
		Addr: srv.addr,
		User: "deploy",
		Auth: config.Auth{Type: "key", KeyEnv: writeKeyEnv(t)},
	}

	keys, err := ScanHostKeys(context.Background(), target, 5*time.Second)
	if err != nil {
		t.Fatalf("ScanHostKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no host keys returned")
	}

	users := srv.recorded()
	if len(users) == 0 {
		t.Fatal("the server never saw a username")
	}
	for _, u := range users {
		if strings.Contains(u, "ssha-host-key-scan") {
			t.Fatalf("scan still authenticates as the invented username %q", u)
		}
		if u != "deploy" {
			t.Fatalf("scan authenticated as %q, want the configured user deploy", u)
		}
	}
}

func TestScanHostKeysOffersNoUsernameWithoutOne(t *testing.T) {
	srv := startScanServer(t)
	target := Target{
		Addr: srv.addr,
		Auth: config.Auth{Type: "key", KeyEnv: writeKeyEnv(t)},
	}

	// The host key is still found; only the username is withheld.
	if _, err := ScanHostKeys(context.Background(), target, 5*time.Second); err != nil {
		t.Fatalf("ScanHostKeys: %v", err)
	}
	if users := srv.recorded(); len(users) != 0 {
		t.Fatalf("with no configured user the scan offered %q", users)
	}
}
