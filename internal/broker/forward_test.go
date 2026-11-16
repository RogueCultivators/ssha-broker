package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"ssha/internal/audit"
)

const forwardConfig = `
hosts:
  - name: web
    addr: 10.0.0.10
    user: deploy
    auth: {type: key, key_path: /tmp/key}
    policy:
      mode: allow
      allow_forwards: ['10.0.0.12:5432']
`

func openForwardBroker(t *testing.T) *Broker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	if err := os.WriteFile(path, []byte(forwardConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenWithOptions(path, Options{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestOpenForwardDeniesOutOfPolicyAndAudits(t *testing.T) {
	b := openForwardBroker(t)
	res, session, err := b.OpenForward(context.Background(), ForwardRequest{
		Host:        "web",
		Destination: "10.0.0.12:6379",
	})
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want a DeniedError", err)
	}
	if session != nil {
		t.Fatal("a denied forward returned a session")
	}
	if res == nil || res.Decision != audit.DecisionDenied {
		t.Fatalf("result = %+v, want denied", res)
	}
	if !strings.Contains(res.Reason, "allow_forwards") {
		t.Errorf("reason = %q, want it to name allow_forwards", res.Reason)
	}

	records, err := b.AuditQuery(audit.Filter{Type: audit.TypeForward}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("audit has %d forward records, want 1", len(records))
	}
	r := records[0]
	if r.Decision != audit.DecisionDenied || r.Forward == nil {
		t.Fatalf("record = %+v, want a denied forward", r)
	}
	if r.Forward.Kind != audit.ForwardDeny || r.Forward.Destination != "10.0.0.12:6379" {
		t.Errorf("forward = %+v", r.Forward)
	}
	if r.ID != res.AuditID {
		t.Errorf("audit id = %q, result id = %q", r.ID, res.AuditID)
	}
}

func TestOpenForwardRejectsANonLoopbackListener(t *testing.T) {
	b := openForwardBroker(t)
	_, _, err := b.OpenForward(context.Background(), ForwardRequest{
		Host:        "web",
		Listen:      "0.0.0.0:2222",
		Destination: "10.0.0.12:5432",
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v, want a loopback refusal", err)
	}
}

// startDirectTCPIPServer is a throwaway SSH server whose direct-tcpip
// channels all lead to forward. It does not care what address the client
// asks for; that is exactly what the echo target needs.
func startDirectTCPIPServer(t *testing.T, forward string) string {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveDirectTCPIP(conn, cfg, forward)
		}
	}()
	return ln.Addr().String()
}

func serveDirectTCPIP(conn net.Conn, cfg *ssh.ServerConfig, forward string) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "direct-tcpip" {
			_ = ch.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		dest, err := net.Dial("tcp", forward)
		if err != nil {
			_ = ch.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		c, chReqs, err := ch.Accept()
		if err != nil {
			_ = dest.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		// Like a real TCP tunnel, each direction closes independently. Closing
		// the channel when the client half-closes would cut off the reply.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(dest, c)
			if cw, ok := dest.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(c, dest)
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		go func() {
			wg.Wait()
			_ = c.Close()
			_ = dest.Close()
		}()
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func writeForwardKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestForwardThroughAnSSHServerEndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	addr := startDirectTCPIPServer(t, echo)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ssha.yaml")
	body := `
hosts:
  - name: web
    addr: ` + host + `
    port: ` + port + `
    user: deploy
    auth: {type: key, key_path: ` + writeForwardKey(t) + `}
    host_key: {insecure: true}
    policy:
      mode: allow
      allow_forwards: ['` + echo + `']
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenWithOptions(path, Options{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, session, err := b.OpenForward(ctx, ForwardRequest{
		Host:        "web",
		Destination: echo,
	})
	if err != nil {
		t.Fatalf("OpenForward: %v", err)
	}
	defer session.Close()
	served := make(chan error, 1)
	go func() { served <- session.Serve(ctx) }()

	c, err := net.Dial("tcp", session.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("round trip")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read through the forward: %v", err)
	}
	_ = c.Close()
	if string(got) != "round trip" {
		t.Fatalf("read %q through the forward", got)
	}

	// Closing the session also closes the listener and records the final
	// connection and close records.
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	records, err := b.AuditQuery(audit.Filter{Type: audit.TypeForward}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := b.AuditVerify(); err != nil || n != len(records) {
		t.Fatalf("audit chain: records=%d err=%v, want %d intact records", n, err, len(records))
	}
	kinds := map[string]*audit.Record{}
	for i := range records {
		if records[i].Forward != nil {
			kinds[records[i].Forward.Kind] = &records[i]
		}
	}
	open, ok := kinds[audit.ForwardOpen]
	if !ok || open.Forward.Listen != res.Listen || open.Decision != audit.DecisionAllowed {
		t.Fatalf("open record = %+v, want allowed with listen %s", open, res.Listen)
	}
	conn, ok := kinds[audit.ForwardConnection]
	if !ok {
		t.Fatal("no connection record")
	}
	if conn.Forward.Peer == "" || conn.Forward.BytesUp < 10 || conn.Forward.BytesDown < 10 {
		t.Errorf("connection record = %+v, want peer and bytes", conn.Forward)
	}
	closed, ok := kinds[audit.ForwardClose]
	if !ok {
		t.Fatal("no close record")
	}
	if closed.Forward.BytesUp < 10 || closed.Forward.BytesDown < 10 {
		t.Errorf("close record = %+v, want the session byte totals", closed.Forward)
	}
}

func TestForwardHintExplainsAJumpedHost(t *testing.T) {
	refused := errors.New(`dial 192.168.0.110:22: ssh: rejected: administratively prohibited ("open failed")`)

	viaJump := (&ForwardSession{host: "公司nas", via: "公司主机(远程)"}).forwardHint(refused)
	for _, want := range []string{"公司nas itself", "jump host 公司主机(远程)", "ssha forward 公司主机(远程)"} {
		if !strings.Contains(viaJump, want) {
			t.Errorf("hint = %q, want it to contain %q", viaJump, want)
		}
	}

	direct := (&ForwardSession{host: "web"}).forwardHint(refused)
	if !strings.Contains(direct, "AllowTcpForwarding") {
		t.Errorf("hint = %q, want AllowTcpForwarding", direct)
	}
	if got := (&ForwardSession{host: "web"}).forwardHint(errors.New("connection refused")); got != "" {
		t.Errorf("hint for an unrelated error = %q, want empty", got)
	}
}

func TestOpenRemoteForwardDeniesOutOfPolicyAndAudits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssha.yaml")
	body := `
hosts:
  - name: web
    addr: 10.0.0.10
    user: deploy
    auth: {type: key, key_path: /tmp/key}
    policy:
      mode: allow
      allow_forwards: ['127.0.0.1:9000']
      allow_remote_forwards: ['127.0.0.1:8000']
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenWithOptions(path, Options{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// 127.0.0.1:9000 is allowed for local forwarding; the two directions have
	// separate allowlists, so this remote forward must be denied.
	res, session, err := b.OpenRemoteForward(context.Background(), RemoteForwardRequest{
		Host:        "web",
		Listen:      "127.0.0.1:0",
		Destination: "127.0.0.1:9000",
	})
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want a DeniedError", err)
	}
	if session != nil {
		t.Fatal("a denied forward returned a session")
	}
	if res == nil || res.Decision != audit.DecisionDenied || res.Direction != audit.ForwardDirectionRemote {
		t.Fatalf("result = %+v, want a denied remote forward", res)
	}
	if !strings.Contains(res.Reason, "allow_remote_forwards") {
		t.Errorf("reason = %q, want it to name allow_remote_forwards", res.Reason)
	}

	records, err := b.AuditQuery(audit.Filter{Type: audit.TypeForward}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Forward == nil {
		t.Fatalf("audit = %+v, want one forward record", records)
	}
	if records[0].Forward.Direction != audit.ForwardDirectionRemote || records[0].Forward.Kind != audit.ForwardDeny {
		t.Errorf("audit forward = %+v, want a denied remote record", records[0].Forward)
	}
}

func TestOpenRemoteForwardRequiresANumericLoopbackListener(t *testing.T) {
	b := openForwardBroker(t)
	_, _, err := b.OpenRemoteForward(context.Background(), RemoteForwardRequest{
		Host:        "web",
		Listen:      "localhost:0",
		Destination: "127.0.0.1:8000",
	})
	if err == nil || !strings.Contains(err.Error(), "numeric loopback") {
		t.Fatalf("error = %v, want a numeric-loopback refusal", err)
	}
}

// startRemoteForwardServer is a throwaway SSH server that implements
// tcpip-forward: it listens on the requested address and opens a
// forwarded-tcpip channel for each connection it accepts. That is the remote
// half of an `ssh -R` tunnel.
func startRemoteForwardServer(t *testing.T) string {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveRemoteForward(conn, cfg)
		}
	}()
	return ln.Addr().String()
}

func serveRemoteForward(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.UnknownChannelType, "the client opens no channels")
		}
	}()

	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				Addr string
				Port uint32
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			bind := net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port)))
			fln, err := net.Listen("tcp", bind)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			listeners = append(listeners, fln)
			port := uint32(fln.Addr().(*net.TCPAddr).Port)
			_ = req.Reply(true, ssh.Marshal(&struct{ Port uint32 }{port}))
			go acceptForwarded(sc, fln, payload.Addr, port)
		case "cancel-tcpip-forward":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func acceptForwarded(sc *ssh.ServerConn, ln net.Listener, addr string, port uint32) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			origin := c.RemoteAddr().(*net.TCPAddr)
			payload := struct {
				Addr       string
				Port       uint32
				OriginAddr string
				OriginPort uint32
			}{addr, port, origin.IP.String(), uint32(origin.Port)}
			ch, reqs, err := sc.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(ch, c)
				_ = ch.CloseWrite()
			}()
			go func() {
				defer wg.Done()
				_, _ = io.Copy(c, ch)
				if cw, ok := c.(*net.TCPConn); ok {
					_ = cw.CloseWrite()
				}
			}()
			wg.Wait()
			_ = ch.Close()
		}(c)
	}
}

func TestRemoteForwardThroughAnSSHServerEndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	addr := startRemoteForwardServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ssha.yaml")
	body := `
hosts:
  - name: web
    addr: ` + host + `
    port: ` + port + `
    user: deploy
    auth: {type: key, key_path: ` + writeForwardKey(t) + `}
    host_key: {insecure: true}
    policy:
      mode: allow
      allow_remote_forwards: ['` + echo + `']
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenWithOptions(path, Options{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, session, err := b.OpenRemoteForward(ctx, RemoteForwardRequest{
		Host:        "web",
		Destination: echo,
	})
	if err != nil {
		t.Fatalf("OpenRemoteForward: %v", err)
	}
	defer session.Close()
	if res.Direction != audit.ForwardDirectionRemote {
		t.Fatalf("direction = %q, want remote", res.Direction)
	}
	served := make(chan error, 1)
	go func() { served <- session.Serve(ctx) }()

	// session.Addr() is the listener on the SSH host; this fake server runs on
	// the same machine, so dialling it exercises the whole path.
	c, err := net.Dial("tcp", session.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("remote round trip")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read through the remote forward: %v", err)
	}
	_ = c.Close()
	if string(got) != "remote round trip" {
		t.Fatalf("read %q through the remote forward", got)
	}

	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	records, err := b.AuditQuery(audit.Filter{Type: audit.TypeForward}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := b.AuditVerify(); err != nil || n != len(records) {
		t.Fatalf("audit chain: records=%d err=%v, want %d intact records", n, err, len(records))
	}
	kinds := map[string]*audit.Record{}
	for i := range records {
		if records[i].Forward == nil {
			continue
		}
		if records[i].Forward.Direction != audit.ForwardDirectionRemote {
			t.Errorf("record direction = %q, want remote", records[i].Forward.Direction)
		}
		kinds[records[i].Forward.Kind] = &records[i]
	}
	if open, ok := kinds[audit.ForwardOpen]; !ok || open.Forward.Listen != session.Addr() {
		t.Fatalf("open record = %+v, want listen %s", open, session.Addr())
	}
	conn, ok := kinds[audit.ForwardConnection]
	if !ok {
		t.Fatal("no connection record")
	}
	if conn.Forward.Peer == "" || conn.Forward.BytesUp == 0 || conn.Forward.BytesDown == 0 {
		t.Errorf("connection record = %+v, want peer and bytes", conn.Forward)
	}
	closed, ok := kinds[audit.ForwardClose]
	if !ok {
		t.Fatal("no close record")
	}
	if closed.Forward.BytesUp == 0 || closed.Forward.BytesDown == 0 {
		t.Errorf("close record = %+v, want the session byte totals", closed.Forward)
	}
}

func TestOpenForwardNormalizesTheDestination(t *testing.T) {
	b := openForwardBroker(t)
	// The allow list has 10.0.0.12:5432; a padded, zero-padded spelling must
	// reach the same rule and get past policy. The connection then fails
	// because the test key does not exist, which is the expected outcome here.
	res, session, err := b.OpenForward(context.Background(), ForwardRequest{
		Host:        "web",
		Destination: " 10.0.0.12:05432 ",
	})
	if res != nil && res.Decision == audit.DecisionDenied {
		t.Fatalf("a normalized destination was denied: %s", res.Reason)
	}
	if session != nil {
		_ = session.Close()
	}
	if err == nil {
		t.Fatal("expected the dial to fail without a server")
	}
	if res == nil || res.Destination != "10.0.0.12:5432" {
		t.Fatalf("result = %+v, want the canonical destination", res)
	}
}
