package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateListen(t *testing.T) {
	good := []string{
		"127.0.0.1:0",
		"127.0.0.1:8080",
		"localhost:0",
		"[::1]:0",
		"127.0.0.2:1234",
	}
	for _, addr := range good {
		if err := ValidateListen(addr); err != nil {
			t.Errorf("ValidateListen(%q): %v", addr, err)
		}
	}
	bad := map[string]string{
		"0.0.0.0:8080":     "loopback",
		":8080":            "every interface",
		"192.168.1.10:808": "loopback",
		"example.com:22":   "loopback",
		"127.0.0.1":        "host:port",
		"127.0.0.1:99999":  "0-65535",
		"127.0.0.1:http":   "0-65535",
	}
	for addr, want := range bad {
		err := ValidateListen(addr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateListen(%q) = %v, want an error containing %q", addr, err, want)
		}
	}
}

func TestNormalizeDestination(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "10.0.0.12:5432", want: "10.0.0.12:5432"},
		{in: "DB.Internal:3306", want: "db.internal:3306"},
		{in: " localhost:05432 ", want: "localhost:5432"},
		{in: "[::1]:6379", want: "[::1]:6379"},
		{in: "10.0.0.12", wantErr: true},
		{in: ":5432", wantErr: true},
		{in: "10.0.0.12:0", wantErr: true},
		{in: "10.0.0.12:70000", wantErr: true},
		{in: "10.0.0.12:redis", wantErr: true},
		{in: "*.internal:5432", wantErr: true},
		{in: "user@host:22", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NormalizeDestination(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeDestination(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDestination(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeDestination(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

type dialFunc func(ctx context.Context, addr string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	return f(ctx, addr)
}

// echoServer is the stand-in for a service behind the SSH host.
func echoServer(t *testing.T) string {
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

func TestTunnelForwardsAndReports(t *testing.T) {
	remote := echoServer(t)
	events := make(chan Event, 1)
	tun, err := Listen(Options{
		Listen:      "127.0.0.1:0",
		Destination: remote,
		Dialer: dialFunc(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}),
		OnConnection: func(ev Event) { events <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tun.Addr(), "127.0.0.1:") {
		t.Fatalf("Addr() = %q, want a loopback listener", tun.Addr())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- tun.Serve(ctx) }()

	c, err := net.Dial("tcp", tun.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = c.Close()
	if string(got) != "hello" {
		t.Fatalf("echoed %q, want %q", got, "hello")
	}

	select {
	case ev := <-events:
		if ev.Err != nil {
			t.Fatalf("event error: %v", ev.Err)
		}
		if ev.BytesUp < 5 || ev.BytesDown < 5 {
			t.Errorf("event bytes up=%d down=%d, want both >= 5", ev.BytesUp, ev.BytesDown)
		}
		if ev.Peer == "" || ev.Destination != remote {
			t.Errorf("event = %+v, want peer and destination filled", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no connection event")
	}

	if err := tun.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	stats := tun.Stats()
	if stats.Conns != 1 || stats.BytesUp < 5 || stats.BytesDown < 5 {
		t.Errorf("Stats = %+v, want one connection and bytes in both directions", stats)
	}
}

func TestTunnelReportsDialFailures(t *testing.T) {
	events := make(chan Event, 1)
	tun, err := Listen(Options{
		Listen:      "127.0.0.1:0",
		Destination: "10.0.0.12:5432",
		Dialer: dialFunc(func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}),
		OnConnection: func(ev Event) { events <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tun.Serve(ctx) }()

	c, err := net.Dial("tcp", tun.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The listener accepts and immediately closes when the far side cannot be
	// reached.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the forwarded connection to close")
	}

	select {
	case ev := <-events:
		if ev.Err == nil || !strings.Contains(ev.Err.Error(), "connection refused") {
			t.Fatalf("event error = %v, want the dial failure", ev.Err)
		}
		if ev.BytesUp != 0 || ev.BytesDown != 0 {
			t.Errorf("failed connection counted bytes: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failure event")
	}
	if stats := tun.Stats(); stats.Conns != 0 {
		t.Errorf("Stats.Conns = %d, want 0 for a failed dial", stats.Conns)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	tun, err := Listen(Options{
		Listen:      "127.0.0.1:0",
		Destination: "10.0.0.12:5432",
		Dialer: dialFunc(func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, errors.New("unused")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
