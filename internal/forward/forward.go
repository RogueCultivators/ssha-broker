// Package forward implements a loopback-only TCP forwarder: one listener, one
// destination, as many short-lived connections as the caller allows.
//
// In the local direction the listener is on this machine and the destination
// is dialled over SSH. In the remote direction the listener belongs to the SSH
// server and the destination is dialled here, so a remote host can reach a
// service that only this machine can see. Neither direction ever binds a
// public interface: the operator, not a remote party, decides what may
// connect, and a public listener would turn a policy-checked tunnel into an
// open proxy.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for a tunnel.
const (
	DefaultMaxConns    = 32
	DefaultDialTimeout = 15 * time.Second
)

// Dialer opens the far side of a forwarded connection. The broker implements
// it over an SSH direct-tcpip channel.
type Dialer interface {
	DialContext(ctx context.Context, addr string) (net.Conn, error)
}

// Options configures a tunnel.
type Options struct {
	// Listen is a loopback host:port. Port 0 picks a free port.
	Listen string
	// Destination is the host:port dialled on the far side.
	Destination string
	Dialer      Dialer
	// MaxConns caps simultaneous forwarded connections. Zero means the
	// default.
	MaxConns int
	// DialTimeout caps one DialContext call. Zero means the default.
	DialTimeout time.Duration
	// OnConnection, when set, is called once per accepted connection after it
	// ends. It runs on the connection's goroutine.
	OnConnection func(Event)
}

// Event describes one forwarded connection.
type Event struct {
	Peer        string
	Destination string
	BytesUp     int64
	BytesDown   int64
	Duration    time.Duration
	Err         error
}

// Stats are the tunnel's lifetime totals.
type Stats struct {
	Conns     int64
	BytesUp   int64
	BytesDown int64
}

// Tunnel is a running loopback listener.
type Tunnel struct {
	opts Options
	ln   net.Listener
	sem  chan struct{}

	mu     sync.Mutex
	live   map[*connPair]struct{}
	closed bool
	wg     sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	conns     atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
}

type connPair struct {
	local  net.Conn
	remote net.Conn
}

// Listen starts a loopback listener. Nothing is accepted until Serve runs.
func Listen(opts Options) (*Tunnel, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	if err := ValidateListen(opts.Listen); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("forward: listen %s: %w", opts.Listen, err)
	}
	// ValidateListen trusts the name localhost; verify what the kernel actually
	// bound, so a hosts file that points localhost elsewhere cannot turn this
	// into a public listener.
	if host, _, err := net.SplitHostPort(ln.Addr().String()); err != nil || !isLoopbackHost(host) {
		_ = ln.Close()
		return nil, fmt.Errorf("forward: listen %s bound non-loopback address %s", opts.Listen, ln.Addr())
	}
	t, err := Wrap(ln, opts)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return t, nil
}

// Wrap turns a listener that is already open into a tunnel. It is used for a
// remote forward, where the listener belongs to the SSH server rather than to
// this process; the caller validates the bind address.
func Wrap(ln net.Listener, opts Options) (*Tunnel, error) {
	if ln == nil {
		return nil, errors.New("forward: no listener")
	}
	if opts.Dialer == nil {
		return nil, errors.New("forward: no dialer")
	}
	if opts.Destination == "" {
		return nil, errors.New("forward: no destination")
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = DefaultMaxConns
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	return &Tunnel{
		opts: opts,
		ln:   ln,
		sem:  make(chan struct{}, opts.MaxConns),
		live: make(map[*connPair]struct{}),
	}, nil
}

// Addr is the listener's actual address, with the chosen port filled in.
func (t *Tunnel) Addr() string { return t.ln.Addr().String() }

// Stats returns lifetime totals.
func (t *Tunnel) Stats() Stats {
	return Stats{
		Conns:     t.conns.Load(),
		BytesUp:   t.bytesUp.Load(),
		BytesDown: t.bytesDown.Load(),
	}
}

// Serve accepts connections until ctx is cancelled or Close is called.
// Cancelling ctx also closes connections that are already running.
func (t *Tunnel) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stop := context.AfterFunc(ctx, func() { _ = t.Close() })
	defer stop()

	for {
		c, err := t.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || t.isClosed() {
				// A remote listener reports a close as io.EOF from the SSH
				// library's forward list, so the closed flag is the reliable
				// signal here rather than the error value.
				return nil
			}
			// A transient accept failure (fd exhaustion, for example) should not
			// end a long-lived tunnel.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case t.sem <- struct{}{}:
		case <-ctx.Done():
			_ = c.Close()
			return nil
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() { <-t.sem }()
			t.handle(ctx, c)
		}()
	}
}

// Close stops the listener and closes every open connection. It is safe to
// call more than once and concurrently with Serve.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()

		t.closeErr = t.ln.Close()

		t.mu.Lock()
		for p := range t.live {
			_ = p.local.Close()
			_ = p.remote.Close()
		}
		t.mu.Unlock()

		t.wg.Wait()

		t.mu.Lock()
		t.live = make(map[*connPair]struct{})
		t.mu.Unlock()
	})
	return t.closeErr
}

func (t *Tunnel) handle(ctx context.Context, local net.Conn) {
	start := time.Now()
	peer := addrString(local.RemoteAddr())
	ev := Event{Peer: peer, Destination: t.opts.Destination}

	remote, err := t.dial(ctx)
	if err != nil {
		_ = local.Close()
		ev.Duration = time.Since(start)
		ev.Err = err
		t.emit(ev)
		return
	}

	p := &connPair{local: local, remote: remote}
	if !t.track(p) {
		_ = local.Close()
		_ = remote.Close()
		ev.Duration = time.Since(start)
		ev.Err = errors.New("tunnel closed")
		t.emit(ev)
		return
	}
	defer t.untrack(p)
	defer local.Close()
	defer remote.Close()

	var up, down atomic.Int64
	done := make(chan struct{}, 2)
	go func() {
		up.Store(copyAndHalfClose(remote, local))
		done <- struct{}{}
	}()
	go func() {
		down.Store(copyAndHalfClose(local, remote))
		done <- struct{}{}
	}()
	<-done
	<-done

	ev.BytesUp = up.Load()
	ev.BytesDown = down.Load()
	ev.Duration = time.Since(start)
	t.conns.Add(1)
	t.bytesUp.Add(ev.BytesUp)
	t.bytesDown.Add(ev.BytesDown)
	t.emit(ev)
}

func (t *Tunnel) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.opts.DialTimeout)
	defer cancel()
	conn, err := t.opts.Dialer.DialContext(ctx, t.opts.Destination)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", t.opts.Destination, err)
	}
	return conn, nil
}

func (t *Tunnel) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *Tunnel) track(p *connPair) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.live[p] = struct{}{}
	return true
}

func (t *Tunnel) untrack(p *connPair) {
	t.mu.Lock()
	delete(t.live, p)
	t.mu.Unlock()
}

func (t *Tunnel) emit(ev Event) {
	if t.opts.OnConnection != nil {
		t.opts.OnConnection(ev)
	}
}

// copyAndHalfClose copies src to dst and then signals EOF in that direction.
// Half-closing rather than closing lets the other direction finish normally:
// a client that sends a request and shuts down its write side still gets the
// response.
func copyAndHalfClose(dst, src net.Conn) int64 {
	n, _ := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
	return n
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// ValidateListen accepts only a loopback host:port. An empty host means all
// interfaces, which is exactly what this must never do.
func ValidateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: expected host:port (bracket IPv6 addresses): %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("listen address %q: the host is empty, which would listen on every interface; use 127.0.0.1", addr)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("listen address %q: only loopback addresses (127.0.0.1, ::1, localhost) are allowed", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("listen address %q: port must be 0-65535", addr)
	}
	return nil
}

// ValidateRemoteListen is ValidateListen for a listener that will be opened by
// the SSH server. It requires a numeric loopback IP: the SSH library reports a
// hostname bind as 0.0.0.0, which would both hide the real bind and make later
// checks meaningless.
func ValidateRemoteListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("remote listen address %q: expected host:port (bracket IPv6 addresses): %w", addr, err)
	}
	ip := net.ParseIP(strings.TrimSuffix(strings.ToLower(host), "."))
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("remote listen address %q: use a numeric loopback IP (127.0.0.1 or ::1)", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("remote listen address %q: port must be 0-65535", addr)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" {
		return true
	}
	if i := strings.LastIndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// NormalizeDestination validates a forwarding destination and returns its
// canonical form: lower-case host and a decimal port. The policy matches and
// the audit log records this form, so `LOCALHOST:05432` cannot look different
// from `localhost:5432`.
func NormalizeDestination(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("destination %q: expected host:port (bracket IPv6 addresses): %w", addr, err)
	}
	if host == "" {
		return "", fmt.Errorf("destination %q: the host is empty", addr)
	}
	if strings.ContainsAny(host, " \t\r\n/@[]*?") {
		return "", fmt.Errorf("destination %q: host contains a character that is not allowed", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("destination %q: port must be 1-65535", addr)
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n)), nil
}
