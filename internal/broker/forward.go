package broker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ssha/internal/audit"
	"ssha/internal/forward"
	"ssha/internal/policy"
	"ssha/internal/sshx"
)

// DefaultForwardKeepAlive is how often an idle tunnel sends an SSH keepalive.
const DefaultForwardKeepAlive = 30 * time.Second

// ForwardRequest asks for a loopback listener on this machine whose
// connections are dialled from one SSH host.
type ForwardRequest struct {
	Host string
	// Listen is a loopback host:port. Empty means 127.0.0.1:0, a random port.
	Listen string
	// Destination is the host:port the SSH server dials. It is dialled from
	// Host itself, not from Host's proxy_jump.
	Destination string
	// OnEvent, when set, is called once per connection after it ends. It is
	// for display: the audit record is written whether or not it is set.
	OnEvent func(ForwardEvent)
}

// RemoteForwardRequest asks the SSH host to listen on its loopback and carry
// connections back to a destination on this machine.
type RemoteForwardRequest struct {
	Host string
	// Listen is a numeric loopback host:port on Host. Empty means 127.0.0.1:0.
	// A hostname is rejected because the SSH library reports it as 0.0.0.0.
	Listen string
	// Destination is the local host:port the remote listener reaches.
	Destination string
	OnEvent     func(ForwardEvent)
}

// ForwardEvent is the caller-facing view of one forwarded connection.
type ForwardEvent struct {
	Peer      string
	BytesUp   int64
	BytesDown int64
	Duration  time.Duration
	Err       error
	Hint      string
}

// ForwardResult describes an accepted or denied forward.
type ForwardResult struct {
	AuditID string `json:"audit_id,omitempty"`
	Host    string `json:"host"`
	// Direction is local or remote.
	Direction string `json:"direction"`
	// Via is the jump host used to reach Host, when there is one. It does not
	// dial the destination.
	Via         string `json:"via,omitempty"`
	Listen      string `json:"listen"`
	Destination string `json:"destination"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
}

// ForwardSession is a running forward. Call Serve to accept connections, and
// Close to stop and write the closing audit record.
type ForwardSession struct {
	broker      *Broker
	host        string
	direction   string
	listen      string
	destination string
	started     time.Time

	tunnel *forward.Tunnel
	client *sshx.Client
	via    string

	onEvent func(ForwardEvent)
	eventMu sync.Mutex

	stopKeep   chan struct{}
	once       sync.Once
	err        error
	remoteLost atomic.Bool
}

// OpenForward checks policy and opens the SSH connection and a loopback
// listener on this machine. Every outcome other than a bad address or a
// connection error is audited, including a policy denial.
func (b *Broker) OpenForward(ctx context.Context, req ForwardRequest) (*ForwardResult, *ForwardSession, error) {
	return b.openForward(ctx, req.Host, req.Listen, req.Destination, req.OnEvent, audit.ForwardDirectionLocal)
}

// OpenRemoteForward checks policy and asks Host to listen on its loopback,
// carrying the connections back to Destination on this machine.
func (b *Broker) OpenRemoteForward(ctx context.Context, req RemoteForwardRequest) (*ForwardResult, *ForwardSession, error) {
	return b.openForward(ctx, req.Host, req.Listen, req.Destination, req.OnEvent, audit.ForwardDirectionRemote)
}

func (b *Broker) openForward(ctx context.Context, host, listen, destination string, onEvent func(ForwardEvent), direction string) (*ForwardResult, *ForwardSession, error) {
	remote := direction == audit.ForwardDirectionRemote
	res := &ForwardResult{Host: host, Listen: listen, Direction: direction, Decision: audit.DecisionAllowed}
	if res.Listen == "" {
		res.Listen = "127.0.0.1:0"
	}
	if remote {
		if err := forward.ValidateRemoteListen(res.Listen); err != nil {
			return nil, nil, err
		}
	} else if err := forward.ValidateListen(res.Listen); err != nil {
		return nil, nil, err
	}
	destination, err := forward.NormalizeDestination(destination)
	if err != nil {
		return nil, nil, err
	}
	res.Destination = destination

	h, err := b.cfg.Host(host)
	if err != nil {
		return nil, nil, err
	}
	res.Via = h.ProxyJump

	compiled := b.policies.For(h.Name)
	var decision policy.Decision
	if remote {
		decision = compiled.DecideRemoteForward(destination)
	} else {
		decision = compiled.DecideForward(destination)
	}
	if !decision.Allowed {
		res.Decision = audit.DecisionDenied
		res.Reason = decision.Reason
		res.AuditID = b.record(&audit.Record{
			Type:     audit.TypeForward,
			Host:     h.Name,
			Decision: audit.DecisionDenied,
			Reason:   decision.Reason,
			Forward: &audit.ForwardInfo{
				Kind:        audit.ForwardDeny,
				Direction:   direction,
				Listen:      res.Listen,
				Destination: destination,
			},
		})
		return res, nil, &DeniedError{Host: h.Name, Command: destination, Reason: decision.Reason}
	}

	target, err := b.ResolveTarget(h)
	if err != nil {
		b.recordForwardFailure(h.Name, direction, res.Listen, destination, err)
		return res, nil, err
	}
	client, err := sshx.Dial(ctx, target)
	if err != nil && sshx.IsConnError(err) {
		// A jump host occasionally drops the first handshake (MaxStartups, a
		// flaky relay); a single retry matches what `ssha run` already does.
		client, err = sshx.Dial(ctx, target)
	}
	if err != nil {
		b.recordForwardFailure(h.Name, direction, res.Listen, destination, err)
		return res, nil, err
	}

	s := &ForwardSession{
		broker:      b,
		host:        h.Name,
		direction:   direction,
		destination: destination,
		started:     time.Now(),
		client:      client,
		via:         h.ProxyJump,
		onEvent:     onEvent,
		stopKeep:    make(chan struct{}),
	}
	var tunnel *forward.Tunnel
	if remote {
		ln, err := client.Listen(res.Listen)
		if err != nil {
			_ = client.Close()
			err = fmt.Errorf("ask %s to listen on %s: %w; its sshd must allow TCP forwarding and a loopback bind", h.Name, res.Listen, err)
			b.recordForwardFailure(h.Name, direction, res.Listen, destination, err)
			return res, nil, err
		}
		if err := forward.ValidateRemoteListen(ln.Addr().String()); err != nil {
			_ = ln.Close()
			_ = client.Close()
			b.recordForwardFailure(h.Name, direction, res.Listen, destination, err)
			return res, nil, err
		}
		tunnel, err = forward.Wrap(ln, forward.Options{
			Listen:       res.Listen,
			Destination:  destination,
			Dialer:       localDialer{},
			OnConnection: s.report,
		})
	} else {
		tunnel, err = forward.Listen(forward.Options{
			Listen:       res.Listen,
			Destination:  destination,
			Dialer:       client,
			OnConnection: s.report,
		})
	}
	if err != nil {
		_ = client.Close()
		b.recordForwardFailure(h.Name, direction, res.Listen, destination, err)
		return res, nil, err
	}
	s.tunnel = tunnel
	s.listen = tunnel.Addr()
	res.Listen = s.listen
	res.AuditID = b.record(&audit.Record{
		Type:     audit.TypeForward,
		Host:     h.Name,
		Decision: audit.DecisionAllowed,
		Forward: &audit.ForwardInfo{
			Kind:        audit.ForwardOpen,
			Direction:   direction,
			Listen:      s.listen,
			Destination: destination,
		},
	})
	go s.keepAlive()
	return res, s, nil
}

// localDialer is the far side of a remote forward: the service on this
// machine that the SSH host's listener reaches.
type localDialer struct{}

func (localDialer) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// Addr is the listener's actual address. For a remote forward it is the
// address on the SSH host.
func (s *ForwardSession) Addr() string { return s.listen }

// Serve accepts connections until ctx is cancelled or the session is closed.
func (s *ForwardSession) Serve(ctx context.Context) error {
	return s.tunnel.Serve(ctx)
}

// Close stops accepting, closes every connection and writes one closing audit
// record with the session totals. It is idempotent.
func (s *ForwardSession) Close() error {
	s.once.Do(func() {
		close(s.stopKeep)
		s.err = s.tunnel.Close()
		_ = s.client.Close()
		stats := s.tunnel.Stats()
		reason := ""
		if s.remoteLost.Load() {
			reason = "ssh connection lost"
		}
		s.broker.record(&audit.Record{
			Type:       audit.TypeForward,
			Host:       s.host,
			Decision:   audit.DecisionAllowed,
			DurationMS: time.Since(s.started).Milliseconds(),
			Reason:     reason,
			Forward: &audit.ForwardInfo{
				Kind:        audit.ForwardClose,
				Direction:   s.direction,
				Listen:      s.listen,
				Destination: s.destination,
				BytesUp:     stats.BytesUp,
				BytesDown:   stats.BytesDown,
			},
		})
	})
	return s.err
}

// RemoteLost reports whether the session ended because its SSH connection
// went away rather than because the operator stopped it.
func (s *ForwardSession) RemoteLost() bool { return s.remoteLost.Load() }

// Stats returns lifetime connection and byte totals. It is safe to call after
// Close.
func (s *ForwardSession) Stats() (conns, bytesUp, bytesDown int64) {
	st := s.tunnel.Stats()
	return st.Conns, st.BytesUp, st.BytesDown
}

func (s *ForwardSession) keepAlive() {
	t := time.NewTicker(DefaultForwardKeepAlive)
	defer t.Stop()
	for {
		select {
		case <-s.stopKeep:
			return
		case <-t.C:
			if err := s.client.KeepAlive(); err != nil {
				// The SSH connection is gone; every new connection would fail,
				// and one waiting in a copy loop is already unwinding. End the
				// session so the CLI reports it instead of listening forever.
				s.remoteLost.Store(true)
				_ = s.Close()
				return
			}
		}
	}
}

// report writes the audit record and hands the event to the caller, one
// connection at a time, so a display callback never interleaves with another.
func (s *ForwardSession) report(ev forward.Event) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	s.recordConnection(ev)
	if s.onEvent != nil {
		s.onEvent(ForwardEvent{
			Peer:      ev.Peer,
			BytesUp:   ev.BytesUp,
			BytesDown: ev.BytesDown,
			Duration:  ev.Duration,
			Err:       ev.Err,
			Hint:      s.forwardHint(ev.Err),
		})
	}
}

func (s *ForwardSession) recordConnection(ev forward.Event) {
	r := &audit.Record{
		Type:       audit.TypeForward,
		Host:       s.host,
		Decision:   audit.DecisionAllowed,
		DurationMS: ev.Duration.Milliseconds(),
		Forward: &audit.ForwardInfo{
			Kind:        audit.ForwardConnection,
			Direction:   s.direction,
			Listen:      s.listen,
			Destination: ev.Destination,
			Peer:        ev.Peer,
			BytesUp:     ev.BytesUp,
			BytesDown:   ev.BytesDown,
		},
	}
	if ev.Err != nil {
		r.ExitCode = -1
		r.Reason = ev.Err.Error()
	}
	s.broker.record(r)
}

// forwardHint turns terse failures into something actionable.
func (s *ForwardSession) forwardHint(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if s.direction == audit.ForwardDirectionRemote {
		if strings.Contains(msg, "connection refused") {
			return fmt.Sprintf("nothing is listening on the local destination %s; start the service before using the forward", s.destination)
		}
		return ""
	}
	if !strings.Contains(msg, "administratively prohibited") && !strings.Contains(msg, "open failed") {
		return ""
	}
	// The common surprise with a jumped host is that the destination is
	// dialled from the final host, not from the jump host.
	if s.via != "" {
		return fmt.Sprintf("the destination is dialled from %s itself, not from jump host %s, and its sshd refused TCP forwarding; if the service is only reachable from %s, run `ssha forward %s --to ...` and allow the target on that host",
			s.host, s.via, s.via, s.via)
	}
	return fmt.Sprintf("the destination is dialled from %s itself; its sshd refused TCP forwarding (AllowTcpForwarding or PermitOpen)", s.host)
}

func (b *Broker) recordForwardFailure(host, direction, listen, destination string, cause error) {
	b.record(&audit.Record{
		Type:     audit.TypeForward,
		Host:     host,
		Decision: audit.DecisionAllowed,
		ExitCode: -1,
		Reason:   fmt.Sprintf("forward failed: %v", cause),
		Forward: &audit.ForwardInfo{
			Kind:        audit.ForwardOpen,
			Direction:   direction,
			Listen:      listen,
			Destination: destination,
		},
	})
}
