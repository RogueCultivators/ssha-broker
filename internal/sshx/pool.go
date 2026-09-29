package sshx

import (
	"context"
	"sync"
	"time"
)

// Pool caches one SSH connection per host so that an agent issuing many
// commands does not pay the handshake cost each time. Connections idle beyond
// idleTTL are closed lazily on the next access.
type Pool struct {
	mu      sync.Mutex
	entries map[string]*entry
	idleTTL time.Duration
}

type entry struct {
	client   *Client
	lastUsed time.Time
}

// NewPool creates a pool. A non-positive idleTTL disables reuse.
func NewPool(idleTTL time.Duration) *Pool {
	if idleTTL <= 0 {
		idleTTL = 5 * time.Minute
	}
	return &Pool{entries: make(map[string]*entry), idleTTL: idleTTL}
}

// Get returns a cached or freshly dialed client for t.
func (p *Pool) Get(ctx context.Context, t Target) (*Client, error) {
	p.mu.Lock()
	p.sweepLocked()
	if e, ok := p.entries[t.Name]; ok {
		e.lastUsed = time.Now()
		c := e.client
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()

	c, err := Dial(ctx, t)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[t.Name]; ok {
		e.lastUsed = time.Now()
		existing := e.client
		go c.Close()
		return existing, nil
	}
	p.entries[t.Name] = &entry{client: c, lastUsed: time.Now()}
	return c, nil
}

// Invalidate drops and closes the cached connection for a host.
func (p *Pool) Invalidate(name string) {
	p.mu.Lock()
	e, ok := p.entries[name]
	if ok {
		delete(p.entries, name)
	}
	p.mu.Unlock()
	if ok {
		_ = e.client.Close()
	}
}

func (p *Pool) sweepLocked() {
	cutoff := time.Now().Add(-p.idleTTL)
	for name, e := range p.entries {
		if e.lastUsed.Before(cutoff) {
			delete(p.entries, name)
			go e.client.Close()
		}
	}
}

// Close closes every pooled connection.
func (p *Pool) Close() error {
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*entry)
	p.mu.Unlock()
	for _, e := range entries {
		_ = e.client.Close()
	}
	return nil
}
