package sshx

import (
	"context"
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
)

// BastionPool shares one SSH connection per bastion among all hosts of a run.
// Hosts behind the bastion only open channels (direct-tcpip) on it, so the
// bastion sees a single login instead of one per host; many parallel logins
// would otherwise hit OpenSSH's MaxStartups limit.
type BastionPool struct {
	mu    sync.Mutex
	conns map[string]*pooled
}

type pooled struct {
	ready chan struct{} // closed once c/err are set
	c     *ssh.Client
	err   error
}

// get returns the shared connection for key, dialing it if needed. Callers
// that arrive while a dial is in flight wait for it and share its result, so a
// dead bastion costs one timeout, not one per host.
func (p *BastionPool) get(ctx context.Context, key string, dial func(context.Context) (*ssh.Client, error)) (*ssh.Client, error) {
	p.mu.Lock()
	if p.conns == nil {
		p.conns = map[string]*pooled{}
	}
	e, ok := p.conns[key]
	if !ok {
		e = &pooled{ready: make(chan struct{})}
		p.conns[key] = e
	}
	p.mu.Unlock()

	if !ok {
		e.c, e.err = dial(ctx)
		if e.err != nil {
			p.evict(key, e) // the next caller tries again
		} else {
			go func() { _ = e.c.Wait(); p.evict(key, e) }() // connection closed: redial next time
		}
		close(e.ready)
	}
	select {
	case <-e.ready:
		return e.c, e.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *BastionPool) evict(key string, e *pooled) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns[key] == e {
		delete(p.conns, key)
	}
}

// broken drops a connection that failed for a reason other than the target
// refusing the tunnel, and closes it.
func (p *BastionPool) broken(key string, c *ssh.Client, err error) {
	var refused *ssh.OpenChannelError
	if errors.As(err, &refused) {
		return // the bastion is fine; it could not reach this target
	}
	p.mu.Lock()
	if e, ok := p.conns[key]; ok && e.c == c {
		delete(p.conns, key)
	}
	p.mu.Unlock()
	_ = c.Close()
}

// Close closes every pooled connection. Call it when the run is over.
func (p *BastionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.conns {
		select {
		case <-e.ready:
			if e.c != nil {
				_ = e.c.Close()
			}
		default: // still dialing; its owner's context ends the dial
		}
		delete(p.conns, k)
	}
}
