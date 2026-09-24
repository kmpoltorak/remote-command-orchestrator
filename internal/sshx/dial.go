// Package sshx implements the SSH transport: dialing (direct and through
// bastions), host key verification, interactive shell sessions with prompt
// detection, and exec-mode commands. It never shells out to an ssh binary.
package sshx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// HostKeys verifies host keys against a known_hosts file, reloading it when it
// changes. Verification cannot be disabled except through Insecure.
type HostKeys struct {
	Path     string
	Insecure bool
	Logger   *slog.Logger

	mu      sync.Mutex
	modTime time.Time
	cb      ssh.HostKeyCallback
}

// Callback returns the host key callback for one connection.
func (h *HostKeys) Callback() (ssh.HostKeyCallback, error) {
	if h.Insecure {
		return func(host string, _ net.Addr, _ ssh.PublicKey) error {
			h.Logger.Warn("INSECURE: host key verification skipped", "host", host)
			return nil
		}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := os.Stat(h.Path)
	if err != nil {
		return nil, domain.Fail(domain.CatHostKeyUnknown, "known_hosts file %s is not readable: %v", h.Path, errors.Unwrap(err))
	}
	if h.cb == nil || !st.ModTime().Equal(h.modTime) {
		cb, err := knownhosts.New(h.Path)
		if err != nil {
			return nil, domain.Fail(domain.CatHostKeyUnknown, "cannot load known_hosts %s: %v", h.Path, err)
		}
		h.cb, h.modTime = cb, st.ModTime()
	}
	return h.cb, nil
}

// Dialer opens SSH connections with explicit timeouts.
type Dialer struct {
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	HostKeys         *HostKeys
}

// Hop is one SSH endpoint with its authentication.
type Hop struct {
	Addr    string
	User    string
	Methods []ssh.AuthMethod
}

// Client is an established connection, possibly tunnelled through a bastion.
type Client struct {
	*ssh.Client
	bastion *ssh.Client
}

// Close closes the target connection and the bastion connection.
func (c *Client) Close() error {
	err := c.Client.Close()
	if c.bastion != nil {
		_ = c.bastion.Close()
	}
	return err
}

// Dial connects to target, optionally through bastion. onConnected is called
// after TCP connect, before authentication (to report AUTHENTICATING).
func (d *Dialer) Dial(ctx context.Context, target Hop, bastion *Hop, onConnected func()) (*Client, error) {
	var bc *ssh.Client
	var conn net.Conn
	var err error
	if bastion != nil {
		raw, err := d.dialTCP(ctx, bastion.Addr)
		if err != nil {
			return nil, prefix(err, "bastion")
		}
		bc, err = d.handshake(ctx, raw, *bastion)
		if err != nil {
			return nil, prefix(err, "bastion")
		}
		dctx, cancel := context.WithTimeout(ctx, d.ConnectTimeout)
		conn, err = bc.DialContext(dctx, "tcp", target.Addr)
		cancel()
		if err != nil {
			_ = bc.Close()
			return nil, ClassifyDial(err, target.Addr)
		}
	} else if conn, err = d.dialTCP(ctx, target.Addr); err != nil {
		return nil, err
	}
	if onConnected != nil {
		onConnected()
	}
	c, err := d.handshake(ctx, conn, target)
	if err != nil {
		if bc != nil {
			_ = bc.Close()
		}
		return nil, err
	}
	return &Client{Client: c, bastion: bc}, nil
}

func prefix(err error, what string) error {
	f := domain.AsFailure(err)
	return &domain.Failure{Category: f.Category, Reason: what + ": " + f.Reason}
}

func (d *Dialer) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.ConnectTimeout, KeepAlive: 30 * time.Second}
	conn, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, ClassifyDial(err, addr)
	}
	return conn, nil
}

// handshake runs the SSH handshake and authentication on conn. The timeout is
// enforced by closing the connection, which works for both TCP connections
// and bastion channels (which do not support deadlines).
func (d *Dialer) handshake(ctx context.Context, conn net.Conn, hop Hop) (*ssh.Client, error) {
	cb, err := d.HostKeys.Callback()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            hop.User,
		Auth:            hop.Methods,
		HostKeyCallback: cb,
		Timeout:         d.HandshakeTimeout,
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(d.HandshakeTimeout, func() { timedOut.Store(true); _ = conn.Close() })
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, hop.Addr, cfg)
	timer.Stop()
	stop()
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, domain.Fail(domain.CatCancelled, "cancelled during SSH handshake with %s", hop.Addr)
		}
		return nil, ClassifyHandshake(err, hop.Addr, timedOut.Load())
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// KnownHostsLine formats a known_hosts entry (used by tests and docs).
func KnownHostsLine(addr string, key ssh.PublicKey) string {
	return fmt.Sprintf("%s %s", knownhosts.Normalize(addr), ssh.MarshalAuthorizedKey(key))
}
