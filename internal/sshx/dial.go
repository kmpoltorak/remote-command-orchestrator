// Package sshx implements the SSH transport: dialing (direct and through
// bastions), host key verification and command execution. It never shells out
// to an ssh binary.
package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// HostKeys verifies host keys against a known_hosts file, reloading it when it
// changes. Verification cannot be disabled except through Insecure.
//
// With AcceptNew, keys of hosts that have no entry yet are appended to the
// file (trust on first use, like OpenSSH's StrictHostKeyChecking=accept-new).
// A host whose key changed is still rejected.
type HostKeys struct {
	Path      string
	Insecure  bool
	AcceptNew bool
	Logger    *slog.Logger

	mu      sync.Mutex
	modTime time.Time
	cb      ssh.HostKeyCallback
}

// Callback returns the strict known_hosts check, without accepting anything new.
func (h *HostKeys) Callback() (ssh.HostKeyCallback, error) {
	if h.Insecure {
		return func(host string, _ net.Addr, _ ssh.PublicKey) error {
			h.Logger.Warn("INSECURE: host key verification skipped", "host", host)
			return nil
		}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.load()
}

// load (re)reads known_hosts when it changed. Callers hold h.mu.
func (h *HostKeys) load() (ssh.HostKeyCallback, error) {
	st, err := os.Stat(h.Path)
	if errors.Is(err, os.ErrNotExist) && h.AcceptNew {
		if err := os.MkdirAll(filepath.Dir(h.Path), 0o700); err != nil {
			return nil, domain.Fail(domain.CatHostKeyUnknown, "cannot create %s: %v", filepath.Dir(h.Path), err)
		}
		if err := os.WriteFile(h.Path, nil, 0o600); err != nil {
			return nil, domain.Fail(domain.CatHostKeyUnknown, "cannot create known_hosts %s: %v", h.Path, err)
		}
		st, err = os.Stat(h.Path)
	}
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

// verifier wraps the strict check: with AcceptNew, an unknown host is added.
func (h *HostKeys) verifier(strict ssh.HostKeyCallback) ssh.HostKeyCallback {
	if !h.AcceptNew || h.Insecure {
		return strict
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := strict(host, remote, key)
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) || len(ke.Want) > 0 {
			return err // accepted, a real mismatch, or another error
		}
		return h.add(host, remote, key)
	}
}

// add appends key for host, unless a concurrent connection already did.
func (h *HostKeys) add(host string, remote net.Addr, key ssh.PublicKey) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cb = nil // force a fresh read under the lock
	cb, err := h.load()
	if err != nil {
		return err
	}
	var ke *knownhosts.KeyError
	if err := cb(host, remote, key); err == nil || !errors.As(err, &ke) || len(ke.Want) > 0 {
		return err // added meanwhile, or now conflicting
	}
	f, err := os.OpenFile(h.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return domain.Fail(domain.CatHostKeyUnknown, "cannot update known_hosts %s: %v", h.Path, err)
	}
	_, werr := fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(host)}, key))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return domain.Fail(domain.CatHostKeyUnknown, "cannot update known_hosts %s: %v", h.Path, werr)
	}
	h.cb = nil
	h.Logger.Warn("new host key added to known_hosts", "host", host, "type", key.Type(), "fingerprint", ssh.FingerprintSHA256(key), "file", h.Path)
	return nil
}

// Dialer opens SSH connections with explicit timeouts.
type Dialer struct {
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	HostKeys         *HostKeys
	// Bastions, when set, shares one connection per bastion across hosts.
	// Without it every host opens its own bastion connection.
	Bastions *BastionPool
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
	bastion *ssh.Client // owned bastion connection; nil when shared via a BastionPool
}

// Close closes the target connection and an owned bastion connection.
func (c *Client) Close() error {
	err := c.Client.Close()
	if c.bastion != nil {
		_ = c.bastion.Close()
	}
	return err
}

// Dial connects to target, optionally through bastion.
func (d *Dialer) Dial(ctx context.Context, target Hop, bastion *Hop) (*Client, error) {
	var bc, owned *ssh.Client
	var conn net.Conn
	var err error
	if bastion != nil {
		key := bastion.User + "@" + bastion.Addr
		if d.Bastions != nil {
			bc, err = d.Bastions.get(ctx, key, func(ctx context.Context) (*ssh.Client, error) { return d.dialHop(ctx, *bastion) })
		} else {
			bc, err = d.dialHop(ctx, *bastion)
			owned = bc
		}
		if err != nil {
			return nil, prefix(err, "bastion")
		}
		dctx, cancel := context.WithTimeout(ctx, d.ConnectTimeout)
		conn, err = bc.DialContext(dctx, "tcp", target.Addr)
		cancel()
		if err != nil {
			if owned != nil {
				_ = owned.Close()
			} else {
				d.Bastions.broken(key, bc, err)
			}
			return nil, ClassifyDial(err, target.Addr)
		}
	} else if conn, err = d.dialTCP(ctx, target.Addr); err != nil {
		return nil, err
	}
	c, err := d.handshake(ctx, conn, target)
	if err != nil {
		if owned != nil {
			_ = owned.Close()
		}
		return nil, err
	}
	return &Client{Client: c, bastion: owned}, nil
}

// dialHop opens a full SSH connection to one endpoint.
func (d *Dialer) dialHop(ctx context.Context, hop Hop) (*ssh.Client, error) {
	raw, err := d.dialTCP(ctx, hop.Addr)
	if err != nil {
		return nil, err
	}
	return d.handshake(ctx, raw, hop)
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
		HostKeyCallback: d.HostKeys.verifier(cb),
		Timeout:         d.HandshakeTimeout,
	}
	if !d.HostKeys.Insecure {
		// Probe with the strict check: the probe key must never be "accepted".
		cfg.HostKeyAlgorithms = knownAlgorithms(cb, hop.Addr)
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(d.HandshakeTimeout, func() { timedOut.Store(true); _ = conn.Close() })
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, hop.Addr, cfg)
	timer.Stop()
	stop()
	if err != nil {
		_ = conn.Close()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, domain.Fail(domain.CatCancelled, "cancelled during SSH handshake with %s", hop.Addr)
		}
		if ctx.Err() != nil { // a deadline, not the user: report it as a timeout
			return nil, domain.Fail(domain.CatHandshakeFailed, "SSH handshake with %s timed out", hop.Addr)
		}
		return nil, ClassifyHandshake(err, hop.Addr, timedOut.Load())
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

var probeKey = sync.OnceValue(func() ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return k
})

// knownAlgorithms returns the host key algorithms that known_hosts holds for
// addr, so the handshake negotiates a key type that can be verified. Servers
// offer several key types (ed25519, ecdsa, rsa) while known_hosts often has
// only one; without this the client may pick another type and report a false
// mismatch. OpenSSH behaves the same way. nil means "no entry": the default
// algorithms are used and verification then fails as HOST_KEY_UNKNOWN.
func knownAlgorithms(cb ssh.HostKeyCallback, addr string) []string {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero // hostname entries are matched by name
	}
	var ke *knownhosts.KeyError
	if !errors.As(cb(addr, &net.TCPAddr{IP: ip, Port: port}, probeKey()), &ke) {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	for _, k := range ke.Want {
		types := []string{k.Key.Type()}
		if types[0] == ssh.KeyAlgoRSA { // one RSA key verifies all RSA signature algorithms
			types = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, t := range types {
			if !seen[t] {
				seen[t] = true
				algos = append(algos, t)
			}
		}
	}
	return algos
}
