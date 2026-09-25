package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/sshtest"
)

func dialer(known string) *Dialer {
	return &Dialer{ConnectTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second,
		HostKeys: &HostKeys{Path: known, Logger: slog.Default()}}
}

func category(err error) domain.Category { return domain.AsFailure(err).Category }

func hop(s *sshtest.Server, pw string) Hop {
	return Hop{Addr: s.Addr, User: "deploy", Methods: []ssh.AuthMethod{ssh.Password(pw)}}
}

func connect(t *testing.T, s *sshtest.Server) *Client {
	t.Helper()
	c, err := dialer(sshtest.WriteKnownHosts(t, s)).Dial(context.Background(), hop(s, "pw"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func run(t *testing.T, c *Client, cmd string, stdin string) (Result, error) {
	t.Helper()
	return Exec(context.Background(), c.Client, Request{Command: cmd, Stdin: []byte(stdin), Timeout: 5 * time.Second, MaxOutput: 1 << 16})
}

func TestAuth(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", AuthorizedKey: signer.PublicKey()})
	d := dialer(sshtest.WriteKnownHosts(t, srv))
	ctx := context.Background()
	c, err := d.Dial(ctx, Hop{Addr: srv.Addr, User: "deploy", Methods: []ssh.AuthMethod{ssh.PublicKeys(signer)}}, nil)
	if err != nil {
		t.Fatalf("key auth: %v", err)
	}
	c.Close()
	c, err = d.Dial(ctx, hop(srv, "pw"), nil)
	if err != nil {
		t.Fatalf("password auth: %v", err)
	}
	c.Close()
	_, err = d.Dial(ctx, hop(srv, "wrong-password"), nil)
	if category(err) != domain.CatAuthFailed || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("want AUTH_FAILED without leak, got %v", err)
	}
}

func TestHostKeyVerification(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	other := sshtest.Start(t, sshtest.Options{Password: "pw"})
	_, port, _ := net.SplitHostPort(srv.Addr)
	mismatch := filepath.Join(t.TempDir(), "kh")
	os.WriteFile(mismatch, []byte("[127.0.0.1]:"+port+" "+string(ssh.MarshalAuthorizedKey(other.HostKey.PublicKey()))), 0o600)
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, nil, 0o600)

	cases := map[string]domain.Category{mismatch: domain.CatHostKeyMismatch, empty: domain.CatHostKeyUnknown, "/nonexistent/kh": domain.CatHostKeyUnknown}
	for path, want := range cases {
		if _, err := dialer(path).Dial(context.Background(), hop(srv, "pw"), nil); category(err) != want {
			t.Errorf("%s: want %s, got %v", path, want, err)
		}
	}
	d := dialer(empty)
	d.HostKeys.Insecure = true
	c, err := d.Dial(context.Background(), hop(srv, "pw"), nil)
	if err != nil {
		t.Fatalf("insecure mode: %v", err)
	}
	c.Close()
}

// Real servers offer several host key types while known_hosts often holds
// just one. The client must negotiate the type it knows, like OpenSSH does,
// instead of reporting a false HOST_KEY_MISMATCH.
func TestHostKeyAlgorithmFromKnownHosts(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	for name, key := range map[string]ssh.PublicKey{"ed25519": srv.HostKey.PublicKey(), "ecdsa": srv.ECDSAKey.PublicKey()} {
		kh := filepath.Join(t.TempDir(), "kh")
		os.WriteFile(kh, []byte(srv.KnownHostsLineFor(key)), 0o600)
		c, err := dialer(kh).Dial(context.Background(), hop(srv, "pw"), nil)
		if err != nil {
			t.Errorf("known_hosts with only %s key: %v", name, err)
			continue
		}
		c.Close()
	}
}

func TestAcceptNewHostKeys(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	kh := filepath.Join(t.TempDir(), "sub", "known_hosts") // missing dir and file are created
	d := dialer(kh)
	d.HostKeys.AcceptNew = true
	// Many parallel first contacts must add the host exactly once.
	errs := make(chan error, 10)
	for range 10 {
		go func() {
			c, err := d.Dial(context.Background(), hop(srv, "pw"), nil)
			if err == nil {
				c.Close()
			}
			errs <- err
		}()
	}
	for range 10 {
		if err := <-errs; err != nil {
			t.Fatalf("first contact: %v", err)
		}
	}
	data, _ := os.ReadFile(kh)
	if n := strings.Count(string(data), "\n"); n != 1 {
		t.Fatalf("want exactly one known_hosts line, got %d:\n%s", n, data)
	}
	// The recorded key is trusted by a strict client afterwards.
	c, err := dialer(kh).Dial(context.Background(), hop(srv, "pw"), nil)
	if err != nil {
		t.Fatalf("strict dial after accept-new: %v", err)
	}
	c.Close()
	// A changed key is still rejected, even with AcceptNew.
	other := sshtest.Start(t, sshtest.Options{Password: "pw"})
	_, port, _ := net.SplitHostPort(srv.Addr)
	os.WriteFile(kh, []byte("[127.0.0.1]:"+port+" "+string(ssh.MarshalAuthorizedKey(other.HostKey.PublicKey()))), 0o600)
	if _, err := d.Dial(context.Background(), hop(srv, "pw"), nil); category(err) != domain.CatHostKeyMismatch {
		t.Fatalf("changed key must fail with accept-new: %v", err)
	}
}

func TestConnectionFailures(t *testing.T) {
	d := dialer("/dev/null")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if _, err := d.Dial(context.Background(), Hop{Addr: closed}, nil); category(err) != domain.CatConnectionRefused {
		t.Fatalf("want CONNECTION_REFUSED, got %v", err)
	}

	silent, _ := net.Listen("tcp", "127.0.0.1:0") // accepts TCP, never speaks SSH
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	d.HandshakeTimeout = 300 * time.Millisecond
	start := time.Now()
	if _, err := d.Dial(context.Background(), Hop{Addr: silent.Addr().String()}, nil); category(err) != domain.CatHandshakeFailed || time.Since(start) > 2*time.Second {
		t.Fatalf("want fast SSH_HANDSHAKE_FAILED, got %v after %s", err, time.Since(start))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := d.Dial(ctx, Hop{Addr: "10.255.255.1:22"}, nil); category(err) != domain.CatConnectionTimeout {
		t.Fatalf("want CONNECTION_TIMEOUT, got %v", err)
	}
	if _, err := d.Dial(context.Background(), Hop{Addr: "no-such-host.invalid:22"}, nil); category(err) != domain.CatDNSFailure {
		t.Fatalf("want DNS_FAILURE, got %v", err)
	}
}

func TestExec(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)

	r, err := run(t, c, "echo hello; echo oops >&2", "")
	if err != nil || r.Stdout != "hello" || r.Stderr != "oops" || *r.ExitCode != 0 {
		t.Fatalf("%v %+v", err, r)
	}
	r, err = run(t, c, "exit 3", "")
	if err != nil || *r.ExitCode != 3 {
		t.Fatalf("non-zero exit is a result, not an error: %v %+v", err, r)
	}
	r, err = run(t, c, "sh -s", "X=from-stdin\necho $X\n")
	if err != nil || r.Stdout != "from-stdin" {
		t.Fatalf("script via stdin: %v %+v", err, r)
	}
	r, _ = run(t, c, "cat", "") // must see EOF, not hang
	if *r.ExitCode != 0 {
		t.Fatalf("%+v", r)
	}
	if srv.Conns.Load() != 1 || srv.Sessions.Load() != 4 {
		t.Fatalf("commands must share one connection: conns=%d sessions=%d", srv.Conns.Load(), srv.Sessions.Load())
	}
}

func TestExecTimeoutAndCancel(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)
	start := time.Now()
	_, err := Exec(context.Background(), c.Client, Request{Command: "sleep 10", Timeout: 300 * time.Millisecond, MaxOutput: 1024})
	if category(err) != domain.CatCommandTimeout || time.Since(start) > 3*time.Second {
		t.Fatalf("want COMMAND_TIMEOUT, got %v after %s", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := Exec(ctx, c.Client, Request{Command: "sleep 10", Timeout: time.Minute, MaxOutput: 1024}); category(err) != domain.CatCancelled {
		t.Fatalf("want CANCELLED, got %v", err)
	}
	// The connection is still usable after a killed command.
	if r, err := run(t, c, "echo ok", ""); err != nil || r.Stdout != "ok" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestExecOutputLimitAndPatterns(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)
	// ~500 KB of output with a marker in the middle that will be dropped.
	cmd := "i=0; while [ $i -lt 5000 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; [ $i -eq 2500 ] && echo NEEDLE; i=$((i+1)); done"
	r, err := Exec(context.Background(), c.Client, Request{Command: cmd, Timeout: 30 * time.Second, MaxOutput: 8192, Patterns: []string{"NEEDLE", "absent"}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Stdout) > 8300 || strings.Contains(r.Stdout, "NEEDLE") {
		t.Fatalf("truncated=%v len=%d", r.Truncated, len(r.Stdout))
	}
	if !r.Found(0) || r.Found(1) {
		t.Fatal("streaming pattern search must see dropped output")
	}
	if !strings.HasPrefix(r.Stdout, "line-0-") || !strings.Contains(r.Stdout, "line-4999-") {
		t.Fatalf("head and tail must be kept: head=%q tail=%q", r.Stdout[:40], r.Stdout[len(r.Stdout)-120:])
	}
}

func TestSessionFailure(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", RejectExec: true})
	c := connect(t, srv)
	if _, err := run(t, c, "true", ""); category(err) != domain.CatSessionFailed {
		t.Fatalf("want SESSION_FAILED, got %v", err)
	}
}

func TestBastion(t *testing.T) {
	target := sshtest.Start(t, sshtest.Options{Password: "pw"})
	bastion := sshtest.Start(t, sshtest.Options{Password: "bpw", AllowForward: true})
	d := dialer(sshtest.WriteKnownHosts(t, target, bastion))
	b := hop(bastion, "bpw")
	c, err := d.Dial(context.Background(), hop(target, "pw"), &b)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Exec(context.Background(), c.Client, Request{Command: "echo via-bastion", Timeout: 5 * time.Second, MaxOutput: 1024})
	c.Close()
	if err != nil || r.Stdout != "via-bastion" {
		t.Fatalf("%v %+v", err, r)
	}
	if bastion.Conns.Load() != 1 || target.Conns.Load() != 1 || len(bastion.Commands()) != 0 {
		t.Fatal("bastion must only tunnel")
	}
	bad := hop(bastion, "nope")
	if _, err = d.Dial(context.Background(), hop(target, "pw"), &bad); category(err) != domain.CatAuthFailed || !strings.HasPrefix(domain.AsFailure(err).Reason, "bastion") {
		t.Fatalf("got %v", err)
	}
}

func TestSharedBastion(t *testing.T) {
	bastion := sshtest.Start(t, sshtest.Options{Password: "bpw", AllowForward: true})
	targets := []*sshtest.Server{}
	for range 4 {
		targets = append(targets, sshtest.Start(t, sshtest.Options{Password: "pw"}))
	}
	d := dialer(sshtest.WriteKnownHosts(t, append(targets, bastion)...))
	d.Bastions = &BastionPool{}
	defer d.Bastions.Close()
	b := hop(bastion, "bpw")

	// 20 hosts at once: a single login on the bastion.
	errs := make(chan error, 20)
	for i := range 20 {
		go func() {
			c, err := d.Dial(context.Background(), hop(targets[i%4], "pw"), &b)
			if err == nil {
				_, err = Exec(context.Background(), c.Client, Request{Command: "true", Timeout: 5 * time.Second, MaxOutput: 1024})
				c.Close() // must not close the shared bastion connection
			}
			errs <- err
		}()
	}
	for range 20 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := bastion.Conns.Load(); n != 1 {
		t.Fatalf("want 1 bastion connection, got %d", n)
	}

	// A target the bastion cannot reach does not break the shared connection.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if _, err := d.Dial(context.Background(), Hop{Addr: closed, User: "x"}, &b); category(err) != domain.CatConnectionRefused {
		t.Fatalf("want CONNECTION_REFUSED, got %v", err)
	}
	if c, err := d.Dial(context.Background(), hop(targets[0], "pw"), &b); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	if n := bastion.Conns.Load(); n != 1 {
		t.Fatalf("refused tunnel must keep the bastion connection, got %d connections", n)
	}

	// A dead bastion connection is replaced on the next dial.
	d.Bastions.mu.Lock()
	for _, e := range d.Bastions.conns {
		e.c.Close()
	}
	d.Bastions.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if c, err := d.Dial(context.Background(), hop(targets[1], "pw"), &b); err != nil {
		t.Fatalf("redial after bastion loss: %v", err)
	} else {
		c.Close()
	}
	if n := bastion.Conns.Load(); n != 2 {
		t.Fatalf("want a second bastion connection, got %d", n)
	}
}

func TestSharedBastionAuthFailureIsShared(t *testing.T) {
	bastion := sshtest.Start(t, sshtest.Options{Password: "bpw", AllowForward: true})
	target := sshtest.Start(t, sshtest.Options{Password: "pw"})
	d := dialer(sshtest.WriteKnownHosts(t, target, bastion))
	d.Bastions = &BastionPool{}
	bad := hop(bastion, "wrong")
	errs := make(chan error, 10)
	for range 10 {
		go func() { _, err := d.Dial(context.Background(), hop(target, "pw"), &bad); errs <- err }()
	}
	for range 10 {
		if err := <-errs; category(err) != domain.CatAuthFailed {
			t.Fatalf("want AUTH_FAILED, got %v", err)
		}
	}
}

func TestNoGoroutineLeaks(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	d := dialer(sshtest.WriteKnownHosts(t, srv))
	cycle := func() {
		c, err := d.Dial(context.Background(), hop(srv, "pw"), nil)
		if err != nil {
			t.Fatal(err)
		}
		Exec(context.Background(), c.Client, Request{Command: "echo x", Timeout: time.Second, MaxOutput: 1024})
		Exec(context.Background(), c.Client, Request{Command: "sleep 5", Timeout: 50 * time.Millisecond, MaxOutput: 1024})
		c.Close()
	}
	cycle() // warm up lazily started goroutines
	time.Sleep(300 * time.Millisecond)
	before := runtime.NumGoroutine()
	for range 10 {
		cycle()
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > before+3 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, g)
	}
}
