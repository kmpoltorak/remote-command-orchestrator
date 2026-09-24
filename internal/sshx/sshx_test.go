package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/sshtest"
)

var promptRe = regexp.MustCompile(`[\w.\-@/:()]+[>#]\s*$`)

func dialer(t *testing.T, known string) *Dialer {
	return &Dialer{
		ConnectTimeout:   2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		HostKeys:         &HostKeys{Path: known, Logger: slog.Default()},
	}
}

func category(err error) domain.Category { return domain.AsFailure(err).Category }

func connect(t *testing.T, srv *sshtest.Server) *Client {
	t.Helper()
	d := dialer(t, srv.WriteKnownHosts(t))
	c, err := d.Dial(context.Background(), Hop{Addr: srv.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("pw")}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func shellOpts() ShellOptions {
	return ShellOptions{PTY: true, Prompt: promptRe, LineEnding: "\n", PagerPatterns: []string{"--More--"}, MaxOutput: 1 << 20, LoginTimeout: 2 * time.Second, PromptSettle: 100 * time.Millisecond}
}

func step(cmd, re string) StepSpec {
	s := StepSpec{Command: cmd, SendNewline: true, CommandTimeout: 3 * time.Second, ExpectTimeout: 2 * time.Second}
	if re != "" {
		s.Regex = regexp.MustCompile(re)
	}
	return s
}

func TestPasswordAndKeyAuth(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", AuthorizedKey: signer.PublicKey()})
	d := dialer(t, srv.WriteKnownHosts(t))
	ctx := context.Background()

	c, err := d.Dial(ctx, Hop{Addr: srv.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.PublicKeys(signer)}}, nil, nil)
	if err != nil {
		t.Fatalf("key auth: %v", err)
	}
	c.Close()

	_, err = d.Dial(ctx, Hop{Addr: srv.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("wrong")}}, nil, nil)
	if category(err) != domain.CatAuthFailed {
		t.Fatalf("want AUTH_FAILED, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("password leaked in error")
	}
}

func TestHostKeyVerification(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	other := sshtest.Start(t, sshtest.Options{Password: "pw"})
	// known_hosts contains other's key under srv's address -> mismatch.
	known := filepath.Join(t.TempDir(), "known_hosts")
	_, port, _ := net.SplitHostPort(srv.Addr)
	os.WriteFile(known, []byte("[127.0.0.1]:"+port+" "+string(ssh.MarshalAuthorizedKey(other.HostKey.PublicKey()))), 0o600)
	hop := Hop{Addr: srv.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("pw")}}

	_, err := dialer(t, known).Dial(context.Background(), hop, nil, nil)
	if category(err) != domain.CatHostKeyMismatch {
		t.Fatalf("want HOST_KEY_MISMATCH, got %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, nil, 0o600)
	_, err = dialer(t, empty).Dial(context.Background(), hop, nil, nil)
	if category(err) != domain.CatHostKeyUnknown {
		t.Fatalf("want HOST_KEY_UNKNOWN, got %v", err)
	}
	_, err = dialer(t, "/nonexistent/known_hosts").Dial(context.Background(), hop, nil, nil)
	if category(err) != domain.CatHostKeyUnknown {
		t.Fatalf("missing known_hosts must fail closed, got %v", err)
	}
	d := dialer(t, empty)
	d.HostKeys.Insecure = true
	c, err := d.Dial(context.Background(), hop, nil, nil)
	if err != nil {
		t.Fatalf("insecure mode: %v", err)
	}
	c.Close()
}

func TestConnectionFailures(t *testing.T) {
	d := dialer(t, "/dev/null")
	// Refused: listen then close to get a free port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_, err := d.Dial(context.Background(), Hop{Addr: addr, User: "x"}, nil, nil)
	if category(err) != domain.CatConnectionRefused {
		t.Fatalf("want CONNECTION_REFUSED, got %v", err)
	}
	// Handshake timeout: a listener that accepts but never speaks SSH.
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
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
	_, err = d.Dial(context.Background(), Hop{Addr: silent.Addr().String(), User: "x"}, nil, nil)
	if category(err) != domain.CatHandshakeFailed || time.Since(start) > 2*time.Second {
		t.Fatalf("want fast SSH_HANDSHAKE_FAILED, got %v after %s", err, time.Since(start))
	}
	// Connect timeout via context deadline on a non-routable address.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = d.Dial(ctx, Hop{Addr: "10.255.255.1:22", User: "x"}, nil, nil)
	if c := category(err); c != domain.CatConnectionTimeout {
		t.Fatalf("want CONNECTION_TIMEOUT, got %v", err)
	}
	// DNS failure.
	_, err = d.Dial(context.Background(), Hop{Addr: "no-such-host.invalid:22", User: "x"}, nil, nil)
	if c := category(err); c != domain.CatDNSFailure {
		t.Fatalf("want DNS_FAILURE, got %v", err)
	}
}

func TestSessionFailure(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", RejectSessions: true})
	c := connect(t, srv)
	_, _, err := OpenShell(context.Background(), c.Client, shellOpts())
	if category(err) != domain.CatSessionFailed {
		t.Fatalf("want SESSION_FAILED, got %v", err)
	}
	_, err = Exec(context.Background(), c.Client, step("hostname", ""), 4096)
	if category(err) != domain.CatSessionFailed {
		t.Fatalf("want SESSION_FAILED, got %v", err)
	}
}

func TestInteractiveWorkflow(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", Banner: "Authorized access only"})
	c := connect(t, srv)
	sh, banner, err := OpenShell(context.Background(), c.Client, shellOpts())
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if !strings.Contains(banner, "Authorized access only") {
		t.Fatalf("banner %q", banner)
	}
	ctx := context.Background()
	for _, s := range []StepSpec{
		step("configure terminal", `\(config\)#\s*$`),
		step("interface Gi0/1", `\(config-if\)#\s*$`),
		step("description TEST", `\(config-if\)#\s*$`),
		step("end", `[^)]#\s*$`),
	} {
		out, err := sh.Run(ctx, s)
		if err != nil {
			t.Fatalf("%s: %v (%+v)", s.Command, err, out)
		}
	}
	if srv.Description("Gi0/1") != "TEST" {
		t.Fatal("description not applied")
	}
	// Echo removed, output normalized, prompt captured separately.
	out, err := sh.Run(ctx, step("show version", ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Output, "show version") || !strings.HasPrefix(out.Output, "Cisco IOS") || out.MatchedPrompt != "router#" {
		t.Fatalf("normalization: %+v", out)
	}
	// Session reuse: one connection, one session for all steps.
	if srv.Conns.Load() != 1 || srv.Sessions.Load() != 1 {
		t.Fatalf("conns=%d sessions=%d", srv.Conns.Load(), srv.Sessions.Load())
	}
}

func TestExpectFailures(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)
	sh, _, err := OpenShell(context.Background(), c.Client, shellOpts())
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	ctx := context.Background()

	// Prompt mismatch: expect config-if, device is in (config).
	out, err := sh.Run(ctx, step("configure terminal", `\(config-if\)#\s*$`))
	if category(err) != domain.CatPromptMismatch || out.MatchedPrompt != "router(config)#" {
		t.Fatalf("want PROMPT_MISMATCH with received prompt, got %v %+v", err, out)
	}
	sh.Run(ctx, step("end", ""))

	// not_contains triggers COMMAND_FAILED; echo is excluded from matching.
	s := step("bogus Invalid", "")
	s.NotContains = []string{"Invalid input"}
	if _, err := sh.Run(ctx, s); category(err) != domain.CatCommandFailed {
		t.Fatalf("want COMMAND_FAILED, got %v", err)
	}
	s = step("show version", "")
	s.NotContains = []string{"show version"} // only in the echo
	s.Contains = []string{"Cisco"}
	if _, err := sh.Run(ctx, s); err != nil {
		t.Fatalf("echo must not count for matching: %v", err)
	}

	// Expect timeout: device goes silent.
	s = step("sleep 2s", "")
	s.ExpectTimeout = 300 * time.Millisecond
	if _, err := sh.Run(ctx, s); category(err) != domain.CatExpectTimeout {
		t.Fatalf("want EXPECT_TIMEOUT, got %v", err)
	}
	time.Sleep(2 * time.Second) // let the device return to the prompt

	// Command (hard) timeout: steady output keeps the idle timer alive.
	s = step("trickle", "")
	s.CommandTimeout = 500 * time.Millisecond
	if _, err := sh.Run(ctx, s); category(err) != domain.CatCommandTimeout {
		t.Fatalf("want COMMAND_TIMEOUT, got %v", err)
	}
}

func TestPagerAndLimits(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)
	sh, _, err := OpenShell(context.Background(), c.Client, shellOpts())
	if err != nil {
		t.Fatal(err)
	}
	out, err := sh.Run(context.Background(), step("show long", `#\s*$`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Output, "line 100") || strings.Contains(out.Output, "--More--") {
		t.Fatalf("pager handling: %q", out.Output[len(out.Output)-200:])
	}
	sh.Close()

	c2 := connect(t, srv)
	o := shellOpts()
	o.MaxPages = 5
	sh2, _, _ := OpenShell(context.Background(), c2.Client, o)
	defer sh2.Close()
	if _, err := sh2.Run(context.Background(), step("show endless", "")); category(err) != domain.CatOutputLimitExceeded {
		t.Fatalf("want OUTPUT_LIMIT_EXCEEDED, got %v", err)
	}
}

func TestSessionDropAndCancel(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	c := connect(t, srv)
	sh, _, _ := OpenShell(context.Background(), c.Client, shellOpts())
	if _, err := sh.Run(context.Background(), step("drop", "")); category(err) != domain.CatSessionFailed {
		t.Fatalf("want SESSION_FAILED, got %v", err)
	}
	if sh.Alive() {
		t.Fatal("shell should be dead")
	}

	c2 := connect(t, srv)
	sh2, _, _ := OpenShell(context.Background(), c2.Client, shellOpts())
	defer sh2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if _, err := sh2.Run(ctx, step("hang", "")); category(err) != domain.CatCancelled || time.Since(start) > time.Second {
		t.Fatalf("want fast CANCELLED, got %v", err)
	}
}

func TestExecMode(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw", Hostname: "app-01"})
	c := connect(t, srv)
	ctx := context.Background()
	out, err := Exec(ctx, c.Client, step("hostname", ""), 4096)
	if err != nil || out.Output != "app-01" || *out.ExitCode != 0 {
		t.Fatalf("%v %+v", err, out)
	}
	out, err = Exec(ctx, c.Client, step("fail", ""), 4096)
	if category(err) != domain.CatCommandFailed || *out.ExitCode != 1 || !strings.Contains(out.Stderr, "boom") {
		t.Fatalf("%v %+v", err, out)
	}
	three := 3
	s := step("exit 3", "")
	s.ExitCode = &three
	if _, err := Exec(ctx, c.Client, s, 4096); err != nil {
		t.Fatal(err)
	}
	s = step("sleep 2s", "")
	s.CommandTimeout = 200 * time.Millisecond
	if _, err := Exec(ctx, c.Client, s, 4096); category(err) != domain.CatCommandTimeout {
		t.Fatalf("want COMMAND_TIMEOUT, got %v", err)
	}
	out, err = Exec(ctx, c.Client, step("flood 10000", ""), 8192)
	if err != nil || !out.Truncated || out.Bytes != 1_000_000 || len(out.Raw) > 8192+100 {
		t.Fatalf("truncation: %v truncated=%v bytes=%d raw=%d", err, out.Truncated, out.Bytes, len(out.Raw))
	}
	if srv.Conns.Load() != 1 {
		t.Fatal("exec steps must share one connection")
	}
}

func TestBastion(t *testing.T) {
	target := sshtest.Start(t, sshtest.Options{Password: "pw", Hostname: "internal"})
	bastion := sshtest.Start(t, sshtest.Options{Password: "bpw", AllowForward: true})
	known := filepath.Join(t.TempDir(), "known_hosts")
	a, _ := os.ReadFile(target.WriteKnownHosts(t))
	b, _ := os.ReadFile(bastion.WriteKnownHosts(t))
	os.WriteFile(known, append(a, b...), 0o600)
	d := dialer(t, known)
	c, err := d.Dial(context.Background(),
		Hop{Addr: target.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("pw")}},
		&Hop{Addr: bastion.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("bpw")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Exec(context.Background(), c.Client, step("hostname", ""), 4096)
	c.Close()
	if err != nil || out.Output != "internal" {
		t.Fatalf("%v %+v", err, out)
	}
	if bastion.Conns.Load() != 1 || target.Conns.Load() != 1 {
		t.Fatal("expected one bastion and one target connection")
	}
	// Bastion auth failure is reported with a bastion prefix.
	_, err = d.Dial(context.Background(),
		Hop{Addr: target.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("pw")}},
		&Hop{Addr: bastion.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("bad")}}, nil)
	if f := domain.AsFailure(err); f.Category != domain.CatAuthFailed || !strings.HasPrefix(f.Reason, "bastion") {
		t.Fatalf("got %v", err)
	}
}

func TestNoGoroutineLeaks(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "pw"})
	d := dialer(t, srv.WriteKnownHosts(t))
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		c, err := d.Dial(context.Background(), Hop{Addr: srv.Addr, User: "admin", Methods: []ssh.AuthMethod{ssh.Password("pw")}}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		sh, _, err := OpenShell(context.Background(), c.Client, shellOpts())
		if err != nil {
			t.Fatal(err)
		}
		sh.Run(context.Background(), step("show version", ""))
		sh.Close()
		c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	// The server side also runs goroutines in-process; allow small slack.
	if g := runtime.NumGoroutine(); g > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, g)
	}
}
