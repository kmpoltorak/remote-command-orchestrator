// Package sshtest runs a real SSH server in-process for tests. Exec requests
// run through the local /bin/sh inside a private temp directory, so tests
// exercise genuine commands, stdin, exit codes and timeouts. This is test
// infrastructure only; the orchestrator itself never executes local shells.
package sshtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Options configure a server.
type Options struct {
	User          string // default "deploy"
	Password      string // enables password auth
	AuthorizedKey ssh.PublicKey
	SudoPassword  string // fake sudo requires this with -S; empty = NOPASSWD
	AllowForward  bool   // act as a bastion (direct-tcpip)
	RejectExec    bool   // accept sessions but refuse exec requests
}

// Server is a running test SSH server.
type Server struct {
	Addr    string
	Dir     string // working directory and $HOME of every command
	HostKey ssh.Signer
	opts    Options
	ln      net.Listener
	binDir  string

	Conns    atomic.Int64 // accepted, authenticated connections
	Sessions atomic.Int64

	mu       sync.Mutex
	commands []string
	running  atomic.Int64
	peak     atomic.Int64
}

// Start launches a server on 127.0.0.1:0; it stops at test cleanup.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	if o.User == "" {
		o.User = "deploy"
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Addr: ln.Addr().String(), Dir: t.TempDir(), HostKey: signer, opts: o, ln: ln, binDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.binDir, "sudo"), []byte(fakeSudo), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{}
	if o.Password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == o.User && string(pw) == o.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	}
	if o.AuthorizedKey != nil {
		want := string(o.AuthorizedKey.Marshal())
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == o.User && string(k.Marshal()) == want {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	}
	cfg.AddHostKey(signer)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Commands returns every exec command received, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.commands...)
}

// PeakConcurrent is the highest number of simultaneously running commands.
func (s *Server) PeakConcurrent() int64 { return s.peak.Load() }

// KnownHostsLine returns a known_hosts entry trusting this server.
func (s *Server) KnownHostsLine() string {
	_, port, _ := net.SplitHostPort(s.Addr)
	return fmt.Sprintf("[127.0.0.1]:%s %s", port, ssh.MarshalAuthorizedKey(s.HostKey.PublicKey()))
}

// WriteKnownHosts writes a known_hosts file trusting the given servers.
func WriteKnownHosts(t testing.TB, servers ...*Server) string {
	t.Helper()
	var data []byte
	for _, s := range servers {
		data = append(data, s.KnownHostsLine()...)
	}
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *Server) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	s.Conns.Add(1)
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			s.Sessions.Add(1)
			go s.session(ch, creqs)
		case "direct-tcpip":
			s.forward(nc)
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func (s *Server) forward(nc ssh.NewChannel) {
	var p struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if !s.opts.AllowForward || ssh.Unmarshal(nc.ExtraData(), &p) != nil {
		_ = nc.Reject(ssh.Prohibited, "forwarding disabled")
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(target, ch); target.Close() }()
	go func() { _, _ = io.Copy(ch, target); ch.Close() }()
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" || s.opts.RejectExec {
			_ = req.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		_ = req.Reply(true, nil)
		s.mu.Lock()
		s.commands = append(s.commands, p.Command)
		s.mu.Unlock()
		code := s.run(ch, reqs, p.Command)
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		return
	}
}

// run executes command with /bin/sh. The process group is killed when the
// client signals, closes the channel, or disconnects.
func (s *Server) run(ch ssh.Channel, reqs <-chan *ssh.Request, command string) int {
	n := s.running.Add(1)
	defer s.running.Add(-1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for range reqs { // any "signal" request or channel close kills the command
			cancel()
		}
		cancel()
	}()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Dir = s.Dir
	cmd.Env = []string{
		"PATH=" + s.binDir + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + s.Dir,
		"SUDO_TEST_PASSWORD=" + s.opts.SudoPassword,
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code
		}
		return 137
	}
	if err != nil {
		return 127
	}
	return 0
}

// fakeSudo mimics the sudo flags the orchestrator uses: -S (password from the
// first stdin line), -n (never prompt), -p, --. The rest of stdin is passed to
// the command, exactly like real sudo.
const fakeSudo = `#!/bin/sh
mode=""
while [ $# -gt 0 ]; do
  case "$1" in
    -S) mode=S; shift ;;
    -n) mode=n; shift ;;
    -k) shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if [ -z "$SUDO_TEST_PASSWORD" ]; then
  : # NOPASSWD: like real sudo, nothing is read from stdin
elif [ "$mode" = S ]; then
  IFS= read -r pw
  if [ "$pw" != "$SUDO_TEST_PASSWORD" ]; then echo "sudo: incorrect password attempt" >&2; exit 1; fi
else
  echo "sudo: a password is required" >&2; exit 1
fi
export SUDO_USER=deploy
exec "$@"
`
