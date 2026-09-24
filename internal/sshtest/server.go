// Package sshtest provides a deterministic in-process SSH server for tests.
// It emulates a Cisco-IOS-like interactive CLI (prompt state machine, echo,
// pagination, enable password) and Linux-like exec commands, and supports
// bastion port forwarding (direct-tcpip).
package sshtest

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Options configure a test server.
type Options struct {
	User           string // default "admin"
	Password       string // enables password auth
	AuthorizedKey  ssh.PublicKey
	Hostname       string // default "router"
	Banner         string
	EnablePassword string
	RejectSessions bool
	AllowForward   bool
	// FailDescription makes "description <value>" return an IOS error.
	FailDescription string
}

// Server is a running test SSH server.
type Server struct {
	Addr    string
	HostKey ssh.Signer
	opts    Options
	ln      net.Listener

	Conns    atomic.Int64
	Sessions atomic.Int64
	Active   atomic.Int64 // currently open connections

	mu       sync.Mutex
	commands []string
	descs    map[string]string
	wg       sync.WaitGroup
}

// Start launches a server on 127.0.0.1:0 and stops it at test cleanup.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	if o.User == "" {
		o.User = "admin"
	}
	if o.Hostname == "" {
		o.Hostname = "router"
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
	s := &Server{Addr: ln.Addr().String(), HostKey: signer, opts: o, ln: ln, descs: map[string]string{}}
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
		want := o.AuthorizedKey.Marshal()
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == o.User && string(k.Marshal()) == string(want) {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	}
	cfg.AddHostKey(signer)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() { defer s.wg.Done(); s.serve(c, cfg) }()
		}
	}()
	t.Cleanup(s.Close)
	return s
}

// Close stops the listener.
func (s *Server) Close() { _ = s.ln.Close() }

// Commands returns every interactive/exec command received, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.commands...)
}

// Description returns the configured description of an interface.
func (s *Server) Description(iface string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.descs[iface]
}

// WriteKnownHosts writes a known_hosts file trusting this server.
func (s *Server) WriteKnownHosts(t testing.TB) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%s %s", s.port(), ssh.MarshalAuthorizedKey(s.HostKey.PublicKey()))
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *Server) port() string { _, p, _ := net.SplitHostPort(s.Addr); return p }

func (s *Server) record(cmd string) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

func (s *Server) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	s.Conns.Add(1)
	s.Active.Add(1)
	defer s.Active.Add(-1)
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			if s.opts.RejectSessions {
				_ = nc.Reject(ssh.Prohibited, "sessions disabled")
				continue
			}
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
	pty := false
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			pty = true
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			s.shell(ch, pty)
			return
		case "exec":
			var p struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &p)
			_ = req.Reply(true, nil)
			code := s.exec(ch, p.Command)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		default:
			_ = req.Reply(req.Type == "env", nil)
		}
	}
}

func (s *Server) exec(ch ssh.Channel, cmd string) int {
	s.record(cmd)
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return 0
	}
	arg := strings.TrimSpace(strings.TrimPrefix(cmd, fields[0]))
	switch fields[0] {
	case "hostname":
		fmt.Fprintf(ch, "%s\n", s.opts.Hostname)
	case "echo":
		fmt.Fprintf(ch, "%s\n", arg)
	case "uname":
		fmt.Fprint(ch, "Linux test 6.1.0 #1 SMP x86_64 GNU/Linux\n")
	case "df":
		fmt.Fprint(ch, "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 50G 10G 40G 20% /\n")
	case "uptime":
		fmt.Fprint(ch, " 10:00:00 up 1 day,  1 user,  load average: 0.00, 0.01, 0.05\n")
	case "exit":
		n, _ := strconv.Atoi(arg)
		return n
	case "fail":
		fmt.Fprint(ch.Stderr(), "boom: operation failed\n")
		return 1
	case "sleep":
		d, _ := time.ParseDuration(arg)
		time.Sleep(d)
	case "flood":
		n, _ := strconv.Atoi(arg)
		line := strings.Repeat("x", 99) + "\n"
		for i := 0; i < n; i++ {
			if _, err := io.WriteString(ch, line); err != nil {
				return 1
			}
		}
	default:
		fmt.Fprintf(ch.Stderr(), "%s: command not found\n", fields[0])
		return 127
	}
	return 0
}

// shell emulates a Cisco-IOS-like CLI.
func (s *Server) shell(ch ssh.Channel, pty bool) {
	r := bufio.NewReader(ch)
	if s.opts.Banner != "" {
		fmt.Fprintf(ch, "%s\r\n", strings.ReplaceAll(s.opts.Banner, "\n", "\r\n"))
	}
	mode := "" // "", "config", "config-if"
	iface := ""
	priv := s.opts.EnablePassword == ""
	prompt := func() string {
		suffix := ">"
		if priv {
			suffix = "#"
		}
		if mode != "" {
			return fmt.Sprintf("%s(%s)#", s.opts.Hostname, mode)
		}
		return s.opts.Hostname + suffix
	}
	w := func(format string, a ...any) { fmt.Fprintf(ch, format, a...) }
	invalid := func() { w("                ^\r\n%% Invalid input detected at '^' marker.\r\n\r\n") }
	w("%s", prompt())
	for {
		line, err := readLine(r, ch, pty)
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		s.record(cmd)
		switch {
		case cmd == "":
		case cmd == "enable":
			w("Password: ")
			pw, err := readLine(r, ch, false) // passwords are never echoed
			if err != nil {
				return
			}
			w("\r\n")
			if strings.TrimSpace(pw) == s.opts.EnablePassword {
				priv = true
			} else {
				w("%% Access denied\r\n")
			}
		case !priv:
			invalid()
		case cmd == "configure terminal" || cmd == "conf t":
			w("Enter configuration commands, one per line.  End with CNTL/Z.\r\n")
			mode = "config"
		case strings.HasPrefix(cmd, "interface ") && mode != "":
			iface = strings.TrimPrefix(cmd, "interface ")
			mode = "config-if"
		case strings.HasPrefix(cmd, "description ") && mode == "config-if":
			d := strings.TrimPrefix(cmd, "description ")
			if s.opts.FailDescription != "" && d == s.opts.FailDescription {
				invalid()
				break
			}
			s.mu.Lock()
			s.descs[iface] = d
			s.mu.Unlock()
		case cmd == "exit" && mode == "config-if":
			mode = "config"
		case cmd == "exit" && mode == "config", cmd == "end":
			mode = ""
		case cmd == "exit" || cmd == "logout":
			return
		case cmd == "terminal length 0":
		case cmd == "write memory" || cmd == "wr":
			w("Building configuration...\r\n[OK]\r\n")
		case cmd == "show version":
			w("Cisco IOS Software, Emulator Software (TEST), Version 15.2\r\nuptime is 1 week\r\n")
		case strings.HasPrefix(cmd, "show interface ") && strings.HasSuffix(cmd, " description"):
			name := strings.TrimSuffix(strings.TrimPrefix(cmd, "show interface "), " description")
			w("Interface                      Status         Protocol Description\r\n%-30s up             up       %s\r\n", name, s.Description(name))
		case cmd == "show long":
			for i := 1; i <= 100; i++ {
				w("line %03d of long output\r\n", i)
				if i%20 == 0 && i < 100 {
					w(" --More-- ")
					if _, err := r.ReadByte(); err != nil {
						return
					}
					w("\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\b")
				}
			}
		case cmd == "show endless":
			for {
				w("more data\r\n --More-- ")
				if _, err := r.ReadByte(); err != nil {
					return
				}
			}
		case cmd == "trickle": // steady output without a prompt, forever
			for {
				if _, err := io.WriteString(ch, "tick\r\n"); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		case strings.HasPrefix(cmd, "sleep "):
			d, _ := time.ParseDuration(strings.TrimPrefix(cmd, "sleep "))
			time.Sleep(d)
		case cmd == "hang":
			w("working...\r\n")
			_, _ = io.Copy(io.Discard, r) // never prints a prompt
			return
		case cmd == "drop":
			return // closes the session abruptly
		default:
			invalid()
		}
		w("%s", prompt())
	}
}

// readLine reads until CR or LF, echoing input when a PTY is allocated.
func readLine(r *bufio.Reader, w io.Writer, echo bool) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\r' || b == '\n' {
			if b == '\r' {
				if r.Buffered() > 0 {
					if nb, _ := r.Peek(1); nb[0] == '\n' {
						_, _ = r.ReadByte()
					}
				}
			}
			if echo {
				_, _ = io.WriteString(w, "\r\n")
			}
			return sb.String(), nil
		}
		sb.WriteByte(b)
		if echo {
			_, _ = w.Write([]byte{b})
		}
	}
}
