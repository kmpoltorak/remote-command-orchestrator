package sshx

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Request is one remote command.
type Request struct {
	Command   string
	Stdin     []byte // sudo password line, script or file content; never logged
	Timeout   time.Duration
	MaxOutput int      // retained bytes per stream
	Patterns  []string // searched in stdout and stderr (see Buffer)
}

// Result is what the command produced. It is filled even on failure.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  *int
	Truncated bool
	Bytes     int64
	Started   bool // the command was started; false if the channel or exec request failed

	stdout, stderr *Buffer
}

// Found reports whether Request.Patterns[i] appeared in stdout or stderr.
func (r Result) Found(i int) bool {
	return r.stdout != nil && (r.stdout.Found(i) || r.stderr.Found(i))
}

// Exec runs one command in a new channel on an existing connection.
// A non-zero exit status is not an error here; the caller checks ExitCode.
// Errors are timeouts, cancellation and broken sessions. The timeout and ctx
// cover opening the channel too: if that hangs, the connection is closed.
func Exec(ctx context.Context, c *ssh.Client, req Request) (Result, error) {
	timer := time.NewTimer(req.Timeout)
	defer timer.Stop()
	timeout := domain.Fail(domain.CatCommandTimeout, "command did not finish within %s", req.Timeout)
	cancelled := domain.Fail(domain.CatCancelled, "cancelled")
	stdout, stderr := NewBuffer(req.MaxOutput, req.Patterns), NewBuffer(req.MaxOutput, req.Patterns)
	type opened struct {
		sess *ssh.Session
		err  error
	}
	ready := make(chan opened, 1)
	go func() {
		sess, err := c.NewSession()
		if err != nil {
			ready <- opened{err: domain.Fail(domain.CatSessionFailed, "cannot open session: %v", err)}
			return
		}
		// A nil Stdin would also send EOF; being explicit documents that a command
		// waiting for input gets EOF instead of hanging until the timeout.
		sess.Stdin = bytes.NewReader(req.Stdin)
		sess.Stdout, sess.Stderr = stdout, stderr
		if err := sess.Start(req.Command); err != nil {
			_ = sess.Close()
			ready <- opened{err: domain.Fail(domain.CatSessionFailed, "cannot start command: %v", err)}
			return
		}
		ready <- opened{sess: sess}
	}()
	var o opened
	var fail error
	select {
	case o = <-ready:
	case <-timer.C:
		fail = timeout
	case <-ctx.Done():
		fail = cancelled
	}
	if fail != nil {
		// Only a stuck transport blocks here; closing it is the only way out.
		_ = c.Close()
		if o = <-ready; o.sess != nil {
			_ = o.sess.Close()
		}
		return Result{}, fail
	}
	if o.err != nil {
		return Result{}, o.err
	}
	sess := o.sess
	defer sess.Close()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	var err error
	select {
	case err = <-done:
	case <-timer.C:
		fail = timeout
	case <-ctx.Done():
		fail = cancelled
	}
	if fail != nil {
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		<-done // buffers are quiescent once Wait returns
	}

	res := Result{
		Started:   true,
		Stdout:    strings.TrimRight(stdout.String(), "\n"),
		Stderr:    strings.TrimRight(stderr.String(), "\n"),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Bytes:     stdout.Total() + stderr.Total(),
		stdout:    stdout,
		stderr:    stderr,
	}
	if fail != nil {
		return res, fail
	}
	var exitErr *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		res.ExitCode = new(int)
	case errors.As(err, &exitErr):
		code := exitErr.ExitStatus()
		res.ExitCode = &code
	case errors.As(err, &missing):
		// Remote side closed without reporting a status; caller treats as failure.
	default:
		return res, domain.Fail(domain.CatSessionFailed, "session failed: %v", err)
	}
	return res, nil
}

// Alive sends an SSH keepalive and reports whether the server answered in time.
func Alive(c *ssh.Client, timeout time.Duration) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err == nil // any reply, even "unsupported", proves the peer is there
	case <-t.C:
		return false
	}
}

// KeepAlive checks the connection every interval and closes it after misses
// unanswered keepalives. A connection silently cut by a network restart then
// fails in seconds instead of hanging until the step timeout. Call stop when done.
func KeepAlive(c *ssh.Client, interval time.Duration, misses int) (stop func()) {
	quit := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		failed := 0
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				if Alive(c, interval) {
					failed = 0
				} else if failed++; failed >= misses {
					_ = c.Close()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(quit) }) }
}
