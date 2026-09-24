package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

const (
	promptWindow   = 4 << 10  // bytes of trailing output checked for prompts
	expectWindow   = 64 << 10 // bytes of trailing output checked for expect regex
	maxBannerBytes = 8 << 10
	defaultSettle  = 300 * time.Millisecond
	defaultPages   = 1000
)

// StepSpec is one fully rendered step as the transport sees it.
type StepSpec struct {
	Command        string
	SendNewline    bool
	Regex          *regexp.Regexp
	Contains       []string
	NotContains    []string
	ExitCode       *int
	CommandTimeout time.Duration // hard deadline for the step
	ExpectTimeout  time.Duration // max silence while waiting for a prompt
}

// StepOutput is what was observed. It is filled even when the step fails.
type StepOutput struct {
	Output        string // normalized: no echo, no trailing prompt, no ANSI/CR
	Raw           string // raw retained bytes
	Stderr        string
	ExitCode      *int
	MatchedPrompt string
	Truncated     bool
	Bytes         int64
}

// ShellOptions configure an interactive session.
type ShellOptions struct {
	PTY           bool
	Terminal      string
	Width, Height int
	Prompt        *regexp.Regexp // "device is waiting for input"
	InitialPrompt *regexp.Regexp // defaults to Prompt
	LineEnding    string
	PagerPatterns []string
	PagerResponse string
	MaxPages      int
	PromptSettle  time.Duration
	LoginTimeout  time.Duration
	MaxOutput     int
}

// Shell is a persistent interactive session reused across workflow steps.
type Shell struct {
	opts    ShellOptions
	session *ssh.Session
	stdin   io.WriteCloser

	mu     sync.Mutex
	cur    *OutputBuffer
	notify chan struct{}
	done   chan struct{}
}

// OpenShell starts an interactive shell and waits for the initial prompt.
// It returns the shell and the captured login banner.
func OpenShell(ctx context.Context, c *ssh.Client, o ShellOptions) (*Shell, string, error) {
	if o.InitialPrompt == nil {
		o.InitialPrompt = o.Prompt
	}
	if o.PromptSettle == 0 {
		o.PromptSettle = defaultSettle
	}
	if o.MaxPages == 0 {
		o.MaxPages = defaultPages
	}
	if o.PagerResponse == "" {
		o.PagerResponse = " "
	}
	sess, err := c.NewSession()
	if err != nil {
		return nil, "", domain.Fail(domain.CatSessionFailed, "cannot open session: %v", err)
	}
	fail := func(format string, a ...any) (*Shell, string, error) {
		_ = sess.Close()
		return nil, "", domain.Fail(domain.CatSessionFailed, format, a...)
	}
	if o.PTY {
		term := o.Terminal
		if term == "" {
			term = "xterm"
		}
		w, h := o.Width, o.Height
		if w == 0 {
			w = 200
		}
		if h == 0 {
			h = 48
		}
		if err := sess.RequestPty(term, h, w, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}); err != nil {
			return fail("PTY request refused: %v", err)
		}
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fail("stdin: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fail("stdout: %v", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return fail("stderr: %v", err)
	}
	if err := sess.Shell(); err != nil {
		return fail("shell request refused: %v", err)
	}
	s := &Shell{
		opts: o, session: sess, stdin: stdin,
		cur:    NewOutputBuffer(maxBannerBytes*2, "", nil),
		notify: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go s.pump(stdout, &wg)
	go s.pump(stderr, &wg)
	go func() { wg.Wait(); close(s.done) }()

	banner, err := s.waitInitial(ctx)
	if err != nil {
		_ = s.Close()
		return nil, "", err
	}
	return s, banner, nil
}

// pump copies one stream into the current capture. It exits when the
// session closes, so no goroutine outlives the shell.
func (s *Shell) pump(r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.mu.Lock()
			_, _ = s.cur.Write(buf[:n])
			s.mu.Unlock()
			select {
			case s.notify <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

// Close terminates the session; the pump goroutines exit on EOF.
func (s *Shell) Close() error {
	err := s.session.Close()
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return err
}

// Alive reports whether the session is still open.
func (s *Shell) Alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *Shell) waitInitial(ctx context.Context) (string, error) {
	timeout := s.opts.LoginTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	check := func() (string, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		text := Clean(string(s.cur.Bytes()))
		if !s.opts.InitialPrompt.MatchString(tailString(text, promptWindow)) {
			return "", false
		}
		banner := Normalize("\n" + text)
		if len(banner) > maxBannerBytes {
			banner = banner[:maxBannerBytes]
		}
		return strings.TrimLeft(banner, "\n"), true
	}
	for {
		select {
		case <-ctx.Done():
			return "", ctxFailure(ctx, "waiting for initial prompt")
		case <-deadline.C:
			_, last := s.snapshotLast()
			return "", domain.Fail(domain.CatExpectTimeout, "initial prompt not detected within %s (last line %q)", timeout, last)
		case <-s.done:
			if b, ok := check(); ok {
				return b, nil
			}
			return "", domain.Fail(domain.CatSessionFailed, "session closed before initial prompt")
		case <-s.notify:
			if b, ok := check(); ok {
				return b, nil
			}
		}
	}
}

func (s *Shell) snapshotLast() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	text := Clean(string(s.cur.Bytes()))
	return text, LastLine(text)
}

func tailString(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func ctxFailure(ctx context.Context, what string) *domain.Failure {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return domain.Fail(domain.CatCommandTimeout, "session timeout exceeded while %s", what)
	}
	return domain.Fail(domain.CatCancelled, "cancelled while %s", what)
}

// Run sends one command and waits for the expected prompt.
//
// Completion: the expect regex matches the output since the command was sent,
// or (without a regex) the profile prompt appears. If the profile prompt
// appears but the expected regex does not match and no more output arrives
// within PromptSettle, the result is PROMPT_MISMATCH. Silence for
// ExpectTimeout gives EXPECT_TIMEOUT; exceeding CommandTimeout gives
// COMMAND_TIMEOUT. contains/not_contains are evaluated after completion.
func (s *Shell) Run(ctx context.Context, spec StepSpec) (StepOutput, error) {
	buf := NewOutputBuffer(s.opts.MaxOutput, spec.Command, patterns(spec))
	s.mu.Lock()
	s.cur = buf
	s.mu.Unlock()
	select { // drop a stale wake-up from earlier output
	case <-s.notify:
	default:
	}
	line := spec.Command
	if spec.SendNewline {
		line += s.opts.LineEnding
	}
	if _, err := io.WriteString(s.stdin, line); err != nil {
		return s.result(buf, spec, ""), domain.Fail(domain.CatSessionFailed, "cannot send command: %v", err)
	}

	hard := time.NewTimer(spec.CommandTimeout)
	idle := time.NewTimer(spec.ExpectTimeout)
	defer hard.Stop()
	defer idle.Stop()
	var settle <-chan time.Time
	pages := 0

	for {
		select {
		case <-ctx.Done():
			return s.result(buf, spec, ""), ctxFailure(ctx, "running step")
		case <-hard.C:
			out := s.result(buf, spec, "")
			return out, domain.Fail(domain.CatCommandTimeout, "command did not complete within %s (last line %q)", spec.CommandTimeout, out.MatchedPrompt)
		case <-idle.C:
			out := s.result(buf, spec, "")
			return out, domain.Fail(domain.CatExpectTimeout, "expected prompt not received within %s of silence (last line %q)", spec.ExpectTimeout, out.MatchedPrompt)
		case <-settle:
			out := s.result(buf, spec, "")
			return out, domain.Fail(domain.CatPromptMismatch, "expected %q, received %q", spec.Regex.String(), out.MatchedPrompt)
		case <-s.done:
			if done, _ := s.evaluate(buf, spec, &pages); done {
				return s.finish(buf, spec)
			}
			return s.result(buf, spec, ""), domain.Fail(domain.CatSessionFailed, "session closed by remote side")
		case <-s.notify:
			resetTimer(idle, spec.ExpectTimeout)
			settle = nil
			done, mismatch := s.evaluate(buf, spec, &pages)
			if pages > s.opts.MaxPages {
				return s.result(buf, spec, ""), domain.Fail(domain.CatOutputLimitExceeded, "pager limit of %d pages exceeded", s.opts.MaxPages)
			}
			if done {
				return s.finish(buf, spec)
			}
			if mismatch {
				settle = time.After(s.opts.PromptSettle)
			}
		}
	}
}

// evaluate handles pager prompts and checks completion. It reports done, or a
// candidate prompt mismatch.
func (s *Shell) evaluate(buf *OutputBuffer, spec StepSpec, pages *int) (done, mismatch bool) {
	s.mu.Lock()
	for _, p := range s.opts.PagerPatterns {
		if buf.StripPager(p) {
			s.mu.Unlock()
			*pages++
			if *pages <= s.opts.MaxPages {
				_, _ = io.WriteString(s.stdin, s.opts.PagerResponse)
			}
			return false, false
		}
	}
	window := Clean(string(buf.Window(expectWindow)))
	s.mu.Unlock()
	atPrompt := s.opts.Prompt.MatchString(tailString(window, promptWindow))
	if spec.Regex != nil {
		if spec.Regex.MatchString(window) {
			return true, false
		}
		return false, atPrompt
	}
	return atPrompt, false
}

func (s *Shell) finish(buf *OutputBuffer, spec StepSpec) (StepOutput, error) {
	out := s.result(buf, spec, "")
	s.mu.Lock()
	err := checkPatterns(buf, spec)
	s.mu.Unlock()
	return out, err
}

func (s *Shell) result(buf *OutputBuffer, _ StepSpec, stderr string) StepOutput {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf.Finish()
	body := Clean(string(buf.Body()))
	return StepOutput{
		Output:        Normalize(body),
		Raw:           string(buf.Bytes()),
		Stderr:        stderr,
		MatchedPrompt: LastLine(body),
		Truncated:     buf.Truncated(),
		Bytes:         buf.Total(),
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	t.Stop()
	t.Reset(d)
}

func patterns(spec StepSpec) []string {
	return append(append([]string{}, spec.Contains...), spec.NotContains...)
}

// checkPatterns evaluates contains/not_contains using the streaming flags.
func checkPatterns(buf *OutputBuffer, spec StepSpec) error {
	for i, c := range spec.Contains {
		if !buf.Found(i) {
			return domain.Fail(domain.CatCommandFailed, "expected output to contain %q", c)
		}
	}
	for i, c := range spec.NotContains {
		if buf.Found(len(spec.Contains) + i) {
			return domain.Fail(domain.CatCommandFailed, "output contains forbidden text %q", c)
		}
	}
	return nil
}

// Exec runs one command in a new channel on the existing connection and
// captures stdout, stderr and the exit status.
//
// Default expectation (no conditions): exit code 0.
func Exec(ctx context.Context, c *ssh.Client, spec StepSpec, maxOutput int) (StepOutput, error) {
	sess, err := c.NewSession()
	if err != nil {
		return StepOutput{}, domain.Fail(domain.CatSessionFailed, "cannot open session: %v", err)
	}
	defer sess.Close()
	pats := patterns(spec)
	stdout := NewOutputBuffer(maxOutput, "", pats)
	stderr := NewOutputBuffer(maxOutput, "", pats)
	sess.Stdout, sess.Stderr = stdout, stderr

	if err := sess.Start(spec.Command); err != nil {
		return StepOutput{}, domain.Fail(domain.CatSessionFailed, "cannot start command: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()

	timer := time.NewTimer(spec.CommandTimeout)
	defer timer.Stop()
	var fail error
	select {
	case err = <-waitErr:
	case <-timer.C:
		fail = domain.Fail(domain.CatCommandTimeout, "command did not complete within %s", spec.CommandTimeout)
	case <-ctx.Done():
		fail = ctxFailure(ctx, "running command")
	}
	if fail != nil {
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		<-waitErr // Wait returns once the channel is closed; buffers are then quiescent.
	}

	out := StepOutput{
		Output:    strings.TrimRight(Clean(string(stdout.Bytes())), "\n"),
		Raw:       string(stdout.Bytes()),
		Stderr:    strings.TrimRight(Clean(string(stderr.Bytes())), "\n"),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Bytes:     stdout.Total() + stderr.Total(),
	}
	if fail != nil {
		return out, fail
	}
	var exitErr *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		code := 0
		out.ExitCode = &code
	case errors.As(err, &exitErr):
		code := exitErr.ExitStatus()
		out.ExitCode = &code
	case errors.As(err, &missing):
	default:
		return out, domain.Fail(domain.CatSessionFailed, "session failed: %v", err)
	}

	want := spec.ExitCode
	if want == nil && spec.Regex == nil && len(pats) == 0 {
		zero := 0
		want = &zero
	}
	if want != nil {
		if out.ExitCode == nil {
			return out, domain.Fail(domain.CatCommandFailed, "remote side did not report an exit status (expected %d)", *want)
		}
		if *out.ExitCode != *want {
			return out, domain.Fail(domain.CatCommandFailed, "exit code %d, expected %d", *out.ExitCode, *want)
		}
	}
	if spec.Regex != nil && !spec.Regex.MatchString(tailString(out.Output, expectWindow)) {
		return out, domain.Fail(domain.CatCommandFailed, "output does not match %q", spec.Regex.String())
	}
	for i, c := range spec.Contains {
		if !stdout.Found(i) && !stderr.Found(i) {
			return out, domain.Fail(domain.CatCommandFailed, "expected output to contain %q", c)
		}
	}
	for i, c := range spec.NotContains {
		j := len(spec.Contains) + i
		if stdout.Found(j) || stderr.Found(j) {
			return out, domain.Fail(domain.CatCommandFailed, "output contains forbidden text %q", c)
		}
	}
	return out, nil
}

// String implements fmt.Stringer for logging without output content.
func (o StepOutput) String() string {
	return fmt.Sprintf("StepOutput{bytes=%d truncated=%v}", o.Bytes, o.Truncated)
}
