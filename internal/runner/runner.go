// Package runner executes a job against many hosts with bounded concurrency
// and produces a report. Everything that can be checked (variables,
// templates, credentials) is checked for every host before any connection
// is opened, so a typo never results in a half-applied change.
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/credentials"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/job"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/sshx"
)

// Options are the run settings (CLI flags).
type Options struct {
	Concurrency      int
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	StepTimeout      time.Duration // default when the job file sets none
	ConnectRetries   int           // extra attempts for transient connection failures
	RetryDelay       time.Duration // base delay; doubles per attempt with jitter
	MaxRetryDelay    time.Duration
	MaxOutput        int // retained bytes per step stream
	KnownHosts       string
	AcceptNewHosts   bool // add keys of unknown hosts to KnownHosts; changed keys still fail
	Insecure         bool
	Env              credentials.Env
	Logger           *slog.Logger
	SkipCredentials  bool // dry-run: preview without reading keys or passwords
	// MaxFailures stops starting new hosts once this many hosts have failed
	// (0 = never stop). Hosts already running finish; the rest are SKIPPED.
	MaxFailures int
	// Progress logs a progress line at this interval (0 = off).
	Progress time.Duration
	// OnHostDone is called as soon as each host has a final result, from
	// several goroutines at once. Used to stream reports to disk.
	OnHostDone func(HostResult)
}

// Input is what to run where.
type Input struct {
	Job     *job.Job
	Targets []domain.Target
	Vars    map[string]string // --var
	VarEnv  map[string]string // --var-env
}

// Plan is one host, fully prepared.
type Plan struct {
	Target  domain.Target
	Actions []job.Action
	auth    *credentials.Auth
	bastion *credentials.Auth
}

// Runner holds prepared plans and the redactor for one run.
type Runner struct {
	opts   Options
	in     Input
	Plans  []Plan
	redact *credentials.Redactor
	dialer *sshx.Dialer
}

// Prepare validates every host up front: variables, templates and secrets.
// It returns all problems at once.
func Prepare(in Input, o Options) (*Runner, error) {
	if o.Env == nil {
		o.Env = os.LookupEnv
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	r := &Runner{opts: o, in: in, redact: &credentials.Redactor{}}
	r.dialer = &sshx.Dialer{
		ConnectTimeout:   o.ConnectTimeout,
		HandshakeTimeout: o.HandshakeTimeout,
		HostKeys:         &sshx.HostKeys{Path: credentials.ExpandHome(o.KnownHosts), Insecure: o.Insecure, AcceptNew: o.AcceptNewHosts, Logger: o.Logger},
	}
	auths := map[string]*credentials.Auth{} // one secret lookup per credential
	resolve := func(c domain.Credential) (*credentials.Auth, error) {
		if o.SkipCredentials {
			return nil, nil
		}
		if a, ok := auths[c.Name]; ok {
			return a, nil
		}
		a, err := credentials.Resolve(c, o.Env)
		if err != nil {
			return nil, err
		}
		r.redact.Add(a.Secrets...)
		auths[c.Name] = a
		return a, nil
	}
	var issues []string
	for _, t := range in.Targets {
		vars, secrets, err := in.Job.Resolve(job.Inputs{Host: t.Variables, Job: in.Vars, JobEnv: in.VarEnv}, o.Env)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: %v", t.Name, err))
			continue
		}
		r.redact.Add(secrets...)
		acts, err := in.Job.Build(vars, job.Settings{Timeout: o.StepTimeout, RetryDelay: o.RetryDelay})
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: %v", t.Name, err))
			continue
		}
		p := Plan{Target: t, Actions: acts}
		if p.auth, err = resolve(t.Credential); err != nil {
			issues = append(issues, fmt.Sprintf("%s: %v", t.Name, err))
		}
		if t.Bastion != nil {
			if p.bastion, err = resolve(t.Bastion.Credential); err != nil {
				issues = append(issues, fmt.Sprintf("%s: bastion: %v", t.Name, err))
			}
		}
		r.Plans = append(r.Plans, p)
	}
	if len(issues) > 0 {
		// Redact: an env-sourced value may appear in a validation message.
		return nil, fmt.Errorf("%s", r.redact.String(strings.Join(issues, "\n")))
	}
	return r, nil
}

// Run executes all plans. It always returns a complete report; cancelled
// hosts are reported as CANCELLED.
func (r *Runner) Run(ctx context.Context) *Report {
	rep := newReport(r.in.Job)
	rep.Hosts = make([]HostResult, len(r.Plans))
	if r.opts.Insecure {
		r.opts.Logger.Warn("INSECURE: host key verification is disabled (--insecure-skip-host-key-check)")
	}
	var failed, done, running atomic.Int64
	finish := func(i int, h HostResult) {
		rep.Hosts[i] = h
		if h.Status == domain.StatusFailed {
			failed.Add(1)
		}
		done.Add(1)
		if r.opts.OnHostDone != nil {
			r.opts.OnHostDone(h)
		}
	}
	stopProgress := r.logProgress(len(r.Plans), &done, &running, &failed)
	defer stopProgress()

	conc := max(1, r.opts.Concurrency)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, p := range r.Plans {
		select {
		case sem <- struct{}{}: // bounded: at most conc host goroutines exist
		case <-ctx.Done():
			finish(i, notStarted(p, domain.StatusCancelled, "cancelled before start"))
			continue
		}
		if m := r.opts.MaxFailures; m > 0 && failed.Load() >= int64(m) {
			<-sem
			finish(i, notStarted(p, domain.StatusSkipped, fmt.Sprintf("not started: %d hosts failed (--max-failures %d)", failed.Load(), m)))
			continue
		}
		running.Add(1)
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			h := r.runHost(ctx, p)
			running.Add(-1)
			finish(i, h)
		}()
	}
	wg.Wait()
	rep.finish()
	return rep
}

// logProgress logs done/total, failures and an ETA until the returned stop is called.
func (r *Runner) logProgress(total int, done, running, failed *atomic.Int64) (stop func()) {
	if r.opts.Progress <= 0 {
		return func() {}
	}
	start := time.Now()
	t := time.NewTicker(r.opts.Progress)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				d := done.Load()
				args := []any{"done", d, "total", total, "running", running.Load(), "failed", failed.Load()}
				if d > 0 {
					eta := time.Duration(float64(time.Since(start)) / float64(d) * float64(int64(total)-d))
					args = append(args, "eta", eta.Round(time.Second).String())
				}
				r.opts.Logger.Info("progress", args...)
			}
		}
	}()
	return func() { t.Stop(); close(quit) }
}

func notStarted(p Plan, status domain.Status, reason string) HostResult {
	h := HostResult{Host: p.Target.Name, Address: p.Target.Addr(), Status: status, Reason: reason}
	if status == domain.StatusCancelled {
		h.Category = domain.CatCancelled
	}
	for _, a := range p.Actions {
		h.Steps = append(h.Steps, StepResult{Name: a.Name, Kind: a.Kind, Command: a.Display, Status: domain.StatusSkipped})
	}
	return h
}

func (r *Runner) runHost(ctx context.Context, p Plan) (h HostResult) {
	start := time.Now()
	log := r.opts.Logger.With("host", p.Target.Name)
	h = HostResult{Host: p.Target.Name, Address: p.Target.Addr(), Status: domain.StatusSuccess}
	fail := func(f *domain.Failure, step string) {
		if h.Category == "" { // first failure decides the host result
			h.Category, h.Reason, h.FailedStep = f.Category, r.redact.String(f.Reason), step
			h.Status = domain.StatusFailed
			if f.Category == domain.CatCancelled {
				h.Status = domain.StatusCancelled
			}
		}
	}
	defer func() {
		h.Duration = Duration(time.Since(start))
		log.Info("host finished", "status", h.Status, "failed_step", h.FailedStep, "category", h.Category, "duration_ms", time.Since(start).Milliseconds())
	}()

	client, err := r.connect(ctx, p, &h, log)
	if err != nil {
		fail(domain.AsFailure(err), "")
		for _, a := range p.Actions {
			h.Steps = append(h.Steps, StepResult{Name: a.Name, Kind: a.Kind, Command: a.Display, Status: domain.StatusSkipped})
		}
		return h
	}
	// The client can be replaced by a reconnect after a reboot/disconnect step.
	// Every blocking call (Dial, Exec, sleeps) honours ctx, so Ctrl+C unblocks them.
	defer func() {
		if client != nil {
			_ = client.Close()
		}
	}()

	sudoPW := r.needsSudoPassword(ctx, client, p)
	stopped := false
	for _, a := range p.Actions {
		if stopped {
			h.Steps = append(h.Steps, StepResult{Name: a.Name, Kind: a.Kind, Command: a.Display, Status: domain.StatusSkipped})
			continue
		}
		var sr StepResult
		var f *domain.Failure
		switch {
		case a.Disconnect:
			sr, f, client = r.runDisconnecting(ctx, client, p, a, sudoPW, log)
		case a.FireAndForget:
			sr, f = r.runStep(ctx, client.Client, p, a, sudoPW, log)
			if f != nil && f.Category != domain.CatCancelled && (f.Category == domain.CatSessionFailed || sr.ExitCode == nil) {
				f = nil // the command cut the connection while starting: that is fine
				sr.Status, sr.Category, sr.Reason = domain.StatusSuccess, "", ""
			}
			if f == nil {
				sr.Note = "started; result not checked (fire and forget)"
			}
		default:
			sr, f = r.runStep(ctx, client.Client, p, a, sudoPW, log)
		}
		h.Steps = append(h.Steps, sr)
		if f != nil {
			fail(f, a.Name)
			if !a.ContinueOnError || client == nil || f.Category == domain.CatCancelled || f.Category == domain.CatSessionFailed {
				stopped = true
			}
		}
	}
	return h
}

// Tunables for reboot/disconnect steps (variables so tests can shorten them).
var (
	// bootIDCommand prints an ID that changes on every boot (Linux).
	bootIDCommand     = "cat /proc/sys/kernel/random/boot_id"
	reconnectDelay    = 5 * time.Second // pause between attempts to reach the host again
	keepaliveInterval = 5 * time.Second // three missed keepalives = connection lost
)

// runDisconnecting runs a step that may drop the connection (reboot, network
// or sshd restart). A lost connection is the expected outcome, not an error.
// Afterwards rco reconnects; for a reboot it waits for a new boot ID, so it
// cannot mistake the host that is still shutting down for one that is back.
// It returns the client to use for the next steps (nil if the host is gone).
func (r *Runner) runDisconnecting(ctx context.Context, c *sshx.Client, p Plan, a job.Action, sudoPW bool, log *slog.Logger) (StepResult, *domain.Failure, *sshx.Client) {
	oldBoot := ""
	if a.Reboot {
		id, f := r.bootID(ctx, c)
		if f != nil {
			f = domain.Fail(f.Category, "cannot read the boot ID before rebooting: %s", f.Reason)
			return StepResult{Name: a.Name, Kind: a.Kind, Command: a.Display, Status: domain.StatusFailed, Category: f.Category, Reason: r.redact.String(f.Reason)}, f, c
		}
		oldBoot = id
	}
	// A silently cut connection (no TCP reset) is noticed within seconds.
	stop := sshx.KeepAlive(c.Client, keepaliveInterval, 3)
	sr, f := r.runStep(ctx, c.Client, p, a, sudoPW, log)
	stop()
	lost := f != nil && (f.Category == domain.CatSessionFailed || (f.Category == domain.CatCommandFailed && sr.ExitCode == nil))
	if f != nil && !lost {
		return sr, f, c // a real failure while the connection was fine
	}
	if lost {
		sr.Status, sr.Category, sr.Reason = domain.StatusSuccess, "", ""
	}
	if !a.Reboot && !lost && sshx.Alive(c.Client, keepaliveInterval) {
		return sr, nil, c // the connection survived, e.g. a quick network restart
	}
	_ = c.Close()
	start := time.Now()
	log.Info("waiting for host to come back", "step", a.Name, "reboot", a.Reboot, "timeout", a.ReconnectTimeout.String())
	nc, wf := r.waitForHost(ctx, p, a.ReconnectTimeout, oldBoot)
	if wf != nil {
		sr.Status, sr.Category, sr.Reason = domain.StatusFailed, wf.Category, r.redact.String(wf.Reason)
		if wf.Category == domain.CatCancelled {
			sr.Status = domain.StatusCancelled
		}
		return sr, wf, nil
	}
	back := time.Since(start).Round(time.Second)
	sr.Note = fmt.Sprintf("connection closed as expected; host back after %s", back)
	if a.Reboot {
		sr.Note = fmt.Sprintf("host rebooted (new boot ID) and was back after %s", back)
	}
	log.Info("host is back", "step", a.Name, "after", back.String())
	return sr, nil, nc
}

// waitForHost reconnects until the host answers (with a boot ID other than
// oldBoot, when set) or timeout passes. Auth and host key errors end the wait:
// they will not fix themselves, and a changed host key must never be retried.
func (r *Runner) waitForHost(ctx context.Context, p Plan, timeout time.Duration, oldBoot string) (*sshx.Client, *domain.Failure) {
	deadline := time.Now().Add(timeout)
	last := domain.Fail(domain.CatConnectionTimeout, "no connection attempt made")
	sawOldBoot := false
	for {
		if sleep(ctx, reconnectDelay) != nil {
			return nil, domain.Fail(domain.CatCancelled, "cancelled while waiting for the host to come back")
		}
		if time.Now().After(deadline) {
			if sawOldBoot {
				return nil, domain.Fail(domain.CatCommandFailed, "host is reachable but was not rebooted within %s (boot ID unchanged)", timeout)
			}
			return nil, domain.Fail(domain.CatConnectionTimeout, "host did not come back within %s (last: %s)", timeout, last.Reason)
		}
		dctx, cancel := context.WithDeadline(ctx, deadline)
		c, err := r.dial(dctx, p)
		cancel()
		if err != nil {
			last = domain.AsFailure(err)
			if ctx.Err() != nil {
				return nil, domain.Fail(domain.CatCancelled, "cancelled while waiting for the host to come back")
			}
			switch last.Category {
			case domain.CatAuthFailed, domain.CatHostKeyMismatch, domain.CatHostKeyUnknown:
				return nil, last
			}
			continue
		}
		if oldBoot == "" {
			return c, nil
		}
		id, f := r.bootID(ctx, c)
		if f == nil && id != oldBoot {
			return c, nil
		}
		_ = c.Close()
		if last = f; f == nil {
			sawOldBoot = true
			last = domain.Fail(domain.CatConnectionTimeout, "host still runs the old boot (not rebooted yet)")
		}
	}
}

func (r *Runner) bootID(ctx context.Context, c *sshx.Client) (string, *domain.Failure) {
	res, err := sshx.Exec(ctx, c.Client, sshx.Request{Command: bootIDCommand, Timeout: 30 * time.Second, MaxOutput: 4096})
	if err != nil {
		return "", domain.AsFailure(err)
	}
	id := strings.TrimSpace(res.Stdout)
	if res.ExitCode == nil || *res.ExitCode != 0 || id == "" {
		return "", domain.Fail(domain.CatCommandFailed, "%s failed: %s", bootIDCommand, lastLine(res.Stderr))
	}
	return id, nil
}

func (r *Runner) dial(ctx context.Context, p Plan) (*sshx.Client, error) {
	target := sshx.Hop{Addr: p.Target.Addr(), User: p.Target.Username, Methods: p.auth.Methods}
	var bastion *sshx.Hop
	if b := p.Target.Bastion; b != nil {
		bastion = &sshx.Hop{Addr: b.Addr(), User: b.Username, Methods: p.bastion.Methods}
	}
	return r.dialer.Dial(ctx, target, bastion, nil)
}

// connect dials with retries for transient failures only.
func (r *Runner) connect(ctx context.Context, p Plan, h *HostResult, log *slog.Logger) (*sshx.Client, error) {
	for attempt := 1; ; attempt++ {
		h.ConnectAttempts = attempt
		c, err := r.dial(ctx, p)
		if err == nil {
			return c, nil
		}
		f := domain.AsFailure(err)
		if !f.Category.Retryable() || attempt > r.opts.ConnectRetries || ctx.Err() != nil {
			return nil, err
		}
		log.Warn("connection failed, retrying", "attempt", attempt, "category", f.Category, "reason", f.Reason)
		if err := sleep(ctx, backoff(r.opts.RetryDelay, r.opts.MaxRetryDelay, attempt)); err != nil {
			return nil, domain.Fail(domain.CatCancelled, "cancelled while waiting to reconnect")
		}
	}
}

// needsSudoPassword probes once per host whether sudo works without a
// password (NOPASSWD). Only if it does not is the password sent. Otherwise a
// password written to stdin would be passed on to the command itself.
func (r *Runner) needsSudoPassword(ctx context.Context, c *sshx.Client, p Plan) bool {
	if p.auth.SudoPassword == "" {
		return false
	}
	for _, a := range p.Actions {
		if a.Sudo {
			res, err := sshx.Exec(ctx, c.Client, sshx.Request{Command: "sudo -n true", Timeout: 30 * time.Second, MaxOutput: 4096})
			return err != nil || res.ExitCode == nil || *res.ExitCode != 0
		}
	}
	return false
}

func (r *Runner) runStep(ctx context.Context, c *ssh.Client, p Plan, a job.Action, sudoPW bool, log *slog.Logger) (sr StepResult, f *domain.Failure) {
	sr = StepResult{Name: a.Name, Kind: a.Kind, Command: a.Display}
	start := time.Now()
	defer func() { sr.Duration = Duration(time.Since(start)) }()
	for try := 0; try <= a.Retries; try++ {
		if try > 0 {
			log.Warn("step failed, retrying", "step", a.Name, "attempt", try+1, "category", f.Category)
			if sleep(ctx, a.RetryDelay) != nil {
				break
			}
		}
		sr.Attempts = try + 1
		var res sshx.Result
		res, f = r.attempt(ctx, c, p, a, sudoPW)
		sr.ExitCode = res.ExitCode
		sr.Stdout, sr.Stderr, sr.Truncated = r.mask(a, res.Stdout), r.mask(a, res.Stderr), res.Truncated
		// Only outcome failures are worth repeating; a dead session or Ctrl+C is not.
		if f == nil || (f.Category != domain.CatCommandFailed && f.Category != domain.CatCommandTimeout) {
			break
		}
	}
	sr.Status = domain.StatusSuccess
	if f != nil {
		sr.Status, sr.Category, sr.Reason = domain.StatusFailed, f.Category, r.redact.String(f.Reason)
		if f.Category == domain.CatCancelled {
			sr.Status = domain.StatusCancelled
		}
	}
	log.Debug("step finished", "step", a.Name, "status", sr.Status, "attempts", sr.Attempts)
	return sr, f
}

func (r *Runner) mask(a job.Action, s string) string {
	if a.Sensitive && s != "" {
		return domain.SensitiveMask
	}
	return r.redact.String(s)
}

// attempt uploads content if needed, runs the command and checks expectations.
func (r *Runner) attempt(ctx context.Context, c *ssh.Client, p Plan, a job.Action, sudoPW bool) (sshx.Result, *domain.Failure) {
	tmp := ""
	if a.Content != nil {
		res, err := sshx.Exec(ctx, c, sshx.Request{Command: job.UploadCommand, Stdin: a.Content, Timeout: a.Timeout, MaxOutput: 4096})
		if err != nil {
			return res, domain.AsFailure(err)
		}
		if res.ExitCode == nil || *res.ExitCode != 0 || res.Stdout == "" {
			return res, domain.Fail(domain.CatCommandFailed, "upload to a remote temp file failed: %s", res.Stderr)
		}
		tmp = res.Stdout
	}
	sudoPW = a.Sudo && sudoPW
	var stdin []byte
	if sudoPW {
		stdin = []byte(p.auth.SudoPassword + "\n")
	}
	patterns := append(append([]string{}, a.Contains...), a.NotContains...)
	res, err := sshx.Exec(ctx, c, sshx.Request{Command: a.Remote(tmp, sudoPW), Stdin: stdin, Timeout: a.Timeout, MaxOutput: r.opts.MaxOutput, Patterns: patterns})
	if err != nil {
		return res, domain.AsFailure(err)
	}
	return res, check(a, res)
}

// check applies expectations: exit code (default 0), contains, not_contains, regex.
func check(a job.Action, res sshx.Result) *domain.Failure {
	switch {
	case res.ExitCode == nil:
		return domain.Fail(domain.CatCommandFailed, "remote side did not report an exit status")
	case *res.ExitCode != a.ExitCode:
		reason := fmt.Sprintf("exit code %d, expected %d", *res.ExitCode, a.ExitCode)
		if line := lastLine(res.Stderr); line != "" && !a.Sensitive {
			reason += ": " + line
		}
		return domain.Fail(domain.CatCommandFailed, "%s", reason)
	}
	for i, s := range a.Contains {
		if !res.Found(i) {
			return domain.Fail(domain.CatCommandFailed, "output does not contain %q", s)
		}
	}
	for i, s := range a.NotContains {
		if res.Found(len(a.Contains) + i) {
			return domain.Fail(domain.CatCommandFailed, "output contains forbidden text %q", s)
		}
	}
	if a.Regex != nil && !a.Regex.MatchString(res.Stdout) {
		return domain.Fail(domain.CatCommandFailed, "output does not match %q", a.Regex.String())
	}
	return nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimSpace(s[strings.LastIndexByte(s, '\n')+1:])
}

func backoff(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base << (attempt - 1)
	if d > maxDelay || d <= 0 {
		d = maxDelay
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter to avoid reconnect storms, not security
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
