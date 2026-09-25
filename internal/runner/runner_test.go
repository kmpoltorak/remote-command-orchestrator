package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/job"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/sshtest"
)

var env = map[string]string{"LOGIN_PW": "login-secret", "SUDO_PW": "sudo-secret", "DB_PW": "db-secret-value"}

func lookup(k string) (string, bool) { v, ok := env[k]; return v, ok }

func target(name string, s *sshtest.Server) domain.Target {
	host, port, _ := net.SplitHostPort(s.Addr)
	p, _ := strconv.Atoi(port)
	return domain.Target{Endpoint: domain.Endpoint{Name: name, Address: host, Port: p, Username: "deploy",
		Credential: domain.Credential{Name: "pw", Type: "password", PasswordEnv: "LOGIN_PW", SudoPasswordEnv: "SUDO_PW"}}}
}

func opts(known string) Options {
	return Options{Concurrency: 10, ConnectTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second,
		StepTimeout: 10 * time.Second, RetryDelay: 10 * time.Millisecond, MaxRetryDelay: 50 * time.Millisecond,
		MaxOutput: 1 << 16, KnownHosts: known, Env: lookup, Logger: slog.New(slog.DiscardHandler)}
}

// loadJob writes a job file (plus extra files) into a temp dir and loads it.
func loadJob(t *testing.T, yaml string, files map[string]string) *job.Job {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
	}
	p := filepath.Join(dir, "job.yaml")
	os.WriteFile(p, []byte(yaml), 0o600)
	j, err := job.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func runJob(t *testing.T, ctx context.Context, in Input, o Options) *Report {
	t.Helper()
	r, err := Prepare(in, o)
	if err != nil {
		t.Fatal(err)
	}
	return r.Run(ctx)
}

func TestFullWorkflow(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret", SudoPassword: "sudo-secret"})
	dest := filepath.Join(srv.Dir, "etc", "app.conf")
	os.MkdirAll(filepath.Dir(dest), 0o755)
	j := loadJob(t, fmt.Sprintf(`
name: full
version: "1.0"
variables:
  greeting: {default: hello}
  db_password: {sensitive: true}
steps:
  - name: cmd
    command: "echo {{ .greeting }} from $(pwd)"
    expect: {contains: "{{ .greeting }}", not_contains: ERROR}
  - name: script
    script: run.sh
  - name: upload
    sudo: true
    copy: {src: app.conf.tmpl, dest: '%s', mode: "0640", template: true}
  - name: verify-upload
    command: 'cat %s'
    expect: {regex: 'port=8080'}
  - name: sudo-check
    sudo: true
    command: "echo sudo-user=$SUDO_USER; cat"   # cat proves stdin is not the password
  - name: secret
    sensitive: true
    command: "echo {{ .db_password }}"
`, dest, dest), map[string]string{
		"run.sh":        "echo script sees $greeting\necho leaked $db_password\n",
		"app.conf.tmpl": "greeting={{ .greeting }}\nport=8080\n",
	})
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}, VarEnv: map[string]string{"db_password": "DB_PW"}}, opts(sshtest.WriteKnownHosts(t, srv)))

	h := rep.Hosts[0]
	if !rep.OK() || h.Status != domain.StatusSuccess {
		t.Fatalf("expected success: %+v", h)
	}
	steps := map[string]StepResult{}
	for _, s := range h.Steps {
		steps[s.Name] = s
	}
	if !strings.HasPrefix(steps["cmd"].Stdout, "hello from "+srv.Dir) && !strings.Contains(steps["cmd"].Stdout, "hello from") {
		t.Errorf("cmd: %+v", steps["cmd"])
	}
	if s := steps["script"]; !strings.Contains(s.Stdout, "script sees hello") || !strings.Contains(s.Stdout, "leaked [REDACTED]") || strings.Contains(s.Stdout, "db-secret-value") {
		t.Errorf("script output must have secrets redacted: %q", s.Stdout)
	}
	data, err := os.ReadFile(dest)
	st, _ := os.Stat(dest)
	if err != nil || string(data) != "greeting=hello\nport=8080\n" || st.Mode().Perm() != 0o640 {
		t.Errorf("upload: %q %v %v", data, err, st.Mode())
	}
	if s := steps["sudo-check"]; s.Stdout != "sudo-user=deploy" {
		t.Errorf("sudo: %+v", s)
	}
	if s := steps["secret"]; s.Command != domain.SensitiveMask || s.Stdout != domain.SensitiveMask {
		t.Errorf("sensitive step leaked: %+v", s)
	}
	// All steps shared one connection; temp files were cleaned up.
	if srv.Conns.Load() != 1 {
		t.Errorf("conns=%d", srv.Conns.Load())
	}
	for _, c := range srv.Commands() {
		if strings.Contains(c, "db-secret-value") || strings.Contains(c, "sudo-secret") {
			t.Errorf("secret appeared in a remote command line: %q", c)
		}
	}
}

func TestFailuresAndContinueOnError(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	j := loadJob(t, `
name: fail
steps:
  - {name: ok, command: "true"}
  - {name: soft, command: "echo warn >&2; exit 4", continue_on_error: true}
  - {name: hard, command: "echo boom >&2; exit 1"}
  - {name: never, command: "touch never-ran"}
`, nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	h := rep.Hosts[0]
	if h.Status != domain.StatusFailed || h.FailedStep != "soft" || h.Category != domain.CatCommandFailed || h.Reason != "exit code 4, expected 0: warn" {
		t.Fatalf("first failure decides the host result: %+v", h)
	}
	want := []domain.Status{domain.StatusSuccess, domain.StatusFailed, domain.StatusFailed, domain.StatusSkipped}
	for i, s := range h.Steps {
		if s.Status != want[i] {
			t.Errorf("step %s: %s, want %s", s.Name, s.Status, want[i])
		}
	}
	if _, err := os.Stat(filepath.Join(srv.Dir, "never-ran")); err == nil {
		t.Error("step after a hard failure must not run")
	}
	if rep.OK() || rep.Summary.Failed != 1 {
		t.Fatalf("%+v", rep.Summary)
	}
}

func TestNoPasswdSudoNeverReceivesPassword(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"}) // NOPASSWD sudo
	j := loadJob(t, "name: n\nsteps: [{name: s, sudo: true, script: s.sh}]",
		map[string]string{"s.sh": "read -r line && echo \"LEAK:$line\" || echo stdin-empty\n"})
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	if s := rep.Hosts[0].Steps[0]; s.Status != domain.StatusSuccess || s.Stdout != "stdin-empty" {
		t.Fatalf("password must not reach the command under NOPASSWD sudo: %+v", s)
	}
}

func TestStepRetry(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	// Fails on the first two tries, succeeds on the third.
	j := loadJob(t, `
name: retry
steps:
  - name: flaky
    command: "n=$(cat c 2>/dev/null || echo 0); n=$((n+1)); echo $n > c; [ $n -ge 3 ]"
    retries: 2
`, nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	if s := rep.Hosts[0].Steps[0]; s.Status != domain.StatusSuccess || s.Attempts != 3 || s.Duration < Duration(20*time.Millisecond) {
		t.Fatalf("%+v", s) // two retry delays of >=5ms each plus command time
	}
	if rep.Hosts[0].Duration <= 0 || rep.Duration <= 0 {
		t.Fatal("durations must be recorded")
	}
}

func TestSudoFailures(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret", SudoPassword: "other"})
	j := loadJob(t, "name: s\nsteps: [{name: s, sudo: true, command: 'true'}]", nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	if h := rep.Hosts[0]; h.Status != domain.StatusFailed || !strings.Contains(h.Reason, "incorrect password") || strings.Contains(h.Reason, "sudo-secret") {
		t.Fatalf("%+v", h)
	}
	// Key credential without sudo password -> sudo -n, which fails fast instead of hanging.
	keyPath, pub := writeKey(t)
	keySrv := sshtest.Start(t, sshtest.Options{AuthorizedKey: pub, SudoPassword: "required"})
	tg := target("h2", keySrv)
	tg.Credential = domain.Credential{Name: "key", Type: "private_key", KeyFile: keyPath}
	rep = runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{tg}}, opts(sshtest.WriteKnownHosts(t, keySrv)))
	if h := rep.Hosts[0]; h.Status != domain.StatusFailed || !strings.Contains(h.Reason, "password is required") {
		t.Fatalf("%+v", h)
	}
}

func writeKey(t *testing.T) (string, ssh.PublicKey) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	p := filepath.Join(t.TempDir(), "id")
	os.WriteFile(p, pem.EncodeToMemory(block), 0o600)
	signer, _ := ssh.NewSignerFromKey(priv)
	return p, signer.PublicKey()
}

func TestConnectionRetryAndAuth(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	dead := target("dead", srv)
	dead.Port, _ = strconv.Atoi(port)
	badAuth := target("bad-auth", srv)
	badAuth.Credential = domain.Credential{Name: "bad", Type: "password", PasswordEnv: "SUDO_PW"}
	j := loadJob(t, "name: c\nsteps: [{name: s, command: 'true'}]", nil)
	o := opts(sshtest.WriteKnownHosts(t, srv))
	o.ConnectRetries = 2
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{dead, badAuth}}, o)
	for _, h := range rep.Hosts {
		switch h.Host {
		case "dead":
			if h.Category != domain.CatConnectionRefused || h.ConnectAttempts != 3 || h.Steps[0].Status != domain.StatusSkipped {
				t.Errorf("refused must be retried: %+v", h)
			}
		case "bad-auth":
			if h.Category != domain.CatAuthFailed || h.ConnectAttempts != 1 {
				t.Errorf("auth failure must not be retried: %+v", h)
			}
		}
	}
}

func TestPrepareValidatesEverythingBeforeConnecting(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	j := loadJob(t, "name: v\nvariables: {x: {required: true}, pw: {sensitive: true}}\nsteps: [{name: s, command: 'echo {{ .x }}'}]", nil)
	ok := target("ok", srv)
	ok.Variables = map[string]string{"x": "1"}
	missingVar := target("missing-var", srv)
	missingEnv := target("missing-env", srv)
	missingEnv.Variables = map[string]string{"x": "1"}
	missingEnv.Credential = domain.Credential{Name: "other", Type: "password", PasswordEnv: "NOT_SET"}
	_, err := Prepare(Input{Job: j, Targets: []domain.Target{ok, missingVar, missingEnv}, VarEnv: map[string]string{"pw": "DB_PW"}}, opts("/dev/null"))
	if err == nil || !strings.Contains(err.Error(), "missing-var") || !strings.Contains(err.Error(), "NOT_SET") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "db-secret-value") {
		t.Fatal("secret leaked in validation error")
	}
	if srv.Conns.Load() != 0 {
		t.Fatal("no host may be contacted when validation fails")
	}
}

func TestBoundedConcurrencyManyHosts(t *testing.T) {
	// One server so its peak counter sees every host at the same instant.
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	var targets []domain.Target
	for i := range 250 {
		targets = append(targets, target(fmt.Sprintf("host-%03d", i), srv))
	}
	j := loadJob(t, "name: many\nsteps: [{name: s, command: 'sleep 0.05; echo done'}]", nil)
	o := opts(sshtest.WriteKnownHosts(t, srv))
	o.Concurrency = 20
	before := runtime.NumGoroutine()
	rep := runJob(t, context.Background(), Input{Job: j, Targets: targets}, o)
	if rep.Summary.Success != 250 {
		t.Fatalf("%v", rep.Summary)
	}
	if peak := srv.PeakConcurrent(); peak > 20 || peak < 4 {
		t.Fatalf("peak concurrent commands %d, want between 4 and 20", peak)
	}
	for i, h := range rep.Hosts { // report order matches input order
		if h.Host != targets[i].Name {
			t.Fatalf("order: %s at %d", h.Host, i)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+10 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > before+10 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, g)
	}
}

func TestMaxFailuresAndProgress(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	var targets []domain.Target
	for i := range 40 {
		targets = append(targets, target(fmt.Sprintf("h%02d", i), srv))
	}
	j := loadJob(t, "name: bad\nsteps: [{name: s, command: 'sleep 0.05; exit 1'}]", nil)
	o := opts(sshtest.WriteKnownHosts(t, srv))
	o.Concurrency, o.MaxFailures, o.Progress = 4, 5, 20*time.Millisecond
	var logs strings.Builder
	var mu sync.Mutex
	o.Logger = slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logs.Write(p) }), nil))
	var streamed atomic.Int64
	o.OnHostDone = func(HostResult) { streamed.Add(1) }
	rep := runJob(t, context.Background(), Input{Job: j, Targets: targets}, o)
	// Up to MaxFailures + (Concurrency-1) hosts can fail: those already running finish.
	if rep.Summary.Failed < 5 || rep.Summary.Failed > 8 || rep.Summary.Skipped != 40-rep.Summary.Failed {
		t.Fatalf("%+v", rep.Summary)
	}
	if streamed.Load() != 40 {
		t.Fatalf("OnHostDone called %d times", streamed.Load())
	}
	if !strings.Contains(rep.Hosts[39].Reason, "--max-failures 5") || !strings.Contains(rep.Summary.String(), "skipped") {
		t.Fatalf("%+v", rep.Hosts[39])
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logs.String(), "msg=progress") {
		t.Fatal("no progress log")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestCancellation(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	var targets []domain.Target
	for i := range 30 {
		targets = append(targets, target(fmt.Sprintf("h%02d", i), srv))
	}
	j := loadJob(t, "name: slow\nsteps: [{name: s, command: 'sleep 30'}, {name: after, command: 'true'}]", nil)
	o := opts(sshtest.WriteKnownHosts(t, srv))
	o.Concurrency = 5
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	rep := runJob(t, ctx, Input{Job: j, Targets: targets}, o)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancellation too slow: %s", time.Since(start))
	}
	if rep.Summary.Cancelled != 30 {
		t.Fatalf("%v", rep.Summary)
	}
	for _, h := range rep.Hosts {
		if h.Steps[1].Status != domain.StatusSkipped {
			t.Fatalf("%s: step after cancel must be skipped", h.Host)
		}
	}
}

func TestBastionRun(t *testing.T) {
	inner := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	bastion := sshtest.Start(t, sshtest.Options{Password: "sudo-secret", AllowForward: true})
	tg := target("internal", inner)
	b := target("bastion", bastion)
	b.Credential = domain.Credential{Name: "b", Type: "password", PasswordEnv: "SUDO_PW"}
	tg.Bastion = &b.Endpoint
	j := loadJob(t, "name: b\nsteps: [{name: s, command: 'echo inside'}]", nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{tg}}, opts(sshtest.WriteKnownHosts(t, inner, bastion)))
	if s := rep.Hosts[0].Steps[0]; s.Stdout != "inside" {
		t.Fatalf("%+v", rep.Hosts[0])
	}
}

// fastReconnect shortens the reboot/disconnect timings for tests and makes the
// boot ID come from the test server's simulated boot_id file.
func fastReconnect(t *testing.T) {
	oldCmd, oldDelay, oldKA := bootIDCommand, reconnectDelay, keepaliveInterval
	bootIDCommand, reconnectDelay, keepaliveInterval = "cat boot_id", 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { bootIDCommand, reconnectDelay, keepaliveInterval = oldCmd, oldDelay, oldKA })
}

func statuses(h HostResult) string {
	var s []string
	for _, st := range h.Steps {
		s = append(s, string(st.Status))
	}
	return strings.Join(s, ",")
}

func TestRebootStep(t *testing.T) {
	fastReconnect(t)
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	before := srv.BootID()
	j := loadJob(t, `
name: reboot
steps:
  - {name: before, command: "echo up"}
  - {name: reboot, command: "rco-test-reboot 400ms", reboot: true}
  - {name: after, command: "cat boot_id"}
`, nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	h := rep.Hosts[0]
	if h.Status != domain.StatusSuccess || statuses(h) != "SUCCESS,SUCCESS,SUCCESS" {
		t.Fatalf("%s %+v", statuses(h), h)
	}
	if !strings.Contains(h.Steps[1].Note, "rebooted") || h.Steps[2].Stdout == strings.TrimSpace(before) {
		t.Fatalf("after-reboot step must run on the rebooted host: %+v", h.Steps)
	}
	if srv.Conns.Load() != 2 {
		t.Fatalf("want initial + one reconnect, got %d connections", srv.Conns.Load())
	}
}

func TestRebootHostDoesNotComeBack(t *testing.T) {
	fastReconnect(t)
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	j := loadJob(t, `
name: reboot
steps:
  - {name: reboot, command: "rco-test-reboot 1h", reboot: true, reconnect_timeout: 400ms}
  - {name: after, command: "true"}
`, nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	h := rep.Hosts[0]
	if h.Status != domain.StatusFailed || h.FailedStep != "reboot" || !strings.Contains(h.Reason, "did not come back within 400ms") || statuses(h) != "FAILED,SKIPPED" {
		t.Fatalf("%s %+v", statuses(h), h)
	}
}

func TestRebootRequiresNewBootID(t *testing.T) {
	fastReconnect(t)
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	// The connection drops but the host never reboots: the old boot ID must
	// not be mistaken for a host that is back.
	j := loadJob(t, "name: r\nsteps: [{name: reboot, command: rco-test-drop, reboot: true, reconnect_timeout: 500ms}]", nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	if h := rep.Hosts[0]; h.Status != domain.StatusFailed || !strings.Contains(h.Reason, "was not rebooted within 500ms") {
		t.Fatalf("%+v", h)
	}
}

func TestDisconnectStep(t *testing.T) {
	fastReconnect(t)
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	j := loadJob(t, `
name: net
steps:
  - {name: restart-network, command: rco-test-drop, disconnect: true}
  - {name: quick-restart, command: "true", disconnect: true}
  - {name: after, command: "echo still-here"}
`, nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	h := rep.Hosts[0]
	if h.Status != domain.StatusSuccess || statuses(h) != "SUCCESS,SUCCESS,SUCCESS" || h.Steps[2].Stdout != "still-here" {
		t.Fatalf("%s %+v", statuses(h), h)
	}
	if !strings.Contains(h.Steps[0].Note, "closed as expected") || h.Steps[1].Note != "" {
		t.Fatalf("notes: %q / %q", h.Steps[0].Note, h.Steps[1].Note)
	}
	if srv.Conns.Load() != 2 {
		t.Fatalf("one reconnect after the drop, none after the quick restart; got %d connections", srv.Conns.Load())
	}
}

func TestUnexpectedDisconnectIsAFailure(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Password: "login-secret"})
	j := loadJob(t, "name: n\nsteps: [{name: s, command: rco-test-drop}, {name: after, command: 'true'}]", nil)
	rep := runJob(t, context.Background(), Input{Job: j, Targets: []domain.Target{target("h1", srv)}}, opts(sshtest.WriteKnownHosts(t, srv)))
	if h := rep.Hosts[0]; h.Status != domain.StatusFailed || statuses(h) != "FAILED,SKIPPED" {
		t.Fatalf("%s %+v", statuses(h), h)
	}
}
