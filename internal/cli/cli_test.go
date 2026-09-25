package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/runner"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/sshtest"
)

type fixture struct {
	srv                  *sshtest.Server
	inv, job, known, dir string
}

func setup(t *testing.T) fixture {
	t.Setenv("RCO_TEST_PW", "cli-secret")
	srv := sshtest.Start(t, sshtest.Options{Password: "cli-secret"})
	_, port, _ := net.SplitHostPort(srv.Addr)
	dir := t.TempDir()
	f := fixture{srv: srv, dir: dir, known: sshtest.WriteKnownHosts(t, srv),
		inv: filepath.Join(dir, "inventory.yaml"), job: filepath.Join(dir, "job.yaml")}
	os.WriteFile(f.inv, []byte(fmt.Sprintf(`
credentials:
  pw: {type: password, username: deploy, password_env: RCO_TEST_PW}
defaults: {credential: pw}
groups:
  web:
    defaults: {tags: [prod]}
    hosts:
      - {name: web-01, address: 127.0.0.1, port: %[1]s, variables: {color: blue}}
      - {name: web-02, address: 127.0.0.1, port: %[1]s, variables: {color: red}}
hosts:
  - {name: other, address: 127.0.0.1, port: %[1]s}
`, port)), 0o600)
	os.WriteFile(f.job, []byte(`
name: cli-test
version: "1.0"
max_failures: "100%"
variables: {color: {default: none}}
steps:
  - {name: greet, command: "echo color={{ .color }}"}
  - {name: fail-on-red, command: "[ {{ .color }} != red ]"}
`), 0o600)
	return f
}

func main(t *testing.T, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestInventoryWithUnknownFieldFails(t *testing.T) {
	f := setup(t)
	os.WriteFile(f.inv, []byte("defaults: {nosuchfield: typo}\n"), 0o600)
	code, _, stderr := main(t, "run", "--inventory", f.inv, "--job", f.job)
	if code != ExitError || !strings.Contains(stderr, "nosuchfield") {
		t.Fatalf("unknown fields must be rejected: %d %s", code, stderr)
	}
}

func TestRunJSONAndReport(t *testing.T) {
	f := setup(t)
	report := filepath.Join(f.dir, "report.yaml")
	code, stdout, stderr := main(t, "run", "--execute", "--inventory", f.inv, "--job", f.job, "--known-hosts", f.known,
		"--group", "web", "--output", "json", "--report", report)
	if code != ExitHostsFailed {
		t.Fatalf("web-02 fails, want exit 2, got %d: %s", code, stderr)
	}
	var rep runner.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout must be pure JSON (logs go to stderr): %v\n%s", err, stdout)
	}
	if rep.Summary.Total != 2 || rep.Summary.Success != 1 || rep.Hosts[1].FailedStep != "fail-on-red" {
		t.Fatalf("%+v", rep)
	}
	if rep.Hosts[0].Steps[0].Stdout != "color=blue" {
		t.Fatalf("host variables: %+v", rep.Hosts[0].Steps[0])
	}
	data, err := os.ReadFile(report)
	st, _ := os.Stat(report)
	var yrep map[string]any
	if err != nil || yaml.Unmarshal(data, &yrep) != nil || yrep["job"] != "cli-test" || st.Mode().Perm() != 0o600 {
		t.Fatalf("report file: %v %v", err, st.Mode())
	}
	if strings.Contains(stdout+stderr+string(data), "cli-secret") {
		t.Fatal("password leaked")
	}
}

func TestRunTableAndVars(t *testing.T) {
	f := setup(t)
	code, stdout, _ := main(t, "run", "--execute", "--inventory", f.inv, "--job", f.job, "--known-hosts", f.known,
		"--host", "other", "--var", "color=green", "--verbose")
	if code != ExitOK || !strings.Contains(stdout, "other") || !strings.Contains(stdout, "| color=green") ||
		!strings.Contains(stdout, "1 hosts: 1 succeeded") {
		t.Fatalf("%d\n%s", code, stdout)
	}
}

func TestRunPreviewsByDefaultAndValidateDoesNotConnect(t *testing.T) {
	f := setup(t)
	os.Unsetenv("RCO_TEST_PW") // a preview must not need secrets
	code, stdout, _ := main(t, "run", "--inventory", f.inv, "--job", f.job, "--tag", "prod")
	t.Setenv("RCO_TEST_PW", "cli-secret")
	if code != ExitOK || !strings.Contains(stdout, "echo color=red") || !strings.Contains(stdout, "preview: 2 hosts") {
		t.Fatalf("%d\n%s", code, stdout)
	}
	code, stdout, _ = main(t, "validate", "--job", f.job)
	if code != ExitOK || !strings.Contains(stdout, "is valid") {
		t.Fatalf("%d %s", code, stdout)
	}
	code, stdout, _ = main(t, "validate", "--job", f.job, "--inventory", f.inv)
	if code != ExitOK || !strings.Contains(stdout, "valid for 3 hosts") {
		t.Fatalf("%d %s", code, stdout)
	}
	os.Unsetenv("RCO_TEST_PW")
	if code, _, stderr := main(t, "validate", "--job", f.job, "--inventory", f.inv); code != ExitError || !strings.Contains(stderr, "RCO_TEST_PW") {
		t.Fatalf("validate must check credentials: %d %s", code, stderr)
	}
	if f.srv.Conns.Load() != 0 {
		t.Fatal("run without --execute and validate must not connect")
	}
}

func TestShortAliases(t *testing.T) {
	f := setup(t)
	code, stdout, stderr := main(t, "run", "--execute", "-i", f.inv, "-j", f.job, "--known-hosts", f.known,
		"-g", "web", "-t", "prod", "-H", "web-01", "-o", "json", "-q", "-c", "1")
	if code != ExitOK || strings.Contains(stderr, "level=INFO") {
		t.Fatalf("%d %s", code, stderr)
	}
	var rep runner.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || rep.Summary.Total != 1 || rep.Hosts[0].Host != "web-01" {
		t.Fatalf("%v %+v", err, rep.Summary)
	}
	if code, out, _ := main(t, "run", "-i", f.inv, "-j", f.job, "-H", "other", "-v"); code != ExitOK || !strings.Contains(out, "preview: 1 hosts") {
		t.Fatalf("bool alias -v: %d %s", code, out)
	}
}

func TestHelpListsEveryFlag(t *testing.T) {
	code, out, _ := main(t, "help")
	if code != ExitOK {
		t.Fatal(code)
	}
	newFlags("x").fs.VisitAll(func(f *flag.Flag) {
		if f.Usage == "alias" {
			if !strings.Contains(out, "-"+f.Name+", --") {
				t.Errorf("alias -%s missing from help", f.Name)
			}
			return
		}
		if !strings.Contains(out, "--"+f.Name+" ") && !strings.Contains(out, "--"+f.Name+"\t") && !strings.Contains(out, "--"+f.Name+"  ") {
			t.Errorf("--%s missing from help", f.Name)
		}
	})
	if !strings.Contains(out, "--timeout DURATION") || !strings.Contains(out, "-c, --concurrency N") {
		t.Errorf("value names:\n%s", out)
	}
}

func TestMaxFailuresFromJobAndOverride(t *testing.T) {
	f := setup(t)
	os.WriteFile(f.job, bytes.Replace(mustRead(f.job), []byte(`max_failures: "100%"`), []byte(`max_failures: 1`), 1), 0o600)
	// The job's max_failures is applied (skipping itself is covered in the runner tests).
	code, stdout, _ := main(t, "run", "--execute", "-i", f.inv, "-j", f.job, "--known-hosts", f.known, "-c", "1", "-o", "json", "-q")
	var r runner.Report
	if code != ExitHostsFailed || json.Unmarshal([]byte(stdout), &r) != nil || r.Summary.Failed != 1 {
		t.Fatalf("%d %+v", code, r.Summary)
	}
	// Preview shows the effective limit; the flag overrides the job.
	_, out, _ := main(t, "run", "-i", f.inv, "-j", f.job, "--max-failures", "50%")
	if !strings.Contains(out, "stop after 2 failed hosts") {
		t.Fatalf("override: %s", out)
	}
	if code, _, stderr := main(t, "run", "-i", f.inv, "-j", f.job, "--max-failures", "0"); code != ExitError || !strings.Contains(stderr, "max failures") {
		t.Fatalf("invalid override must fail: %d %s", code, stderr)
	}
}

func mustRead(p string) []byte { b, _ := os.ReadFile(p); return b }

func TestJSONLReportAndOnlyFailed(t *testing.T) {
	f := setup(t)
	rep := filepath.Join(f.dir, "run.jsonl")
	code, _, stderr := main(t, "run", "--execute", "-i", f.inv, "-j", f.job, "--known-hosts", f.known, "--report", rep, "-q")
	if code != ExitHostsFailed {
		t.Fatalf("web-02 fails: %d %s", code, stderr)
	}
	data, _ := os.ReadFile(rep)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 || !strings.Contains(lines[3], `"summary"`) {
		t.Fatalf("want 3 host lines + summary:\n%s", data)
	}
	// Rerun only what did not succeed (web-02 still fails: inventory variables win).
	code, stdout, stderr := main(t, "run", "--execute", "-i", f.inv, "-j", f.job, "--known-hosts", f.known,
		"--only-failed", rep, "-o", "json", "-q")
	var r runner.Report
	if code != ExitHostsFailed || json.Unmarshal([]byte(stdout), &r) != nil || r.Summary.Total != 1 || r.Hosts[0].Host != "web-02" {
		t.Fatalf("%d %s %s", code, stdout, stderr)
	}
	// A preview must not leave an empty report behind.
	os.Remove(rep)
	main(t, "run", "-i", f.inv, "-j", f.job, "--report", rep)
	if _, err := os.Stat(rep); err == nil {
		t.Fatal("preview must not create a .jsonl report")
	}
}

func TestUsageErrors(t *testing.T) {
	f := setup(t)
	cases := [][]string{
		{},
		{"bogus"},
		{"run", "--job", f.job},
		{"run", "--inventory", f.inv},
		{"run", "--inventory", f.inv, "--job", f.job, "--output", "xml"},
		{"run", "--inventory", f.inv, "--job", f.job, "--var", "novalue"},
		{"run", "--inventory", f.inv, "--job", f.job, "--host", "nope"},
		{"run", "--inventory", f.inv, "--job", f.job, "--tag", "no-such-tag"},
	}
	for _, args := range cases {
		if code, _, _ := main(t, args...); code != ExitError {
			t.Errorf("%v: want exit 1, got %d", args, code)
		}
	}
	if code, out, _ := main(t, "version"); code != ExitOK || !strings.HasPrefix(out, "rco ") {
		t.Fatal("version")
	}
}
