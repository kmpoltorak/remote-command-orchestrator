package cli

import (
	"bytes"
	"encoding/json"
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
	srv                   *sshtest.Server
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
defaults: {credential: pw, address: unused}
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
	code, _, stderr := main(t, "run", "--inventory", f.inv, "--job", f.job, "--known-hosts", f.known)
	if code != ExitError || !strings.Contains(stderr, "address") {
		t.Fatalf("defaults.address is not a valid field: %d %s", code, stderr)
	}
}

func fixInventory(f fixture) {
	data, _ := os.ReadFile(f.inv)
	os.WriteFile(f.inv, bytes.Replace(data, []byte(", address: unused"), nil, 1), 0o600)
}

func TestRunJSONAndReport(t *testing.T) {
	f := setup(t)
	fixInventory(f)
	report := filepath.Join(f.dir, "report.yaml")
	code, stdout, stderr := main(t, "run", "--inventory", f.inv, "--job", f.job, "--known-hosts", f.known,
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
	fixInventory(f)
	code, stdout, _ := main(t, "run", "--inventory", f.inv, "--job", f.job, "--known-hosts", f.known,
		"--host", "other", "--var", "color=green", "--verbose")
	if code != ExitOK || !strings.Contains(stdout, "other") || !strings.Contains(stdout, "| color=green") ||
		!strings.Contains(stdout, "1 hosts: 1 succeeded") {
		t.Fatalf("%d\n%s", code, stdout)
	}
}

func TestDryRunAndValidateDoNotConnect(t *testing.T) {
	f := setup(t)
	fixInventory(f)
	code, stdout, _ := main(t, "run", "--inventory", f.inv, "--job", f.job, "--dry-run", "--tag", "prod")
	if code != ExitOK || !strings.Contains(stdout, "echo color=red") || !strings.Contains(stdout, "dry run: 2 hosts") {
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
	if f.srv.Conns.Load() != 0 {
		t.Fatal("dry-run and validate must not connect")
	}
}

func TestUsageErrors(t *testing.T) {
	f := setup(t)
	fixInventory(f)
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
