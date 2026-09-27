//go:build integration

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/runner"
)

// TestIntegrationAlpine runs a job against a disposable container with real
// OpenSSH, busybox, bash and password sudo: what internal/sshtest only fakes.
// Needs Docker. Run with: make integration
func TestIntegrationAlpine(t *testing.T) {
	docker(t, "build", "-q", "-t", "rco-it", "../../test/integration")
	id := docker(t, "run", "-d", "--rm", "-p", "127.0.0.1::22", "rco-it")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(docker(t, "logs", id), "Server listening"); {
		if time.Now().After(deadline) {
			t.Fatal("sshd did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	host, port, err := net.SplitHostPort(strings.Fields(docker(t, "port", id, "22/tcp"))[0])
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("RCO_IT_PW", "deploy-pass")
	t.Setenv("RCO_IT_TOKEN", "s3cret-value")
	dir := t.TempDir()
	inv := filepath.Join(dir, "hosts.yaml")
	os.WriteFile(inv, []byte(fmt.Sprintf(`
credentials:
  pw: {type: password, username: deploy, password_env: RCO_IT_PW}
hosts:
  - {name: alpine, address: %s, port: %s, credential: pw}
`, host, port)), 0o600)

	code, stdout, stderr := main(t, "run", "--execute", "-i", inv, "-j", "../../test/integration/job",
		"--known-hosts", filepath.Join(dir, "known_hosts"), "--accept-new-host-keys",
		"--var-env", "token=RCO_IT_TOKEN", "-o", "json", "-q")
	var rep runner.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, stdout, stderr)
	}
	if code != ExitOK || rep.Hosts[0].Status != domain.StatusSuccess {
		t.Fatalf("exit %d, host %s: failed step %q: %s\n%s", code, rep.Hosts[0].Status, rep.Hosts[0].FailedStep, rep.Hosts[0].Reason, stdout)
	}
	for _, secret := range []string{"s3cret-value", "deploy-pass"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("secret %q leaked into the output", secret)
		}
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
