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
	_, inv, known := container(t, "rco-it", "../../test/integration", "Server listening", "deploy", "deploy-pass")
	t.Setenv("RCO_IT_TOKEN", "s3cret-value")
	stdout, stderr := runOK(t, "-i", inv, "-j", "../../test/integration/job", "--known-hosts", known,
		"--var-env", "token=RCO_IT_TOKEN")
	for _, secret := range []string{"s3cret-value", "deploy-pass"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("secret %q leaked into the output", secret)
		}
	}
}

// TestIntegrationOpenWrtLike runs a job against dropbear with busybox only (no
// bash, no sudo), logged in as root, as on OpenWrt: copy with busybox tools, a
// disconnect step that really kills the session, and fire_and_forget.
func TestIntegrationOpenWrtLike(t *testing.T) {
	id, inv, known := container(t, "rco-it-openwrt", "../../test/integration/openwrt", "Not backgrounding", "root", "router-pass")
	runOK(t, "-i", inv, "-j", "../../test/integration/openwrt/job", "--known-hosts", known)
	// The fire_and_forget command sleeps 1s; it must survive the end of the session.
	for deadline := time.Now().Add(15 * time.Second); exec.Command("docker", "exec", id, "test", "-f", "/tmp/rco-fired").Run() != nil; {
		if time.Now().After(deadline) {
			t.Fatal("fire_and_forget command did not run to completion after the session ended")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// container builds and starts image from dir, waits for the ready log line and
// writes an inventory with one host that logs in with user/password.
func container(t *testing.T, image, dir, ready, user, password string) (id, inv, known string) {
	t.Helper()
	docker(t, "build", "-q", "-t", image, dir)
	id = docker(t, "run", "-d", "--rm", "-p", "127.0.0.1::22", image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(docker(t, "logs", id), ready); {
		if time.Now().After(deadline) {
			t.Fatal("ssh server did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	host, port, err := net.SplitHostPort(strings.Fields(docker(t, "port", id, "22/tcp"))[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RCO_IT_PW", password)
	tmp := t.TempDir()
	inv = filepath.Join(tmp, "hosts.yaml")
	os.WriteFile(inv, []byte(fmt.Sprintf(`
credentials:
  pw: {type: password, username: %s, password_env: RCO_IT_PW}
hosts:
  - {name: target, address: %s, port: %s, credential: pw}
`, user, host, port)), 0o600)
	return id, inv, filepath.Join(tmp, "known_hosts")
}

// runOK executes rco and fails the test unless the single host succeeded.
func runOK(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	code, stdout, stderr := main(t, append([]string{"run", "--execute", "--accept-new-host-keys", "-o", "json", "-q"}, args...)...)
	var rep runner.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, stdout, stderr)
	}
	if code != ExitOK || rep.Hosts[0].Status != domain.StatusSuccess {
		t.Fatalf("exit %d, host %s: failed step %q: %s\n%s", code, rep.Hosts[0].Status, rep.Hosts[0].FailedStep, rep.Hosts[0].Reason, stdout)
	}
	return stdout, stderr
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
