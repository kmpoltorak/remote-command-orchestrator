package job

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExamplesLoad(t *testing.T) {
	files, _ := filepath.Glob("../../examples/jobs/*/job.yaml")
	if len(files) < 3 {
		t.Fatalf("expected examples, got %d", len(files))
	}
	for _, f := range files {
		j, err := Load(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(j.Hash) != 64 {
			t.Errorf("%s: hash %q", f, j.Hash)
		}
	}
}

func TestLoadDirectory(t *testing.T) {
	j, err := Load("../../examples/jobs/configure-ntp")
	if err != nil || j.Name != "configure-ntp" || j.Path != filepath.Join("../../examples/jobs/configure-ntp", DefaultFile) {
		t.Fatalf("%v %+v", err, j)
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("directory without job.yaml must fail")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"yaml":              "name: [",
		"no name":           "steps: [{name: a, command: x}]",
		"no steps":          "name: a\nmax_failures: 1",
		"duplicate":         "name: a\nmax_failures: 1\nsteps: [{name: s, command: x}, {name: s, command: y}]",
		"two kinds":         "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, script: y.sh}]",
		"no kind":           "name: a\nmax_failures: 1\nsteps: [{name: s}]",
		"bad regex":         "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, expect: {regex: '(['}}]",
		"bad timeout":       "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, timeout: 5parsecs}]",
		"retries":           "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, retries: 11}]",
		"undeclared var":    "name: a\nmax_failures: 1\nsteps: [{name: s, command: 'echo {{ .x }}'}]",
		"template func":     "name: a\nmax_failures: 1\nvariables: {x: {}}\nsteps: [{name: s, command: '{{ printf .x }}'}]",
		"unknown field":     "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, expcet: {}}]",
		"sensitive leak":    "name: a\nmax_failures: 1\nvariables: {pw: {sensitive: true}}\nsteps: [{name: s, command: 'echo {{ .pw }}'}]",
		"relative dest":     "name: a\nmax_failures: 1\nsteps: [{name: s, copy: {src: f, dest: etc/x}}]",
		"bad mode":          "name: a\nmax_failures: 1\nsteps: [{name: s, copy: {src: f, dest: /etc/x, mode: '999'}}]",
		"exit code range":   "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, expect: {exit_code: 300}}]",
		"sensitive default": "name: a\nmax_failures: 1\nvariables: {pw: {sensitive: true, default: x}}\nsteps: [{name: s, command: x}]",
		"reboot copy":       "name: a\nmax_failures: 1\nsteps: [{name: s, reboot: true, copy: {src: f, dest: /x}}]",
		"reboot retries":    "name: a\nmax_failures: 1\nsteps: [{name: s, command: reboot, reboot: true, retries: 1}]",
		"no max_failures":   "name: a\nsteps: [{name: s, command: x}]",
		"bad max_failures":  "name: a\nmax_failures: 0\nsteps: [{name: s, command: x}]",
		"max_failures pct":  "name: a\nmax_failures: 150%\nsteps: [{name: s, command: x}]",
		"ff not last":       "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, fire_and_forget: true}, {name: t, command: y}]",
		"ff with expect":    "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, fire_and_forget: true, expect: {contains: ok}}]",
		"ff with reboot":    "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, fire_and_forget: true, reboot: true}]",
		"ff script":         "name: a\nmax_failures: 1\nsteps: [{name: s, script: x.sh, fire_and_forget: true}]",
		"orphan reconnect":  "name: a\nmax_failures: 1\nsteps: [{name: s, command: x, reconnect_timeout: 1m}]",
	}
	for name, doc := range cases {
		var ve *ValidationError
		if _, err := Parse([]byte(doc)); !errors.As(err, &ve) {
			t.Errorf("%s: expected ValidationError, got %v", name, err)
		}
	}
}

func TestLoadMissingFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "j.yaml")
	os.WriteFile(p, []byte("name: a\nmax_failures: 1\nsteps: [{name: s, script: nope.sh}, {name: c, copy: {src: nope, dest: /x}}]"), 0o600)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "nope.sh") || !strings.Contains(err.Error(), `"c"`) {
		t.Fatalf("got %v", err)
	}
}

func TestReferencesAndRender(t *testing.T) {
	out, err := Render("a {{ .x }} b {{.y}}", map[string]string{"x": "1", "y": "{{ .x }}"})
	if err != nil || out != "a 1 b {{ .x }}" {
		t.Fatalf("%q %v", out, err)
	}
	for _, bad := range []string{"{{ call .f }}", "{{ .a }}{{", "{{ .a | printf }}", "{{- .a }}"} {
		if _, err := References(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if _, err := Render("{{ .missing }}", nil); err == nil {
		t.Fatal("missing var must fail")
	}
}

const demo = `
name: demo
max_failures: 1
variables:
  iface: {required: true}
  site: {default: dc1}
  pw: {sensitive: true}
steps:
  - name: s
    command: "echo {{ .iface }} {{ .site }}"
`

func TestResolvePrecedence(t *testing.T) {
	j, err := Parse([]byte(demo))
	if err != nil {
		t.Fatal(err)
	}
	env := func(k string) (string, bool) { return map[string]string{"PW": "s3cret"}[k], k == "PW" }
	vars, secrets, err := j.Resolve(Inputs{
		Host:   map[string]string{"iface": "host"},
		Job:    map[string]string{"iface": "job", "site": "job-site"},
		JobEnv: map[string]string{"pw": "PW"},
	}, env)
	if err != nil {
		t.Fatal(err)
	}
	if vars["iface"] != "host" || vars["site"] != "job-site" || vars["pw"] != "s3cret" {
		t.Fatalf("precedence: %v", vars)
	}
	if len(secrets) == 0 || secrets[0] != "s3cret" {
		t.Fatalf("secrets: %v", secrets)
	}
	vars, _, _ = j.Resolve(Inputs{Host: map[string]string{"iface": "x"}}, env)
	if vars["site"] != "dc1" {
		t.Fatal("default not applied")
	}
	_, _, err = j.Resolve(Inputs{Job: map[string]string{"pw": "literal", "site": "a\nreboot"}}, env)
	msg := err.Error()
	for _, want := range []string{"--var-env", "control character", `"iface" is not set`} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %s", want, msg)
		}
	}
}

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "run.sh"), []byte("echo hi\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "conf.tmpl"), []byte("server {{ .srv }}\n"), 0o600)
	p := filepath.Join(dir, "job.yaml")
	os.WriteFile(p, []byte(`
name: b
max_failures: 10%
variables: {srv: {}, pw: {sensitive: true}}
defaults: {timeout: 5s, sudo: true}
steps:
  - {name: cmd, command: "echo '{{ .srv }}'", sudo: false, retries: 2}
  - {name: sudo-cmd, command: "systemctl restart x", timeout: 1m}
  - {name: script, script: run.sh}
  - {name: copy, copy: {src: conf.tmpl, dest: "/etc/x y.conf", template: true}}
  - {name: secret, command: "login {{ .pw }}", sensitive: true}
`), 0o600)
	j, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	acts, err := j.Build(map[string]string{"srv": "ntp1", "pw": "hunter2"}, Settings{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if a := acts[0]; a.Remote("", true) != "echo 'ntp1'" || a.Sudo || a.Timeout != 5*time.Second || a.Retries != 2 {
		t.Fatalf("cmd: %+v", a)
	}
	if a := acts[1]; a.Remote("", true) != `sudo -k -S -p '' -- sh -c 'systemctl restart x'` || a.Timeout != time.Minute {
		t.Fatalf("sudo: %q", a.Remote("", true))
	}
	if got := acts[1].Remote("", false); got != `sudo -n -- sh -c 'systemctl restart x'` {
		t.Fatalf("NOPASSWD sudo: %q", got)
	}
	if a := acts[2]; a.Remote("/tmp/t", true) != `sudo -k -S -p '' -- sh -c 'bash '\''/tmp/t'\'''; rc=$?; rm -f '/tmp/t'; exit $rc` ||
		!strings.HasPrefix(string(a.Content), "export pw='hunter2'\nexport srv='ntp1'\necho hi") {
		t.Fatalf("script: %q %q", a.Remote("/tmp/t", true), a.Content)
	}
	a := acts[3]
	if string(a.Content) != "server ntp1\n" || a.Mode != "0644" || !strings.Contains(a.Display, "mode 0644") ||
		!strings.Contains(a.Remote("/tmp/t", false), `mv -f '\''/etc/x y.conf.rco-tmp'\'' '\''/etc/x y.conf'\''`) {
		t.Fatalf("copy: %q", a.Remote("/tmp/t", false))
	}
	if a := acts[4]; a.Display != "[SENSITIVE]" {
		t.Fatalf("sensitive display leaked: %q", a.Display)
	}
}

func TestParseMaxFailures(t *testing.T) {
	cases := map[string]int{"3": 3, "10%": 100, "0.1%": 1, "100%": 1000}
	for in, want := range cases {
		if got, err := ParseMaxFailures(in, 1000); err != nil || got != want {
			t.Errorf("%q: got %d %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "-1", "abc", "101%", "2.5"} {
		if _, err := ParseMaxFailures(bad, 1000); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestQuote(t *testing.T) {
	if got := Quote(`it's`); got != `'it'\''s'` {
		t.Fatal(got)
	}
}

func TestRebootAndDisconnectDefaults(t *testing.T) {
	j, err := Parse([]byte(`
name: r
max_failures: "100%"
steps:
  - {name: reboot, command: systemctl reboot, reboot: true}
  - {name: net, command: systemctl restart networking, disconnect: true, reconnect_timeout: 2m}
  - {name: plain, command: "true"}
`))
	if err != nil {
		t.Fatal(err)
	}
	acts, err := j.Build(nil, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if a := acts[0]; !a.Reboot || !a.Disconnect || a.ReconnectTimeout != DefaultRebootTimeout {
		t.Fatalf("reboot: %+v", a)
	}
	if a := acts[1]; a.Reboot || !a.Disconnect || a.ReconnectTimeout != 2*time.Minute {
		t.Fatalf("disconnect: %+v", a)
	}
	if a := acts[2]; a.Disconnect || a.ReconnectTimeout != 0 {
		t.Fatalf("plain: %+v", a)
	}
}
