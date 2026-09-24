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
	files, _ := filepath.Glob("../../examples/jobs/*.yaml")
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

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"yaml":              "name: [",
		"no name":           "steps: [{name: a, command: x}]",
		"no steps":          "name: a",
		"duplicate":         "name: a\nsteps: [{name: s, command: x}, {name: s, command: y}]",
		"two kinds":         "name: a\nsteps: [{name: s, command: x, script: y.sh}]",
		"no kind":           "name: a\nsteps: [{name: s}]",
		"bad regex":         "name: a\nsteps: [{name: s, command: x, expect: {regex: '(['}}]",
		"bad timeout":       "name: a\nsteps: [{name: s, command: x, timeout: 5parsecs}]",
		"retries":           "name: a\nsteps: [{name: s, command: x, retries: 11}]",
		"undeclared var":    "name: a\nsteps: [{name: s, command: 'echo {{ .x }}'}]",
		"template func":     "name: a\nvariables: {x: {}}\nsteps: [{name: s, command: '{{ printf .x }}'}]",
		"unknown field":     "name: a\nsteps: [{name: s, command: x, expcet: {}}]",
		"sensitive leak":    "name: a\nvariables: {pw: {sensitive: true}}\nsteps: [{name: s, command: 'echo {{ .pw }}'}]",
		"relative dest":     "name: a\nsteps: [{name: s, copy: {src: f, dest: etc/x}}]",
		"bad mode":          "name: a\nsteps: [{name: s, copy: {src: f, dest: /etc/x, mode: '999'}}]",
		"exit code range":   "name: a\nsteps: [{name: s, command: x, expect: {exit_code: 300}}]",
		"sensitive default": "name: a\nvariables: {pw: {sensitive: true, default: x}}\nsteps: [{name: s, command: x}]",
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
	os.WriteFile(p, []byte("name: a\nsteps: [{name: s, script: nope.sh}, {name: c, copy: {src: nope, dest: /x}}]"), 0o600)
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
	acts, err := j.Build(map[string]string{"srv": "ntp1", "pw": "hunter2"}, Settings{Timeout: 30 * time.Second}, true)
	if err != nil {
		t.Fatal(err)
	}
	if a := acts[0]; a.Command != "echo 'ntp1'" || a.Sudo || a.Timeout != 5*time.Second || a.Retries != 2 {
		t.Fatalf("cmd: %+v", a)
	}
	if a := acts[1]; a.Command != `sudo -S -p '' -- sh -c 'systemctl restart x'` || a.Timeout != time.Minute {
		t.Fatalf("sudo: %+v", a)
	}
	if a := acts[2]; a.Command != "sudo -S -p '' -- bash -s" || !strings.HasPrefix(string(a.Stdin), "export pw='hunter2'\nexport srv='ntp1'\necho hi") {
		t.Fatalf("script: %q %q", a.Command, a.Stdin)
	}
	if a := acts[3]; string(a.Stdin) != "server ntp1\n" || !strings.Contains(a.Command, `'\''/etc/x y.conf.rco-tmp'\''`) || !strings.Contains(a.Display, "mode 0644") {
		t.Fatalf("copy: %+v", a)
	}
	if a := acts[4]; a.Display != "[SENSITIVE]" {
		t.Fatalf("sensitive display leaked: %q", a.Display)
	}
	acts, _ = j.Build(map[string]string{"srv": "x", "pw": "y"}, Settings{}, false)
	if !strings.HasPrefix(acts[1].Command, "sudo -n -- ") {
		t.Fatalf("NOPASSWD sudo: %q", acts[1].Command)
	}
}

func TestQuote(t *testing.T) {
	if got := Quote(`it's`); got != `'it'\''s'` {
		t.Fatal(got)
	}
}
