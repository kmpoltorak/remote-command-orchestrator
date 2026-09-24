package commandprompt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplesParse(t *testing.T) {
	files, _ := filepath.Glob("../../examples/command-prompts/*.yaml")
	if len(files) < 4 {
		t.Fatalf("expected at least 4 examples, got %d", len(files))
	}
	for _, f := range files {
		p, _, err := LoadFile(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(p.Hash) != 64 {
			t.Errorf("%s: bad hash %q", f, p.Hash)
		}
	}
}

const valid = `
name: demo
version: "1.0"
defaults:
  command_timeout: 10s
variables:
  iface: {required: true}
  desc: {default: "none"}
  secret: {sensitive: true}
prechecks:
  - name: pre
    command: show version
    expect: {contains: Cisco}
steps:
  - name: s1
    command: "interface {{ .iface }}"
    timeout: 3s
    retries: 2
    expect:
      regex: '\(config-if\)#\s*$'
      not_contains: ["Invalid input", "Error"]
  - name: s2
    command: "{{.secret}}"
    sensitive: true
postchecks:
  - name: post
    command: show run
    expect:
      contains: "{{ .desc }}"
rollback:
  on_failure: true
  steps:
    - name: rb
      command: "no description"
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Timeout.Seconds() != 3 || *p.Steps[0].Retries != 2 || len(p.Steps[0].Expect.NotContains) != 2 {
		t.Fatalf("%+v", p.Steps[0])
	}
	if p.Prechecks[0].Expect.Contains[0] != "Cisco" {
		t.Fatal("scalar contains not parsed")
	}
	if !p.Rollback.OnFailure || len(p.AllSteps()) != 5 {
		t.Fatal("rollback/allsteps")
	}
	if p.ResolveMode("exec") != "exec" || p.ResolveMode("") != ModeInteractive {
		t.Fatal("mode resolution")
	}
	// Hash is content based.
	p2, _ := Parse([]byte(valid + "\n"))
	if p.Hash == p2.Hash {
		t.Fatal("hash must change with content")
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"yaml syntax":        "name: [",
		"missing name":       "version: '1'\nsteps: [{name: a, command: x}]",
		"missing version":    "name: a\nsteps: [{name: a, command: x}]",
		"no steps":           "name: a\nversion: '1'",
		"duplicate step":     "name: a\nversion: '1'\nsteps: [{name: a, command: x}, {name: a, command: y}]",
		"bad regex":          "name: a\nversion: '1'\nsteps: [{name: a, command: x, expect: {regex: '(['}}]",
		"bad timeout":        "name: a\nversion: '1'\nsteps: [{name: a, command: x, timeout: 10parsecs}]",
		"negative retries":   "name: a\nversion: '1'\nsteps: [{name: a, command: x, retries: -1}]",
		"undeclared var":     "name: a\nversion: '1'\nsteps: [{name: a, command: '{{ .nope }}'}]",
		"template function":  "name: a\nversion: '1'\nvariables: {x: {}}\nsteps: [{name: a, command: '{{ printf \"%s\" .x }}'}]",
		"unknown field":      "name: a\nversion: '1'\nsteps: [{name: a, command: x, expcet: {regex: a}}]",
		"exit code in shell": "name: a\nversion: '1'\nsession: {mode: interactive}\nsteps: [{name: a, command: x, expect: {exit_code: 0}}]",
		"sensitive leak":     "name: a\nversion: '1'\nvariables: {pw: {sensitive: true}}\nsteps: [{name: a, command: '{{ .pw }}'}]",
		"bad retry_on":       "name: a\nversion: '1'\nretry: {retry_on: [NOPE]}\nsteps: [{name: a, command: x}]",
		"rollback no steps":  "name: a\nversion: '1'\nrollback: {on_failure: true}\nsteps: [{name: a, command: x}]",
		"regex template":     "name: a\nversion: '1'\nvariables: {x: {}}\nsteps: [{name: a, command: x, expect: {regex: '{{ .x }}'}}]",
		"bad when":           "name: a\nversion: '1'\nsteps: [{name: a, command: x, when: {variable: z, exists: true}}]",
		"sensitive default":  "name: a\nversion: '1'\nvariables: {pw: {sensitive: true, default: x}}\nsteps: [{name: a, command: x}]",
	}
	for name, doc := range cases {
		_, err := Parse([]byte(doc))
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: expected ValidationError, got %v", name, err)
		}
	}
}

func TestRenderAndReferences(t *testing.T) {
	out, err := Render("interface {{ .iface }} desc {{.d}}", map[string]string{"iface": "Gi0/1", "d": "x"})
	if err != nil || out != "interface Gi0/1 desc x" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := Render("{{ .missing }}", nil); err == nil {
		t.Fatal("missing variable must fail")
	}
	for _, bad := range []string{"{{ call .f }}", "{{ .a }}{{", "{{ .a | printf }}", "{{- .a }}"} {
		if _, err := References(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	// Values are inserted literally, never re-evaluated.
	out, _ = Render("x {{ .a }}", map[string]string{"a": "{{ .b }}"})
	if out != "x {{ .b }}" {
		t.Fatalf("got %q", out)
	}
}

func TestVariablePrecedenceAndSensitive(t *testing.T) {
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	src := VarSources{
		JobVars:  map[string]string{"iface": "job-if", "desc": "job-desc"},
		HostVars: map[string]string{"iface": "host-if"},
		JobEnv:   map[string]string{"secret": "ENABLE_PW"},
	}
	if issues := p.CheckSources(src); len(issues) != 0 {
		t.Fatal(issues)
	}
	vars, secrets, err := p.ResolveVars(src, func(k string) (string, bool) {
		return map[string]string{"ENABLE_PW": "s3cr3t"}[k], k == "ENABLE_PW"
	})
	if err != nil {
		t.Fatal(err)
	}
	if vars["iface"] != "host-if" || vars["desc"] != "job-desc" || vars["secret"] != "s3cr3t" {
		t.Fatalf("precedence broken: %v", vars)
	}
	if len(secrets) == 0 || secrets[0] != "s3cr3t" {
		t.Fatalf("secret not registered: %v", secrets)
	}
	// Defaults apply when nothing else is set.
	vars, _, _ = p.ResolveVars(VarSources{HostVars: map[string]string{"iface": "a"}}, func(string) (string, bool) { return "", false })
	if vars["desc"] != "none" {
		t.Fatalf("default not applied: %v", vars)
	}

	bad := p.CheckSources(VarSources{JobVars: map[string]string{"secret": "literal", "desc": "a\nreload"}})
	joined := strings.Join(bad, "|")
	for _, want := range []string{"sensitive variable", "control character", `required variable "iface"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing issue %q in %v", want, bad)
		}
	}
	if _, _, err := p.ResolveVars(VarSources{HostVars: map[string]string{"iface": "a"}, JobEnv: map[string]string{"secret": "UNSET"}}, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("unset env reference must fail")
	}
}

func TestWhen(t *testing.T) {
	yes, no, eq := true, false, "x"
	vars := map[string]string{"a": "x", "empty": ""}
	cases := []struct {
		w    *When
		want bool
	}{
		{nil, true},
		{&When{Variable: "a", Exists: &yes}, true},
		{&When{Variable: "b", Exists: &yes}, false},
		{&When{Variable: "empty", Exists: &no}, true},
		{&When{Variable: "a", Equals: &eq}, true},
		{&When{Variable: "b", Equals: &eq}, false},
	}
	for i, c := range cases {
		if got := c.w.Holds(vars); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestReadLimited(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, MaxFileSize+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLimited(big); err == nil {
		t.Fatal("oversized file must be rejected")
	}
	if _, err := ReadLimited(dir); err == nil {
		t.Fatal("directory must be rejected")
	}
}
