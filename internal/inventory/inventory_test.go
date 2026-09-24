package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplesParse(t *testing.T) {
	files, _ := filepath.Glob("../../examples/inventories/*.yaml")
	if len(files) < 3 {
		t.Fatalf("expected 3 examples, got %d", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

const inv = `
credentials:
  net: {type: private_key, username: automation, key_file: /k}
  pw: {type: password, username: admin, password_env: PW}
bastions:
  b1: {address: bastion.example.com, credential: net}
defaults:
  variables: {site: dc1, description: default-desc}
groups:
  routers:
    defaults:
      port: 2222
      credential: net
      profile: cisco_ios
      tags: [production]
      variables: {description: group-desc}
    hosts:
      - name: router-01
        address: 10.0.0.1
        variables: {description: host-desc}
      - name: router-02
        address: 10.0.0.2
        port: 22
        tags: [edge]
  linux:
    hosts:
      - name: app-01
        address: 10.0.1.1
        username: deploy
        profile: linux
        bastion: b1
hosts:
  - name: sw-01
    address: 10.0.2.1
    credential: pw
`

func TestResolveAndPrecedence(t *testing.T) {
	i, err := Parse([]byte(inv))
	if err != nil {
		t.Fatal(err)
	}
	all, err := i.Resolve(Selector{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("got %d hosts", len(all))
	}
	byName := map[string]int{}
	for idx, h := range all {
		byName[h.Name] = idx
	}
	r1 := all[byName["router-01"]]
	if r1.Port != 2222 || r1.Username != "automation" || r1.Credential.Name != "net" || r1.Profile.Name != "cisco_ios" {
		t.Fatalf("router-01: %+v", r1)
	}
	if r1.Variables["description"] != "host-desc" || r1.Variables["site"] != "dc1" {
		t.Fatalf("variable precedence: %v", r1.Variables)
	}
	r2 := all[byName["router-02"]]
	if r2.Port != 22 || r2.Variables["description"] != "group-desc" || len(r2.Tags) != 2 {
		t.Fatalf("router-02: %+v", r2)
	}
	app := all[byName["app-01"]]
	if app.Credential.Type != "agent" || app.Bastion == nil || app.Bastion.Port != 22 || app.Bastion.Username != "automation" || app.Profile.Mode != "exec" {
		t.Fatalf("app-01: %+v", app)
	}
	sw := all[byName["sw-01"]]
	if sw.Username != "admin" || sw.Profile.Name != "generic_network_device" {
		t.Fatalf("sw-01: %+v", sw)
	}
}

func TestFiltering(t *testing.T) {
	i, err := Parse([]byte(inv))
	if err != nil {
		t.Fatal(err)
	}
	names := func(sel Selector) string {
		hs, err := i.Resolve(sel)
		if err != nil {
			return "ERR:" + err.Error()
		}
		var n []string
		for _, h := range hs {
			n = append(n, h.Name)
		}
		return strings.Join(n, ",")
	}
	cases := map[string]Selector{
		"router-01,router-02":        {Groups: []string{"routers"}},
		"app-01,router-01,router-02": {Groups: []string{"routers", "linux"}},
		"router-02":                  {Tags: []string{"edge"}},
		"router-01":                  {Groups: []string{"routers"}, Hosts: []string{"router-01", "sw-01"}},
		"router-01,sw-01":            {Hosts: []string{"router-01", "sw-01"}},
	}
	for want, sel := range cases {
		if got := names(sel); got != want {
			t.Errorf("%+v: got %s want %s", sel, got, want)
		}
	}
	if got := names(Selector{Hosts: []string{"nope"}}); !strings.HasPrefix(got, "ERR") {
		t.Error("unknown host must error")
	}
	if got := names(Selector{Groups: []string{"nope"}}); !strings.HasPrefix(got, "ERR") {
		t.Error("unknown group must error")
	}
}

func TestInvalidInventories(t *testing.T) {
	cases := map[string]string{
		"duplicate host":       "hosts: [{name: a, address: x, credential: c}, {name: a, address: y, credential: c}]\ncredentials: {c: {type: agent, username: u}}",
		"missing address":      "hosts: [{name: a}]",
		"unknown credential":   "hosts: [{name: a, address: x, username: u, credential: nope}]",
		"plaintext password":   "credentials: {c: {type: password, username: u, password: hunter2}}\nhosts: [{name: a, address: x, credential: c}]",
		"password without env": "credentials: {c: {type: password, username: u}}\nhosts: [{name: a, address: x, credential: c}]",
		"unknown bastion":      "hosts: [{name: a, address: x, username: u, bastion: nope}]",
		"unknown profile":      "hosts: [{name: a, address: x, username: u, profile: nope}]",
		"bad port":             "hosts: [{name: a, address: x, username: u, port: 70000}]",
		"no username":          "hosts: [{name: a, address: x}]",
		"newline variable":     "hosts: [{name: a, address: x, username: u, variables: {d: \"a\\nb\"}}]",
		"bad profile regex":    "profiles: {p: {prompt_regex: '(['}}\nhosts: [{name: a, address: x, username: u, profile: p}]",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestCustomProfileOverlay(t *testing.T) {
	i, err := Parse([]byte("profiles:\n  cisco_ios: {login_timeout: 20s, setup_commands: [terminal length 0]}\n  mydev: {prompt_regex: 'dev>$'}\nhosts: [{name: a, address: x, username: u, profile: mydev}]"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := i.Profile("cisco_ios")
	if p.LoginTimeout.Seconds() != 20 || len(p.SetupCommands) != 1 || p.Pager.Patterns[0] != "--More--" {
		t.Fatalf("%+v", p)
	}
	d, _ := i.Profile("mydev")
	if d.PromptRegex != "dev>$" || d.Mode != "interactive" {
		t.Fatalf("%+v", d)
	}
}
