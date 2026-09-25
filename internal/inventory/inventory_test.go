package inventory

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplesLoad(t *testing.T) {
	files, _ := filepath.Glob("../../examples/inventories/*/hosts.yaml")
	if len(files) < 2 {
		t.Fatalf("expected examples, got %d", len(files))
	}
	for _, f := range files {
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

const inv = `
credentials:
  key: {type: private_key, username: deploy, key_file: /k}
  pw: {type: password, username: admin, password_env: PW}
bastions:
  b1: {address: bastion.example.com, credential: key}
defaults:
  credential: key
  variables: {site: dc1, ntp: default}
groups:
  web:
    defaults:
      port: 2222
      tags: [production]
      variables: {ntp: group}
    hosts:
      - {name: web-01, address: 10.0.0.1, variables: {ntp: host}}
      - {name: web-02, address: 10.0.0.2, port: 22, tags: [canary]}
  db:
    hosts:
      - {name: db-01, address: 10.0.1.1, username: postgres, bastion: b1}
hosts:
  - {name: old-01, address: 10.0.2.1, credential: pw}
`

func TestResolveAndPrecedence(t *testing.T) {
	i, err := Parse([]byte(inv))
	if err != nil {
		t.Fatal(err)
	}
	all, _ := i.Select(Selector{})
	by := map[string]int{}
	for n, h := range all {
		by[h.Name] = n
	}
	w1 := all[by["web-01"]]
	if w1.Port != 2222 || w1.Username != "deploy" || w1.Variables["ntp"] != "host" || w1.Variables["site"] != "dc1" {
		t.Fatalf("web-01: %+v", w1)
	}
	w2 := all[by["web-02"]]
	if w2.Port != 22 || w2.Variables["ntp"] != "group" || strings.Join(w2.Tags, ",") != "production,canary" {
		t.Fatalf("web-02: %+v", w2)
	}
	db := all[by["db-01"]]
	if db.Username != "postgres" || db.Bastion == nil || db.Bastion.Port != 22 || db.Bastion.Username != "deploy" {
		t.Fatalf("db-01: %+v", db)
	}
	if old := all[by["old-01"]]; old.Username != "admin" || old.Credential.Type != "password" {
		t.Fatalf("old-01: %+v", old)
	}
}

func TestFiltering(t *testing.T) {
	i, _ := Parse([]byte(inv))
	names := func(sel Selector) string {
		hs, err := i.Select(sel)
		if err != nil {
			return "ERR"
		}
		var n []string
		for _, h := range hs {
			n = append(n, h.Name)
		}
		return strings.Join(n, ",")
	}
	cases := map[string]Selector{
		"db-01,old-01,web-01,web-02": {},
		"web-01,web-02":              {Groups: []string{"web"}},
		"db-01,web-01,web-02":        {Groups: []string{"web", "db"}},
		"web-02":                     {Tags: []string{"canary"}},
		"web-01":                     {Groups: []string{"web"}, Hosts: []string{"web-01", "old-01"}},
		"ERR":                        {Hosts: []string{"nope"}},
	}
	for want, sel := range cases {
		if got := names(sel); got != want {
			t.Errorf("%+v: got %s want %s", sel, got, want)
		}
	}
	if names(Selector{Groups: []string{"nope"}}) != "ERR" {
		t.Error("unknown group must fail")
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]string{
		"duplicate":          "credentials: {c: {type: private_key, username: u, key_file: k}}\nhosts: [{name: a, address: x, credential: c}, {name: a, address: y, credential: c}]",
		"no address":         "hosts: [{name: a}]",
		"no credential":      "hosts: [{name: a, address: x, username: u}]",
		"unknown credential": "hosts: [{name: a, address: x, username: u, credential: nope}]",
		"plaintext password": "credentials: {c: {type: password, username: u, password: hunter2}}\nhosts: [{name: a, address: x, credential: c}]",
		"no password env":    "credentials: {c: {type: password, username: u}}\nhosts: [{name: a, address: x, credential: c}]",
		"unknown bastion":    "credentials: {c: {type: private_key, username: u, key_file: k}}\nhosts: [{name: a, address: x, credential: c, bastion: nope}]",
		"bad port":           "credentials: {c: {type: private_key, username: u, key_file: k}}\nhosts: [{name: a, address: x, credential: c, port: 70000}]",
		"newline variable":   "credentials: {c: {type: private_key, username: u, key_file: k}}\nhosts: [{name: a, address: x, credential: c, variables: {d: \"a\\nb\"}}]",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
