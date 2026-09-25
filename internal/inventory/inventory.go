// Package inventory parses host inventories, resolves per-host settings and
// filters hosts by group, tag and name.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/job"
)

// Inventory is the parsed YAML document.
type Inventory struct {
	Credentials map[string]domain.Credential `yaml:"credentials"`
	Bastions    map[string]Bastion           `yaml:"bastions"`
	Defaults    Defaults                     `yaml:"defaults"`
	Groups      map[string]Group             `yaml:"groups"`
	Hosts       []Host                       `yaml:"hosts"`
}

// Bastion is a jump host.
type Bastion struct {
	Address    string `yaml:"address"`
	Port       int    `yaml:"port"`
	Username   string `yaml:"username"`
	Credential string `yaml:"credential"`
}

// Defaults are inherited by hosts (inventory defaults < group defaults < host).
type Defaults struct {
	Port       int               `yaml:"port"`
	Username   string            `yaml:"username"`
	Credential string            `yaml:"credential"`
	Bastion    string            `yaml:"bastion"`
	Tags       []string          `yaml:"tags"`
	Variables  map[string]string `yaml:"variables"`
}

// Group is a named set of hosts sharing defaults.
type Group struct {
	Defaults Defaults `yaml:"defaults"`
	Hosts    []Host   `yaml:"hosts"`
}

// Host is one entry; empty fields inherit.
type Host struct {
	Name       string            `yaml:"name"`
	Address    string            `yaml:"address"`
	Port       int               `yaml:"port"`
	Username   string            `yaml:"username"`
	Credential string            `yaml:"credential"`
	Bastion    string            `yaml:"bastion"`
	Tags       []string          `yaml:"tags"`
	Variables  map[string]string `yaml:"variables"`
}

// Selector filters hosts: AND across kinds, OR within a kind. Empty = all.
type Selector struct {
	Groups []string `json:"groups,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
}

var hostNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)

// Load reads and parses an inventory file.
func Load(path string) (*Inventory, error) {
	data, err := job.ReadFile(path, job.MaxFileSize)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates an inventory.
func Parse(data []byte) (*Inventory, error) {
	var inv Inventory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("inventory YAML: %w", err)
	}
	if _, err := inv.Select(Selector{}); err != nil {
		return nil, err
	}
	return &inv, nil
}

// Select returns the matching hosts, resolved and sorted by name.
func (inv *Inventory) Select(sel Selector) ([]domain.Target, error) {
	var errs []string
	seen := map[string]bool{}
	var all []domain.Target
	add := func(group string, gd Defaults, h Host) {
		switch {
		case !hostNamePattern.MatchString(h.Name):
			errs = append(errs, fmt.Sprintf("host %q: invalid or missing name", h.Name))
			return
		case seen[h.Name]:
			errs = append(errs, fmt.Sprintf("host %q: defined more than once", h.Name))
			return
		}
		seen[h.Name] = true
		t, err := inv.resolve(group, gd, h)
		if err != nil {
			errs = append(errs, fmt.Sprintf("host %q: %v", h.Name, err))
			return
		}
		all = append(all, t)
	}
	for g, grp := range inv.Groups {
		for _, h := range grp.Hosts {
			add(g, grp.Defaults, h)
		}
	}
	for _, h := range inv.Hosts {
		add("", Defaults{}, h)
	}
	for _, g := range sel.Groups {
		if _, ok := inv.Groups[g]; !ok {
			errs = append(errs, fmt.Sprintf("unknown group %q", g))
		}
	}
	for _, h := range sel.Hosts {
		if !seen[h] {
			errs = append(errs, fmt.Sprintf("unknown host %q", h))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New("inventory invalid: " + strings.Join(errs, "; "))
	}
	var out []domain.Target
	for _, t := range all {
		if anyOf(sel.Groups, t.Group) && anyOf(sel.Tags, t.Tags...) && anyOf(sel.Hosts, t.Name) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func anyOf(want []string, have ...string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		for _, h := range have {
			if w == h {
				return true
			}
		}
	}
	return false
}

func first[T comparable](vals ...T) T {
	var zero T
	for _, v := range vals {
		if v != zero {
			return v
		}
	}
	return zero
}

func (inv *Inventory) resolve(group string, gd Defaults, h Host) (domain.Target, error) {
	d := inv.Defaults
	t := domain.Target{Group: group}
	t.Name, t.Address = h.Name, h.Address
	t.Port = first(h.Port, gd.Port, d.Port, 22)
	if t.Address == "" {
		return t, errors.New("address is required")
	}
	if t.Port < 1 || t.Port > 65535 {
		return t, fmt.Errorf("port %d out of range", t.Port)
	}
	for _, m := range []map[string]string{d.Variables, gd.Variables, h.Variables} {
		for k, v := range m {
			if err := job.CheckValue(v); err != nil {
				return t, fmt.Errorf("variable %q: %w", k, err)
			}
			if t.Variables == nil {
				t.Variables = map[string]string{}
			}
			t.Variables[k] = v
		}
	}
	tags := map[string]bool{}
	for _, tag := range append(append(append([]string{}, d.Tags...), gd.Tags...), h.Tags...) {
		if !tags[tag] {
			tags[tag] = true
			t.Tags = append(t.Tags, tag)
		}
	}
	cred, err := inv.credential(first(h.Credential, gd.Credential, d.Credential))
	if err != nil {
		return t, err
	}
	t.Credential = cred
	t.Username = first(h.Username, gd.Username, d.Username, cred.Username)
	if t.Username == "" {
		return t, errors.New("username is required (host, defaults or credential)")
	}
	if name := first(h.Bastion, gd.Bastion, d.Bastion); name != "" {
		b, ok := inv.Bastions[name]
		if !ok {
			return t, fmt.Errorf("unknown bastion %q", name)
		}
		bc, err := inv.credential(b.Credential)
		if err != nil {
			return t, fmt.Errorf("bastion %q: %w", name, err)
		}
		t.Bastion = &domain.Endpoint{Name: name, Address: b.Address, Port: first(b.Port, 22), Username: first(b.Username, bc.Username), Credential: bc}
		if t.Bastion.Address == "" || t.Bastion.Username == "" {
			return t, fmt.Errorf("bastion %q: address and username are required", name)
		}
	}
	return t, nil
}

func (inv *Inventory) credential(name string) (domain.Credential, error) {
	if name == "" {
		return domain.Credential{}, errors.New("credential is required")
	}
	c, ok := inv.Credentials[name]
	if !ok {
		return c, fmt.Errorf("unknown credential %q", name)
	}
	c.Name = name
	switch c.Type {
	case "password":
		if c.PasswordEnv == "" {
			return c, fmt.Errorf("credential %q: password_env is required (plaintext passwords are not accepted)", name)
		}
	case "private_key":
		if c.KeyFile == "" {
			return c, fmt.Errorf("credential %q: key_file is required", name)
		}
	default:
		return c, fmt.Errorf("credential %q: type must be password or private_key", name)
	}
	return c, nil
}
