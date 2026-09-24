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

	"github.com/kmpoltorak/remote-command-orchestrator/internal/commandprompt"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Inventory is the parsed YAML document.
type Inventory struct {
	Credentials map[string]domain.CredentialRef `yaml:"credentials"`
	Bastions    map[string]Bastion              `yaml:"bastions"`
	Profiles    map[string]domain.Profile       `yaml:"profiles"`
	Defaults    Defaults                        `yaml:"defaults"`
	Groups      map[string]Group                `yaml:"groups"`
	Hosts       []Host                          `yaml:"hosts"`
}

// Bastion is a jump host definition.
type Bastion struct {
	Address    string `yaml:"address"`
	Port       int    `yaml:"port"`
	Username   string `yaml:"username"`
	Credential string `yaml:"credential"`
}

// Defaults are settings inherited by hosts.
type Defaults struct {
	Port         int               `yaml:"port"`
	Username     string            `yaml:"username"`
	Credential   string            `yaml:"credential"`
	Bastion      string            `yaml:"bastion"`
	Profile      string            `yaml:"profile"`
	Tags         []string          `yaml:"tags"`
	Variables    map[string]string `yaml:"variables"`
	VariablesEnv map[string]string `yaml:"variables_env"`
}

// Group is a named set of hosts sharing defaults.
type Group struct {
	Defaults Defaults `yaml:"defaults"`
	Hosts    []Host   `yaml:"hosts"`
}

// Host is one inventory entry. Empty fields inherit from group and inventory defaults.
type Host struct {
	Name         string            `yaml:"name"`
	Address      string            `yaml:"address"`
	Port         int               `yaml:"port"`
	Username     string            `yaml:"username"`
	Credential   string            `yaml:"credential"`
	Bastion      string            `yaml:"bastion"`
	Profile      string            `yaml:"profile"`
	Tags         []string          `yaml:"tags"`
	Variables    map[string]string `yaml:"variables"`
	VariablesEnv map[string]string `yaml:"variables_env"`
}

// Selector filters hosts: AND across kinds, OR within a kind. Empty = all.
type Selector struct {
	Groups []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Tags   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Hosts  []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
}

var hostNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)

// Parse decodes and structurally validates an inventory.
func Parse(data []byte) (*Inventory, error) {
	if len(data) > commandprompt.MaxFileSize {
		return nil, fmt.Errorf("inventory exceeds %d bytes", commandprompt.MaxFileSize)
	}
	var inv Inventory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("inventory YAML: %w", err)
	}
	if _, err := inv.Resolve(Selector{}); err != nil {
		return nil, err
	}
	return &inv, nil
}

// Resolve returns the selected hosts as fully resolved targets, sorted by name.
func (inv *Inventory) Resolve(sel Selector) ([]domain.Target, error) {
	var errs []string
	seen := map[string]bool{}
	var all []domain.Target
	add := func(group string, gd Defaults, h Host) {
		if !hostNamePattern.MatchString(h.Name) {
			errs = append(errs, fmt.Sprintf("host %q: invalid or missing name", h.Name))
			return
		}
		if seen[h.Name] {
			errs = append(errs, fmt.Sprintf("host %q: defined more than once", h.Name))
			return
		}
		seen[h.Name] = true
		t, err := inv.resolveHost(group, gd, h)
		if err != nil {
			errs = append(errs, fmt.Sprintf("host %q: %v", h.Name, err))
			return
		}
		all = append(all, t)
	}
	groupNames := make([]string, 0, len(inv.Groups))
	for g := range inv.Groups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)
	for _, g := range groupNames {
		for _, h := range inv.Groups[g].Hosts {
			add(g, inv.Groups[g].Defaults, h)
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
		return nil, errors.New("inventory invalid: " + strings.Join(errs, "; "))
	}
	var out []domain.Target
	for _, t := range all {
		if sel.matches(t) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s Selector) matches(t domain.Target) bool {
	anyOf := func(want []string, have ...string) bool {
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
	return anyOf(s.Groups, t.Group) && anyOf(s.Tags, t.Tags...) && anyOf(s.Hosts, t.Name)
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

func (inv *Inventory) resolveHost(group string, gd Defaults, h Host) (domain.Target, error) {
	d := inv.Defaults
	t := domain.Target{
		Name:        h.Name,
		Address:     h.Address,
		Port:        first(h.Port, gd.Port, d.Port, 22),
		Group:       group,
		Variables:   merge(d.Variables, gd.Variables, h.Variables),
		VariableEnv: merge(d.VariablesEnv, gd.VariablesEnv, h.VariablesEnv),
	}
	if t.Address == "" {
		return t, errors.New("address is required")
	}
	if t.Port < 1 || t.Port > 65535 {
		return t, fmt.Errorf("port %d out of range", t.Port)
	}
	tagSet := map[string]bool{}
	for _, tag := range append(append(append([]string{}, d.Tags...), gd.Tags...), h.Tags...) {
		if !tagSet[tag] {
			tagSet[tag] = true
			t.Tags = append(t.Tags, tag)
		}
	}
	for k, v := range t.Variables {
		if err := commandprompt.CheckValue(v); err != nil {
			return t, fmt.Errorf("variable %q: %v", k, err)
		}
	}

	cred, err := inv.credential(first(h.Credential, gd.Credential, d.Credential))
	if err != nil {
		return t, err
	}
	t.Credential = cred
	t.Username = first(h.Username, gd.Username, d.Username, cred.Username)
	if t.Username == "" {
		return t, errors.New("username is required (host, group defaults, defaults or credential)")
	}

	if b := first(h.Bastion, gd.Bastion, d.Bastion); b != "" {
		def, ok := inv.Bastions[b]
		if !ok {
			return t, fmt.Errorf("unknown bastion %q", b)
		}
		bc, err := inv.credential(def.Credential)
		if err != nil {
			return t, fmt.Errorf("bastion %q: %v", b, err)
		}
		ep := &domain.Endpoint{Name: b, Address: def.Address, Port: first(def.Port, 22), Username: first(def.Username, bc.Username), Credential: bc}
		if ep.Address == "" || ep.Username == "" {
			return t, fmt.Errorf("bastion %q: address and username are required", b)
		}
		t.Bastion = ep
	}

	p, err := inv.Profile(first(h.Profile, gd.Profile, d.Profile, "generic_network_device"))
	if err != nil {
		return t, err
	}
	t.Profile = p
	return t, nil
}

// credential resolves a reference; an empty name means ssh-agent.
func (inv *Inventory) credential(name string) (domain.CredentialRef, error) {
	if name == "" {
		return domain.CredentialRef{Name: "ssh-agent", Type: "agent"}, nil
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
	case "agent":
	default:
		return c, fmt.Errorf("credential %q: type must be password, private_key or agent", name)
	}
	return c, nil
}

func merge(maps ...map[string]string) map[string]string {
	var out map[string]string
	for _, m := range maps {
		for k, v := range m {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}
