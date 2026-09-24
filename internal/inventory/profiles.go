package inventory

import (
	"fmt"
	"regexp"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/commandprompt"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

func ptr[T any](v T) *T { return &v }

// Builtin profiles. Vendors appear only here, as data.
var Builtin = map[string]domain.Profile{
	"linux": {
		Mode:        commandprompt.ModeExec,
		PromptRegex: `[$#]\s*$`,
		LineEnding:  "\n",
		PTY:         ptr(false),
	},
	"cisco_ios": {
		Mode:        commandprompt.ModeInteractive,
		PromptRegex: `[\w.\-@/:()]+[>#]\s*$`,
		LineEnding:  "\n",
		PTY:         ptr(true),
		Pager:       domain.PagerConfig{Patterns: []string{"--More--"}, Response: " "},
	},
	"cisco_nxos": {
		Mode:        commandprompt.ModeInteractive,
		PromptRegex: `[\w.\-@/:()]+[>#]\s*$`,
		LineEnding:  "\n",
		PTY:         ptr(true),
		Pager:       domain.PagerConfig{Patterns: []string{"--More--"}, Response: " "},
	},
	"juniper_junos": {
		Mode:        commandprompt.ModeInteractive,
		PromptRegex: `[\w.\-@]+[>#%]\s*$`,
		LineEnding:  "\n",
		PTY:         ptr(true),
		Pager:       domain.PagerConfig{Patterns: []string{"---(more"}, Response: " "},
	},
	"generic_network_device": {
		Mode:        commandprompt.ModeInteractive,
		PromptRegex: `[\w.\-@/:()~]+[>#$%]\s*$`,
		LineEnding:  "\n",
		PTY:         ptr(true),
		Pager:       domain.PagerConfig{Patterns: []string{"--More--"}, Response: " "},
	},
}

// Profile returns a named profile: custom inventory profiles overlay the
// builtin of the same name, or generic_network_device when none exists.
func (inv *Inventory) Profile(name string) (domain.Profile, error) {
	base, isBuiltin := Builtin[name]
	custom, isCustom := inv.Profiles[name]
	if !isBuiltin && !isCustom {
		return domain.Profile{}, fmt.Errorf("unknown profile %q", name)
	}
	if !isBuiltin {
		base = Builtin["generic_network_device"]
	}
	if isCustom {
		base = overlay(base, custom)
	}
	base.Name = name
	return base, ValidateProfile(base)
}

func overlay(b, c domain.Profile) domain.Profile {
	b.Mode = first(c.Mode, b.Mode)
	b.PromptRegex = first(c.PromptRegex, b.PromptRegex)
	b.InitialPromptRegex = first(c.InitialPromptRegex, b.InitialPromptRegex)
	b.LineEnding = first(c.LineEnding, b.LineEnding)
	b.Terminal = first(c.Terminal, b.Terminal)
	b.Width = first(c.Width, b.Width)
	b.Height = first(c.Height, b.Height)
	b.LoginTimeout = first(c.LoginTimeout, b.LoginTimeout)
	b.PromptSettle = first(c.PromptSettle, b.PromptSettle)
	if c.PTY != nil {
		b.PTY = c.PTY
	}
	if c.SetupCommands != nil {
		b.SetupCommands = c.SetupCommands
	}
	if c.Pager.Patterns != nil {
		b.Pager.Patterns = c.Pager.Patterns
	}
	b.Pager.Response = first(c.Pager.Response, b.Pager.Response)
	b.Pager.MaxPages = first(c.Pager.MaxPages, b.Pager.MaxPages)
	return b
}

// ValidateProfile checks regexes and ranges.
func ValidateProfile(p domain.Profile) error {
	switch p.Mode {
	case "", commandprompt.ModeInteractive, commandprompt.ModeExec:
	default:
		return fmt.Errorf("profile %q: mode must be interactive or exec", p.Name)
	}
	for _, re := range []string{p.PromptRegex, p.InitialPromptRegex} {
		if len(re) > commandprompt.MaxRegexLen {
			return fmt.Errorf("profile %q: regex too long", p.Name)
		}
		if _, err := regexp.Compile(re); err != nil {
			return fmt.Errorf("profile %q: invalid regex: %v", p.Name, err)
		}
	}
	if p.LoginTimeout < 0 || p.LoginTimeout > time.Hour || p.PromptSettle < 0 || p.PromptSettle > time.Minute {
		return fmt.Errorf("profile %q: login_timeout/prompt_settle out of range", p.Name)
	}
	if p.Pager.MaxPages < 0 || p.Pager.MaxPages > 100000 {
		return fmt.Errorf("profile %q: pager.max_pages out of range", p.Name)
	}
	for _, c := range p.SetupCommands {
		if err := commandprompt.CheckValue(c); err != nil {
			return fmt.Errorf("profile %q: setup command: %v", p.Name, err)
		}
	}
	return nil
}
