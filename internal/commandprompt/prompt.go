// Package commandprompt parses, validates and renders command prompt files:
// ordered multi-step SSH workflows with expectations.
package commandprompt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxFileSize bounds command prompt and inventory files.
const MaxFileSize = 1 << 20

// Session modes.
const (
	ModeInteractive = "interactive"
	ModeExec        = "exec"
)

// Prompt is a parsed command prompt.
type Prompt struct {
	Name        string              `yaml:"name" json:"name"`
	Description string              `yaml:"description" json:"description,omitempty"`
	Version     string              `yaml:"version" json:"version"`
	Metadata    map[string]string   `yaml:"metadata" json:"metadata,omitempty"`
	Session     Session             `yaml:"session" json:"session"`
	Defaults    Defaults            `yaml:"defaults" json:"defaults"`
	Retry       RetryPolicy         `yaml:"retry" json:"retry"`
	Variables   map[string]Variable `yaml:"variables" json:"variables,omitempty"`
	Prechecks   []Step              `yaml:"prechecks" json:"prechecks,omitempty"`
	Steps       []Step              `yaml:"steps" json:"steps"`
	Postchecks  []Step              `yaml:"postchecks" json:"postchecks,omitempty"`
	Rollback    Rollback            `yaml:"rollback" json:"rollback"`

	// Hash is the hex SHA-256 of the raw file content.
	Hash string `yaml:"-" json:"hash"`
}

// Session overrides profile session settings.
type Session struct {
	Mode     string `yaml:"mode" json:"mode,omitempty"`
	Profile  string `yaml:"profile" json:"profile,omitempty"`
	PTY      *bool  `yaml:"pty" json:"pty,omitempty"`
	Terminal string `yaml:"terminal" json:"terminal,omitempty"`
	Width    int    `yaml:"width" json:"width,omitempty"`
	Height   int    `yaml:"height" json:"height,omitempty"`
}

// Defaults apply to every step unless overridden.
type Defaults struct {
	CommandTimeout time.Duration `yaml:"command_timeout" json:"command_timeout,omitempty"`
	ExpectTimeout  time.Duration `yaml:"expect_timeout" json:"expect_timeout,omitempty"`
	SessionTimeout time.Duration `yaml:"session_timeout" json:"session_timeout,omitempty"`
	Retries        int           `yaml:"retries" json:"retries,omitempty"`
	RetryDelay     time.Duration `yaml:"retry_delay" json:"retry_delay,omitempty"`
	DelayAfter     time.Duration `yaml:"delay_after" json:"delay_after,omitempty"`
}

// RetryPolicy controls host execution retry (re-running the whole workflow)
// and overrides of SSH connection retry.
type RetryPolicy struct {
	ConnectionRetries *int          `yaml:"connection_retries" json:"connection_retries,omitempty"`
	HostAttempts      int           `yaml:"host_attempts" json:"host_attempts,omitempty"`
	Delay             time.Duration `yaml:"delay" json:"delay,omitempty"`
	MaxDelay          time.Duration `yaml:"max_delay" json:"max_delay,omitempty"`
	RetryOn           []string      `yaml:"retry_on" json:"retry_on,omitempty"`
	AfterCommandsSent bool          `yaml:"after_commands_sent" json:"after_commands_sent,omitempty"`
}

// Variable declares a template variable.
type Variable struct {
	Required    bool    `yaml:"required" json:"required,omitempty"`
	Default     *string `yaml:"default" json:"default,omitempty"`
	Sensitive   bool    `yaml:"sensitive" json:"sensitive,omitempty"`
	Description string  `yaml:"description" json:"description,omitempty"`
}

// Rollback is an explicitly defined rollback block.
type Rollback struct {
	OnFailure bool   `yaml:"on_failure" json:"on_failure,omitempty"`
	Steps     []Step `yaml:"steps" json:"steps,omitempty"`
}

// Step is one command with its expectation.
type Step struct {
	Name            string        `yaml:"name" json:"name"`
	Description     string        `yaml:"description" json:"description,omitempty"`
	Command         string        `yaml:"command" json:"command"`
	When            *When         `yaml:"when" json:"when,omitempty"`
	Expect          Expect        `yaml:"expect" json:"expect"`
	Timeout         time.Duration `yaml:"timeout" json:"timeout,omitempty"`
	ExpectTimeout   time.Duration `yaml:"expect_timeout" json:"expect_timeout,omitempty"`
	Retries         *int          `yaml:"retries" json:"retries,omitempty"`
	RetryDelay      time.Duration `yaml:"retry_delay" json:"retry_delay,omitempty"`
	ContinueOnError bool          `yaml:"continue_on_error" json:"continue_on_error,omitempty"`
	SendNewline     *bool         `yaml:"send_newline" json:"send_newline,omitempty"`
	Sensitive       bool          `yaml:"sensitive" json:"sensitive,omitempty"`
	DelayAfter      *time.Duration `yaml:"delay_after" json:"delay_after,omitempty"`
}

// NewlineEnabled reports whether a line ending is sent after the command (default true).
func (s Step) NewlineEnabled() bool { return s.SendNewline == nil || *s.SendNewline }

// When is a deliberately tiny conditional: variable existence or equality.
type When struct {
	Variable string  `yaml:"variable" json:"variable"`
	Exists   *bool   `yaml:"exists" json:"exists,omitempty"`
	Equals   *string `yaml:"equals" json:"equals,omitempty"`
}

// Holds evaluates the condition against resolved variables.
func (w *When) Holds(vars map[string]string) bool {
	if w == nil {
		return true
	}
	v, ok := vars[w.Variable]
	ok = ok && v != ""
	if w.Exists != nil && ok != *w.Exists {
		return false
	}
	if w.Equals != nil && (!ok || v != *w.Equals) {
		return false
	}
	return true
}

// Expect lists conditions; all specified conditions must hold.
type Expect struct {
	Regex       string     `yaml:"regex" json:"regex,omitempty"`
	Contains    StringList `yaml:"contains" json:"contains,omitempty"`
	NotContains StringList `yaml:"not_contains" json:"not_contains,omitempty"`
	ExitCode    *int       `yaml:"exit_code" json:"exit_code,omitempty"`
}

// IsZero reports whether no condition is set.
func (e Expect) IsZero() bool {
	return e.Regex == "" && len(e.Contains) == 0 && len(e.NotContains) == 0 && e.ExitCode == nil
}

// StringList accepts either a scalar string or a list of strings.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *StringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = StringList{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*l = s
	return nil
}

// AllSteps returns every step in declaration order, rollback last.
func (p *Prompt) AllSteps() []Step {
	out := append([]Step{}, p.Prechecks...)
	out = append(out, p.Steps...)
	out = append(out, p.Postchecks...)
	return append(out, p.Rollback.Steps...)
}

// UsesExitCode reports whether any step expects an exit code.
func (p *Prompt) UsesExitCode() bool {
	for _, s := range p.AllSteps() {
		if s.Expect.ExitCode != nil {
			return true
		}
	}
	return false
}

// ResolveMode applies the documented mode resolution:
// explicit session.mode > exec when exit_code is used > profile mode > interactive.
func (p *Prompt) ResolveMode(profileMode string) string {
	switch {
	case p.Session.Mode != "":
		return p.Session.Mode
	case p.UsesExitCode():
		return ModeExec
	case profileMode != "":
		return profileMode
	}
	return ModeInteractive
}

// Parse decodes and validates a command prompt. Unknown fields are rejected so
// that typos (e.g. "expcet") never silently disable a check.
func Parse(data []byte) (*Prompt, error) {
	if len(data) > MaxFileSize {
		return nil, &ValidationError{Issues: []string{fmt.Sprintf("file exceeds %d bytes", MaxFileSize)}}
	}
	var p Prompt
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &ValidationError{Issues: []string{"file is empty"}}
		}
		return nil, &ValidationError{Issues: []string{"YAML syntax: " + err.Error()}}
	}
	sum := sha256.Sum256(data)
	p.Hash = hex.EncodeToString(sum[:])
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads and parses a command prompt file.
func LoadFile(path string) (*Prompt, []byte, error) {
	data, err := ReadLimited(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := Parse(data)
	return p, data, err
}

// ReadLimited reads a regular file up to MaxFileSize bytes.
func ReadLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s: file exceeds %d bytes", path, MaxFileSize)
	}
	return data, nil
}
