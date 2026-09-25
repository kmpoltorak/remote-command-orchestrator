// Package job parses and validates job files: ordered lists of remote
// commands, bash scripts and file uploads to run on Linux-like hosts.
package job

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Limits enforced by validation.
const (
	MaxFileSize = 1 << 20  // job, inventory and script files
	MaxCopySize = 10 << 20 // uploaded files
	MaxRetries  = 10
	MaxTimeout  = 24 * time.Hour
	MaxRegexLen = 1024
	DefaultMode = "0644"
)

// Job is a parsed job file.
type Job struct {
	Name        string              `yaml:"name" json:"name"`
	Description string              `yaml:"description" json:"description,omitempty"`
	Version     string              `yaml:"version" json:"version,omitempty"`
	Variables   map[string]Variable `yaml:"variables" json:"variables,omitempty"`
	Defaults    Defaults            `yaml:"defaults" json:"defaults"`
	Steps       []Step              `yaml:"steps" json:"steps"`

	// Hash is the SHA-256 of the job file plus every script and uploaded file,
	// so a report identifies exactly what was executed.
	Hash string `yaml:"-" json:"hash"`
	Path string `yaml:"-" json:"path"`
}

// Variable declares a {{ .name }} template variable.
type Variable struct {
	Required    bool    `yaml:"required" json:"required,omitempty"`
	Default     *string `yaml:"default" json:"default,omitempty"`
	Sensitive   bool    `yaml:"sensitive" json:"sensitive,omitempty"`
	Description string  `yaml:"description" json:"description,omitempty"`
}

// Defaults apply to every step unless the step overrides them.
type Defaults struct {
	Timeout    time.Duration `yaml:"timeout" json:"timeout,omitempty"`
	Retries    int           `yaml:"retries" json:"retries,omitempty"`
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay,omitempty"`
	Sudo       bool          `yaml:"sudo" json:"sudo,omitempty"`
}

// Step is exactly one of: command, script or copy.
type Step struct {
	Name            string        `yaml:"name" json:"name"`
	Description     string        `yaml:"description" json:"description,omitempty"`
	Command         string        `yaml:"command" json:"command,omitempty"`
	Script          string        `yaml:"script" json:"script,omitempty"`
	Copy            *Copy         `yaml:"copy" json:"copy,omitempty"`
	Sudo            *bool         `yaml:"sudo" json:"sudo,omitempty"`
	Expect          Expect        `yaml:"expect" json:"expect"`
	Timeout         time.Duration `yaml:"timeout" json:"timeout,omitempty"`
	Retries         *int          `yaml:"retries" json:"retries,omitempty"`
	RetryDelay      time.Duration `yaml:"retry_delay" json:"retry_delay,omitempty"`
	ContinueOnError bool          `yaml:"continue_on_error" json:"continue_on_error,omitempty"`
	Sensitive       bool          `yaml:"sensitive" json:"sensitive,omitempty"`

	scriptBody []byte
}

// Copy uploads a local file. Src is relative to the job file directory.
type Copy struct {
	Src      string `yaml:"src" json:"src"`
	Dest     string `yaml:"dest" json:"dest"`
	Mode     string `yaml:"mode" json:"mode,omitempty"`
	Template bool   `yaml:"template" json:"template,omitempty"`

	body []byte
}

// Expect lists conditions; all must hold. Without conditions the step
// succeeds on exit code 0.
type Expect struct {
	ExitCode    *int       `yaml:"exit_code" json:"exit_code,omitempty"`
	Contains    StringList `yaml:"contains" json:"contains,omitempty"`
	NotContains StringList `yaml:"not_contains" json:"not_contains,omitempty"`
	Regex       string     `yaml:"regex" json:"regex,omitempty"`
}

// StringList accepts a scalar string or a list of strings.
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

// ValidationError aggregates every problem found.
type ValidationError struct {
	Issues []string `json:"issues"`
}

func (e *ValidationError) Error() string { return "job invalid: " + strings.Join(e.Issues, "; ") }

// DefaultFile is the job file name inside a job directory.
const DefaultFile = "job.yaml"

// Load reads a job file and every file it references, then validates it.
// path may be a job directory, meaning <dir>/job.yaml; keeping each job in its
// own directory keeps its scripts and files next to it.
func Load(path string) (*Job, error) {
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		path = filepath.Join(path, DefaultFile)
	}
	data, err := ReadFile(path, MaxFileSize)
	if err != nil {
		return nil, err
	}
	j, err := Parse(data)
	if err != nil {
		return nil, err
	}
	j.Path = path
	dir := filepath.Dir(path)
	h := sha256.New()
	h.Write(data)
	var issues []string
	for i := range j.Steps {
		s := &j.Steps[i]
		switch {
		case s.Script != "":
			if s.scriptBody, err = ReadFile(filepath.Join(dir, s.Script), MaxFileSize); err != nil {
				issues = append(issues, fmt.Sprintf("step %q: %v", s.Name, err))
			}
			h.Write(s.scriptBody)
		case s.Copy != nil:
			if s.Copy.body, err = ReadFile(filepath.Join(dir, s.Copy.Src), MaxCopySize); err != nil {
				issues = append(issues, fmt.Sprintf("step %q: %v", s.Name, err))
				continue
			}
			h.Write(s.Copy.body)
			if s.Copy.Template {
				issues = append(issues, j.checkRefs(string(s.Copy.body), fmt.Sprintf("step %q copy.src", s.Name), true)...)
			}
		}
	}
	if len(issues) > 0 {
		return nil, &ValidationError{Issues: issues}
	}
	j.Hash = hex.EncodeToString(h.Sum(nil))
	return j, nil
}

// Parse decodes and validates job YAML. Unknown fields are rejected so a typo
// (e.g. "expcet") never silently disables a check.
func Parse(data []byte) (*Job, error) {
	var j Job
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&j); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &ValidationError{Issues: []string{"file is empty"}}
		}
		return nil, &ValidationError{Issues: []string{"YAML: " + err.Error()}}
	}
	sum := sha256.Sum256(data)
	j.Hash = hex.EncodeToString(sum[:])
	if err := j.Validate(); err != nil {
		return nil, err
	}
	return &j, nil
}

// ReadFile reads a regular file of at most limit bytes.
func ReadFile(path string, limit int64) ([]byte, error) {
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
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: file exceeds %d bytes", path, limit)
	}
	return data, nil
}

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	modePattern = regexp.MustCompile(`^0?[0-7]{3}$`)
)

// Validate checks structure, names, durations, regexes and variable references.
func (j *Job) Validate() error {
	var issues []string
	add := func(format string, a ...any) { issues = append(issues, fmt.Sprintf(format, a...)) }
	if !namePattern.MatchString(j.Name) {
		add("name is required and must match %s", namePattern)
	}
	if j.Defaults.Timeout < 0 || j.Defaults.Timeout > MaxTimeout || j.Defaults.RetryDelay < 0 {
		add("defaults: timeout must be 0-%s and retry_delay >= 0", MaxTimeout)
	}
	if j.Defaults.Retries < 0 || j.Defaults.Retries > MaxRetries {
		add("defaults.retries must be 0-%d", MaxRetries)
	}
	for name, v := range j.Variables {
		if !varPattern.MatchString(name) {
			add("variable %q: name must match %s", name, varPattern)
		}
		if v.Sensitive && v.Default != nil {
			add("variable %q: sensitive variables cannot have a default", name)
		}
		if v.Default != nil {
			if err := CheckValue(*v.Default); err != nil {
				add("variable %q default: %v", name, err)
			}
		}
	}
	if len(j.Steps) == 0 {
		add("steps: at least one step is required")
	}
	seen := map[string]bool{}
	for i := range j.Steps {
		s := &j.Steps[i]
		loc := fmt.Sprintf("steps[%d]", i)
		if !namePattern.MatchString(s.Name) {
			add("%s: name is required and must match %s", loc, namePattern)
		} else if seen[s.Name] {
			add("%s: duplicate step name %q", loc, s.Name)
		}
		seen[s.Name] = true
		kinds := 0
		for _, set := range []bool{s.Command != "", s.Script != "", s.Copy != nil} {
			if set {
				kinds++
			}
		}
		if kinds != 1 {
			add("%s: exactly one of command, script or copy is required", loc)
		}
		if s.Copy != nil {
			if s.Copy.Src == "" || !strings.HasPrefix(s.Copy.Dest, "/") {
				add("%s: copy needs src and an absolute dest", loc)
			}
			if err := CheckValue(s.Copy.Dest); err != nil {
				add("%s: copy.dest: %v", loc, err)
			}
			if s.Copy.Mode != "" && !modePattern.MatchString(s.Copy.Mode) {
				add("%s: copy.mode %q must be octal like 0644", loc, s.Copy.Mode)
			}
		}
		if s.Timeout < 0 || s.Timeout > MaxTimeout || s.RetryDelay < 0 {
			add("%s: timeout must be 0-%s and retry_delay >= 0", loc, MaxTimeout)
		}
		if s.Retries != nil && (*s.Retries < 0 || *s.Retries > MaxRetries) {
			add("%s: retries must be 0-%d", loc, MaxRetries)
		}
		e := s.Expect
		if e.ExitCode != nil && (*e.ExitCode < 0 || *e.ExitCode > 255) {
			add("%s: expect.exit_code must be 0-255", loc)
		}
		if len(e.Regex) > MaxRegexLen {
			add("%s: expect.regex longer than %d", loc, MaxRegexLen)
		} else if _, err := regexp.Compile(e.Regex); err != nil {
			add("%s: expect.regex: %v", loc, err)
		}
		for _, c := range append(append([]string{}, e.Contains...), e.NotContains...) {
			if c == "" {
				add("%s: expect contains/not_contains entries must not be empty", loc)
			}
		}
		texts := append(append([]string{s.Command}, e.Contains...), e.NotContains...)
		if s.Copy != nil {
			texts = append(texts, s.Copy.Dest)
		}
		for _, t := range texts {
			issues = append(issues, j.checkRefs(t, loc, s.Sensitive)...)
		}
		if strings.Contains(e.Regex, "{{") {
			add("%s: expect.regex must not contain template references", loc)
		}
	}
	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

// checkRefs validates template syntax and that referenced variables are declared.
// A sensitive variable may only appear where it is never printed: in steps
// marked sensitive, or inside uploaded file content (allowSensitive).
func (j *Job) checkRefs(text, loc string, allowSensitive bool) []string {
	refs, err := References(text)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", loc, err)}
	}
	var issues []string
	for _, r := range refs {
		v, ok := j.Variables[r]
		switch {
		case !ok:
			issues = append(issues, fmt.Sprintf("%s: undeclared variable %q", loc, r))
		case v.Sensitive && !allowSensitive:
			issues = append(issues, fmt.Sprintf("%s: uses sensitive variable %q and must be marked sensitive: true", loc, r))
		}
	}
	return issues
}
