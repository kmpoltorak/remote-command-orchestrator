package commandprompt

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Limits enforced by validation.
const (
	MaxRegexLen   = 1024
	MaxStepRetry  = 10
	MaxHostRetry  = 10
	MaxTimeout    = 24 * time.Hour
	MaxSteps      = 500
	MaxCommandLen = 8192
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	varPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

// ValidationError aggregates every problem found in a file.
type ValidationError struct {
	Issues []string `json:"issues"`
}

func (e *ValidationError) Error() string {
	return "command prompt invalid: " + strings.Join(e.Issues, "; ")
}

// Validate checks everything that can be checked without hosts: required
// fields, unique names, durations, regexes, variable references, retries,
// expectation types and template syntax.
func (p *Prompt) Validate() error {
	v := &validator{}
	if p.Name == "" {
		v.add("name is required")
	} else if !namePattern.MatchString(p.Name) {
		v.add("name %q must match %s", p.Name, namePattern)
	}
	if strings.TrimSpace(p.Version) == "" {
		v.add("version is required")
	}
	switch p.Session.Mode {
	case "", ModeInteractive, ModeExec:
	default:
		v.add("session.mode %q must be interactive or exec", p.Session.Mode)
	}
	if p.Session.Width < 0 || p.Session.Height < 0 || p.Session.Width > 1000 || p.Session.Height > 1000 {
		v.add("session width/height must be 0-1000")
	}
	v.dur("defaults.command_timeout", p.Defaults.CommandTimeout)
	v.dur("defaults.expect_timeout", p.Defaults.ExpectTimeout)
	v.dur("defaults.session_timeout", p.Defaults.SessionTimeout)
	v.dur("defaults.retry_delay", p.Defaults.RetryDelay)
	v.dur("defaults.delay_after", p.Defaults.DelayAfter)
	if p.Defaults.Retries < 0 || p.Defaults.Retries > MaxStepRetry {
		v.add("defaults.retries must be 0-%d", MaxStepRetry)
	}

	r := p.Retry
	if r.HostAttempts < 0 || r.HostAttempts > MaxHostRetry {
		v.add("retry.host_attempts must be 0-%d", MaxHostRetry)
	}
	if r.ConnectionRetries != nil && (*r.ConnectionRetries < 0 || *r.ConnectionRetries > 20) {
		v.add("retry.connection_retries must be 0-20")
	}
	v.dur("retry.delay", r.Delay)
	v.dur("retry.max_delay", r.MaxDelay)
	if r.MaxDelay > 0 && r.MaxDelay < r.Delay {
		v.add("retry.max_delay must be >= retry.delay")
	}
	for _, c := range r.RetryOn {
		if !domain.ValidCategory(domain.Category(c)) {
			v.add("retry.retry_on: unknown failure category %q", c)
		}
	}

	for name, variable := range p.Variables {
		if !varPattern.MatchString(name) {
			v.add("variable name %q must match %s", name, varPattern)
		}
		if variable.Sensitive && variable.Default != nil {
			v.add("variable %q: sensitive variables cannot have a default", name)
		}
		if variable.Default != nil {
			if err := CheckValue(*variable.Default); err != nil {
				v.add("variable %q default: %v", name, err)
			}
		}
	}

	if len(p.Steps) == 0 {
		v.add("steps: at least one step is required")
	}
	if n := len(p.AllSteps()); n > MaxSteps {
		v.add("too many steps (%d > %d)", n, MaxSteps)
	}
	if p.Rollback.OnFailure && len(p.Rollback.Steps) == 0 {
		v.add("rollback.on_failure requires rollback.steps")
	}
	seen := map[string]string{}
	check := func(phase string, steps []Step) {
		for i, s := range steps {
			v.step(p, fmt.Sprintf("%s[%d]", phase, i), s, seen)
		}
	}
	check("prechecks", p.Prechecks)
	check("steps", p.Steps)
	check("postchecks", p.Postchecks)
	check("rollback.steps", p.Rollback.Steps)

	if len(v.issues) > 0 {
		return &ValidationError{Issues: v.issues}
	}
	return nil
}

type validator struct{ issues []string }

func (v *validator) add(format string, a ...any) {
	v.issues = append(v.issues, fmt.Sprintf(format, a...))
}

func (v *validator) dur(field string, d time.Duration) {
	if d < 0 || d > MaxTimeout {
		v.add("%s must be between 0 and %s", field, MaxTimeout)
	}
}

func (v *validator) step(p *Prompt, loc string, s Step, seen map[string]string) {
	if s.Name == "" {
		v.add("%s: name is required", loc)
	} else {
		if !namePattern.MatchString(s.Name) {
			v.add("%s: name %q must match %s", loc, s.Name, namePattern)
		}
		if prev, dup := seen[s.Name]; dup {
			v.add("%s: duplicate step name %q (also %s)", loc, s.Name, prev)
		}
		seen[s.Name] = loc
	}
	if s.Command == "" && s.NewlineEnabled() == false {
		v.add("%s: command is required when send_newline is false", loc)
	}
	if len(s.Command) > MaxCommandLen {
		v.add("%s: command exceeds %d bytes", loc, MaxCommandLen)
	}
	// Commands and contains/not_contains strings may use {{ .var }}; regexes may not,
	// because substituted values would need escaping and could alter the pattern.
	var refs []string
	for _, text := range append([]string{s.Command}, append(append([]string{}, s.Expect.Contains...), s.Expect.NotContains...)...) {
		r, err := References(text)
		if err != nil {
			v.add("%s: %v", loc, err)
		}
		refs = append(refs, r...)
	}
	if strings.Contains(s.Expect.Regex, "{{") {
		v.add("%s: expect.regex must not contain template references", loc)
	}
	for _, ref := range refs {
		decl, ok := p.Variables[ref]
		if !ok {
			v.add("%s: command references undeclared variable %q", loc, ref)
			continue
		}
		if decl.Sensitive && !s.Sensitive {
			v.add("%s: uses sensitive variable %q and must be marked sensitive: true", loc, ref)
		}
	}
	if s.When != nil {
		if _, ok := p.Variables[s.When.Variable]; !ok {
			v.add("%s: when.variable %q is not declared", loc, s.When.Variable)
		}
		if s.When.Exists == nil && s.When.Equals == nil {
			v.add("%s: when requires exists or equals", loc)
		}
	}
	v.dur(loc+".timeout", s.Timeout)
	v.dur(loc+".expect_timeout", s.ExpectTimeout)
	v.dur(loc+".retry_delay", s.RetryDelay)
	if s.DelayAfter != nil {
		v.dur(loc+".delay_after", *s.DelayAfter)
	}
	if s.Retries != nil && (*s.Retries < 0 || *s.Retries > MaxStepRetry) {
		v.add("%s: retries must be 0-%d", loc, MaxStepRetry)
	}

	e := s.Expect
	if e.Regex != "" {
		if len(e.Regex) > MaxRegexLen {
			v.add("%s: expect.regex exceeds %d characters", loc, MaxRegexLen)
		} else if _, err := regexp.Compile(e.Regex); err != nil {
			v.add("%s: expect.regex invalid: %v", loc, err)
		}
	}
	for _, c := range append(append([]string{}, e.Contains...), e.NotContains...) {
		if c == "" {
			v.add("%s: expect contains/not_contains entries must not be empty", loc)
		}
		if len(c) > MaxRegexLen {
			v.add("%s: expect string exceeds %d characters", loc, MaxRegexLen)
		}
	}
	if e.ExitCode != nil {
		if *e.ExitCode < 0 || *e.ExitCode > 255 {
			v.add("%s: expect.exit_code must be 0-255", loc)
		}
		if p.Session.Mode == ModeInteractive {
			v.add("%s: expect.exit_code requires session.mode exec", loc)
		}
	}
}
