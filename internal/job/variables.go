package job

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The only template form is {{ .name }}. It is a plain lookup, not a template
// engine: nothing in a job file can call functions or execute code locally.
var (
	refPattern  = regexp.MustCompile(`\{\{\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	openPattern = regexp.MustCompile(`\{\{`)
	varPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

// References returns the variables used in s, or an error for any template
// action other than {{ .name }}.
func References(s string) ([]string, error) {
	valid := refPattern.FindAllStringSubmatchIndex(s, -1)
	opens := openPattern.FindAllStringIndex(s, -1)
	if len(opens) != len(valid) {
		return nil, fmt.Errorf("template syntax: only {{ .variable }} is supported")
	}
	var out []string
	for i, m := range valid {
		if m[0] != opens[i][0] {
			return nil, fmt.Errorf("template syntax: only {{ .variable }} is supported")
		}
		out = append(out, s[m[2]:m[3]])
	}
	return out, nil
}

// Render substitutes {{ .name }} references; a missing variable is an error.
func Render(s string, vars map[string]string) (string, error) {
	if _, err := References(s); err != nil {
		return "", err
	}
	var missing []string
	out := refPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := refPattern.FindStringSubmatch(m)[1]
		v, ok := vars[name]
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("missing variable(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// CheckValue rejects control characters (a newline in a variable would
// silently add another shell command).
func CheckValue(v string) error {
	for _, r := range v {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return fmt.Errorf("value contains control character %U", r)
		}
	}
	return nil
}

// Inputs are the variable sources for one host.
// Precedence: Host > Job/JobEnv > job file defaults.
type Inputs struct {
	Host   map[string]string // inventory host/group/defaults variables
	Job    map[string]string // --var name=value
	JobEnv map[string]string // --var-env name=ENV_NAME (required for sensitive variables)
}

// Resolve applies precedence and reads env references through lookup.
// It returns the values and the secrets the caller must redact.
func (j *Job) Resolve(in Inputs, lookup func(string) (string, bool)) (map[string]string, []string, error) {
	vars := map[string]string{}
	var secrets []string
	var issues []string
	for name, d := range j.Variables {
		if d.Default != nil {
			vars[name] = *d.Default
		}
	}
	for k, v := range in.Job {
		vars[k] = v
	}
	for k, envName := range in.JobEnv {
		v, ok := lookup(envName)
		if !ok {
			issues = append(issues, fmt.Sprintf("variable %q: environment variable %s is not set", k, envName))
			continue
		}
		vars[k] = v
		secrets = append(secrets, v)
	}
	for k, v := range in.Host {
		vars[k] = v
	}
	for k, v := range vars {
		if err := CheckValue(v); err != nil {
			issues = append(issues, fmt.Sprintf("variable %q: %v", k, err))
		}
	}
	for name, d := range j.Variables {
		_, lit := in.Job[name]
		_, host := in.Host[name]
		if d.Sensitive && (lit || host) {
			issues = append(issues, fmt.Sprintf("sensitive variable %q must be passed with --var-env, not as a literal", name))
		}
		if d.Required && vars[name] == "" {
			issues = append(issues, fmt.Sprintf("required variable %q is not set", name))
		}
		if d.Sensitive && vars[name] != "" {
			secrets = append(secrets, vars[name])
		}
	}
	if len(issues) > 0 {
		sort.Strings(issues)
		return nil, nil, &ValidationError{Issues: issues}
	}
	return vars, secrets, nil
}
