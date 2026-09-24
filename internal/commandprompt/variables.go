package commandprompt

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The only template form accepted is {{ .name }}. This is a plain lookup,
// not a template engine, so templates cannot execute code or call functions.
var (
	refPattern  = regexp.MustCompile(`\{\{\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	openPattern = regexp.MustCompile(`\{\{`)
)

// References returns the variable names used by s, or an error if s contains
// any template action other than {{ .name }}.
func References(s string) ([]string, error) {
	valid := refPattern.FindAllStringSubmatchIndex(s, -1)
	opens := openPattern.FindAllStringIndex(s, -1)
	if len(opens) != len(valid) {
		return nil, fmt.Errorf("template syntax: only {{ .variable }} is supported")
	}
	for i := range valid {
		if valid[i][0] != opens[i][0] {
			return nil, fmt.Errorf("template syntax: only {{ .variable }} is supported")
		}
	}
	var out []string
	for _, m := range valid {
		out = append(out, s[m[2]:m[3]])
	}
	return out, nil
}

// Render substitutes {{ .name }} references. A missing variable is an error.
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

// CheckValue rejects control characters. A newline in an interactive session
// would inject an extra command, so values must be single-line.
func CheckValue(v string) error {
	for _, r := range v {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return fmt.Errorf("value contains control character %U", r)
		}
	}
	return nil
}

// VarSources are the variable inputs for one host, before env resolution.
// Literal maps may be persisted; *Env maps hold only environment variable names.
type VarSources struct {
	JobVars  map[string]string
	JobEnv   map[string]string
	HostVars map[string]string
	HostEnv  map[string]string
}

// CheckSources validates variable inputs against declarations without
// resolving environment values. It is used at job creation.
func (p *Prompt) CheckSources(src VarSources) []string {
	var issues []string
	for _, layer := range []struct {
		name     string
		lit, env map[string]string
	}{{"job", src.JobVars, src.JobEnv}, {"host", src.HostVars, src.HostEnv}} {
		for k, val := range layer.lit {
			if _, dup := layer.env[k]; dup {
				issues = append(issues, fmt.Sprintf("%s variable %q given both as literal and env reference", layer.name, k))
			}
			if d, ok := p.Variables[k]; ok && d.Sensitive {
				issues = append(issues, fmt.Sprintf("sensitive variable %q must be supplied as an env reference, not a literal", k))
			}
			if err := CheckValue(val); err != nil {
				issues = append(issues, fmt.Sprintf("%s variable %q: %v", layer.name, k, err))
			}
		}
		for k, envName := range layer.env {
			if !varPattern.MatchString(envName) {
				issues = append(issues, fmt.Sprintf("%s variable %q: invalid environment variable name %q", layer.name, k, envName))
			}
		}
	}
	for name, d := range p.Variables {
		if !d.Required {
			continue
		}
		_, a := src.HostVars[name]
		_, b := src.HostEnv[name]
		_, c := src.JobVars[name]
		_, e := src.JobEnv[name]
		if !a && !b && !c && !e && d.Default == nil {
			issues = append(issues, fmt.Sprintf("required variable %q is not set", name))
		}
	}
	sort.Strings(issues)
	return issues
}

// ResolveVars applies precedence host > job > prompt default and reads env
// references through lookup. It returns the values and the list of values
// that must be redacted (sensitive variables and all env-sourced values).
func (p *Prompt) ResolveVars(src VarSources, lookup func(string) (string, bool)) (map[string]string, []string, error) {
	vars := map[string]string{}
	var secrets []string
	for name, d := range p.Variables {
		if d.Default != nil {
			vars[name] = *d.Default
		}
	}
	apply := func(lit, env map[string]string) error {
		for k, v := range lit {
			vars[k] = v
		}
		for k, envName := range env {
			v, ok := lookup(envName)
			if !ok {
				return fmt.Errorf("variable %q: environment variable %s is not set", k, envName)
			}
			if err := CheckValue(v); err != nil {
				return fmt.Errorf("variable %q: %v", k, err)
			}
			vars[k] = v
			secrets = append(secrets, v)
		}
		return nil
	}
	if err := apply(src.JobVars, src.JobEnv); err != nil {
		return nil, nil, err
	}
	if err := apply(src.HostVars, src.HostEnv); err != nil {
		return nil, nil, err
	}
	for name, d := range p.Variables {
		if d.Required {
			if _, ok := vars[name]; !ok {
				return nil, nil, fmt.Errorf("required variable %q is not set", name)
			}
		}
		if d.Sensitive && vars[name] != "" {
			secrets = append(secrets, vars[name])
		}
	}
	return vars, secrets, nil
}
