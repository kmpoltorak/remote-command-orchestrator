package job

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Action is one step made concrete for a host.
type Action struct {
	Name            string
	Kind            string // command | script | copy
	Display         string // what reports show; [SENSITIVE] for sensitive steps
	Command         string // remote command line
	Stdin           []byte // script / file content (never shown)
	Sudo            bool
	ExitCode        int
	Contains        []string
	NotContains     []string
	Regex           *regexp.Regexp
	Timeout         time.Duration
	Retries         int
	RetryDelay      time.Duration
	ContinueOnError bool
	Sensitive       bool
}

// Settings are CLI-level defaults the job file can override.
type Settings struct {
	Timeout    time.Duration
	RetryDelay time.Duration
}

// Build renders every step for one host. sudoPassword reports whether a sudo
// password will be written to stdin (sudo -S) or sudo must not prompt (-n).
func (j *Job) Build(vars map[string]string, s Settings, sudoPassword bool) ([]Action, error) {
	out := make([]Action, 0, len(j.Steps))
	for _, st := range j.Steps {
		a, err := j.build(st, vars, s, sudoPassword)
		if err != nil {
			return nil, domain.Fail(domain.CatTemplateError, "step %q: %v", st.Name, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func (j *Job) build(st Step, vars map[string]string, s Settings, sudoPassword bool) (Action, error) {
	a := Action{
		Name:            st.Name,
		Sudo:            j.Defaults.Sudo,
		Timeout:         first(st.Timeout, j.Defaults.Timeout, s.Timeout),
		Retries:         j.Defaults.Retries,
		RetryDelay:      first(st.RetryDelay, j.Defaults.RetryDelay, s.RetryDelay),
		ContinueOnError: st.ContinueOnError,
		Sensitive:       st.Sensitive,
	}
	if st.Sudo != nil {
		a.Sudo = *st.Sudo
	}
	if st.Retries != nil {
		a.Retries = *st.Retries
	}
	if st.Expect.ExitCode != nil {
		a.ExitCode = *st.Expect.ExitCode
	}
	if st.Expect.Regex != "" {
		a.Regex = regexp.MustCompile(st.Expect.Regex) // validated in Validate
	}
	var err error
	if a.Contains, err = renderAll(st.Expect.Contains, vars); err != nil {
		return a, err
	}
	if a.NotContains, err = renderAll(st.Expect.NotContains, vars); err != nil {
		return a, err
	}

	switch {
	case st.Command != "":
		a.Kind = "command"
		cmd, err := Render(st.Command, vars)
		if err != nil {
			return a, err
		}
		a.Display = cmd
		a.Command = cmd
		if a.Sudo {
			a.Command = sudoPrefix(sudoPassword) + "sh -c " + Quote(cmd)
		}
	case st.Script != "":
		a.Kind = "script"
		a.Display = "bash -s < " + st.Script
		a.Command = "bash -s"
		if a.Sudo {
			a.Command = sudoPrefix(sudoPassword) + "bash -s"
		}
		// Variables are exported at the top of the script stream (stdin, so
		// they never appear in the remote process list).
		a.Stdin = append([]byte(exports(vars)), st.scriptBody...)
	case st.Copy != nil:
		a.Kind = "copy"
		dest, err := Render(st.Copy.Dest, vars)
		if err != nil {
			return a, err
		}
		body := st.Copy.body
		if st.Copy.Template {
			r, err := Render(string(body), vars)
			if err != nil {
				return a, err
			}
			body = []byte(r)
		}
		mode := st.Copy.Mode
		if mode == "" {
			mode = DefaultMode
		}
		a.Display = fmt.Sprintf("copy %s -> %s (mode %s)", st.Copy.Src, dest, mode)
		a.Command = uploadCommand(dest, mode)
		if a.Sudo {
			a.Command = sudoPrefix(sudoPassword) + "sh -c " + Quote(a.Command)
		}
		a.Stdin = body
	}
	if a.Sensitive {
		a.Display = domain.SensitiveMask
	}
	return a, nil
}

// uploadCommand writes stdin to a temp file next to dest and renames it into
// place, so readers never observe a partially written file.
func uploadCommand(dest, mode string) string {
	tmp := Quote(dest + ".rco-tmp")
	return fmt.Sprintf("umask 077 && cat > %s && chmod %s %s && mv -f %s %s", tmp, mode, tmp, tmp, Quote(dest))
}

func sudoPrefix(password bool) string {
	if password {
		return "sudo -S -p '' -- " // password is the first line of stdin
	}
	return "sudo -n -- " // never hang on a password prompt
}

func exports(vars map[string]string) string {
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		fmt.Fprintf(&b, "export %s=%s\n", k, Quote(vars[k]))
	}
	return b.String()
}

// Quote returns s as a single POSIX shell word.
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func renderAll(in []string, vars map[string]string) ([]string, error) {
	var out []string
	for _, s := range in {
		r, err := Render(s, vars)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func first(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}
