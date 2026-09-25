package job

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Step kinds.
const (
	KindCommand = "command"
	KindScript  = "script"
	KindCopy    = "copy"
)

// Action is one step made concrete for a host.
//
// Script and copy content is first uploaded, as the login user, to a private
// temp file (see UploadCommand); Remote then runs against that file. This
// keeps stdin of a sudo command reserved for the sudo password, so the
// password can never leak into a script or a file when sudo does not prompt.
type Action struct {
	Name             string
	Kind             string
	Display          string // what reports show; [SENSITIVE] for sensitive steps
	Shell            string // KindCommand: rendered command
	Content          []byte // KindScript / KindCopy: bytes to upload (never shown)
	Dest             string // KindCopy
	Mode             string // KindCopy
	Sudo             bool
	ExitCode         int
	Contains         []string
	NotContains      []string
	Regex            *regexp.Regexp
	Timeout          time.Duration
	Retries          int
	RetryDelay       time.Duration
	ContinueOnError  bool
	Sensitive        bool
	Reboot           bool          // wait for the host to come back with a new boot ID
	Disconnect       bool          // connection loss is expected (always true with Reboot)
	ReconnectTimeout time.Duration // how long to wait for the host to be reachable again
	FireAndForget    bool          // start in the background and check nothing
}

// Default reconnect timeouts.
const (
	DefaultRebootTimeout     = 10 * time.Minute
	DefaultDisconnectTimeout = 5 * time.Minute
)

// UploadCommand stores stdin in a new 0600 temp file and prints its path.
const UploadCommand = `umask 077 && t=$(mktemp) && cat > "$t" && printf '%s' "$t"`

// Remote returns the command line to run. tmp is the uploaded temp file for
// script/copy steps. sudoPassword selects sudo -S (password on stdin) or -n.
func (a Action) Remote(tmp string, sudoPassword bool) string {
	wrap := func(cmd string) string {
		if !a.Sudo {
			return cmd
		}
		if sudoPassword {
			// -k ignores cached credentials so sudo always consumes the password line.
			return "sudo -k -S -p '' -- sh -c " + Quote(cmd)
		}
		return "sudo -n -- sh -c " + Quote(cmd) // never hang on a password prompt
	}
	switch {
	case a.Kind == KindScript:
		return cleanup(wrap("bash "+Quote(tmp)), tmp)
	case a.Kind == KindCommand && a.Content != nil: // sensitive command, see build
		return cleanup(wrap("sh "+Quote(tmp)), tmp)
	case a.FireAndForget:
		// The subshell ignores SIGHUP and drops the session's stdio, so the
		// command keeps running when the connection closes; the launcher
		// itself exits at once. POSIX sh only (works with busybox ash).
		return wrap(fmt.Sprintf("(trap '' HUP; %s) </dev/null >/dev/null 2>&1 &", a.Shell))
	case a.Kind == KindCopy:
		// Copy to a temp name beside dest, then rename: readers never see a
		// partial file, and the file is owned by the (sudo) user doing the copy.
		part := Quote(a.Dest + ".rco-tmp")
		inner := fmt.Sprintf("cp %s %s && chmod %s %s && mv -f %s %s", Quote(tmp), part, a.Mode, part, part, Quote(a.Dest))
		return cleanup(wrap(inner), tmp)
	}
	return wrap(a.Shell)
}

func cleanup(cmd, tmp string) string {
	return fmt.Sprintf("%s; rc=$?; rm -f %s; exit $rc", cmd, Quote(tmp))
}

// Settings are CLI-level defaults the job file can override.
type Settings struct {
	Timeout    time.Duration
	RetryDelay time.Duration
}

// Build renders every step for one host.
func (j *Job) Build(vars map[string]string, s Settings) ([]Action, error) {
	out := make([]Action, 0, len(j.Steps))
	for _, st := range j.Steps {
		a, err := j.build(st, vars, s)
		if err != nil {
			return nil, domain.Fail(domain.CatTemplateError, "step %q: %v", st.Name, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func (j *Job) build(st Step, vars map[string]string, s Settings) (Action, error) {
	a := Action{
		Name:            st.Name,
		Sudo:            j.Defaults.Sudo,
		Timeout:         first(st.Timeout, j.Defaults.Timeout, s.Timeout),
		Retries:         j.Defaults.Retries,
		RetryDelay:      first(st.RetryDelay, j.Defaults.RetryDelay, s.RetryDelay),
		ContinueOnError: st.ContinueOnError,
		Sensitive:       st.Sensitive,
		Reboot:          st.Reboot,
		Disconnect:      st.Reboot || st.Disconnect,
		FireAndForget:   st.FireAndForget,
	}
	if a.Disconnect {
		a.ReconnectTimeout = first(st.ReconnectTimeout, DefaultDisconnectTimeout)
		if a.Reboot {
			a.ReconnectTimeout = first(st.ReconnectTimeout, DefaultRebootTimeout)
		}
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
		a.Kind = KindCommand
		if a.Shell, err = Render(st.Command, vars); err != nil {
			return a, err
		}
		a.Display = a.Shell
	case st.Script != "":
		a.Kind = KindScript
		a.Display = "script " + st.Script
		// Job variables are exported at the top of the script.
		a.Content = append([]byte(exports(vars)), st.scriptBody...)
	case st.Copy != nil:
		a.Kind = KindCopy
		if a.Dest, err = Render(st.Copy.Dest, vars); err != nil {
			return a, err
		}
		a.Content = st.Copy.body
		if st.Copy.Template {
			r, err := Render(string(a.Content), vars)
			if err != nil {
				return a, err
			}
			a.Content = []byte(r)
		}
		a.Mode = st.Copy.Mode
		if a.Mode == "" {
			a.Mode = DefaultMode
		}
		a.Display = fmt.Sprintf("copy %s -> %s (mode %s)", st.Copy.Src, a.Dest, a.Mode)
	}
	if a.Sensitive {
		a.Display = domain.SensitiveMask
		if a.Kind == KindCommand {
			// Keep secrets out of the remote process list (ps): the command
			// travels as file content instead of as an argument.
			a.Content = []byte(a.Shell + "\n")
		}
	}
	return a, nil
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
