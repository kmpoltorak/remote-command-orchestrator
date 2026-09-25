// Package cli implements the rco command line. Results go to stdout, logs to
// stderr, so `rco run --output json | jq` always works.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/inventory"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/job"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/runner"
)

// Version is set at build time with -ldflags "-X .../cli.Version=v1.2.3".
var Version = "dev"

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1 // usage, validation or I/O error
	ExitHostsFailed = 2 // run finished but at least one host failed or was cancelled
)

const usage = `rco — run commands, scripts and file uploads on many Linux hosts over SSH

Usage:
  rco run      --inventory FILE --job JOB [selectors] [options]   preview only
  rco run      --inventory FILE --job JOB [selectors] --execute   apply changes
  rco validate --job JOB [--inventory FILE [selectors]]

JOB is a job directory (containing job.yaml) or a job YAML file.
  rco version

Selectors (repeatable; AND across kinds, OR within a kind; none = all hosts):
  -g/--group NAME   -t/--tag NAME   -H/--host NAME

Short flags: -i inventory, -j job, -c concurrency, -o output, -v verbose, -q quiet.

Run "rco run -h" for all options.
`

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitError
	}
	switch args[0] {
	case "run":
		return run(args[1:], stdout, stderr, false)
	case "validate":
		return run(args[1:], stdout, stderr, true)
	case "version", "--version":
		fmt.Fprintln(stdout, "rco", Version)
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return ExitError
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdout, stderr io.Writer, validateOnly bool) int {
	name := "run"
	if validateOnly {
		name = "validate"
	}
	fs := flag.NewFlagSet("rco "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		groups, tags, hosts, vars, varEnvs multi
		o                                  runner.Options
	)
	invPath := fs.String("inventory", "", "inventory YAML file")
	jobPath := fs.String("job", "", "job directory (with job.yaml) or job YAML file")
	fs.Var(&groups, "group", "select hosts in group (repeatable)")
	fs.Var(&tags, "tag", "select hosts with tag (repeatable)")
	fs.Var(&hosts, "host", "select host by name (repeatable)")
	fs.Var(&vars, "var", "job variable NAME=VALUE (repeatable)")
	fs.Var(&varEnvs, "var-env", "job variable NAME=ENV_VAR read from the environment; required for sensitive variables (repeatable)")
	fs.IntVar(&o.Concurrency, "concurrency", 100, "maximum hosts processed at the same time")
	fs.DurationVar(&o.StepTimeout, "timeout", 5*time.Minute, "default per-step timeout (job file values win)")
	fs.DurationVar(&o.ConnectTimeout, "connect-timeout", 10*time.Second, "TCP connect timeout")
	fs.DurationVar(&o.HandshakeTimeout, "handshake-timeout", 15*time.Second, "SSH handshake and authentication timeout")
	fs.IntVar(&o.ConnectRetries, "connect-retries", 2, "extra connection attempts for transient failures (never for auth or host key errors)")
	fs.DurationVar(&o.RetryDelay, "retry-delay", 2*time.Second, "base delay between retries (exponential with jitter)")
	fs.DurationVar(&o.MaxRetryDelay, "max-retry-delay", 30*time.Second, "maximum delay between connection retries")
	fs.IntVar(&o.MaxOutput, "max-output", 1<<20, "bytes of stdout/stderr kept per step (head and tail are kept)")
	fs.StringVar(&o.KnownHosts, "known-hosts", "~/.ssh/known_hosts", "known_hosts file used to verify host keys")
	fs.BoolVar(&o.AcceptNewHosts, "accept-new-host-keys", false, "add keys of hosts missing from known_hosts (trust on first use); changed keys still fail")
	fs.BoolVar(&o.Insecure, "insecure-skip-host-key-check", false, "INSECURE: do not verify host keys (lab use only)")
	output := fs.String("output", "table", "result format on stdout: table, json or yaml")
	reportPath := fs.String("report", "", "also write the full report to FILE (.json, .yaml or .yml)")
	execute := fs.Bool("execute", false, "actually run the job; without it rco only previews what would run, without connecting")
	verbose := fs.Bool("verbose", false, "table output: include every step with its output")
	quiet := fs.Bool("quiet", false, "log only warnings and errors")
	// Short aliases share the long flag's value. --execute deliberately has
	// none: applying changes should always be typed out in full.
	for short, long := range map[string]string{
		"i": "inventory", "j": "job", "g": "group", "t": "tag", "H": "host",
		"c": "concurrency", "o": "output", "v": "verbose", "q": "quiet",
	} {
		fs.Var(fs.Lookup(long).Value, short, "short for --"+long)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	level := slog.LevelInfo
	if *quiet {
		level = slog.LevelWarn
	}
	o.Logger = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return ExitError
	}

	switch {
	case fs.NArg() > 0:
		return fail("unexpected argument %q", fs.Arg(0))
	case *jobPath == "":
		return fail("--job is required")
	case *invPath == "" && !validateOnly:
		return fail("--inventory is required")
	case *output != "table" && *output != "json" && *output != "yaml":
		return fail("--output must be table, json or yaml")
	case o.Concurrency < 1 || o.MaxOutput < 1024:
		return fail("--concurrency must be >= 1 and --max-output >= 1024")
	}
	j, err := job.Load(*jobPath)
	if err != nil {
		return fail("%v", err)
	}
	if validateOnly && *invPath == "" {
		fmt.Fprintf(stdout, "job %q is valid (%d steps, sha256 %s)\n", j.Name, len(j.Steps), j.Hash[:12])
		return ExitOK
	}
	inv, err := inventory.Load(*invPath)
	if err != nil {
		return fail("%v", err)
	}
	targets, err := inv.Select(inventory.Selector{Groups: groups, Tags: tags, Hosts: hosts})
	if err != nil {
		return fail("%v", err)
	}
	if len(targets) == 0 {
		return fail("no hosts match the selectors")
	}
	in := runner.Input{Job: j, Targets: targets}
	if in.Vars, err = pairs(vars, "--var"); err != nil {
		return fail("%v", err)
	}
	if in.VarEnv, err = pairs(varEnvs, "--var-env"); err != nil {
		return fail("%v", err)
	}
	// A preview must work without access to keys and passwords; validate checks them.
	o.SkipCredentials = !*execute && !validateOnly
	r, err := runner.Prepare(in, o)
	if err != nil {
		return fail("validation failed, no host was contacted:\n%v", err)
	}
	if validateOnly {
		fmt.Fprintf(stdout, "job %q is valid for %d hosts\n", j.Name, len(targets))
		return ExitOK
	}
	if !*execute {
		return printPreview(stdout, *output, r)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o.Logger.Info("starting", "job", j.Name, "hosts", len(targets), "concurrency", o.Concurrency)
	rep := r.Run(ctx)
	if *reportPath != "" {
		if err := writeReport(*reportPath, rep); err != nil {
			fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		}
	}
	if err := printReport(stdout, *output, *verbose, rep); err != nil {
		return fail("%v", err)
	}
	if !rep.OK() {
		return ExitHostsFailed
	}
	return ExitOK
}

func pairs(in []string, flagName string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range in {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s %q: expected NAME=VALUE", flagName, kv)
		}
		out[k] = v
	}
	return out, nil
}

func encode(w io.Writer, format string, v any) error {
	if format == "yaml" {
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer enc.Close()
		return enc.Encode(v)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeReport(path string, rep *runner.Report) error {
	format := "json"
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		format = "yaml"
	}
	// 0600: reports contain command output.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := encode(f, format, rep); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func printReport(w io.Writer, format string, verbose bool, rep *runner.Report) error {
	if format != "table" {
		return encode(w, format, rep)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tSTATUS\tFAILED STEP\tREASON\tDURATION")
	for _, h := range rep.Hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", h.Host, h.Status, dash(h.FailedStep), dash(h.Reason), h.Duration)
		if verbose {
			for i, s := range h.Steps {
				fmt.Fprintf(tw, "  %d. %s\t%s\t%s\t%s\t%s\n", i+1, s.Name, s.Status, s.Command, dash(s.Reason), s.Duration)
				for _, line := range outputLines(s.Stdout, s.Stderr) {
					fmt.Fprintf(tw, "     %s\t\t\t\t\n", line)
				}
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%s in %s (job %s, sha256 %.12s)\n", rep.Summary, rep.Duration, rep.Job, rep.Hash)
	return nil
}

func outputLines(stdout, stderr string) []string {
	var out []string
	for _, s := range []struct{ prefix, text string }{{"| ", stdout}, {"! ", stderr}} {
		if s.text == "" {
			continue
		}
		for _, l := range strings.Split(s.text, "\n") {
			out = append(out, s.prefix+strings.ReplaceAll(l, "\t", "    "))
		}
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type dryHost struct {
	Host    string    `json:"host" yaml:"host"`
	Address string    `json:"address" yaml:"address"`
	User    string    `json:"user" yaml:"user"`
	Bastion string    `json:"bastion,omitempty" yaml:"bastion,omitempty"`
	Steps   []dryStep `json:"steps" yaml:"steps"`
}

type dryStep struct {
	Name    string `json:"name" yaml:"name"`
	Kind    string `json:"kind" yaml:"kind"`
	Command string `json:"command" yaml:"command"`
	Sudo    bool   `json:"sudo,omitempty" yaml:"sudo,omitempty"`
	Timeout string `json:"timeout" yaml:"timeout"`
}

func printPreview(w io.Writer, format string, r *runner.Runner) int {
	var out []dryHost
	for _, p := range r.Plans {
		d := dryHost{Host: p.Target.Name, Address: p.Target.Addr(), User: p.Target.Username}
		if p.Target.Bastion != nil {
			d.Bastion = p.Target.Bastion.Name
		}
		for _, a := range p.Actions {
			d.Steps = append(d.Steps, dryStep{Name: a.Name, Kind: a.Kind, Command: a.Display, Sudo: a.Sudo, Timeout: a.Timeout.String()})
		}
		out = append(out, d)
	}
	if format != "table" {
		if err := encode(w, format, out); err != nil {
			return ExitError
		}
		return ExitOK
	}
	for _, d := range out {
		via := ""
		if d.Bastion != "" {
			via = " via " + d.Bastion
		}
		fmt.Fprintf(w, "%s (%s@%s%s)\n", d.Host, d.User, d.Address, via)
		for i, s := range d.Steps {
			sudo := ""
			if s.Sudo {
				sudo = "[sudo] "
			}
			fmt.Fprintf(w, "  %d. %-20s %s%s\n", i+1, s.Name, sudo, s.Command)
		}
	}
	fmt.Fprintf(w, "\npreview: %d hosts, nothing was executed. Add --execute to apply.\n", len(out))
	return ExitOK
}
