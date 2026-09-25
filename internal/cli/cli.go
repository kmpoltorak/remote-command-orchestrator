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
  rco run      -i INVENTORY -j JOB [selectors] [options]              preview only
  rco run      -i INVENTORY -j JOB [selectors] [options] --execute    apply changes
  rco validate -j JOB [-i INVENTORY [selectors]]                      check without connecting
  rco version
  rco help

JOB is a job directory (containing job.yaml) or a job YAML file.
Selectors are repeatable: AND across kinds, OR within a kind; none = all hosts.
Every flag also works with a single dash (-execute).

Exit codes: 0 all hosts succeeded, 1 usage or validation error (nothing contacted),
2 some hosts failed, were skipped or cancelled.

Options:
`

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stderr)
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
		printHelp(stdout)
		return ExitOK
	}
	fmt.Fprintf(stderr, "unknown command %q (see rco help)\n", args[0])
	return ExitError
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// flags holds every run/validate option. One definition serves parsing and help.
type flags struct {
	fs                                           *flag.FlagSet
	inv, groups, tags, hosts, vars, varEnvs      multi
	o                                            runner.Options
	job, output, report, onlyFailed, maxFailures string
	execute, verbose, quiet                      bool
}

// Short aliases share the long flag's value. --execute deliberately has none:
// applying changes should always be typed out in full.
var aliases = map[string]string{
	"inventory": "i", "job": "j", "group": "g", "tag": "t", "host": "H",
	"concurrency": "c", "output": "o", "verbose": "v", "quiet": "q",
}

func newFlags(name string) *flags {
	f := &flags{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	fs, o := f.fs, &f.o
	// Backquoted words name the flag's value in help output.
	fs.Var(&f.inv, "inventory", "inventory `FILE`; repeat to combine files (e.g. common.yaml + prod.yaml)")
	fs.StringVar(&f.job, "job", "", "`JOB` directory (with job.yaml) or job YAML file")
	fs.Var(&f.groups, "group", "select hosts in group `NAME` (repeatable)")
	fs.Var(&f.tags, "tag", "select hosts with tag `NAME` (repeatable)")
	fs.Var(&f.hosts, "host", "select host `NAME` (repeatable)")
	fs.BoolVar(&f.execute, "execute", false, "actually run the job; without it rco only previews, connecting to nothing")
	fs.Var(&f.vars, "var", "job variable `NAME=VALUE` (repeatable)")
	fs.Var(&f.varEnvs, "var-env", "job variable `NAME=ENV_VAR` read from the environment; required for sensitive variables (repeatable)")
	fs.IntVar(&o.Concurrency, "concurrency", 100, "maximum hosts processed at the same time")
	fs.StringVar(&f.maxFailures, "max-failures", "", "override the job's max_failures: stop starting new hosts after `N` failed hosts, or N% of all hosts; the rest are SKIPPED")
	fs.StringVar(&f.onlyFailed, "only-failed", "", "run only on hosts that did not succeed in a previous `REPORT` (.json, .yaml or .jsonl)")
	fs.DurationVar(&o.StepTimeout, "timeout", 5*time.Minute, "default per-step timeout (job file values win)")
	fs.DurationVar(&o.ConnectTimeout, "connect-timeout", 10*time.Second, "TCP connect timeout")
	fs.DurationVar(&o.HandshakeTimeout, "handshake-timeout", 15*time.Second, "SSH handshake and authentication timeout")
	fs.IntVar(&o.ConnectRetries, "connect-retries", 2, "extra connection attempts for transient failures (never for auth or host key errors)")
	fs.DurationVar(&o.RetryDelay, "retry-delay", 2*time.Second, "base delay between retries (exponential with jitter)")
	fs.DurationVar(&o.MaxRetryDelay, "max-retry-delay", 30*time.Second, "maximum delay between connection retries")
	fs.IntVar(&o.MaxOutput, "max-output", 1<<20, "`BYTES` of stdout/stderr kept per step (head and tail are kept)")
	fs.StringVar(&o.KnownHosts, "known-hosts", "~/.ssh/known_hosts", "known_hosts `FILE` used to verify host keys")
	fs.BoolVar(&o.AcceptNewHosts, "accept-new-host-keys", false, "add keys of hosts missing from known_hosts (trust on first use); changed keys still fail")
	fs.BoolVar(&o.Insecure, "insecure-skip-host-key-check", false, "INSECURE: do not verify host keys (lab use only)")
	fs.StringVar(&f.output, "output", "table", "result `FORMAT` on stdout: table, json or yaml")
	fs.StringVar(&f.report, "report", "", "also write the full report to `FILE` (.json, .yaml; .jsonl is written host by host as results arrive)")
	fs.BoolVar(&f.verbose, "verbose", false, "table output: include every step with its output")
	fs.BoolVar(&f.quiet, "quiet", false, "log only warnings and errors (hides progress)")
	for long, short := range aliases {
		fs.Var(fs.Lookup(long).Value, short, "alias")
	}
	return f
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, usage)
	printFlags(w, newFlags("rco").fs)
}

// printFlags lists flags in definition order as "-i, --inventory FILE".
func printFlags(w io.Writer, fs *flag.FlagSet) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, name := range flagOrder {
		f := fs.Lookup(name)
		arg, usage := flag.UnquoteUsage(f)
		if _, isBool := f.Value.(interface{ IsBoolFlag() bool }); isBool {
			arg = ""
		} else {
			arg = map[string]string{"int": "N", "duration": "DURATION", "value": "VALUE", "string": "VALUE"}[arg] + strings.TrimLeft(arg, "abcdefghijklmnopqrstuvwxyz")
		}
		head := "    --" + name
		if short, ok := aliases[name]; ok {
			head = "-" + short + ", --" + name
		}
		if arg != "" {
			head += " " + arg
		}
		if def := f.DefValue; def != "" && def != "false" && def != "0" {
			usage += " (default " + def + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\n", head, usage)
	}
	_ = tw.Flush()
}

// flagOrder is the help order (flag.VisitAll would sort alphabetically).
var flagOrder = []string{
	"inventory", "job", "group", "tag", "host", "execute", "var", "var-env",
	"concurrency", "max-failures", "only-failed", "timeout", "connect-timeout", "handshake-timeout",
	"connect-retries", "retry-delay", "max-retry-delay", "max-output",
	"known-hosts", "accept-new-host-keys", "insecure-skip-host-key-check",
	"output", "report", "verbose", "quiet",
}

func run(args []string, stdout, stderr io.Writer, validateOnly bool) int {
	name := "rco run"
	if validateOnly {
		name = "rco validate"
	}
	f := newFlags(name)
	f.fs.SetOutput(stderr)
	f.fs.Usage = func() { printHelp(stderr) }
	if err := f.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	o := f.o
	level := slog.LevelInfo
	if f.quiet {
		level = slog.LevelWarn
	}
	o.Logger = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return ExitError
	}

	switch {
	case f.fs.NArg() > 0:
		return fail("unexpected argument %q", f.fs.Arg(0))
	case f.job == "":
		return fail("--job is required")
	case len(f.inv) == 0 && !validateOnly:
		return fail("--inventory is required")
	case f.output != "table" && f.output != "json" && f.output != "yaml":
		return fail("--output must be table, json or yaml")
	case o.Concurrency < 1 || o.MaxOutput < 1024:
		return fail("--concurrency must be >= 1 and --max-output >= 1024")
	}
	j, err := job.Load(f.job)
	if err != nil {
		return fail("%v", err)
	}
	if validateOnly && len(f.inv) == 0 {
		fmt.Fprintf(stdout, "job %q is valid (%d steps, sha256 %s)\n", j.Name, len(j.Steps), j.Hash[:12])
		return ExitOK
	}
	inv, err := inventory.Load(f.inv...)
	if err != nil {
		return fail("%v", err)
	}
	targets, err := inv.Select(inventory.Selector{Groups: f.groups, Tags: f.tags, Hosts: f.hosts})
	if err != nil {
		return fail("%v", err)
	}
	if f.onlyFailed != "" {
		if targets, err = onlyFailed(f.onlyFailed, j.Name, targets, o.Logger); err != nil {
			return fail("--only-failed: %v", err)
		}
	}
	if len(targets) == 0 {
		return fail("no hosts match the selectors")
	}
	// The job's max_failures applies unless --max-failures overrides it.
	limit := j.MaxFailures
	if f.maxFailures != "" {
		limit = f.maxFailures
	}
	if o.MaxFailures, err = job.ParseMaxFailures(limit, len(targets)); err != nil {
		return fail("max failures %v", err)
	}
	in := runner.Input{Job: j, Targets: targets}
	if in.Vars, err = pairs(f.vars, "--var"); err != nil {
		return fail("%v", err)
	}
	if in.VarEnv, err = pairs(f.varEnvs, "--var-env"); err != nil {
		return fail("%v", err)
	}
	// A preview must work without access to keys and passwords; validate checks them.
	o.SkipCredentials = !f.execute && !validateOnly
	o.Progress = 10 * time.Second
	stream, err := openStream(f.report, &o)
	if err != nil {
		return fail("--report: %v", err)
	}
	r, err := runner.Prepare(in, o)
	if err != nil {
		stream.discard()
		return fail("validation failed, no host was contacted:\n%v", err)
	}
	if validateOnly {
		fmt.Fprintf(stdout, "job %q is valid for %d hosts\n", j.Name, len(targets))
		return ExitOK
	}
	if !f.execute {
		stream.discard()
		return printPreview(stdout, f.output, r, o.MaxFailures)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o.Logger.Info("starting", "job", j.Name, "hosts", len(targets), "concurrency", o.Concurrency, "max_failures", o.MaxFailures)
	rep := r.Run(ctx)
	if stream != nil {
		if err := stream.close(rep); err != nil {
			fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		}
	} else if f.report != "" {
		if err := writeReport(f.report, rep); err != nil {
			fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		}
	}
	if err := printReport(stdout, f.output, f.verbose, rep); err != nil {
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
				if s.Note != "" {
					fmt.Fprintf(tw, "     ~ %s\t\t\t\t\n", s.Note)
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

func printPreview(w io.Writer, format string, r *runner.Runner, maxFailures int) int {
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
	fmt.Fprintf(w, "\npreview: %d hosts, stop after %d failed hosts; nothing was executed. Add --execute to apply.\n", len(out), maxFailures)
	return ExitOK
}
