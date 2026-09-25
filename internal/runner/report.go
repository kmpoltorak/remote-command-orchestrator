package runner

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/job"
)

// Report is the full result of a run. It contains no credentials; sensitive
// steps and secret values are masked.
type Report struct {
	Job        string       `json:"job" yaml:"job"`
	Version    string       `json:"version,omitempty" yaml:"version,omitempty"`
	Hash       string       `json:"hash" yaml:"hash"`
	StartedAt  time.Time    `json:"started_at" yaml:"started_at"`
	FinishedAt time.Time    `json:"finished_at" yaml:"finished_at"`
	Duration   Duration     `json:"duration" yaml:"duration"`
	Summary    Summary      `json:"summary" yaml:"summary"`
	Hosts      []HostResult `json:"hosts" yaml:"hosts"`
}

// Summary counts hosts per final status.
type Summary struct {
	Total     int `json:"total" yaml:"total"`
	Success   int `json:"success" yaml:"success"`
	Failed    int `json:"failed" yaml:"failed"`
	Cancelled int `json:"cancelled" yaml:"cancelled"`
	Skipped   int `json:"skipped,omitempty" yaml:"skipped,omitempty"`
}

// HostResult is the outcome for one host.
type HostResult struct {
	Host            string          `json:"host" yaml:"host"`
	Address         string          `json:"address" yaml:"address"`
	Status          domain.Status   `json:"status" yaml:"status"`
	FailedStep      string          `json:"failed_step,omitempty" yaml:"failed_step,omitempty"`
	Category        domain.Category `json:"failure_category,omitempty" yaml:"failure_category,omitempty"`
	Reason          string          `json:"failure_reason,omitempty" yaml:"failure_reason,omitempty"`
	ConnectAttempts int             `json:"connect_attempts,omitempty" yaml:"connect_attempts,omitempty"`
	Duration        Duration        `json:"duration" yaml:"duration"`
	Steps           []StepResult    `json:"steps" yaml:"steps"`
}

// StepResult is the outcome of one step (its last attempt).
type StepResult struct {
	Name      string          `json:"name" yaml:"name"`
	Kind      string          `json:"kind" yaml:"kind"`
	Command   string          `json:"command" yaml:"command"`
	Status    domain.Status   `json:"status" yaml:"status"`
	Attempts  int             `json:"attempts,omitempty" yaml:"attempts,omitempty"`
	ExitCode  *int            `json:"exit_code,omitempty" yaml:"exit_code,omitempty"`
	Stdout    string          `json:"stdout,omitempty" yaml:"stdout,omitempty"`
	Stderr    string          `json:"stderr,omitempty" yaml:"stderr,omitempty"`
	Truncated bool            `json:"output_truncated,omitempty" yaml:"output_truncated,omitempty"`
	Note      string          `json:"note,omitempty" yaml:"note,omitempty"` // e.g. reboot completed
	Duration  Duration        `json:"duration" yaml:"duration"`
	Category  domain.Category `json:"failure_category,omitempty" yaml:"failure_category,omitempty"`
	Reason    string          `json:"failure_reason,omitempty" yaml:"failure_reason,omitempty"`
}

// Duration marshals as a human-readable string ("1.5s").
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).Round(time.Millisecond).String() }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON implements json.Unmarshaler so saved reports can be read back.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func newReport(j *job.Job) *Report {
	return &Report{Job: j.Name, Version: j.Version, Hash: j.Hash, StartedAt: time.Now().UTC()}
}

func (r *Report) finish() {
	r.FinishedAt = time.Now().UTC()
	r.Duration = Duration(r.FinishedAt.Sub(r.StartedAt))
	r.Summary = Summary{Total: len(r.Hosts)}
	for _, h := range r.Hosts {
		switch h.Status {
		case domain.StatusSuccess:
			r.Summary.Success++
		case domain.StatusCancelled:
			r.Summary.Cancelled++
		case domain.StatusSkipped:
			r.Summary.Skipped++
		default:
			r.Summary.Failed++
		}
	}
}

// OK reports whether every host succeeded.
func (r *Report) OK() bool { return r.Summary.Success == r.Summary.Total }

func (s Summary) String() string {
	out := fmt.Sprintf("%d hosts: %d succeeded, %d failed, %d cancelled", s.Total, s.Success, s.Failed, s.Cancelled)
	if s.Skipped > 0 {
		out += fmt.Sprintf(", %d skipped", s.Skipped)
	}
	return out
}
