package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
	"github.com/kmpoltorak/remote-command-orchestrator/internal/runner"
)

// jsonlStream writes one JSON line per host as soon as it finishes, then a
// final summary line. If rco itself is killed, finished hosts are on disk.
type jsonlStream struct {
	path string
	mu   sync.Mutex
	f    *os.File
	err  error
}

// openStream starts a .jsonl report and hooks it into the runner. Other
// formats are written at the end and return nil.
func openStream(path string, o *runner.Options) (*jsonlStream, error) {
	if !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // reports contain command output
	if err != nil {
		return nil, err
	}
	s := &jsonlStream{path: path, f: f}
	o.OnHostDone = func(h runner.HostResult) { s.line(h) }
	return s, nil
}

func (s *jsonlStream) line(v any) {
	data, err := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		_, err = s.f.Write(append(data, '\n'))
	}
	if s.err == nil {
		s.err = err
	}
}

// close writes the summary line: the report without its hosts.
func (s *jsonlStream) close(rep *runner.Report) error {
	s.line(struct {
		Job        string          `json:"job"`
		Version    string          `json:"version,omitempty"`
		Hash       string          `json:"hash"`
		StartedAt  any             `json:"started_at"`
		FinishedAt any             `json:"finished_at"`
		Duration   runner.Duration `json:"duration"`
		Summary    runner.Summary  `json:"summary"`
	}{rep.Job, rep.Version, rep.Hash, rep.StartedAt, rep.FinishedAt, rep.Duration, rep.Summary})
	if err := s.f.Close(); s.err == nil {
		s.err = err
	}
	return s.err
}

// discard removes the file when nothing was run (preview, validation error).
func (s *jsonlStream) discard() {
	if s != nil {
		_ = s.f.Close()
		_ = os.Remove(s.path)
	}
}

// prevHost is the part of a saved report that --only-failed needs.
type prevHost struct {
	Host   string        `json:"host" yaml:"host"`
	Status domain.Status `json:"status" yaml:"status"`
}

// onlyFailed keeps the targets that did not succeed in a previous report
// (.json, .yaml/.yml or .jsonl). Hosts missing from the report are dropped.
func onlyFailed(path, jobName string, targets []domain.Target, log *slog.Logger) ([]domain.Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var prev struct {
		Job   string     `json:"job" yaml:"job"`
		Hosts []prevHost `json:"hosts" yaml:"hosts"`
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl":
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 1<<20), 64<<20) // host lines carry step output
		for sc.Scan() {
			var line struct {
				prevHost
				Job string `json:"job"`
			}
			if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if line.Host != "" {
				prev.Hosts = append(prev.Hosts, line.prevHost)
			}
			if line.Job != "" {
				prev.Job = line.Job
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &prev)
	default:
		err = json.Unmarshal(data, &prev)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if prev.Job != "" && prev.Job != jobName {
		log.Warn("report is from a different job", "report_job", prev.Job, "job", jobName)
	}
	retry := map[string]bool{}
	for _, h := range prev.Hosts {
		retry[h.Host] = h.Status != domain.StatusSuccess
	}
	var out []domain.Target
	for _, t := range targets {
		if retry[t.Name] {
			out = append(out, t)
		}
	}
	log.Info("rerunning hosts that did not succeed", "report", path, "hosts", len(out))
	return out, nil
}
