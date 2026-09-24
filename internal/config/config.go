// Package config loads process configuration from environment variables.
//
// Precedence (highest first): CLI flags > environment variables > built-in defaults.
// Command prompt defaults and step fields override the SSH timeouts per job.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Lock modes for HOST_EXECUTION_LOCKING.
const (
	LockNone            = "none"
	LockPerHost         = "per-host"
	LockPerHostPerGroup = "per-host-per-group"
)

// Shutdown policies.
const (
	ShutdownDrain  = "drain"
	ShutdownCancel = "cancel"
)

// Timeouts groups the SSH timeouts.
type Timeouts struct {
	Connect   time.Duration `json:"connect"`
	Handshake time.Duration `json:"handshake"`
	Command   time.Duration `json:"command"`
	Expect    time.Duration `json:"expect"`
	Session   time.Duration `json:"session"`
}

// Retry groups SSH connection retry settings.
type Retry struct {
	Count    int           `json:"count"`
	Delay    time.Duration `json:"delay"`
	MaxDelay time.Duration `json:"max_delay"`
}

// Config is the full process configuration.
type Config struct {
	AppEnv   string
	HTTPPort int
	LogLevel string

	DatabaseURL string

	MaxConcurrency       int
	Timeouts             Timeouts
	Retry                Retry
	MaxStepOutputBytes   int
	MaxHostOutputBytes   int64
	StoreRawOutput       bool
	HostLocking          string
	CommandDelay         time.Duration
	HostStartRate        float64 // hosts per second; 0 = unlimited
	KnownHostsFile       string
	InsecureSkipHostKey  bool
	QueuePollInterval    time.Duration
	WorkerLeaseTimeout   time.Duration
	ShutdownPolicy       string
	ShutdownTimeout      time.Duration
	CommandPromptsDir    string
	InventoriesDir       string
	APIToken             string
	APIAuthDisabled      bool
	WebhookURL           string
	WebhookSecret        string
	WebhookTimeout       time.Duration
	WebhookRetries       int
	WebhookAllowInsecure bool
	NotificationRetries  int
	SMTP                 SMTP
}

// SMTP holds email settings. Password is never logged.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	TLS      string // starttls | tls | none
}

// Enabled reports whether SMTP is configured.
func (s SMTP) Enabled() bool { return s.Host != "" && s.From != "" }

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	p := parser{getenv: getenv}
	home, _ := os.UserHomeDir()
	c := &Config{
		AppEnv:              p.str("APP_ENV", "production"),
		HTTPPort:            p.int("HTTP_PORT", 8080),
		LogLevel:            p.str("LOG_LEVEL", "info"),
		DatabaseURL:         p.str("DATABASE_URL", ""),
		MaxConcurrency:      p.int("SSH_MAX_CONCURRENCY", 100),
		MaxStepOutputBytes:  p.int("MAX_STEP_OUTPUT_BYTES", 1<<20),
		MaxHostOutputBytes:  int64(p.int("MAX_HOST_OUTPUT_BYTES", 16<<20)),
		StoreRawOutput:      p.bool("STORE_RAW_OUTPUT", false),
		CommandDelay:        p.dur("COMMAND_DELAY", 0),
		KnownHostsFile:      p.str("KNOWN_HOSTS_FILE", filepath.Join(home, ".ssh", "known_hosts")),
		InsecureSkipHostKey: p.bool("SSH_INSECURE_SKIP_HOST_KEY_CHECK", false),
		QueuePollInterval:   p.dur("QUEUE_POLL_INTERVAL", 500*time.Millisecond),
		WorkerLeaseTimeout:  p.dur("WORKER_LEASE_TIMEOUT", 60*time.Second),
		ShutdownPolicy:      p.str("SHUTDOWN_POLICY", ShutdownDrain),
		ShutdownTimeout:     p.dur("SHUTDOWN_TIMEOUT", 60*time.Second),
		CommandPromptsDir:   p.str("COMMAND_PROMPTS_DIR", "./command-prompts"),
		InventoriesDir:      p.str("INVENTORIES_DIR", "./inventories"),
		APIToken:            p.str("API_TOKEN", ""),
		APIAuthDisabled:     p.bool("API_AUTH_DISABLED", false),
		WebhookURL:          p.str("WEBHOOK_URL", ""),
		WebhookSecret:       p.str("WEBHOOK_SECRET", ""),
		WebhookTimeout:      p.dur("WEBHOOK_TIMEOUT", 10*time.Second),
		WebhookRetries:      p.int("WEBHOOK_RETRIES", 5),
		WebhookAllowInsecure: p.bool("WEBHOOK_ALLOW_INSECURE", false),
		NotificationRetries: p.int("NOTIFICATION_RETRIES", 5),
		Timeouts: Timeouts{
			Connect:   p.dur("SSH_CONNECT_TIMEOUT", 10*time.Second),
			Handshake: p.dur("SSH_HANDSHAKE_TIMEOUT", 10*time.Second),
			Command:   p.dur("SSH_COMMAND_TIMEOUT", 30*time.Second),
			Expect:    p.dur("SSH_EXPECT_TIMEOUT", 10*time.Second),
			Session:   p.dur("SSH_SESSION_TIMEOUT", 5*time.Minute),
		},
		Retry: Retry{
			Count:    p.int("SSH_RETRY_COUNT", 3),
			Delay:    p.dur("SSH_RETRY_DELAY", 2*time.Second),
			MaxDelay: p.dur("SSH_RETRY_MAX_DELAY", 30*time.Second),
		},
		SMTP: SMTP{
			Host:     p.str("SMTP_HOST", ""),
			Port:     p.int("SMTP_PORT", 587),
			Username: p.str("SMTP_USERNAME", ""),
			Password: p.str("SMTP_PASSWORD", ""),
			From:     p.str("SMTP_FROM", ""),
			TLS:      strings.ToLower(p.str("SMTP_TLS", "starttls")),
		},
	}
	if to := p.str("SMTP_TO", ""); to != "" {
		for _, a := range strings.Split(to, ",") {
			if a = strings.TrimSpace(a); a != "" {
				c.SMTP.To = append(c.SMTP.To, a)
			}
		}
	}
	c.HostLocking = p.lockMode("HOST_EXECUTION_LOCKING", LockPerHost)
	c.HostStartRate = p.rate("HOST_START_RATE")
	if err := errors.Join(append(p.errs, c.Validate())...); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks value ranges. It is called by Load and again after CLI overrides.
func (c *Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, a ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, a...))
		}
	}
	check(c.HTTPPort > 0 && c.HTTPPort < 65536, "HTTP_PORT must be 1-65535")
	check(c.MaxConcurrency >= 1 && c.MaxConcurrency <= 10000, "SSH_MAX_CONCURRENCY must be 1-10000")
	check(c.Timeouts.Connect > 0 && c.Timeouts.Handshake > 0 && c.Timeouts.Command > 0 &&
		c.Timeouts.Expect > 0 && c.Timeouts.Session > 0, "SSH timeouts must be positive")
	check(c.Retry.Count >= 0 && c.Retry.Count <= 20, "SSH_RETRY_COUNT must be 0-20")
	check(c.Retry.Delay >= 0 && c.Retry.MaxDelay >= c.Retry.Delay, "SSH_RETRY_MAX_DELAY must be >= SSH_RETRY_DELAY")
	check(c.MaxStepOutputBytes >= 4096, "MAX_STEP_OUTPUT_BYTES must be >= 4096")
	check(c.MaxHostOutputBytes >= int64(c.MaxStepOutputBytes), "MAX_HOST_OUTPUT_BYTES must be >= MAX_STEP_OUTPUT_BYTES")
	check(c.ShutdownPolicy == ShutdownDrain || c.ShutdownPolicy == ShutdownCancel, "SHUTDOWN_POLICY must be drain or cancel")
	check(c.SMTP.TLS == "starttls" || c.SMTP.TLS == "tls" || c.SMTP.TLS == "none", "SMTP_TLS must be starttls, tls or none")
	check(c.WebhookRetries >= 0 && c.NotificationRetries >= 0, "retry counts must be >= 0")
	check(c.QueuePollInterval > 0 && c.WorkerLeaseTimeout > 0, "queue intervals must be positive")
	return errors.Join(errs...)
}

type parser struct {
	getenv func(string) string
	errs   []error
}

func (p *parser) str(key, def string) string {
	if v := strings.TrimSpace(p.getenv(key)); v != "" {
		return v
	}
	return def
}

func (p *parser) int(key string, def int) int {
	v := p.str(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: invalid integer %q", key, v))
		return def
	}
	return n
}

func (p *parser) bool(key string, def bool) bool {
	v := p.str(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: invalid boolean %q", key, v))
		return def
	}
	return b
}

func (p *parser) dur(key string, def time.Duration) time.Duration {
	v := p.str(key, "")
	if v == "" {
		return def
	}
	if v == "0" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		p.errs = append(p.errs, fmt.Errorf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}

func (p *parser) lockMode(key, def string) string {
	v, err := ParseLockMode(p.str(key, def))
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return v
}

// ParseLockMode accepts none|per-host|per-host-per-group and boolean aliases.
func ParseLockMode(v string) (string, error) {
	switch strings.ToLower(v) {
	case "true", "1", "yes", LockPerHost:
		return LockPerHost, nil
	case "false", "0", "no", LockNone:
		return LockNone, nil
	case LockPerHostPerGroup:
		return LockPerHostPerGroup, nil
	}
	return "", fmt.Errorf("invalid host locking mode %q", v)
}

func (p *parser) rate(key string) float64 {
	v := p.str(key, "")
	if v == "" || v == "0" {
		return 0
	}
	r, err := ParseRate(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: %w", key, err))
	}
	return r
}

// ParseRate parses "50/s", "600/m" or a bare number (per second).
func ParseRate(v string) (float64, error) {
	num, unit, _ := strings.Cut(v, "/")
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid rate %q", v)
	}
	switch unit {
	case "", "s":
		return n, nil
	case "m":
		return n / 60, nil
	}
	return 0, fmt.Errorf("invalid rate unit in %q (use /s or /m)", v)
}
