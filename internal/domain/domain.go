// Package domain holds the core types shared by every layer: statuses,
// failure categories, host targets and device profiles.
package domain

import (
	"errors"
	"fmt"
	"time"
)

// JobStatus is the lifecycle state of a job.
type JobStatus string

const (
	JobQueued         JobStatus = "QUEUED"
	JobRunning        JobStatus = "RUNNING"
	JobSuccess        JobStatus = "SUCCESS"
	JobPartialFailure JobStatus = "PARTIAL_FAILURE"
	JobFailed         JobStatus = "FAILED"
	JobCancelled      JobStatus = "CANCELLED"
)

// Terminal reports whether no further work will happen for the job.
func (s JobStatus) Terminal() bool {
	switch s {
	case JobSuccess, JobPartialFailure, JobFailed, JobCancelled:
		return true
	}
	return false
}

// HostStatus is the execution state of one host within a job.
type HostStatus string

const (
	HostQueued           HostStatus = "QUEUED"
	HostWaiting          HostStatus = "WAITING"
	HostConnecting       HostStatus = "CONNECTING"
	HostAuthenticating   HostStatus = "AUTHENTICATING"
	HostRunning          HostStatus = "RUNNING"
	HostRetrying         HostStatus = "RETRYING"
	HostSuccess          HostStatus = "SUCCESS"
	HostFailed           HostStatus = "FAILED"
	HostTimeout          HostStatus = "TIMEOUT"
	HostAuthFailed       HostStatus = "AUTH_FAILED"
	HostConnectionFailed HostStatus = "CONNECTION_FAILED"
	HostPromptMismatch   HostStatus = "PROMPT_MISMATCH"
	HostCancelled        HostStatus = "CANCELLED"
	HostUnknown          HostStatus = "UNKNOWN"
)

// AllHostStatuses lists every host status in display order.
var AllHostStatuses = []HostStatus{
	HostQueued, HostWaiting, HostConnecting, HostAuthenticating, HostRunning, HostRetrying,
	HostSuccess, HostFailed, HostTimeout, HostAuthFailed, HostConnectionFailed,
	HostPromptMismatch, HostCancelled, HostUnknown,
}

// ActiveHostStatuses are the states in which a worker owns the host.
var ActiveHostStatuses = []HostStatus{HostConnecting, HostAuthenticating, HostRunning, HostRetrying}

// Terminal reports whether the host execution has finished.
func (s HostStatus) Terminal() bool {
	switch s {
	case HostQueued, HostWaiting, HostConnecting, HostAuthenticating, HostRunning, HostRetrying:
		return false
	}
	return true
}

// Active reports whether a worker currently owns the host.
func (s HostStatus) Active() bool {
	for _, a := range ActiveHostStatuses {
		if s == a {
			return true
		}
	}
	return false
}

// StepStatus is the result of one step try.
type StepStatus string

const (
	StepRunning StepStatus = "RUNNING"
	StepSuccess StepStatus = "SUCCESS"
	StepFailed  StepStatus = "FAILED"
	StepSkipped StepStatus = "SKIPPED"
)

// Phase identifies which block of a command prompt a step belongs to.
type Phase string

const (
	PhasePrecheck  Phase = "precheck"
	PhaseMain      Phase = "main"
	PhasePostcheck Phase = "postcheck"
	PhaseRollback  Phase = "rollback"
)

// RollbackStatus records the outcome of the rollback block.
type RollbackStatus string

const (
	RollbackNotRun  RollbackStatus = "NOT_RUN"
	RollbackSuccess RollbackStatus = "SUCCESS"
	RollbackFailed  RollbackStatus = "FAILED"
)

// Category is a structured failure classification.
type Category string

const (
	CatConnectionTimeout   Category = "CONNECTION_TIMEOUT"
	CatConnectionRefused   Category = "CONNECTION_REFUSED"
	CatDNSFailure          Category = "DNS_FAILURE"
	CatAuthFailed          Category = "AUTH_FAILED"
	CatHostKeyMismatch     Category = "HOST_KEY_MISMATCH"
	CatHostKeyUnknown      Category = "HOST_KEY_UNKNOWN"
	CatHandshakeFailed     Category = "SSH_HANDSHAKE_FAILED"
	CatSessionFailed       Category = "SESSION_FAILED"
	CatCommandTimeout      Category = "COMMAND_TIMEOUT"
	CatExpectTimeout       Category = "EXPECT_TIMEOUT"
	CatPromptMismatch      Category = "PROMPT_MISMATCH"
	CatCommandFailed       Category = "COMMAND_FAILED"
	CatOutputLimitExceeded Category = "OUTPUT_LIMIT_EXCEEDED"
	CatTemplateError       Category = "TEMPLATE_ERROR"
	CatPromptInvalid       Category = "COMMAND_PROMPT_INVALID"
	CatCancelled           Category = "CANCELLED"
	CatInterrupted         Category = "INTERRUPTED"
	CatInternalError       Category = "INTERNAL_ERROR"
)

// AllCategories lists every known failure category.
var AllCategories = []Category{
	CatConnectionTimeout, CatConnectionRefused, CatDNSFailure, CatAuthFailed, CatHostKeyMismatch,
	CatHostKeyUnknown, CatHandshakeFailed, CatSessionFailed, CatCommandTimeout, CatExpectTimeout,
	CatPromptMismatch, CatCommandFailed, CatOutputLimitExceeded, CatTemplateError, CatPromptInvalid,
	CatCancelled, CatInterrupted, CatInternalError,
}

// ValidCategory reports whether c is a known category.
func ValidCategory(c Category) bool {
	for _, k := range AllCategories {
		if c == k {
			return true
		}
	}
	return false
}

// HostStatus maps a failure category to the terminal host status.
func (c Category) HostStatus() HostStatus {
	switch c {
	case "":
		return HostSuccess
	case CatAuthFailed:
		return HostAuthFailed
	case CatConnectionTimeout, CatConnectionRefused, CatDNSFailure, CatHostKeyMismatch,
		CatHostKeyUnknown, CatHandshakeFailed:
		return HostConnectionFailed
	case CatCommandTimeout, CatExpectTimeout:
		return HostTimeout
	case CatPromptMismatch:
		return HostPromptMismatch
	case CatCancelled:
		return HostCancelled
	case CatInterrupted:
		return HostUnknown
	}
	return HostFailed
}

// ConnectionRetryable reports whether a connection-phase failure may be retried
// without risk (nothing has been executed on the host yet).
func (c Category) ConnectionRetryable() bool {
	switch c {
	case CatConnectionTimeout, CatConnectionRefused, CatHandshakeFailed, CatSessionFailed:
		return true
	}
	return false
}

// StepRetryable reports whether an explicitly configured step retry applies.
func (c Category) StepRetryable() bool {
	switch c {
	case CatCommandTimeout, CatExpectTimeout, CatPromptMismatch, CatCommandFailed:
		return true
	}
	return false
}

// Failure is a classified error. Reason must never contain secrets; callers
// pass reasons through a Redactor before building a Failure from remote data.
type Failure struct {
	Category Category
	Reason   string
}

func (f *Failure) Error() string { return string(f.Category) + ": " + f.Reason }

// Fail builds a Failure with a formatted reason.
func Fail(c Category, format string, args ...any) *Failure {
	return &Failure{Category: c, Reason: fmt.Sprintf(format, args...)}
}

// AsFailure extracts a Failure from err, classifying unknown errors as INTERNAL_ERROR.
func AsFailure(err error) *Failure {
	if err == nil {
		return nil
	}
	var f *Failure
	if errors.As(err, &f) {
		return f
	}
	return &Failure{Category: CatInternalError, Reason: err.Error()}
}

// CredentialRef describes how to obtain a secret. It never holds the secret.
type CredentialRef struct {
	Name          string `json:"name" yaml:"-"`
	Type          string `json:"type" yaml:"type"` // password | private_key | agent
	Username      string `json:"username,omitempty" yaml:"username"`
	PasswordEnv   string `json:"password_env,omitempty" yaml:"password_env"`
	KeyFile       string `json:"key_file,omitempty" yaml:"key_file"`
	PassphraseEnv string `json:"passphrase_env,omitempty" yaml:"passphrase_env"`
}

// Endpoint is an SSH endpoint (used for bastions).
type Endpoint struct {
	Name       string        `json:"name"`
	Address    string        `json:"address"`
	Port       int           `json:"port"`
	Username   string        `json:"username"`
	Credential CredentialRef `json:"credential"`
}

// PagerConfig describes how to page through "--More--" style output.
type PagerConfig struct {
	Patterns []string `json:"patterns,omitempty" yaml:"patterns"`
	Response string   `json:"response,omitempty" yaml:"response"`
	MaxPages int      `json:"max_pages,omitempty" yaml:"max_pages"`
}

// Profile captures device/shell behaviour without hard-coding vendors.
type Profile struct {
	Name               string        `json:"name" yaml:"-"`
	Mode               string        `json:"mode,omitempty" yaml:"mode"` // interactive | exec
	PromptRegex        string        `json:"prompt_regex,omitempty" yaml:"prompt_regex"`
	InitialPromptRegex string        `json:"initial_prompt_regex,omitempty" yaml:"initial_prompt_regex"`
	LineEnding         string        `json:"line_ending,omitempty" yaml:"line_ending"`
	PTY                *bool         `json:"pty,omitempty" yaml:"pty"`
	Terminal           string        `json:"terminal,omitempty" yaml:"terminal"`
	Width              int           `json:"width,omitempty" yaml:"width"`
	Height             int           `json:"height,omitempty" yaml:"height"`
	LoginTimeout       time.Duration `json:"login_timeout,omitempty" yaml:"login_timeout"`
	PromptSettle       time.Duration `json:"prompt_settle,omitempty" yaml:"prompt_settle"`
	SetupCommands      []string      `json:"setup_commands,omitempty" yaml:"setup_commands"`
	Pager              PagerConfig   `json:"pager" yaml:"pager"`
}

// Target is the fully resolved, secret-free description of one host.
// It is snapshotted into the job at creation time.
type Target struct {
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Group       string            `json:"group,omitempty"`
	Username    string            `json:"username"`
	Credential  CredentialRef     `json:"credential"`
	Bastion     *Endpoint         `json:"bastion,omitempty"`
	Profile     Profile           `json:"profile"`
	Tags        []string          `json:"tags,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
	VariableEnv map[string]string `json:"variable_env,omitempty"`
}

// Addr returns host:port.
func (t Target) Addr() string { return fmt.Sprintf("%s:%d", t.Address, t.Port) }

// SensitiveMask replaces sensitive values in persisted records.
const SensitiveMask = "[SENSITIVE]"
