// Package domain holds the types shared by every layer: failure categories,
// statuses and resolved host targets.
package domain

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Status is the outcome of a host or a step.
type Status string

const (
	StatusSuccess   Status = "SUCCESS"
	StatusFailed    Status = "FAILED"
	StatusSkipped   Status = "SKIPPED"
	StatusCancelled Status = "CANCELLED"
)

// Category is a structured failure classification.
type Category string

const (
	CatConnectionTimeout Category = "CONNECTION_TIMEOUT"
	CatConnectionRefused Category = "CONNECTION_REFUSED"
	CatDNSFailure        Category = "DNS_FAILURE"
	CatAuthFailed        Category = "AUTH_FAILED"
	CatHostKeyMismatch   Category = "HOST_KEY_MISMATCH"
	CatHostKeyUnknown    Category = "HOST_KEY_UNKNOWN"
	CatHandshakeFailed   Category = "SSH_HANDSHAKE_FAILED"
	CatSessionFailed     Category = "SESSION_FAILED"
	CatCommandTimeout    Category = "COMMAND_TIMEOUT"
	CatCommandFailed     Category = "COMMAND_FAILED"
	CatTemplateError     Category = "TEMPLATE_ERROR"
	CatCancelled         Category = "CANCELLED"
	CatInternalError     Category = "INTERNAL_ERROR"
)

// Retryable reports whether a connection failure may be retried safely:
// nothing has run on the host yet and the cause may be transient.
// Auth, host key and DNS failures are deterministic and never retried.
func (c Category) Retryable() bool {
	switch c {
	case CatConnectionTimeout, CatConnectionRefused, CatHandshakeFailed, CatSessionFailed:
		return true
	}
	return false
}

// Failure is a classified error. Reasons pass through the redactor before
// they are shown or written anywhere.
type Failure struct {
	Category Category
	Reason   string
}

func (f *Failure) Error() string { return string(f.Category) + ": " + f.Reason }

// Fail builds a Failure with a formatted reason.
func Fail(c Category, format string, args ...any) *Failure {
	return &Failure{Category: c, Reason: fmt.Sprintf(format, args...)}
}

// AsFailure extracts a Failure from err; unknown errors become INTERNAL_ERROR.
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

// Credential describes where a secret lives. It never holds the secret itself.
type Credential struct {
	Name            string `yaml:"-" json:"name"`
	Type            string `yaml:"type" json:"type"` // password | private_key
	Username        string `yaml:"username" json:"username,omitempty"`
	PasswordEnv     string `yaml:"password_env" json:"password_env,omitempty"`
	KeyFile         string `yaml:"key_file" json:"key_file,omitempty"`
	PassphraseEnv   string `yaml:"passphrase_env" json:"passphrase_env,omitempty"`
	SudoPasswordEnv string `yaml:"sudo_password_env" json:"sudo_password_env,omitempty"`
}

// Endpoint is a resolved SSH endpoint.
type Endpoint struct {
	Name       string     `json:"name"`
	Address    string     `json:"address"`
	Port       int        `json:"port"`
	Username   string     `json:"username"`
	Credential Credential `json:"credential"`
}

// Addr returns host:port (IPv6 safe).
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Address, strconv.Itoa(e.Port)) }

// Target is one fully resolved host.
type Target struct {
	Endpoint
	Group     string            `json:"group,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
	Bastion   *Endpoint         `json:"bastion,omitempty"`
}

// SensitiveMask replaces sensitive values in output and reports.
const SensitiveMask = "[SENSITIVE]"
