// Package credentials turns credential references into SSH auth methods and
// provides the Redactor that scrubs secrets from every persisted or logged string.
package credentials

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Env abstracts environment lookup for tests.
type Env func(string) (string, bool)

// Auth is a resolved authentication. Close releases agent connections.
type Auth struct {
	Methods []ssh.AuthMethod
	Secrets []string
	closers []func() error
}

// Close releases resources (ssh-agent socket).
func (a *Auth) Close() {
	for _, c := range a.closers {
		_ = c()
	}
}

// Resolve reads the secret material for ref at execution time. Secrets are
// returned so the caller can register them with a Redactor; they are never
// persisted. Errors never include secret values.
func Resolve(ref domain.CredentialRef, env Env) (*Auth, error) {
	a := &Auth{}
	switch ref.Type {
	case "password":
		pw, ok := env(ref.PasswordEnv)
		if !ok || pw == "" {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: environment variable %s is not set", ref.Name, ref.PasswordEnv)
		}
		a.Secrets = append(a.Secrets, pw)
		a.Methods = []ssh.AuthMethod{
			ssh.Password(pw),
			// Many network devices only offer keyboard-interactive.
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		}
	case "private_key":
		signer, secrets, err := loadKey(ref, env)
		if err != nil {
			return nil, err
		}
		a.Secrets = secrets
		a.Methods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	case "agent":
		sock, ok := env("SSH_AUTH_SOCK")
		if !ok || sock == "" {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: SSH_AUTH_SOCK is not set", ref.Name)
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot connect to ssh-agent: %v", ref.Name, err)
		}
		a.closers = append(a.closers, conn.Close)
		a.Methods = []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(conn).Signers)}
	default:
		return nil, domain.Fail(domain.CatAuthFailed, "credential %q: unsupported type %q", ref.Name, ref.Type)
	}
	return a, nil
}

func loadKey(ref domain.CredentialRef, env Env) (ssh.Signer, []string, error) {
	path := ExpandHome(ref.KeyFile)
	data, err := os.ReadFile(path)
	if err != nil {
		// The path is not secret; the file content never appears in errors.
		return nil, nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot read key file %s: %v", ref.Name, path, errors.Unwrap(err))
	}
	if ref.PassphraseEnv != "" {
		pass, ok := env(ref.PassphraseEnv)
		if !ok {
			return nil, nil, domain.Fail(domain.CatAuthFailed, "credential %q: environment variable %s is not set", ref.Name, ref.PassphraseEnv)
		}
		s, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
		if err != nil {
			return nil, nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot decrypt private key", ref.Name)
		}
		return s, []string{pass}, nil
	}
	s, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, nil, domain.Fail(domain.CatAuthFailed, "credential %q: private key is encrypted but passphrase_env is not set", ref.Name)
		}
		return nil, nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot parse private key", ref.Name)
	}
	return s, nil, nil
}

// ExpandHome expands a leading "~/".
func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// MinSecretLen is the minimum length of a value the redactor will scrub.
// Shorter values would mangle unrelated output; such secrets are too weak anyway.
const MinSecretLen = 3

// Redactor replaces known secret values with [REDACTED]. It is safe for concurrent use.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// NewRedactor returns a redactor seeded with secrets.
func NewRedactor(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Add(secrets...)
	return r
}

// Add registers additional secrets.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= MinSecretLen {
			r.secrets = append(r.secrets, s)
		}
	}
	// Longest first so overlapping secrets are fully replaced.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
}

// String returns s with every registered secret replaced.
func (r *Redactor) String(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, sec := range r.secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, "[REDACTED]")
		}
	}
	return s
}

// Error returns a redacted error message.
func (r *Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(err.Error())
}

// Failure redacts a failure's reason.
func (r *Redactor) Failure(f *domain.Failure) *domain.Failure {
	if f == nil {
		return nil
	}
	return &domain.Failure{Category: f.Category, Reason: r.String(f.Reason)}
}

// Describe renders a credential reference for display without secrets.
func Describe(ref domain.CredentialRef) string {
	return fmt.Sprintf("%s(%s)", ref.Name, ref.Type)
}
