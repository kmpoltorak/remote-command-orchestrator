// Package credentials turns credential references into SSH auth methods and
// provides the Redactor that scrubs secrets from everything shown or written.
package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// Env looks up environment variables (os.LookupEnv in production).
type Env func(string) (string, bool)

// Auth is resolved secret material for one endpoint. It lives only in memory.
type Auth struct {
	Methods      []ssh.AuthMethod
	SudoPassword string   // empty = sudo must not prompt (NOPASSWD)
	Secrets      []string // everything the redactor must scrub
}

// Resolve reads secrets for c at execution time. Errors never contain secret values.
func Resolve(c domain.Credential, env Env) (*Auth, error) {
	a := &Auth{}
	switch c.Type {
	case "password":
		pw, ok := env(c.PasswordEnv)
		if !ok || pw == "" {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: environment variable %s is not set", c.Name, c.PasswordEnv)
		}
		a.Secrets = append(a.Secrets, pw)
		a.SudoPassword = pw
		a.Methods = []ssh.AuthMethod{
			ssh.Password(pw),
			// Some sshd configs only offer keyboard-interactive for passwords.
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				answers := make([]string, len(qs))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		}
	case "private_key":
		signer, err := loadKey(c, env, a)
		if err != nil {
			return nil, err
		}
		a.Methods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	default:
		return nil, domain.Fail(domain.CatAuthFailed, "credential %q: unsupported type %q", c.Name, c.Type)
	}
	if c.SudoPasswordEnv != "" {
		pw, ok := env(c.SudoPasswordEnv)
		if !ok || pw == "" {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: environment variable %s is not set", c.Name, c.SudoPasswordEnv)
		}
		a.SudoPassword = pw
		a.Secrets = append(a.Secrets, pw)
	}
	return a, nil
}

func loadKey(c domain.Credential, env Env, a *Auth) (ssh.Signer, error) {
	path := ExpandHome(c.KeyFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot read key file %s: %v", c.Name, path, errors.Unwrap(err))
	}
	if c.PassphraseEnv != "" {
		pass, ok := env(c.PassphraseEnv)
		if !ok {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: environment variable %s is not set", c.Name, c.PassphraseEnv)
		}
		a.Secrets = append(a.Secrets, pass)
		s, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
		if err != nil {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot decrypt private key", c.Name)
		}
		return s, nil
	}
	s, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, domain.Fail(domain.CatAuthFailed, "credential %q: key is encrypted but passphrase_env is not set", c.Name)
		}
		return nil, domain.Fail(domain.CatAuthFailed, "credential %q: cannot parse private key", c.Name)
	}
	return s, nil
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

// MinSecretLen is the shortest value the redactor scrubs; shorter values
// would mangle unrelated output (and are too weak to be real secrets).
const MinSecretLen = 3

// Redactor replaces known secrets with [REDACTED]. Safe for concurrent use.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// Add registers secrets.
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	return s
}
