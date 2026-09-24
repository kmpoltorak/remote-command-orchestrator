package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

func envOf(m map[string]string) Env {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func writeKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolvePassword(t *testing.T) {
	a, err := Resolve(domain.CredentialRef{Name: "c", Type: "password", PasswordEnv: "PW"}, envOf(map[string]string{"PW": "hunter22"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Methods) != 2 || a.Secrets[0] != "hunter22" {
		t.Fatalf("%+v", a)
	}
	_, err = Resolve(domain.CredentialRef{Name: "c", Type: "password", PasswordEnv: "PW"}, envOf(nil))
	if f := domain.AsFailure(err); f.Category != domain.CatAuthFailed {
		t.Fatalf("got %v", err)
	}
}

func TestResolveKeys(t *testing.T) {
	plain := writeKey(t, "")
	if _, err := Resolve(domain.CredentialRef{Type: "private_key", KeyFile: plain}, envOf(nil)); err != nil {
		t.Fatal(err)
	}
	enc := writeKey(t, "correct horse")
	ref := domain.CredentialRef{Name: "k", Type: "private_key", KeyFile: enc, PassphraseEnv: "PASS"}
	a, err := Resolve(ref, envOf(map[string]string{"PASS": "correct horse"}))
	if err != nil {
		t.Fatal(err)
	}
	if a.Secrets[0] != "correct horse" {
		t.Fatal("passphrase must be registered as secret")
	}
	_, err = Resolve(ref, envOf(map[string]string{"PASS": "wrong"}))
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("bad passphrase error must not leak: %v", err)
	}
	ref.PassphraseEnv = ""
	if _, err := Resolve(ref, envOf(nil)); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("got %v", err)
	}
	if _, err := Resolve(domain.CredentialRef{Type: "private_key", KeyFile: "/nonexistent"}, envOf(nil)); err == nil {
		t.Fatal("missing key must fail")
	}
}

func TestRedactor(t *testing.T) {
	r := NewRedactor("hunter22", "ab", "hunter22-long")
	got := r.String("pw=hunter22-long other=hunter22 ab")
	if strings.Contains(got, "hunter22") {
		t.Fatalf("leak: %s", got)
	}
	if !strings.Contains(got, " ab") {
		t.Fatal("secrets shorter than MinSecretLen are ignored")
	}
	f := r.Failure(domain.Fail(domain.CatCommandFailed, "echoed hunter22"))
	if strings.Contains(f.Reason, "hunter22") {
		t.Fatal("failure reason leak")
	}
	var nilR *Redactor
	if nilR.String("x") != "x" {
		t.Fatal("nil redactor must pass through")
	}
}
