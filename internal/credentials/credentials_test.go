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

// WriteKey writes a fresh ed25519 key, optionally encrypted.
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

func TestPassword(t *testing.T) {
	c := domain.Credential{Name: "c", Type: "password", PasswordEnv: "PW"}
	a, err := Resolve(c, envOf(map[string]string{"PW": "hunter22"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Methods) != 2 || a.SudoPassword != "hunter22" || a.Secrets[0] != "hunter22" {
		t.Fatalf("%+v", a)
	}
	if _, err := Resolve(c, envOf(nil)); domain.AsFailure(err).Category != domain.CatAuthFailed {
		t.Fatalf("got %v", err)
	}
}

func TestKeys(t *testing.T) {
	if a, err := Resolve(domain.Credential{Type: "private_key", KeyFile: writeKey(t, "")}, envOf(nil)); err != nil || a.SudoPassword != "" {
		t.Fatalf("%v %+v", err, a)
	}
	ref := domain.Credential{Name: "k", Type: "private_key", KeyFile: writeKey(t, "correct horse"), PassphraseEnv: "PASS", SudoPasswordEnv: "SUDO"}
	a, err := Resolve(ref, envOf(map[string]string{"PASS": "correct horse", "SUDO": "sudo-pw"}))
	if err != nil {
		t.Fatal(err)
	}
	if a.SudoPassword != "sudo-pw" || len(a.Secrets) != 2 {
		t.Fatalf("%+v", a)
	}
	_, err = Resolve(ref, envOf(map[string]string{"PASS": "wrong-pass", "SUDO": "x"}))
	if err == nil || strings.Contains(err.Error(), "wrong-pass") {
		t.Fatalf("bad passphrase must fail without leaking: %v", err)
	}
	ref.PassphraseEnv = ""
	if _, err := Resolve(ref, envOf(map[string]string{"SUDO": "x"})); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("got %v", err)
	}
	if _, err := Resolve(domain.Credential{Type: "private_key", KeyFile: "/nonexistent"}, envOf(nil)); err == nil {
		t.Fatal("missing key must fail")
	}
}

func TestRedactor(t *testing.T) {
	var r Redactor
	r.Add("hunter22", "ab", "hunter22-long")
	got := r.String("pw=hunter22-long other=hunter22 ab")
	if strings.Contains(got, "hunter22") || !strings.Contains(got, " ab") {
		t.Fatalf("got %s", got)
	}
	for range 1000 {
		r.Add("hunter22")
	}
	if len(r.secrets) != 2 {
		t.Fatalf("duplicates must be ignored, have %d secrets", len(r.secrets))
	}
}
