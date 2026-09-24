package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxConcurrency != 100 || c.Timeouts.Connect != 10*time.Second || c.Timeouts.Session != 5*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.HostLocking != LockPerHost || c.Retry.Count != 3 || c.InsecureSkipHostKey {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestOverridesAndAliases(t *testing.T) {
	c, err := Load(env(map[string]string{
		"SSH_MAX_CONCURRENCY":    "250",
		"SSH_EXPECT_TIMEOUT":     "3s",
		"HOST_EXECUTION_LOCKING": "false",
		"HOST_START_RATE":        "600/m",
		"SMTP_TO":                "a@x.io, b@x.io",
		"COMMAND_DELAY":          "0",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxConcurrency != 250 || c.Timeouts.Expect != 3*time.Second || c.HostLocking != LockNone {
		t.Fatalf("%+v", c)
	}
	if c.HostStartRate != 10 || len(c.SMTP.To) != 2 {
		t.Fatalf("rate=%v to=%v", c.HostStartRate, c.SMTP.To)
	}
}

func TestInvalidValues(t *testing.T) {
	_, err := Load(env(map[string]string{
		"SSH_MAX_CONCURRENCY":    "abc",
		"SSH_CONNECT_TIMEOUT":    "-1s",
		"HOST_EXECUTION_LOCKING": "maybe",
		"HOST_START_RATE":        "5/h",
		"MAX_STEP_OUTPUT_BYTES":  "10",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"SSH_MAX_CONCURRENCY", "SSH_CONNECT_TIMEOUT", "HOST_EXECUTION_LOCKING", "HOST_START_RATE", "MAX_STEP_OUTPUT_BYTES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}
