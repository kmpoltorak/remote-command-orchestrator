package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestCategoryHostStatus(t *testing.T) {
	cases := map[Category]HostStatus{
		"":                     HostSuccess,
		CatAuthFailed:          HostAuthFailed,
		CatConnectionTimeout:   HostConnectionFailed,
		CatHostKeyMismatch:     HostConnectionFailed,
		CatDNSFailure:          HostConnectionFailed,
		CatExpectTimeout:       HostTimeout,
		CatCommandTimeout:      HostTimeout,
		CatPromptMismatch:      HostPromptMismatch,
		CatCancelled:           HostCancelled,
		CatInterrupted:         HostUnknown,
		CatCommandFailed:       HostFailed,
		CatOutputLimitExceeded: HostFailed,
	}
	for c, want := range cases {
		if got := c.HostStatus(); got != want {
			t.Errorf("%s: got %s want %s", c, got, want)
		}
	}
	for _, c := range AllCategories {
		if !c.HostStatus().Terminal() {
			t.Errorf("%s maps to non-terminal status", c)
		}
	}
}

func TestRetryClassification(t *testing.T) {
	for _, c := range []Category{CatAuthFailed, CatHostKeyMismatch, CatHostKeyUnknown, CatPromptInvalid, CatPromptMismatch, CatCommandFailed, CatDNSFailure} {
		if c.ConnectionRetryable() {
			t.Errorf("%s must not be connection-retryable", c)
		}
	}
	for _, c := range []Category{CatConnectionTimeout, CatConnectionRefused, CatHandshakeFailed, CatSessionFailed} {
		if !c.ConnectionRetryable() {
			t.Errorf("%s must be connection-retryable", c)
		}
	}
	if CatSessionFailed.StepRetryable() || CatCancelled.StepRetryable() {
		t.Error("session failure / cancel are not step retryable")
	}
	if !CatPromptMismatch.StepRetryable() {
		t.Error("prompt mismatch is step retryable when configured")
	}
}

func TestAsFailure(t *testing.T) {
	f := Fail(CatAuthFailed, "bad creds for %s", "x")
	wrapped := fmt.Errorf("wrap: %w", f)
	if got := AsFailure(wrapped); got.Category != CatAuthFailed {
		t.Fatalf("got %v", got)
	}
	if got := AsFailure(errors.New("boom")); got.Category != CatInternalError {
		t.Fatalf("got %v", got)
	}
	if AsFailure(nil) != nil {
		t.Fatal("nil expected")
	}
}
