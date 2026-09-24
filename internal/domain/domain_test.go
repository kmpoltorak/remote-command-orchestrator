package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestRetryable(t *testing.T) {
	for _, c := range []Category{CatAuthFailed, CatHostKeyMismatch, CatHostKeyUnknown, CatDNSFailure, CatCommandFailed, CatCancelled} {
		if c.Retryable() {
			t.Errorf("%s must not be retryable", c)
		}
	}
	for _, c := range []Category{CatConnectionTimeout, CatConnectionRefused, CatHandshakeFailed, CatSessionFailed} {
		if !c.Retryable() {
			t.Errorf("%s must be retryable", c)
		}
	}
}

func TestAsFailure(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", Fail(CatAuthFailed, "bad"))
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

func TestAddr(t *testing.T) {
	if got := (Endpoint{Address: "::1", Port: 22}).Addr(); got != "[::1]:22" {
		t.Fatal(got)
	}
}
