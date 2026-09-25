package sshx

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/domain"
)

// ClassifyDial classifies TCP connection errors.
func ClassifyDial(err error, addr string) *domain.Failure {
	var dnsErr *net.DNSError
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return domain.Fail(domain.CatCancelled, "cancelled while connecting to %s", addr)
	case errors.As(err, &dnsErr):
		if dnsErr.IsTimeout {
			return domain.Fail(domain.CatConnectionTimeout, "DNS lookup timeout for %s", dnsErr.Name)
		}
		return domain.Fail(domain.CatDNSFailure, "DNS lookup failed for %s: %s", dnsErr.Name, dnsErr.Err)
	case errors.Is(err, syscall.ECONNREFUSED):
		return domain.Fail(domain.CatConnectionRefused, "connection refused by %s", addr)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return domain.Fail(domain.CatConnectionTimeout, "connection to %s timed out", addr)
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		// Treated as a transient network failure (retryable) but reported verbatim.
		return domain.Fail(domain.CatConnectionTimeout, "network unreachable for %s: %v", addr, err)
	}
	if strings.Contains(err.Error(), "connect failed") { // bastion tunnel refusal
		return domain.Fail(domain.CatConnectionRefused, "bastion could not reach %s: %v", addr, err)
	}
	return domain.Fail(domain.CatConnectionTimeout, "connection to %s failed: %v", addr, err)
}

// ClassifyHandshake classifies SSH handshake/auth errors.
func ClassifyHandshake(err error, addr string, timedOut bool) *domain.Failure {
	var keyErr *knownhosts.KeyError
	var f *domain.Failure
	msg := err.Error()
	switch {
	case errors.As(err, &f):
		return f
	case errors.As(err, &keyErr):
		if len(keyErr.Want) > 0 {
			return domain.Fail(domain.CatHostKeyMismatch, "host key for %s does not match known_hosts (possible man-in-the-middle)", addr)
		}
		host, port, _ := net.SplitHostPort(addr)
		return domain.Fail(domain.CatHostKeyUnknown, "host key for %s is not in known_hosts (verify the fingerprint, then: ssh-keyscan -p %s %s >> ~/.ssh/known_hosts, or run with --accept-new-host-keys)", addr, port, host)
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods remain"):
		return domain.Fail(domain.CatAuthFailed, "authentication failed for %s", addr)
	case timedOut:
		return domain.Fail(domain.CatHandshakeFailed, "SSH handshake with %s timed out", addr)
	case errors.Is(err, context.Canceled):
		return domain.Fail(domain.CatCancelled, "cancelled during SSH handshake with %s", addr)
	case errors.Is(err, io.EOF):
		return domain.Fail(domain.CatHandshakeFailed, "connection closed during SSH handshake with %s", addr)
	}
	return domain.Fail(domain.CatHandshakeFailed, "SSH handshake with %s failed: %v", addr, err)
}
