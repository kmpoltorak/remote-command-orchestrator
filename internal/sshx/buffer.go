package sshx

import (
	"bytes"
	"fmt"
)

// Buffer holds one stream of command output with bounded memory.
//
// While output fits in limit bytes everything is kept. Beyond that the first
// limit/2 bytes (head) and the last limit/2 bytes (tail) are kept and the
// middle is dropped; String() joins them with a truncation marker.
//
// Patterns (contains/not_contains) are searched over the whole stream as it
// arrives, so text in the dropped middle still counts.
type Buffer struct {
	limit     int
	head      []byte
	tail      []byte
	total     int64
	truncated bool

	pats  []string
	found []bool
	carry []byte // last len(longest pattern)-1 bytes, for matches split across writes
	keep  int
}

// NewBuffer creates a buffer that retains about limit bytes.
func NewBuffer(limit int, patterns []string) *Buffer {
	b := &Buffer{limit: limit, pats: patterns, found: make([]bool, len(patterns))}
	for _, p := range patterns {
		b.keep = max(b.keep, len(p)-1)
	}
	return b
}

// Write implements io.Writer and never fails.
func (b *Buffer) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	b.scan(p)
	half := b.limit / 2
	switch {
	case !b.truncated && len(b.head)+len(p) <= b.limit:
		b.head = append(b.head, p...)
	case !b.truncated:
		b.truncated = true
		b.tail = append(append([]byte{}, b.head[min(half, len(b.head)):]...), p...)
		b.head = b.head[:min(half, len(b.head))]
	default:
		b.tail = append(b.tail, p...)
	}
	if len(b.tail) > 2*half { // amortized trim keeps memory <= ~1.5x limit
		b.tail = append([]byte{}, b.tail[len(b.tail)-half:]...)
	}
	return len(p), nil
}

func (b *Buffer) scan(p []byte) {
	if len(b.pats) == 0 || len(p) == 0 {
		return
	}
	buf := append(append([]byte{}, b.carry...), p...)
	for i, pat := range b.pats {
		if !b.found[i] && bytes.Contains(buf, []byte(pat)) {
			b.found[i] = true
		}
	}
	b.carry = append(b.carry[:0], buf[max(0, len(buf)-b.keep):]...)
}

// Found reports whether pattern i appeared anywhere in the stream.
func (b *Buffer) Found(i int) bool { return b.found[i] }

// Truncated reports whether bytes were dropped.
func (b *Buffer) Truncated() bool { return b.truncated }

// Total is the number of bytes received.
func (b *Buffer) Total() int64 { return b.total }

// String returns the retained output.
func (b *Buffer) String() string {
	if !b.truncated {
		return string(b.head)
	}
	t := b.tail[max(0, len(b.tail)-b.limit/2):]
	dropped := b.total - int64(len(b.head)) - int64(len(t))
	return fmt.Sprintf("%s\n...[truncated %d bytes]...\n%s", b.head, dropped, t)
}
