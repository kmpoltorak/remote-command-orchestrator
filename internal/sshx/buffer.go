package sshx

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// OutputBuffer holds the output of one step with bounded memory.
//
// Retention: while the output fits in limit bytes everything is kept. Beyond
// that the first limit/2 bytes (head) and the last limit/2 bytes (tail) are
// kept and the middle is dropped. Bytes() joins them with a truncation marker.
//
// contains/not_contains patterns are searched in a streaming fashion over the
// full stream (excluding the command echo line), so dropped bytes still count.
type OutputBuffer struct {
	limit     int
	head      []byte
	tail      []byte
	total     int64
	truncated bool

	echo      string // command whose echo is expected as the first line
	echoDone  bool
	bodyStart int // offset in head after the echo line

	pats  []string
	found []bool
	carry []byte
	keep  int
}

// NewOutputBuffer creates a buffer. echo may be empty (no echo expected).
func NewOutputBuffer(limit int, echo string, patterns []string) *OutputBuffer {
	b := &OutputBuffer{limit: limit, echo: strings.TrimSpace(echo), pats: patterns, found: make([]bool, len(patterns))}
	for _, p := range patterns {
		if len(p)-1 > b.keep {
			b.keep = len(p) - 1
		}
	}
	if b.echo == "" {
		b.echoDone = true
	}
	return b
}

// Write implements io.Writer. It never fails.
func (b *OutputBuffer) Write(p []byte) (int, error) {
	n := len(p)
	b.total += int64(n)
	if !b.truncated && len(b.head)+n <= b.limit {
		b.head = append(b.head, p...)
		if !b.echoDone {
			b.detectEcho(false)
			return n, nil
		}
		b.scan(p)
		return n, nil
	}
	if !b.echoDone {
		b.detectEcho(true)
	}
	half := b.limit / 2
	if !b.truncated {
		b.truncated = true
		b.tail = append(append([]byte{}, b.head[min(half, len(b.head)):]...), p...)
		b.head = b.head[:min(half, len(b.head))]
		if b.bodyStart > len(b.head) {
			b.bodyStart = len(b.head)
		}
	} else {
		b.tail = append(b.tail, p...)
	}
	if len(b.tail) > 2*half {
		b.tail = append([]byte{}, b.tail[len(b.tail)-half:]...)
	}
	b.scan(p)
	return n, nil
}

// detectEcho decides whether the first line is the echoed command. Until it
// is decided nothing is scanned; then the body after the echo is scanned once.
func (b *OutputBuffer) detectEcho(force bool) {
	i := bytes.IndexByte(b.head, '\n')
	if i < 0 && !force && len(b.head) < len(b.echo)+512 {
		return
	}
	b.echoDone = true
	if i >= 0 && strings.Contains(Clean(string(b.head[:i])), b.echo) {
		b.bodyStart = i + 1
	}
	b.scan(b.head[b.bodyStart:])
}

func (b *OutputBuffer) scan(p []byte) {
	if len(b.pats) == 0 || len(p) == 0 {
		return
	}
	buf := append(append([]byte{}, b.carry...), p...)
	for i, pat := range b.pats {
		if !b.found[i] && bytes.Contains(buf, []byte(pat)) {
			b.found[i] = true
		}
	}
	if len(buf) > b.keep {
		buf = buf[len(buf)-b.keep:]
	}
	b.carry = append(b.carry[:0], buf...)
}

// Finish completes echo detection for output that never produced a newline.
func (b *OutputBuffer) Finish() {
	if !b.echoDone {
		b.detectEcho(true)
	}
}

// Found reports whether pattern index i appeared in the stream.
func (b *OutputBuffer) Found(i int) bool { return b.found[i] }

// Truncated reports whether bytes were dropped.
func (b *OutputBuffer) Truncated() bool { return b.truncated }

// Total returns the number of bytes received.
func (b *OutputBuffer) Total() int64 { return b.total }

// Bytes returns retained output (head + marker + tail when truncated).
func (b *OutputBuffer) Bytes() []byte {
	if !b.truncated {
		return b.head
	}
	half := b.limit / 2
	t := b.tail
	if len(t) > half {
		t = t[len(t)-half:]
	}
	dropped := b.total - int64(len(b.head)) - int64(len(t))
	out := append([]byte{}, b.head...)
	out = append(out, fmt.Sprintf("\n...[truncated %d bytes]...\n", dropped)...)
	return append(out, t...)
}

// Body returns retained output without the echo line.
func (b *OutputBuffer) Body() []byte {
	all := b.Bytes()
	if b.bodyStart <= len(all) {
		return all[b.bodyStart:]
	}
	return all
}

// Window returns up to n trailing bytes of the body; used for prompt matching.
func (b *OutputBuffer) Window(n int) []byte {
	var src []byte
	if b.truncated {
		src = b.tail
	} else {
		src = b.head[b.bodyStart:]
	}
	if len(src) > n {
		src = src[len(src)-n:]
	}
	return src
}

// StripPager removes the last occurrence of pattern from the final line and
// reports whether it was present.
func (b *OutputBuffer) StripPager(pattern string) bool {
	target := &b.head
	if b.truncated {
		target = &b.tail
	}
	s := *target
	start := bytes.LastIndexByte(s, '\n') + 1
	if start < b.bodyStart && !b.truncated {
		start = b.bodyStart
	}
	j := bytes.LastIndex(s[start:], []byte(pattern))
	if j < 0 {
		return false
	}
	j += start
	*target = append(s[:j], s[j+len(pattern):]...)
	return true
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEMc]`)

// Clean removes ANSI escapes, carriage returns, backspaces and NUL bytes.
func Clean(s string) string {
	if strings.IndexByte(s, 0x1b) >= 0 {
		s = ansiPattern.ReplaceAllString(s, "")
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\b', 0:
			return -1
		}
		return r
	}, s)
}

// LastLine returns the trimmed text after the final newline.
func LastLine(s string) string {
	s = strings.TrimRight(s, " \t\n")
	return strings.TrimSpace(s[strings.LastIndexByte(s, '\n')+1:])
}

// Normalize removes the trailing prompt line from cleaned body text.
func Normalize(body string) string {
	body = strings.TrimRight(body, " \t\n")
	if i := strings.LastIndexByte(body, '\n'); i >= 0 {
		return strings.TrimRight(body[:i], " \t\n")
	}
	return ""
}
