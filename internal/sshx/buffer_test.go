package sshx

import (
	"strings"
	"testing"
)

func TestBuffer(t *testing.T) {
	b := NewBuffer(100, []string{"NEEDLE", "absent"})
	b.Write([]byte(strings.Repeat("a", 60)))
	b.Write([]byte("xxNEE"))
	b.Write([]byte("DLExx" + strings.Repeat("b", 200)))
	b.Write([]byte("END"))
	if !b.Truncated() || b.Total() != 273 {
		t.Fatalf("truncated=%v total=%d", b.Truncated(), b.Total())
	}
	out := b.String()
	if !strings.HasPrefix(out, strings.Repeat("a", 50)) || !strings.HasSuffix(out, "END") || !strings.Contains(out, "[truncated 173 bytes]") {
		t.Fatalf("retention: %q", out)
	}
	if !b.Found(0) || b.Found(1) {
		t.Fatal("pattern split across writes must be found; absent must not")
	}
	big := NewBuffer(100, nil) // a single write larger than the limit
	big.Write([]byte("HEAD" + strings.Repeat("x", 500) + "TAIL"))
	if s := big.String(); !strings.HasPrefix(s, "HEAD") || !strings.HasSuffix(s, "TAIL") || !strings.Contains(s, "[truncated 408 bytes]") {
		t.Fatalf("oversized first write: %q", s)
	}
	small := NewBuffer(100, nil)
	small.Write([]byte("hi"))
	if small.String() != "hi" || small.Truncated() {
		t.Fatal("small output must be kept verbatim")
	}
}
