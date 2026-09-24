package sshx

import (
	"strings"
	"testing"
)

func TestOutputBufferRetention(t *testing.T) {
	b := NewOutputBuffer(100, "", []string{"NEEDLE"})
	b.Write([]byte(strings.Repeat("a", 60)))
	b.Write([]byte("xxNEE"))
	b.Write([]byte("DLExx" + strings.Repeat("b", 200)))
	b.Write([]byte("END"))
	if !b.Truncated() || b.Total() != 273 {
		t.Fatalf("truncated=%v total=%d", b.Truncated(), b.Total())
	}
	out := string(b.Bytes())
	if !strings.HasPrefix(out, strings.Repeat("a", 50)) || !strings.HasSuffix(out, "END") || !strings.Contains(out, "[truncated 173 bytes]") {
		t.Fatalf("head/tail retention: %q", out)
	}
	if !b.Found(0) {
		t.Fatal("pattern split across writes and dropped from retention must still be found")
	}
	if len(b.Window(10)) != 10 || string(b.Window(3)) != "END" {
		t.Fatal("window")
	}
}

func TestOutputBufferEcho(t *testing.T) {
	b := NewOutputBuffer(1000, "show run | include Error", []string{"Error"})
	b.Write([]byte("show run | include Error\r\n"))
	b.Write([]byte("no problems\r\nrouter#"))
	b.Finish()
	if b.Found(0) {
		t.Fatal("echo line must not be scanned")
	}
	if got := Clean(string(b.Body())); got != "no problems\nrouter#" {
		t.Fatalf("body %q", got)
	}
	// Without an echo the first line is real output.
	b = NewOutputBuffer(1000, "secret-cmd", []string{"Error"})
	b.Write([]byte("Error happened\r\nrouter#"))
	b.Finish()
	if !b.Found(0) {
		t.Fatal("non-echo first line must be scanned")
	}
}

func TestStripPager(t *testing.T) {
	b := NewOutputBuffer(1000, "", nil)
	b.Write([]byte("line1\r\n --More-- "))
	if !b.StripPager("--More--") || strings.Contains(string(b.Bytes()), "More") {
		t.Fatal("pager not stripped")
	}
	if b.StripPager("--More--") {
		t.Fatal("double strip")
	}
}

func TestCleanNormalize(t *testing.T) {
	raw := "\x1b[?2004hshow ver\r\nCisco \x1b[1mIOS\x1b[0m\r\nline2\r\nrouter# "
	c := Clean(raw)
	if strings.ContainsAny(c, "\x1b\r") {
		t.Fatalf("clean: %q", c)
	}
	if LastLine(c) != "router#" {
		t.Fatalf("last line %q", LastLine(c))
	}
	if Normalize("Cisco IOS\nline2\nrouter# ") != "Cisco IOS\nline2" {
		t.Fatal("normalize")
	}
}
