package armor

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

func encode(t *testing.T, data []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.String()
}

func decode(s string) ([]byte, error) {
	return io.ReadAll(NewReader(strings.NewReader(s)))
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 47, 48, 49, 63, 64, 65, 192, 4096, 100_000} {
		data := make([]byte, n)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		got, err := decode(encode(t, data))
		if err != nil {
			t.Fatalf("n=%d: decode: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestFraming(t *testing.T) {
	enc := encode(t, []byte("hello sindook"))
	if !strings.HasPrefix(enc, begin+"\n") || !strings.HasSuffix(enc, end+"\n") {
		t.Fatalf("bad framing:\n%s", enc)
	}
	for _, line := range strings.Split(strings.TrimSuffix(enc, "\n"), "\n") {
		if len(line) > cols && line != begin && line != end {
			t.Fatalf("line over %d cols: %q", cols, line)
		}
	}
}

func TestChunkedWrites(t *testing.T) {
	data := make([]byte, 10_000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for i := 0; i < len(data); i += 7 {
		end := i + 7
		if end > len(data) {
			end = len(data)
		}
		if _, err := w.Write(data[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decode(buf.String())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("chunked round trip failed: %v", err)
	}
}

func TestIsArmored(t *testing.T) {
	enc := encode(t, []byte("x"))
	if !IsArmored([]byte(enc)) {
		t.Fatal("armored input not detected")
	}
	if !IsArmored([]byte("\n\n  " + enc)) {
		t.Fatal("leading whitespace not tolerated")
	}
	if IsArmored([]byte("SINDOOK2 binary...")) {
		t.Fatal("binary input misdetected as armor")
	}
}

func TestLeadingBlankLinesAndCRLF(t *testing.T) {
	enc := encode(t, []byte("carriage return survivor"))
	crlf := strings.ReplaceAll(enc, "\n", "\r\n")
	got, err := decode("\n\n" + crlf)
	if err != nil || string(got) != "carriage return survivor" {
		t.Fatalf("crlf decode: %v", err)
	}
}

func TestMissingTerminator(t *testing.T) {
	enc := encode(t, []byte("truncate me"))
	trunc := strings.TrimSuffix(enc, end+"\n")
	if _, err := decode(trunc); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for missing end line, got %v", err)
	}
}

func TestTrailingGarbage(t *testing.T) {
	enc := encode(t, []byte("clean"))
	if _, err := decode(enc + "\n\n"); err != nil {
		t.Fatalf("trailing whitespace should be fine: %v", err)
	}
	if _, err := decode(enc + "junk\n"); !errors.Is(err, ErrTrailing) {
		t.Fatalf("want ErrTrailing, got %v", err)
	}
}

func TestCorruptBody(t *testing.T) {
	big := make([]byte, 300)
	enc := encode(t, big)
	for name, mangle := range map[string]func(string) string{
		"bad character":   func(s string) string { return strings.Replace(s, "A", "!", 1) },
		"ragged line":     func(s string) string { return strings.Replace(s, "\n", "A\n", 2) },
		"blank body line": func(s string) string { return strings.Replace(s, "\n", "\n\n", 2) },
		"padding mid-body": func(s string) string {
			lines := strings.Split(s, "\n")
			lines[1] = lines[1][:60] + "A==="
			return strings.Join(lines, "\n")
		},
	} {
		if _, err := decode(mangle(enc)); err == nil {
			t.Fatalf("%s: corrupt armor accepted", name)
		}
	}
}

func TestOversizedLine(t *testing.T) {
	long := begin + "\n" + strings.Repeat("A", 2048) + "\n" + end + "\n"
	if _, err := decode(long); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for oversized line, got %v", err)
	}
}
