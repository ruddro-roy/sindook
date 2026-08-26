package armor

import (
	"bytes"
	"errors"
	"testing"
)

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, errors.New("write failure") }

// TestArmorWriteAfterClose covers the closed-writer guard.
func TestArmorWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := w.Write([]byte("more")); err == nil {
		t.Fatal("write after close accepted")
	}
	// Close is idempotent.
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// TestArmorWriterFailingSink covers error propagation through start, the
// base64 encoder, the line writer, and the end marker.
func TestArmorWriterFailingSink(t *testing.T) {
	w := NewWriter(failWriter{})
	if _, err := w.Write([]byte("payload")); err == nil {
		t.Fatal("write through a failing sink succeeded")
	}
	if err := w.Close(); err == nil {
		t.Fatal("close through a failing sink succeeded")
	}

	// Close on a fresh writer must still emit the begin marker and fail.
	w2 := NewWriter(failWriter{})
	if err := w2.Close(); err == nil {
		t.Fatal("fresh close through a failing sink succeeded")
	}
}

// TestLineWriterWrap covers column accounting across the wrap boundary.
func TestLineWriterWrap(t *testing.T) {
	var buf bytes.Buffer
	lw := &lineWriter{w: &buf}
	chunk := bytes.Repeat([]byte("A"), cols+5)
	n, err := lw.Write(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(chunk) {
		t.Fatalf("lineWriter wrote %d of %d bytes", n, len(chunk))
	}
	if lw.col != 5 {
		t.Fatalf("column counter = %d, want 5", lw.col)
	}
	if got := len(bytes.Split(buf.Bytes(), []byte("\n"))); got != 2 {
		t.Fatalf("expected one wrap, got %d lines", got)
	}
}
