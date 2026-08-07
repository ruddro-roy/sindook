//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// This exercises the same staged replacement used by forced seal, open, and
// key-output operations on Windows.
func TestWithOutputForceReplacesExistingFileOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(path, []byte("old output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := withOutput(path, true, false, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement output")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement output" {
		t.Fatalf("forced output = %q, want replacement output", got)
	}
}
