//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWithOutputNewFilesAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.txt")
	if err := withOutput(path, false, false, func(w io.Writer) error {
		_, err := io.WriteString(w, "sensitive plaintext")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("new output mode = %#o, want %#o", got, want)
	}
}

func TestWithOutputForceTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := withOutput(path, true, false, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("forced output mode = %#o, want %#o", got, want)
	}
}
