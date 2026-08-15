//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWarnInsecurePerms checks the mode-based warning: a 0644 file is flagged
// and the same file tightened to 0600 is not.
func TestWarnInsecurePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := warnInsecurePerms(path, info); got == "" {
		t.Fatal("warnInsecurePerms = \"\", want a warning for a 0644 file")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := warnInsecurePerms(path, info); got != "" {
		t.Fatalf("warnInsecurePerms = %q, want \"\" for a 0600 file", got)
	}
}

// TestReplaceStagedReplacesExistingFile checks that a staged file atomically
// takes the place of an existing target and that the staged file itself is
// gone afterwards.
func TestReplaceStagedReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "staged.txt")
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceStaged(staged, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target content = %q, want %q", got, "new")
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged file still exists after replacement (err=%v)", err)
	}
}
