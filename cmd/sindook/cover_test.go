package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestInspectCommand covers the CLI wrapper around box.Inspect: plain and
// JSON output on a freshly sealed file, and the error path on garbage.
func TestInspectCommand(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := newIdentity(t, dir, "alice.key")
	plain := write(t, filepath.Join(dir, "doc.txt"), []byte("inspect me"))
	mustRun(t, cmdSeal, "-r", pubPath, plain)
	sealed := plain + ".sindook"

	out, err := captureStdout(t, func() error { return cmdInspect([]string{sealed}) })
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, want := range []string{"doc.txt", "recipient", "v2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plain inspect output missing %q:\n%s", want, out)
		}
	}

	js, err := captureStdout(t, func() error { return cmdInspect([]string{"-json", sealed}) })
	if err != nil {
		t.Fatalf("inspect -json: %v", err)
	}
	if !strings.Contains(js, "\"file\"") {
		t.Fatalf("json inspect output missing file field:\n%s", js)
	}

	if err := cmdInspect([]string{write(t, filepath.Join(dir, "garbage"), []byte("not sindook"))}); err == nil {
		t.Fatal("inspect accepted a non-sindook file")
	}
}

// TestCompletionShells covers every supported completion emitter.
func TestCompletionShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell", "pwsh"} {
		out, err := captureStdout(t, func() error { return cmdCompletion([]string{shell}) })
		if err != nil {
			t.Fatalf("%s completion: %v", shell, err)
		}
		if !strings.Contains(out, "sindook") {
			t.Fatalf("%s completion does not mention sindook", shell)
		}
	}
	if err := cmdCompletion([]string{"tcsh"}); err == nil {
		t.Fatal("completion accepted an unsupported shell")
	}
}

// TestLoadIdentity covers the identity loader directly: a generated key
// loads, and garbage is rejected.
func TestLoadIdentity(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := newIdentity(t, dir, "alice.key")
	k, err := loadIdentity(keyPath)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if k == nil || len(k.PublicKey()) == 0 {
		t.Fatal("loadIdentity returned no key")
	}
	if _, err := loadIdentity(write(t, filepath.Join(dir, "bad.key"), []byte("garbage"))); err == nil {
		t.Fatal("loadIdentity accepted a garbage identity file")
	}
}
