package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruddro-roy/sindook/internal/box"
)

// After sindook init, the everyday commands need no credential flags:
// seal, verify, rewrap, and open all use the default identity.
func TestInitThenNoFlagFlow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(dir, "config"))
	key := filepath.Join(dir, "me.key")
	mustRun(t, cmdInit, "-o", key)

	plain := []byte("after init, no flags needed")
	in := write(t, filepath.Join(dir, "notes.txt"), plain)

	mustRun(t, cmdSeal, in)
	if _, err := os.Stat(in + ext); err != nil {
		t.Fatalf("seal without flags did not create %s: %v", in+ext, err)
	}

	mustRun(t, cmdVerify, in+ext)

	out := filepath.Join(dir, "out.txt")
	mustRun(t, cmdOpen, "-o", out, in+ext)
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open without flags mismatch: %v", err)
	}

	mustRun(t, cmdRewrap, "-r", key+".pub", in+ext)
	mustRun(t, cmdOpen, "-o", out, "-f", in+ext)
	got, err = os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open after no-flag rewrap mismatch: %v", err)
	}
}

// With no default identity, the missing-credential errors teach the next
// command instead of only refusing.
func TestFirstRunHints(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(dir, "config"))
	in := write(t, filepath.Join(dir, "notes.txt"), []byte("x"))

	err := cmdSeal([]string{in})
	if err == nil || !strings.Contains(err.Error(), "sindook init") {
		t.Fatalf("seal with no recipients and no default: err = %v, want a sindook init hint", err)
	}

	err = cmdOpen([]string{in + ext})
	if err == nil || !strings.Contains(err.Error(), "sindook init") {
		t.Fatalf("open with no credential and no default: err = %v, want a sindook init hint", err)
	}
}

// Opening a passphrase-sealed file with an identity names -p, and opening a
// recipient-sealed file with the wrong identity adds the same suggestion on
// top of ErrWrongKey.
func TestOpenWrongCredentialSuggestsPassphrase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SINDOOK_CONFIG_DIR", filepath.Join(dir, "config"))
	_, ownerPub := newIdentity(t, dir, "owner.key")
	otherKey, _ := newIdentity(t, dir, "other.key")

	pass := write(t, filepath.Join(dir, "pass"), []byte("correct horse battery staple\n"))

	// Passphrase-only file opened with an identity.
	pIn := write(t, filepath.Join(dir, "pass-notes.txt"), []byte("passphrase only"))
	mustRun(t, cmdSeal, "-passfile", pass, pIn)
	err := cmdOpen([]string{"-i", otherKey, "-o", filepath.Join(dir, "out1.txt"), pIn + ext})
	if err == nil || !errors.Is(err, box.ErrNeedPassphrase) {
		t.Fatalf("identity on a passphrase file: err = %v, want ErrNeedPassphrase", err)
	}

	// Recipient file opened with the wrong identity.
	rIn := write(t, filepath.Join(dir, "owner-notes.txt"), []byte("recipient only"))
	mustRun(t, cmdSeal, "-r", ownerPub, rIn)
	err = cmdOpen([]string{"-i", otherKey, "-o", filepath.Join(dir, "out2.txt"), rIn + ext})
	if err == nil || !errors.Is(err, box.ErrWrongKey) {
		t.Fatalf("wrong identity on a recipient file: err = %v, want ErrWrongKey", err)
	}
	if !strings.Contains(err.Error(), "add -p") {
		t.Fatalf("wrong identity on a recipient file: err = %v, want an add -p suggestion", err)
	}
}
