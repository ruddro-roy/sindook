package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewrapInPlaceRefusesSymbolicLink(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	_, newPub := newIdentity(t, dir, "new.key")
	in := write(t, filepath.Join(dir, "vault.txt"), []byte("do not leave an old copy behind"))
	mustRun(t, cmdSeal, "-r", oldPub, in)

	sealed := in + ext
	before, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.sindook")
	if err := os.Symlink(sealed, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if err := cmdRewrap([]string{"-i", oldKey, "-r", newPub, "-deep", link}); err == nil {
		t.Fatal("rewrap accepted a symbolic-link input")
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("rewrap replaced the symbolic link")
	}
	after, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("rewrap changed the symlink target")
	}
}

// TestRewrapIncremental exercises the -keep and -drop-* flags end to end:
// adding a recipient without disturbing existing slots, dropping by slot
// number and by identity, and stripping passphrase slots.
func TestRewrapIncremental(t *testing.T) {
	dir := t.TempDir()
	aKey, aPub := newIdentity(t, dir, "a.key")
	bKey, bPub := newIdentity(t, dir, "b.key")
	cKey, cPub := newIdentity(t, dir, "c.key")
	passfile := write(t, filepath.Join(dir, "pass"), []byte("slot pass\n"))
	in := write(t, filepath.Join(dir, "doc.txt"), []byte("incremental slots"))
	mustRun(t, cmdSeal, "-r", aPub, "-r", bPub, "-passfile", passfile, in)
	sealed := in + ext

	// keep + add: the two existing recipients and the passphrase slot are
	// preserved, carol's slot is appended.
	mustRun(t, cmdRewrap, "-i", aKey, "-keep", "-r", cPub, sealed)
	mustRun(t, cmdVerify, "-i", cKey, sealed)
	mustRun(t, cmdVerify, "-passfile", passfile, sealed)

	// Slot numbers follow inspect's listing: slot 2 is b's.
	mustRun(t, cmdRewrap, "-i", aKey, "-drop-slot", "2", sealed)
	if err := cmdVerify([]string{"-i", bKey, sealed}); err == nil {
		t.Fatal("dropped recipient still opens after -drop-slot")
	}
	mustRun(t, cmdVerify, "-i", aKey, sealed)
	mustRun(t, cmdVerify, "-i", cKey, sealed)

	// -drop-i removes every slot the named identity opens; -drop-pass-slots
	// strips the passphrase slot without knowing it.
	mustRun(t, cmdRewrap, "-i", aKey, "-drop-i", cKey, "-drop-pass-slots", sealed)
	if err := cmdVerify([]string{"-i", cKey, sealed}); err == nil {
		t.Fatal("dropped identity still opens after -drop-i")
	}
	if err := cmdVerify([]string{"-passfile", passfile, sealed}); err == nil {
		t.Fatal("dropped passphrase still opens after -drop-pass-slots")
	}
	mustRun(t, cmdVerify, "-i", aKey, sealed)
}

func TestRewrapIncrementalDropPassfile(t *testing.T) {
	dir := t.TempDir()
	_, aPub := newIdentity(t, dir, "a.key")
	passfile := write(t, filepath.Join(dir, "pass"), []byte("slot pass\n"))
	other := write(t, filepath.Join(dir, "other"), []byte("other pass\n"))
	in := write(t, filepath.Join(dir, "mix.txt"), []byte("mixed"))
	mustRun(t, cmdSeal, "-r", aPub, "-passfile", passfile, in)
	sealed := in + ext
	mustRun(t, cmdRewrap, "-passfile", passfile, "-keep", "-new-passfile", other, sealed)

	// -drop-passfile removes exactly the slot that passphrase opens.
	mustRun(t, cmdRewrap, "-passfile", passfile, "-drop-passfile", other, sealed)
	if err := cmdVerify([]string{"-passfile", other, sealed}); err == nil {
		t.Fatal("dropped passphrase still opens after -drop-passfile")
	}
	mustRun(t, cmdVerify, "-passfile", passfile, sealed)
}

func TestRewrapIncrementalErrors(t *testing.T) {
	dir := t.TempDir()
	aKey, aPub := newIdentity(t, dir, "a.key")
	bKey, _ := newIdentity(t, dir, "b.key")
	_, cPub := newIdentity(t, dir, "c.key")
	in := write(t, filepath.Join(dir, "doc.txt"), []byte("errors"))
	mustRun(t, cmdSeal, "-r", aPub, in)
	sealed := in + ext
	before, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"-i", aKey, "-keep", "-deep", "-r", cPub, sealed},
		{"-i", aKey, "-drop-slot", "0", sealed},
		{"-i", aKey, "-drop-slot", "bogus", sealed},
		{"-i", aKey, "-drop-slot", "5", sealed},
		{"-i", aKey, "-drop-i", bKey, sealed},
		{"-i", aKey, "-drop-i", aKey, sealed},
	} {
		if err := cmdRewrap(args); err == nil {
			t.Fatalf("%v: want error", args)
		}
	}
	after, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a failed incremental rewrap modified the file")
	}
}

func TestRewrapEditArmoredStaysArmored(t *testing.T) {
	dir := t.TempDir()
	aKey, aPub := newIdentity(t, dir, "a.key")
	cKey, cPub := newIdentity(t, dir, "c.key")
	in := write(t, filepath.Join(dir, "msg.txt"), []byte("armored edit"))

	mustRun(t, cmdSeal, "-r", aPub, "-a", in)
	sealed := in + ext
	mustRun(t, cmdRewrap, "-i", aKey, "-keep", "-r", cPub, sealed)

	raw, _ := os.ReadFile(sealed)
	if !strings.HasPrefix(string(raw), "-----BEGIN SINDOOK ENCRYPTED FILE-----") {
		t.Fatal("incremental rewrap dropped the armor")
	}
	mustRun(t, cmdVerify, "-i", aKey, sealed)
	mustRun(t, cmdVerify, "-i", cKey, sealed)
}

func TestReplaceStagedRemovesTemporaryFileWhenReplacementFails(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, ".sindook-rewrap-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(dir, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := replaceStaged(tmpName, destination); err == nil {
		t.Fatal("replaceStaged succeeded with a directory destination")
	}
	if _, err := os.Stat(tmpName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file remains after failed replacement: %v", err)
	}
}
