package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
