package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestShredRemovesFile(t *testing.T) {
	path := write(t, filepath.Join(t.TempDir(), "secret.txt"), []byte("top secret content"))
	mustRun(t, cmdShred, path)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still exists after shred: %v", err)
	}
}

func TestShredEmptyFile(t *testing.T) {
	path := write(t, filepath.Join(t.TempDir(), "empty.txt"), nil)
	mustRun(t, cmdShred, path)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty file still exists after shred: %v", err)
	}
}

func TestShredSinglePass(t *testing.T) {
	path := write(t, filepath.Join(t.TempDir(), "one.txt"), []byte("single pass"))
	mustRun(t, cmdShred, "-n", "1", path)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still exists after shred -n 1: %v", err)
	}
}

func TestShredPortableGlob(t *testing.T) {
	dir := t.TempDir()
	first := write(t, filepath.Join(dir, "first.wipe"), []byte("first"))
	second := write(t, filepath.Join(dir, "second.wipe"), []byte("second"))
	mustRun(t, cmdShred, "-glob", filepath.Join(dir, "*.wipe"))
	for _, path := range []string{first, second} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists after shred glob: %v", path, err)
		}
	}
}

func TestShredRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs extra privileges on Windows")
	}
	dir := t.TempDir()
	target := write(t, filepath.Join(dir, "target.txt"), []byte("keep me"))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := cmdShred([]string{link}); err == nil {
		t.Fatal("shred accepted a symbolic link")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep me" {
		t.Fatalf("symlink target was damaged: %q %v", got, err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
}

func TestShredRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cmdShred([]string{sub}); err == nil {
		t.Fatal("shred accepted a directory")
	}
	if info, err := os.Stat(sub); err != nil || !info.IsDir() {
		t.Fatalf("directory was damaged: %v", err)
	}
}

func TestShredMissingFileErrors(t *testing.T) {
	if err := cmdShred([]string{filepath.Join(t.TempDir(), "nope.txt")}); err == nil {
		t.Fatal("shred of a missing file succeeded")
	}
}

func TestShredPassRangeErrors(t *testing.T) {
	dir := t.TempDir()
	path := write(t, filepath.Join(dir, "secret.txt"), []byte("content"))
	for _, n := range []string{"0", "65"} {
		if err := cmdShred([]string{"-n", n, path}); err == nil {
			t.Fatalf("shred -n %s was accepted", n)
		}
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("file was removed after rejected pass count: %v", err)
	}
}

func TestShredNoFilesErrors(t *testing.T) {
	if err := cmdShred(nil); err == nil {
		t.Fatal("shred with no files succeeded")
	}
}
