package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const usageShred = `usage: sindook shred [-n PASSES] [-glob PATTERN] FILE...

Overwrite and delete regular files. Each file is overwritten with
cryptographic random data (PASSES passes, default 3), truncated, and
removed.

flags:
  -n PASSES    number of overwrite passes (1-64, default 3)
  -glob PATTERN
                include files matching a portable filesystem pattern

examples:
  sindook shred secret.txt
  sindook shred -n 7 old-backup.tar.gz
  sindook shred -glob "old/*.txt"
  sindook shred -- -file-that-starts-with-a-dash

sindook shred cannot guarantee erasure on SSDs, journaled or
copy-on-write filesystems, or in backups.
`

const (
	shredDefaultPasses = 3
	shredBlockSize     = 1 << 20
)

func cmdShred(args []string) error {
	fs := newFlagSet("shred", usageShred)
	passes := fs.Int("n", shredDefaultPasses, "")
	var globs multiFlag
	fs.Var(&globs, "glob", "")
	parseInterspersedFlags(fs, args)
	if *passes < 1 || *passes > 64 {
		return usagef("shred: -n must be between 1 and 64, got %d", *passes)
	}
	files, err := expandInputs(fs.Args(), globs)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return usagef("shred: no files to shred")
	}
	fmt.Fprintln(os.Stderr, "sindook: shred cannot guarantee erasure on SSDs, journaled or copy-on-write filesystems, or in backups")

	var errs []error
	for _, path := range files {
		if err := shredOne(path, *passes); err != nil {
			errs = append(errs, fmt.Errorf("sindook: shred %s: %w", path, err))
			continue
		}
		fmt.Fprintf(os.Stderr, "shredded %s\n", path)
	}
	return errors.Join(errs...)
}

// shredOne overwrites a single regular file with random data, truncates it,
// and removes it. The parent directory is fsynced best-effort so the
// removal itself is durable where the filesystem supports it.
func shredOne(path string, passes int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to shred symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to shred non-regular file")
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, shredBlockSize)
	for pass := 0; pass < passes; pass++ {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		remaining := info.Size()
		for remaining > 0 {
			n := int64(len(buf))
			if remaining < n {
				n = remaining
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				return err
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		syncParentDir(path)
	}
	return nil
}

// syncParentDir makes the removal durable where the filesystem supports
// directory fsync. Purely best-effort: any failure is ignored.
func syncParentDir(path string) {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return
	}
	defer d.Close()
	d.Sync()
}
