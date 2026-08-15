//go:build !windows

package main

import (
	"fmt"
	"os"
)

// applyPathACL is a no-op on POSIX systems. Restrictive permissions there are
// applied at creation time through Chmod and the process umask, and
// warnInsecurePerms flags anything the umask did not tighten, so no separate
// ACL step is needed. The path and isDir arguments are accepted so callers
// remain platform-independent.
func applyPathACL(path string, isDir bool) error {
	return nil
}

// warnInsecurePerms returns a single-line warning when path grants any access
// beyond its owner, as a 0644 identity file would. Files that are already
// 0600 or stricter return an empty string. The message names the chmod 600
// remediation.
func warnInsecurePerms(path string, info os.FileInfo) string {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("sindook: warning: %s is readable by others (mode %04o); restrict it with chmod 600", path, info.Mode().Perm())
	}
	return ""
}

// replaceStaged replaces path with staged. On POSIX, os.Rename is atomic
// within a filesystem, so readers see either the old file or the new one. If
// the rename fails, the staged file is removed so a failed operation does not
// leave a second copy of sensitive output beside the original.
func replaceStaged(staged, path string) error {
	if err := os.Rename(staged, path); err != nil {
		os.Remove(staged)
		return err
	}
	return nil
}
