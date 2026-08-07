//go:build windows

package main

import (
	"path/filepath"
	"testing"
)

// Windows does not allow replacement while the input remains open without
// delete sharing. This protects the in-place rewrap path from a platform-only
// regression.
func TestRewrapInPlaceClosesInputBeforeReplaceOnWindows(t *testing.T) {
	dir := t.TempDir()
	oldKey, oldPub := newIdentity(t, dir, "old.key")
	newKey, newPub := newIdentity(t, dir, "new.key")
	in := write(t, filepath.Join(dir, "vault.txt"), []byte("replace the header safely"))
	mustRun(t, cmdSeal, "-r", oldPub, in)

	sealed := in + ext
	mustRun(t, cmdRewrap, "-i", oldKey, "-r", newPub, sealed)
	mustRun(t, cmdVerify, "-i", newKey, sealed)
}
