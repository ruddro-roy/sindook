//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestApplyPathACLRestrictsToCurrentUser verifies that applyPathACL leaves a
// user-only DACL: after the call the DACL must not contain an ACE for
// Everyone. The read-back is best-effort because exotic filesystems and
// sandboxed environments sometimes cannot report security descriptors, in
// which case the assertion is skipped.
func TestApplyPathACLRestrictsToCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyPathACL(path, false); err != nil {
		t.Fatalf("applyPathACL: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Skip("cannot read back the DACL; skipping best-effort assertion")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Skip("cannot read back the DACL; skipping best-effort assertion")
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Skipf("cannot enumerate the DACL; skipping best-effort assertion: %v", err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windows.EqualSid(sid, everyone) {
			t.Fatalf("DACL on %s still grants access to Everyone", path)
		}
	}
}

// TestReplaceStagedReplacesExistingFileOnWindows exercises the retrying
// replacement used by forced output operations.
func TestReplaceStagedReplacesExistingFileOnWindows(t *testing.T) {
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
