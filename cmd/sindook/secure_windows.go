//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SetFileSecurityW is not wrapped by x/sys/windows, so it is reached through
// a lazy advapi32 proc. The security descriptor itself is built with
// windows.SecurityDescriptorFromString, which wraps
// ConvertStringSecurityDescriptorToSecurityDescriptorW.
var (
	modAdvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procSetFileSecurityW = modAdvapi32.NewProc("SetFileSecurityW")
)

// applyPathACL replaces the DACL of path with a single entry granting full
// control to the current user only, so identity files and sealed output stay
// private even when the containing directory's inheritance would grant access
// to other accounts. The descriptor is built from the SDDL string
// "D:P(A;OICI;FA;;;SID)" and applied with
// DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION so inherited
// entries are replaced rather than merged. The OICI inheritance flags in the
// SDDL are harmless on plain files and let new children of a directory
// inherit the same restriction. Every failure, including access denied and
// volumes without security support, is returned as a descriptive error; the
// function never panics.
func applyPathACL(path string, isDir bool) error {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("sindook: opening process token to restrict ACL on %s: %w", path, err)
	}
	defer tok.Close()

	user, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("sindook: resolving current user to restrict ACL on %s: %w", path, err)
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return fmt.Errorf("sindook: cannot convert the current user SID to a string for %s", path)
	}

	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return fmt.Errorf("sindook: building security descriptor for %s: %w", path, err)
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("sindook: encoding path %s: %w", path, err)
	}
	r1, _, e1 := procSetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(sd)),
	)
	if r1 == 0 {
		if e1 == nil {
			e1 = errors.New("SetFileSecurityW failed")
		}
		switch {
		case errors.Is(e1, windows.ERROR_ACCESS_DENIED):
			return fmt.Errorf("sindook: access denied restricting the ACL of %s: %w", path, e1)
		case errors.Is(e1, windows.ERROR_NOT_SUPPORTED):
			return fmt.Errorf("sindook: the volume holding %s does not support security descriptors: %w", path, e1)
		default:
			return fmt.Errorf("sindook: restricting the ACL of %s: %w", path, e1)
		}
	}
	return nil
}

// warnInsecurePerms is a best-effort check for a DACL that lets Everyone
// (S-1-1-0) or BUILTIN\Users (S-1-5-32-545) modify path. It never raises a
// false alarm: if the security descriptor cannot be read or interpreted it
// returns "", and an explicit deny entry for the same SID overrides an allow
// entry. info is unused on Windows, where mode bits do not express who can
// access a file.
func warnInsecurePerms(path string, info os.FileInfo) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return ""
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ""
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return ""
	}
	users, err := windows.StringToSid("S-1-5-32-545")
	if err != nil {
		return ""
	}

	// GENERIC_WRITE is checked alongside FILE_GENERIC_WRITE and GENERIC_ALL
	// because it resolves to the generic write right for these ACEs.
	const writeBits = windows.FILE_GENERIC_WRITE | windows.GENERIC_WRITE | windows.GENERIC_ALL
	granted, denied := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return ""
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windows.EqualSid(sid, everyone) && !windows.EqualSid(sid, users) {
			continue
		}
		if ace.Mask&writeBits == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			granted = true
		case windows.ACCESS_DENIED_ACE_TYPE:
			denied = true
		}
	}
	if granted && !denied {
		return fmt.Sprintf("sindook: warning: %s is writable by Everyone or BUILTIN\\Users; tighten its ACL so only your account can modify it", path)
	}
	return ""
}

// replaceStaged replaces path with staged, retrying os.Rename up to 10 times
// with 50ms pauses between attempts because antivirus scanners and indexers
// transiently hold newly written files on Windows. When the retries are
// exhausted it falls back to MoveFileEx with
// MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH. If every attempt fails,
// the staged file is removed so a failed operation does not leave a second
// copy of sensitive output beside the original, and the last error is
// returned.
func replaceStaged(staged, path string) error {
	const attempts = 10
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		if err := os.Rename(staged, path); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	from, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		os.Remove(staged)
		return lastErr
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		os.Remove(staged)
		return lastErr
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err == nil {
		return nil
	} else {
		os.Remove(staged)
		return fmt.Errorf("sindook: replacing %s after %d rename retries and the MoveFileEx fallback: %w", path, attempts, err)
	}
}
