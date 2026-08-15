//go:build linux

package memguard

import "golang.org/x/sys/unix"

func lockAll() error {
	// The most lenient mode is tried last: MCL_ONFAULT locks pages only as
	// they are faulted in, which succeeds under a small RLIMIT_MEMLOCK.
	return mlockall([]int{
		unix.MCL_CURRENT | unix.MCL_FUTURE,
		unix.MCL_FUTURE,
		unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT,
	})
}
