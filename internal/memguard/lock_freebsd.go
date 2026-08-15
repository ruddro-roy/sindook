//go:build freebsd

package memguard

import "golang.org/x/sys/unix"

func lockAll() error {
	return mlockall([]int{
		unix.MCL_CURRENT | unix.MCL_FUTURE,
		unix.MCL_FUTURE,
	})
}
