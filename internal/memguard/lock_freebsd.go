//go:build freebsd

package memguard

import "golang.org/x/sys/unix"

func lockAll() error {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err == nil {
		if lim.Cur != unix.RLIM_INFINITY && lim.Cur < 96*1024*1024 {
			return unix.Mlockall(unix.MCL_CURRENT)
		}
	}
	return mlockall([]int{
		unix.MCL_CURRENT | unix.MCL_FUTURE,
		unix.MCL_FUTURE,
		unix.MCL_CURRENT,
	})
}
