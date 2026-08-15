//go:build linux

package memguard

import "golang.org/x/sys/unix"

func lockAll() error {
	// On GitHub Actions ubuntu runners RLIMIT_MEMLOCK is ~8 MiB. Locking
	// future mappings (MCL_FUTURE) marks every new heap page as VM_LOCKED, so
	// the next 64 MiB argon2id allocation faults and hits the limit, and the
	// Go runtime throws "out of memory: cannot allocate 67108864-byte block".
	// That is worse than not locking. Only use MCL_FUTURE when the limit is
	// large enough to cover argon2id (64 MiB) plus headroom.
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err == nil {
		if lim.Cur != unix.RLIM_INFINITY && lim.Cur < 96*1024*1024 {
			return unix.Mlockall(unix.MCL_CURRENT)
		}
	}
	return mlockall([]int{
		unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT,
		unix.MCL_CURRENT | unix.MCL_FUTURE,
		unix.MCL_CURRENT,
	})
}
