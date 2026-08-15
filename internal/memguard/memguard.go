// Package memguard collects the memory-hardening primitives used by the
// crypto code: Wipe overwrites key buffers once they are no longer needed,
// and LockAll makes a best-effort attempt to keep the process working set
// out of swap so key material cannot be written to disk by the kernel.
package memguard

import (
	"errors"
	"runtime"
	"sync"
)

// ErrUnsupported reports that the platform has no usable memory-locking
// mechanism reachable from pure Go, so key material cannot be kept out of
// swap. It is not a configuration problem the user can fix.
var ErrUnsupported = errors.New("memguard: memory locking is not supported on this platform")

// Wipe overwrites b with zero bytes in place using a plain loop. It never
// changes the slice length or capacity, and the trailing KeepAlive stops
// the compiler from proving the writes dead and removing them. Only wipe
// buffers the caller owns; never wipe a []byte parameter that was passed
// in by a caller of your function.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

var (
	lockOnce sync.Once
	lockErr  error
)

// LockAll makes a best-effort attempt to lock the process working set into
// physical memory so key material cannot be paged out to swap. Only the
// first call performs any work; later calls return the remembered result.
// If the platform does not support memory locking, or the OS denies the
// request (for example under a low RLIMIT_MEMLOCK), LockAll returns an
// error and the process keeps running unlocked.
func LockAll() error {
	lockOnce.Do(func() {
		lockErr = lockAll()
	})
	return lockErr
}

// Status returns a short human-readable summary of the memory lock state:
// "locked" if LockAll succeeded, otherwise "unlocked: <err>".
func Status() string {
	if err := LockAll(); err != nil {
		return "unlocked: " + err.Error()
	}
	return "locked"
}
