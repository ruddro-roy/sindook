//go:build darwin

package memguard

import (
	"errors"

	"golang.org/x/sys/unix"
)

// macOS implements mlockall in libSystem (10.12+), but the raw syscall is
// not reachable through the Go runtime's syscall path, so pure-Go binaries
// observe ENOSYS. Report it as unsupported rather than as a fixable
// configuration problem.
func lockAll() error {
	err := mlockall([]int{
		unix.MCL_CURRENT | unix.MCL_FUTURE,
		unix.MCL_FUTURE,
	})
	if errors.Is(err, unix.ENOSYS) {
		return ErrUnsupported
	}
	return err
}
