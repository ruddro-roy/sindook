// Package filelock takes advisory exclusive locks on open files so two
// rotations of the same archive cannot interleave their writes. The lock is
// advisory: it stops other sindook processes, not an unrelated program that
// writes the file directly. That residual case is what the generation
// compare-and-swap in the rotation protocol covers.
package filelock

import (
	"errors"
	"os"
)

// ErrLocked reports that another process holds the lock. Rotation fails
// rather than waiting, so a stuck holder cannot hang a batch run forever.
var ErrLocked = errors.New("sindook: file is locked by another sindook process")

// ErrUnsupported reports a platform with no advisory locking. Callers decide
// whether to refuse the operation or proceed unlocked; sindook refuses by
// default, because a silent unlocked rotation is the failure mode that
// corrupts a header.
var ErrUnsupported = errors.New("sindook: advisory file locking is not supported on this platform")

// Unlocker releases a lock. Release is idempotent.
type Unlocker interface {
	Release() error
}

// TryLock takes an exclusive lock on f without blocking. It returns
// ErrLocked if another process holds it.
func TryLock(f *os.File) (Unlocker, error) { return tryLock(f) }
