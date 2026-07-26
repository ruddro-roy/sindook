//go:build windows

package filelock

import (
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

type windowsLock struct {
	f    *os.File
	once sync.Once
	err  error
}

// lockRange covers the whole address space so the lock is on the file rather
// than on any region of it.
const lockLow, lockHigh uint32 = ^uint32(0), ^uint32(0)

func (l *windowsLock) Release() error {
	l.once.Do(func() {
		l.err = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, lockLow, lockHigh, new(windows.Overlapped))
	})
	return l.err
}

func tryLock(f *os.File) (Unlocker, error) {
	const flags = windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, lockLow, lockHigh, new(windows.Overlapped))
	switch err {
	case nil:
		return &windowsLock{f: f}, nil
	case windows.ERROR_LOCK_VIOLATION, windows.ERROR_IO_PENDING:
		return nil, ErrLocked
	default:
		return nil, err
	}
}
