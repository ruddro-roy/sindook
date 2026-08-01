//go:build unix

package filelock

import (
	"os"
	"sync"
	"syscall"
)

type unixLock struct {
	f    *os.File
	once sync.Once
	err  error
}

func (l *unixLock) Release() error {
	l.once.Do(func() {
		l.err = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	})
	return l.err
}

func tryLock(f *os.File) (Unlocker, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return &unixLock{f: f}, nil
	case err == syscall.EWOULDBLOCK || err == syscall.EAGAIN:
		return nil, ErrLocked
	// Some filesystems, notably older network mounts, reject flock outright.
	// Report that honestly rather than pretending the file is locked.
	case err == syscall.ENOTSUP || err == syscall.EOPNOTSUPP || err == syscall.EINVAL:
		return nil, ErrUnsupported
	default:
		return nil, err
	}
}
