//go:build !linux && !darwin && !freebsd && !windows

package memguard

func lockAll() error {
	return ErrUnsupported
}
