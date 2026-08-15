//go:build linux || darwin || freebsd

package memguard

import "golang.org/x/sys/unix"

// mlockall tries each flag combination in order and returns the first
// success; if every attempt fails it returns the error from the last one.
func mlockall(attempts []int) error {
	var err error
	for _, flags := range attempts {
		if err = unix.Mlockall(flags); err == nil {
			return nil
		}
	}
	return err
}
