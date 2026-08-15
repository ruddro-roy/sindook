//go:build windows

package memguard

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lockAll walks the process address space with VirtualQuery and locks every
// committed region into the working set with VirtualLock. A region that
// fails to lock is recorded and the walk continues; any failure is reported
// once the whole address space has been covered.
func lockAll() error {
	var mbi windows.MemoryBasicInformation
	var errs []error
	locked := 0
	for addr := uintptr(0); ; {
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT {
			if err := windows.VirtualLock(mbi.BaseAddress, mbi.RegionSize); err != nil {
				errs = append(errs, err)
			} else {
				locked++
			}
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	if len(errs) > 0 {
		return errors.Join(append([]error{errors.New("memguard: failed to lock process memory")}, errs...)...)
	}
	if locked == 0 {
		return errors.New("memguard: no committed memory regions found")
	}
	return nil
}
