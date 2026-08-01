//go:build !unix && !windows

package filelock

import "os"

func tryLock(*os.File) (Unlocker, error) { return nil, ErrUnsupported }
