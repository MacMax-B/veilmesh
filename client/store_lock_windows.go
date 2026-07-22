//go:build windows

package client

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockClientStoreFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
}

func unlockClientStoreFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}

func syncClientDirectory(directory string) error {
	// Critical record replacements use MoveFileEx(MOVEFILE_WRITE_THROUGH).
	// Windows exposes no documented directory-fsync primitive; cache/expired
	// record removals are revalidated and may safely be repeated after restart.
	return nil
}
