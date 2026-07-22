//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package client

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockClientStoreFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func unlockClientStoreFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func syncClientDirectory(directory string) error {
	handle, err := os.Open(directory) // #nosec G304 -- validated private store directory, opened only for fsync.
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
