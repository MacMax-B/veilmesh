//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package node

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockNodeStoreFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func unlockNodeStoreFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func lockNodeKeyFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func tryLockNodeKeyFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func unlockNodeKeyFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN) // #nosec G115 -- kernel file descriptors fit the platform int ABI.
}

func syncPrivateDirectory(directory string) error {
	handle, err := os.Open(directory) // #nosec G304 -- validated private directory, opened only for fsync.
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
