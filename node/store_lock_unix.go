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
