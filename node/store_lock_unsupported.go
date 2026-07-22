//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package node

import (
	"errors"
	"os"
)

func lockNodeStoreFile(*os.File) error {
	return errors.New("node store locking is unsupported on this platform")
}

func unlockNodeStoreFile(*os.File) error { return nil }

func lockNodeKeyFile(*os.File) error {
	return errors.New("node signing key locking is unsupported on this platform")
}

func tryLockNodeKeyFile(*os.File) error {
	return errors.New("node signing key locking is unsupported on this platform")
}

func unlockNodeKeyFile(*os.File) error { return nil }

func syncPrivateDirectory(string) error {
	return errors.New("node private-directory synchronization is unsupported on this platform")
}
