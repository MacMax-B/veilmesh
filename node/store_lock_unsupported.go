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
