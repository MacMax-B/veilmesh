//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package client

import (
	"errors"
	"os"
)

func lockClientStoreFile(*os.File) error {
	return errors.New("encrypted client store locking is unsupported on this platform")
}

func unlockClientStoreFile(*os.File) error { return nil }

func syncClientDirectory(string) error {
	return errors.New("encrypted client-store directory synchronization is unsupported on this platform")
}
