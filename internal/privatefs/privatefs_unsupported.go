//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package privatefs

import (
	"errors"
	"os"
)

type Kind uint8

const (
	RegularFile Kind = iota + 1
	Directory
)

func Restrict(string, Kind) error {
	return errors.New("private filesystem permissions are unsupported on this platform")
}

func Validate(string, os.FileInfo, Kind) error {
	return errors.New("private filesystem permissions are unsupported on this platform")
}

func ValidateKeyParent(string, os.FileInfo) error {
	return errors.New("private key parent validation is unsupported on this platform")
}

func Replace(string, string) error {
	return errors.New("private atomic replacement is unsupported on this platform")
}

func PublishNoReplace(string, string) (bool, error) {
	return false, errors.New("private no-clobber publication is unsupported on this platform")
}
