//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package privatefs

import (
	"errors"
	"os"
	"syscall"
)

type Kind uint8

const (
	RegularFile Kind = iota + 1
	Directory
)

// Restrict applies the platform's private owner-only permissions.
func Restrict(path string, kind Kind) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := validateTypeAndOwner(before, kind); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if kind == Directory {
		mode = 0o700
	} else if kind != RegularFile {
		return errors.New("invalid private filesystem object kind")
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, info) {
		return errors.New("private filesystem path changed while restricting permissions")
	}
	return Validate(path, info, kind)
}

// Validate checks type, symlink status, and absence of group/world access.
func Validate(_ string, info os.FileInfo, kind Kind) error {
	if err := validateTypeAndOwner(info, kind); err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private filesystem permissions are not owner-only")
	}
	return nil
}

func validateTypeAndOwner(info os.FileInfo, kind Kind) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private filesystem object is missing or a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) { // #nosec G115 -- Unix effective UIDs are represented as uint32 by Stat_t.
		return errors.New("private filesystem object is not owned by the effective user")
	}
	switch kind {
	case RegularFile:
		if !info.Mode().IsRegular() {
			return errors.New("private filesystem object is not a regular file")
		}
	case Directory:
		if !info.IsDir() {
			return errors.New("private filesystem object is not a directory")
		}
	default:
		return errors.New("invalid private filesystem object kind")
	}
	return nil
}

// ValidateKeyParent permits traversal/read access but never group/world writes;
// the key file itself is still owner-only. This supports conventional 0755
// service configuration parents without allowing another user to replace it.
func ValidateKeyParent(_ string, info os.FileInfo) error {
	if err := validateTypeAndOwner(info, Directory); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("private key parent is writable by another principal")
	}
	return nil
}

func Replace(source, target string) error {
	return os.Rename(source, target)
}

// PublishNoReplace uses a same-filesystem hard link for atomic no-clobber
// publication. The caller still owns and must unlink source after success.
func PublishNoReplace(source, target string) (bool, error) {
	return false, os.Link(source, target)
}
