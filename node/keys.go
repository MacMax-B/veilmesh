package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/MacMax-B/propagare/internal/privatefs"
	"github.com/MacMax-B/propagare/pqcrypto"
)

const (
	maxNodeSigningKeyBytes = 64 * 1024
	maxNodeLockFileBytes   = 4 * 1024
)

var ErrNodeSigningKeyMissing = errors.New("node signing key is missing")

type committedPrivateWriteError struct{ cause error }

func (err *committedPrivateWriteError) Error() string {
	return "private record committed but durability sync failed"
}
func (err *committedPrivateWriteError) Unwrap() error { return err.cause }

func privateWriteCommitted(err error) bool {
	var committed *committedPrivateWriteError
	return errors.As(err, &committed)
}

// NodeSignerLease keeps exclusive ownership of a node identity for the whole
// server lifetime. Closing it allows a later process to acquire the identity.
type NodeSignerLease struct {
	Signer  *pqcrypto.HybridSigner
	Created bool
	file    *os.File
	once    sync.Once
	err     error
}

func (lease *NodeSignerLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		if lease.file != nil {
			lease.err = errors.Join(unlockNodeKeyFile(lease.file), lease.file.Close())
			lease.file = nil
		}
	})
	return lease.err
}

// LoadOrCreateSigner is a one-shot provisioning helper. A running node must
// use AcquireNodeSigner so the identity cannot be active in two processes.
func LoadOrCreateSigner(path string) (*pqcrypto.HybridSigner, error) {
	path, directory, err := prepareNodeKeyPath(path)
	if err != nil {
		return nil, err
	}
	lockFile, err := acquireNodeKeyLock(directory, filepath.Base(path), false)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = unlockNodeKeyFile(lockFile)
		_ = lockFile.Close()
	}()
	signer, _, err := loadOrCreateSignerLocked(path, directory, true)
	return signer, err
}

// AcquireNodeSigner loads a node signer under a nonblocking lifetime lease.
// When allowCreate is false, a missing key fails closed instead of silently
// changing an identity already bound to retained node data.
func AcquireNodeSigner(path string, allowCreate bool) (*NodeSignerLease, error) {
	path, directory, err := prepareNodeKeyPath(path)
	if err != nil {
		return nil, err
	}
	lockFile, err := acquireNodeKeyLock(directory, filepath.Base(path), true)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*NodeSignerLease, error) {
		_ = unlockNodeKeyFile(lockFile)
		_ = lockFile.Close()
		return nil, cause
	}
	signer, created, err := loadOrCreateSignerLocked(path, directory, allowCreate)
	if err != nil {
		return fail(err)
	}
	return &NodeSignerLease{Signer: signer, Created: created, file: lockFile}, nil
}

func prepareNodeKeyPath(path string) (string, string, error) {
	if path == "" || strings.HasPrefix(filepath.Base(path), ".propagare-private-") {
		return "", "", errors.New("invalid node signing key path")
	}
	directory := filepath.Dir(path)
	if err := ensurePrivateKeyDirectory(directory); err != nil {
		return "", "", err
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", "", errors.New("node signing key parent could not be resolved")
	}
	directory, err = filepath.Abs(resolvedDirectory)
	if err != nil {
		return "", "", errors.New("node signing key parent could not be resolved")
	}
	path = filepath.Join(directory, filepath.Base(path))
	if err := ensurePrivateKeyDirectory(directory); err != nil {
		return "", "", err
	}
	return path, directory, nil
}

func loadOrCreateSignerLocked(path, directory string, allowCreate bool) (*pqcrypto.HybridSigner, bool, error) {
	if err := cleanupPrivateTemporaries(directory, filepath.Base(path)); err != nil {
		return nil, false, err
	}
	loaded, exists, err := loadNodeSigner(path)
	if err != nil {
		return nil, false, err
	}
	if exists {
		if err := syncPrivateDirectory(directory); err != nil {
			return nil, false, err
		}
		return loaded, false, nil
	}
	if !allowCreate {
		return nil, false, ErrNodeSigningKeyMissing
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		return nil, false, err
	}
	material := signer.PrivateMaterial()
	defer wipeSigningMaterial(&material)
	encoded, err := json.Marshal(material)
	if err != nil {
		return nil, false, err
	}
	defer wipeBytes(encoded)
	if err := writePrivateAtomicNoReplace(path, encoded); err != nil {
		if errors.Is(err, os.ErrExist) {
			winner, winnerExists, loadErr := loadNodeSigner(path)
			if loadErr != nil {
				return nil, false, loadErr
			}
			if winnerExists {
				if syncErr := syncPrivateDirectory(directory); syncErr != nil {
					return nil, false, syncErr
				}
				return winner, false, nil
			}
		}
		return nil, false, err
	}
	return signer, true, nil
}

func ensurePrivateKeyDirectory(directory string) error {
	_, initialErr := os.Lstat(directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("node signing key parent must be a real directory")
	}
	if errors.Is(initialErr, os.ErrNotExist) || privateNodeDirectoryIsEmpty(directory) {
		if err := privatefs.Restrict(directory, privatefs.Directory); err != nil {
			return errors.New("node signing key parent permissions could not be restricted")
		}
	} else if err := privatefs.ValidateKeyParent(directory, info); err != nil {
		return errors.New("node signing key parent must not be writable by untrusted principals")
	}
	return nil
}

func privateNodeDirectoryIsEmpty(directory string) bool {
	handle, err := os.Open(directory) // #nosec G304 -- operator-selected key parent, read only for one entry.
	if err != nil {
		return false
	}
	defer handle.Close()
	entries, err := handle.ReadDir(1)
	return (err == nil || errors.Is(err, io.EOF)) && len(entries) == 0
}

func acquireNodeKeyLock(directory, targetBase string, lifetimeLease bool) (*os.File, error) {
	lockPath := filepath.Join(directory, ".propagare-key-"+targetBase+".lock")
	created := false
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Size() < 0 || info.Size() > maxNodeLockFileBytes ||
			privatefs.Validate(lockPath, info, privatefs.RegularFile) != nil {
			return nil, errors.New("node signing key lock is not a private regular file")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- scoped to the validated key parent.
	if err != nil {
		return nil, err
	}
	if created {
		if err := privatefs.Restrict(lockPath, privatefs.RegularFile); err != nil {
			file.Close()
			return nil, err
		}
	}
	openedInfo, openedErr := file.Stat()
	pathInfo, pathErr := os.Lstat(lockPath)
	if openedErr != nil || pathErr != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		file.Close()
		return nil, errors.New("node signing key lock path changed during open")
	}
	lock := lockNodeKeyFile
	if lifetimeLease {
		lock = tryLockNodeKeyFile
	}
	if err := lock(file); err != nil {
		file.Close()
		return nil, errors.New("node signing key lock could not be acquired")
	}
	return file, nil
}

func loadNodeSigner(path string) (*pqcrypto.HybridSigner, bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !validPrivateRegularFile(path, pathInfo, maxNodeSigningKeyBytes) {
		return nil, false, errors.New("node signing key file is not a private regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0) // #nosec G304 -- explicit operator-selected path, verified before and after open.
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	openedInfo, openedErr := file.Stat()
	currentInfo, currentErr := os.Lstat(path)
	if openedErr != nil || currentErr != nil || !validPrivateRegularFileBasic(openedInfo, maxNodeSigningKeyBytes) ||
		!validPrivateRegularFile(path, currentInfo, maxNodeSigningKeyBytes) || !os.SameFile(openedInfo, currentInfo) {
		return nil, false, errors.New("node signing key path changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxNodeSigningKeyBytes+1))
	if err != nil {
		return nil, false, err
	}
	defer wipeBytes(data)
	if len(data) == 0 || len(data) > maxNodeSigningKeyBytes {
		return nil, false, errors.New("node signing key file has invalid size")
	}
	var material pqcrypto.PrivateSigningMaterial
	defer wipeSigningMaterial(&material)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&material); err != nil {
		return nil, false, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, false, errors.New("node signing key must contain one JSON value")
	}
	signer, err := pqcrypto.NewHybridSigner(material)
	if err != nil {
		return nil, false, err
	}
	return signer, true, nil
}

func validPrivateRegularFile(path string, info os.FileInfo, maximum int64) bool {
	return validPrivateRegularFileBasic(info, maximum) && privatefs.Validate(path, info, privatefs.RegularFile) == nil
}

func validPrivateRegularFileBasic(info os.FileInfo, maximum int64) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maximum
}

func wipeSigningMaterial(material *pqcrypto.PrivateSigningMaterial) {
	if material == nil {
		return
	}
	wipeBytes(material.Ed25519Private)
	wipeBytes(material.MLDSA65Private)
	material.Ed25519Private = nil
	material.MLDSA65Private = nil
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func cleanupPrivateTemporaries(directory, targetBase string) error {
	handle, err := os.Open(directory) // #nosec G304 -- validated key parent, scanned in bounded pages.
	if err != nil {
		return err
	}
	defer handle.Close()
	paths := make([]string, 0)
	found := 0
	prefix := ".propagare-private-"
	if targetBase != "" {
		prefix += targetBase + "-"
	}
	for {
		entries, readErr := handle.ReadDir(256)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), prefix) {
				continue
			}
			found++
			if found > maxNodeAbandonedTemporaries {
				return errors.New("too many abandoned private key temporary files")
			}
			info, infoErr := entry.Info()
			path := filepath.Join(directory, entry.Name())
			if infoErr != nil || info.Size() < 0 || info.Size() > maxNodeSigningKeyBytes ||
				privatefs.Validate(path, info, privatefs.RegularFile) != nil {
				return errors.New("invalid abandoned private temporary file")
			}
			paths = append(paths, path)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if len(paths) > 0 {
		return syncPrivateDirectory(directory)
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) (returnErr error) {
	return writePrivateAtomicWithSync(path, data, syncPrivateDirectory)
}

func writePrivateAtomicWithSync(path string, data []byte, syncDirectory func(string) error) (returnErr error) {
	if syncDirectory == nil {
		return errors.New("private directory synchronization is unavailable")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".propagare-private-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	temporaryOwned := true
	defer func() {
		_ = temporary.Close()
		if returnErr != nil && temporaryOwned {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := privatefs.Restrict(temporaryPath, privatefs.RegularFile); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := privatefs.Replace(temporaryPath, path); err != nil {
		return err
	}
	temporaryOwned = false
	if err := syncDirectory(directory); err != nil {
		return &committedPrivateWriteError{cause: err}
	}
	return nil
}

func writePrivateAtomicNoReplace(path string, data []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".propagare-private-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	temporaryOwned := true
	defer func() {
		_ = temporary.Close()
		if temporaryOwned {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := privatefs.Restrict(temporaryPath, privatefs.RegularFile); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Publication is no-clobber on every supported platform. Unix uses a hard
	// link; Windows uses MoveFileEx without REPLACE_EXISTING and with WRITE_THROUGH.
	consumed, err := privatefs.PublishNoReplace(temporaryPath, path)
	if err != nil {
		return err
	}
	if consumed {
		temporaryOwned = false
	} else {
		if err := os.Remove(temporaryPath); err != nil {
			return err
		}
		temporaryOwned = false
	}
	return syncPrivateDirectory(directory)
}
