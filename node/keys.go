package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"propagare/pqcrypto"
)

func LoadOrCreateSigner(path string) (*pqcrypto.HybridSigner, error) {
	if path == "" || strings.HasPrefix(filepath.Base(path), ".propagare-private-") {
		return nil, errors.New("invalid node signing key path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	if err := cleanupPrivateTemporaries(filepath.Dir(path), filepath.Base(path)); err != nil {
		return nil, err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 64*1024 {
			return nil, errors.New("node signing key file is not a private regular file")
		}
	}
	// The key path is an explicit operator configuration value. Lstat above
	// rejects symlinks, non-regular files, broad permissions, and oversized data.
	data, err := os.ReadFile(path) // #nosec G304 -- intentional operator-selected private key path.
	if err == nil {
		var material pqcrypto.PrivateSigningMaterial
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&material); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, errors.New("node signing key must contain one JSON value")
		}
		return pqcrypto.NewHybridSigner(material)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(signer.PrivateMaterial())
	if err != nil {
		return nil, err
	}
	if err := writePrivateAtomic(path, encoded); err != nil {
		return nil, err
	}
	return signer, nil
}

func cleanupPrivateTemporaries(directory, targetBase string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	prefix := ".propagare-private-"
	if targetBase != "" {
		prefix += targetBase + "-"
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("invalid abandoned private temporary file")
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncPrivateDirectory(directory)
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".propagare-private-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncPrivateDirectory(directory)
}

func syncPrivateDirectory(directory string) error {
	directoryHandle, err := os.Open(directory) // #nosec G304 -- parent of the explicit operator/store path, opened only for fsync.
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
