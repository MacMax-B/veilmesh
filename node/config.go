package node

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MacMax-B/propagare/protocol"
)

type Config struct {
	ListenAddress         string
	DataDir               string
	KeyFile               string
	BaseDifficulty        uint8
	EpochSeconds          int64
	MaxItemBytes          int
	StorageCapacity       int64
	MailboxQuota          int64
	MaxFetchItems         int
	MaxFetchBytes         int64
	SweepInterval         time.Duration
	MaxConcurrentRequests int
}

func DefaultConfig() Config {
	return Config{
		ListenAddress:         "127.0.0.1:8787",
		DataDir:               "./propagare-data",
		KeyFile:               "./propagare-secrets/node-key.json",
		BaseDifficulty:        16,
		EpochSeconds:          10 * 60,
		MaxItemBytes:          protocol.DefaultMaxItemBytes,
		StorageCapacity:       10 * 1024 * 1024 * 1024,
		MailboxQuota:          16 * 1024 * 1024,
		MaxFetchItems:         protocol.DefaultMaxFetchItems,
		MaxFetchBytes:         protocol.DefaultMaxFetchBytes,
		SweepInterval:         5 * time.Minute,
		MaxConcurrentRequests: 128,
	}
}

func (c Config) Validate() error {
	if c.BaseDifficulty > protocol.MaxWorkDifficulty-2 ||
		c.EpochSeconds < protocol.MinWorkEpochSeconds || c.EpochSeconds > protocol.MaxWorkEpochSeconds ||
		c.MaxItemBytes <= 0 || c.MaxItemBytes > protocol.DefaultMaxItemBytes ||
		c.StorageCapacity <= 0 || c.MailboxQuota <= 0 || c.MailboxQuota > c.StorageCapacity ||
		c.MaxFetchItems <= 0 || c.MaxFetchItems > protocol.DefaultMaxFetchItems ||
		c.MaxFetchBytes <= 0 || c.MaxFetchBytes > protocol.DefaultMaxFetchBytes ||
		c.SweepInterval <= 0 || c.MaxConcurrentRequests <= 0 || c.MaxConcurrentRequests > 4096 {
		return errors.New("invalid node configuration bounds")
	}
	dataDir, err := canonicalConfiguredPath(c.DataDir)
	if err != nil {
		return errors.New("invalid node data directory path")
	}
	keyFile, err := canonicalConfiguredPath(c.KeyFile)
	if err != nil {
		return errors.New("invalid node signing key path")
	}
	if pathsOverlap(dataDir, keyFile) {
		return errors.New("node data directory and signing key path must not overlap")
	}
	return nil
}

// canonicalConfiguredPath resolves every existing path prefix, then appends
// any not-yet-created suffix. This catches both lexical overlap and overlap
// hidden behind an existing symlink without requiring startup paths to exist.
func canonicalConfiguredPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty path")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	current := absolute
	var suffix []string
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return "", resolveErr
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", statErr
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// ValidateServerTransport prevents accidental public cleartext operation. Plain
// HTTP is permitted by default only on loopback and, with an explicit
// development switch, on literal private addresses. Unspecified/wildcard and
// public listeners always require TLS.
func ValidateServerTransport(listenAddress string, tlsEnabled, allowPrivateHTTP bool) error {
	if tlsEnabled {
		return nil
	}
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return errors.New("invalid node listen address")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return errors.New("plain HTTP requires a literal loopback or private listen address")
	}
	address = address.Unmap()
	if address.IsLoopback() || allowPrivateHTTP && address.IsPrivate() {
		return nil
	}
	return errors.New("TLS is required for non-loopback node listeners")
}

func (c Config) EffectiveDifficulty(used int64) uint8 {
	if c.StorageCapacity <= 0 {
		return c.BaseDifficulty
	}
	ratio := float64(used) / float64(c.StorageCapacity)
	switch {
	case ratio >= 0.95:
		return min(c.BaseDifficulty+2, uint8(protocol.MaxWorkDifficulty))
	case ratio >= 0.80:
		return min(c.BaseDifficulty+1, uint8(protocol.MaxWorkDifficulty))
	default:
		return c.BaseDifficulty
	}
}
