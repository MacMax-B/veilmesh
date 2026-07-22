package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ClientStoreVersion            = 1
	DefaultClientStorageBytes     = int64(10 * 1024 * 1024 * 1024)
	MaxClientStorageBytes         = DefaultClientStorageBytes
	MinClientStorageBytes         = int64(64 * 1024)
	MaxLocalRecordPayloadBytes    = 4 * 1024 * 1024
	MaxClientStoreRecords         = 262_144
	maxLocalRecordFileBytes       = 6 * 1024 * 1024
	localRecordAccountingOverhead = int64(4 * 1024)
	localRecordSuffix             = ".vmc"
	localStoreLockFilename        = ".client-store.lock"
	localRecordDomain             = "veilmesh/client-store/v1\x00"
)

var (
	ErrClientStoreClosed   = errors.New("client store is closed")
	ErrClientStorageFull   = errors.New("client storage limit reached with no safely prunable records")
	ErrLocalRecordNotFound = errors.New("local client record not found")
)

type PrunePolicy string

const (
	// PruneNever protects protocol-critical state until explicitly deleted. An
	// expired record may still be removed because it can no longer be used.
	PruneNever PrunePolicy = "never"
	// PruneOldest makes cache/history data immediately eligible for oldest-first
	// eviction when the configured storage limit is reached.
	PruneOldest PrunePolicy = "oldest"
	// PruneAfterExpiry protects the record until ExpiresAt.
	PruneAfterExpiry PrunePolicy = "after_expiry"
)

const (
	LocalKindDelivery    = "delivery"
	LocalKindInbox       = "inbox"
	LocalKindOutbox      = "outbox"
	LocalKindFileCache   = "file_cache"
	LocalKindReplay      = "replay"
	LocalKindGroupState  = "group_state"
	LocalKindDeviceEvent = "device_event"
	LocalKindReputation  = "reputation"
)

// LocalRecord is encrypted as one authenticated unit. PrunePolicy must be
// explicit: caches and user-selected history use PruneOldest, while pending
// protocol state uses PruneNever or PruneAfterExpiry.
type LocalRecord struct {
	Version     uint8       `json:"version"`
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	ExpiresAt   time.Time   `json:"expires_at,omitempty"`
	PrunePolicy PrunePolicy `json:"prune_policy"`
	Payload     []byte      `json:"payload"`
}

type PruneReport struct {
	Records int   `json:"records"`
	Bytes   int64 `json:"bytes"`
}

type ClientStorageUsage struct {
	UsedBytes  int64 `json:"used_bytes"`
	MaxBytes   int64 `json:"max_bytes"`
	Records    int   `json:"records"`
	MaxRecords int   `json:"max_records"`
}

// ClientStore is the framework-independent persistence boundary used by Core.
// Production key material must be loaded from an OS/hardware-backed SecretVault
// and supplied to the encrypted implementation; it is never written beside the
// database.
type ClientStore interface {
	Put(ctx context.Context, record LocalRecord, now time.Time) (PruneReport, error)
	Get(ctx context.Context, id string) (LocalRecord, error)
	Delete(ctx context.Context, id string) error
	PruneTo(ctx context.Context, targetBytes int64, now time.Time) (PruneReport, error)
	SetLimit(ctx context.Context, maxBytes int64, now time.Time) (PruneReport, error)
	Usage() ClientStorageUsage
	Close() error
}

type DiskClientStoreConfig struct {
	Directory string
	Key       []byte
	MaxBytes  int64
}

type localRecordMeta struct {
	ID          string
	Kind        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	PrunePolicy PrunePolicy
	Path        string
	Charge      int64
}

// EncryptedDiskStore uses AES-256-GCM with a fresh random nonce per atomic
// record write. File names are hashes of record IDs; all record metadata and
// payload bytes are encrypted at rest.
type EncryptedDiskStore struct {
	mu       sync.RWMutex
	dir      string
	key      []byte
	maxBytes int64
	used     int64
	entries  map[string]localRecordMeta
	lockFile *os.File
	closed   bool
}

func NewEncryptedDiskStore(config DiskClientStoreConfig, now time.Time) (*EncryptedDiskStore, error) {
	if config.Directory == "" || len(config.Key) != 32 || now.IsZero() {
		return nil, errors.New("client store requires a directory, AES-256 key, and current time")
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = DefaultClientStorageBytes
	}
	if !validClientStorageLimit(config.MaxBytes) {
		return nil, errors.New("client storage limit is out of range")
	}
	if err := ensurePrivateDirectory(config.Directory); err != nil {
		return nil, err
	}
	lockFile, err := acquireClientStoreLock(config.Directory)
	if err != nil {
		return nil, err
	}
	store := &EncryptedDiskStore{
		dir: config.Directory, key: append([]byte(nil), config.Key...), maxBytes: config.MaxBytes,
		entries: make(map[string]localRecordMeta), lockFile: lockFile,
	}
	directory, err := os.Open(config.Directory) // #nosec G304 -- validated private client-store directory.
	if err != nil {
		store.Close()
		return nil, err
	}
	defer directory.Close()
	removedTemporary := false
	for {
		entries, readErr := directory.ReadDir(256)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			store.Close()
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.Name() == localStoreLockFilename {
				info, infoErr := entry.Info()
				if infoErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
					store.Close()
					return nil, errors.New("client store lock is not a private regular file")
				}
				continue
			}
			if strings.HasPrefix(entry.Name(), ".vmc-private-") {
				path := filepath.Join(config.Directory, entry.Name())
				info, infoErr := entry.Info()
				if infoErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
					store.Close()
					return nil, errors.New("client store contains an invalid temporary record")
				}
				if err := os.Remove(path); err != nil {
					store.Close()
					return nil, err
				}
				removedTemporary = true
				continue
			}
			if !strings.HasSuffix(entry.Name(), localRecordSuffix) {
				store.Close()
				return nil, errors.New("client store directory contains an unmanaged entry")
			}
			if !validLocalRecordFilename(entry.Name()) {
				store.Close()
				return nil, errors.New("client store contains an invalid record filename")
			}
			path := filepath.Join(config.Directory, entry.Name())
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
				info.Size() <= 0 || info.Size() > maxLocalRecordFileBytes {
				store.Close()
				return nil, errors.New("client store contains an invalid private record file")
			}
			record, err := store.readRecord(path, entry.Name())
			if err != nil {
				store.Close()
				return nil, err
			}
			if localRecordFilename(record.ID) != entry.Name() {
				zero(record.Payload)
				store.Close()
				return nil, errors.New("client record ID does not match its authenticated path")
			}
			if _, duplicate := store.entries[record.ID]; duplicate {
				zero(record.Payload)
				store.Close()
				return nil, errors.New("duplicate client record ID")
			}
			charge := localRecordCharge(info.Size())
			store.entries[record.ID] = metaFromRecord(record, path, charge)
			store.used += charge
			zero(record.Payload)
			if store.used > store.maxBytes || len(store.entries) > MaxClientStoreRecords {
				store.mu.Lock()
				_, err = store.pruneToLocked(context.Background(), store.maxBytes, MaxClientStoreRecords, now, "")
				store.mu.Unlock()
				if err != nil {
					store.Close()
					return nil, err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if removedTemporary {
		if err := syncClientDirectory(config.Directory); err != nil {
			store.Close()
			return nil, err
		}
	}
	return store, nil
}

func (store *EncryptedDiskStore) Put(ctx context.Context, record LocalRecord, now time.Time) (PruneReport, error) {
	if ctx == nil {
		return PruneReport{}, errors.New("client store context is required")
	}
	select {
	case <-ctx.Done():
		return PruneReport{}, ctx.Err()
	default:
	}
	record = normalizeLocalRecord(record)
	defer zero(record.Payload)
	if err := validateLocalRecord(record, now); err != nil {
		return PruneReport{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return PruneReport{}, ErrClientStoreClosed
	}
	filename := localRecordFilename(record.ID)
	encoded, err := store.sealRecord(record, filename)
	if err != nil {
		return PruneReport{}, err
	}
	defer zero(encoded)
	newCharge := localRecordCharge(int64(len(encoded)))
	old := store.entries[record.ID]
	targetBeforeWrite := store.maxBytes - newCharge + old.Charge
	if targetBeforeWrite < 0 {
		return PruneReport{}, ErrClientStorageFull
	}
	targetRecords := MaxClientStoreRecords
	if old.ID == "" {
		targetRecords--
	}
	report, err := store.pruneToLocked(ctx, targetBeforeWrite, targetRecords, now, record.ID)
	if err != nil {
		return report, err
	}
	path := filepath.Join(store.dir, filename)
	if err := writeClientPrivateAtomic(path, encoded); err != nil {
		return report, err
	}
	store.used = store.used - old.Charge + newCharge
	store.entries[record.ID] = metaFromRecord(record, path, newCharge)
	return report, nil
}

func (store *EncryptedDiskStore) Get(ctx context.Context, id string) (LocalRecord, error) {
	if ctx == nil || !validLocalRecordID(id) {
		return LocalRecord{}, errors.New("invalid local record lookup")
	}
	select {
	case <-ctx.Done():
		return LocalRecord{}, ctx.Err()
	default:
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return LocalRecord{}, ErrClientStoreClosed
	}
	meta, ok := store.entries[id]
	if !ok {
		return LocalRecord{}, ErrLocalRecordNotFound
	}
	record, err := store.readRecord(meta.Path, filepath.Base(meta.Path))
	if err != nil {
		return LocalRecord{}, err
	}
	return record, nil
}

func (store *EncryptedDiskStore) Delete(ctx context.Context, id string) error {
	if ctx == nil || !validLocalRecordID(id) {
		return errors.New("invalid local record deletion")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return ErrClientStoreClosed
	}
	meta, ok := store.entries[id]
	if !ok {
		return ErrLocalRecordNotFound
	}
	if err := store.deleteMetaLocked(meta); err != nil {
		return err
	}
	return syncClientDirectory(store.dir)
}

func (store *EncryptedDiskStore) PruneTo(ctx context.Context, targetBytes int64, now time.Time) (PruneReport, error) {
	if ctx == nil || targetBytes < 0 || targetBytes > store.maxBytes || now.IsZero() {
		return PruneReport{}, errors.New("invalid client prune target")
	}
	select {
	case <-ctx.Done():
		return PruneReport{}, ctx.Err()
	default:
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return PruneReport{}, ErrClientStoreClosed
	}
	return store.pruneToLocked(ctx, targetBytes, MaxClientStoreRecords, now, "")
}

func (store *EncryptedDiskStore) SetLimit(ctx context.Context, maxBytes int64, now time.Time) (PruneReport, error) {
	if ctx == nil || !validClientStorageLimit(maxBytes) || now.IsZero() {
		return PruneReport{}, errors.New("invalid client storage limit")
	}
	select {
	case <-ctx.Done():
		return PruneReport{}, ctx.Err()
	default:
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return PruneReport{}, ErrClientStoreClosed
	}
	report, err := store.pruneToLocked(ctx, maxBytes, MaxClientStoreRecords, now, "")
	if err != nil {
		return report, err
	}
	store.maxBytes = maxBytes
	return report, nil
}

func (store *EncryptedDiskStore) Usage() ClientStorageUsage {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return ClientStorageUsage{
		UsedBytes: store.used, MaxBytes: store.maxBytes,
		Records: len(store.entries), MaxRecords: MaxClientStoreRecords,
	}
}

func (store *EncryptedDiskStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	zero(store.key)
	store.key = nil
	store.entries = nil
	store.used = 0
	var unlockErr, closeErr error
	if store.lockFile != nil {
		unlockErr = unlockClientStoreFile(store.lockFile)
		closeErr = store.lockFile.Close()
		store.lockFile = nil
	}
	return errors.Join(unlockErr, closeErr)
}

func acquireClientStoreLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, localStoreLockFilename)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("client store lock is not a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed file in validated private store directory.
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	openedInfo, openedErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if openedErr != nil || pathErr != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		file.Close()
		return nil, errors.New("client store lock path changed during open")
	}
	if err := lockClientStoreFile(file); err != nil {
		file.Close()
		return nil, errors.New("client store is already open or cannot be locked")
	}
	return file, nil
}

func (store *EncryptedDiskStore) pruneToLocked(ctx context.Context, targetBytes int64, targetRecords int, now time.Time, excludeID string) (PruneReport, error) {
	if store.used <= targetBytes && len(store.entries) <= targetRecords {
		return PruneReport{}, nil
	}
	candidates := make([]localRecordMeta, 0, len(store.entries))
	for _, meta := range store.entries {
		if meta.ID != excludeID && localRecordPrunable(meta, now) {
			candidates = append(candidates, meta)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftExpired := !candidates[i].ExpiresAt.IsZero() && !candidates[i].ExpiresAt.After(now)
		rightExpired := !candidates[j].ExpiresAt.IsZero() && !candidates[j].ExpiresAt.After(now)
		if leftExpired != rightExpired {
			return leftExpired
		}
		if candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	need := store.used - targetBytes
	if need < 0 {
		need = 0
	}
	recordsToRemove := len(store.entries) - targetRecords
	if recordsToRemove < 0 {
		recordsToRemove = 0
	}
	var available int64
	count := 0
	for count < len(candidates) && (available < need || count < recordsToRemove) {
		available += candidates[count].Charge
		count++
	}
	if available < need || count < recordsToRemove {
		return PruneReport{}, ErrClientStorageFull
	}
	var report PruneReport
	for _, meta := range candidates[:count] {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}
		if err := store.deleteMetaLocked(meta); err != nil {
			return report, err
		}
		report.Records++
		report.Bytes += meta.Charge
	}
	if report.Records > 0 {
		if err := syncClientDirectory(store.dir); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (store *EncryptedDiskStore) deleteMetaLocked(meta localRecordMeta) error {
	if err := os.Remove(meta.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(store.entries, meta.ID)
	store.used -= meta.Charge
	return nil
}

func (store *EncryptedDiskStore) sealRecord(record LocalRecord, filename string) ([]byte, error) {
	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)
	aead, err := clientStoreAEAD(store.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	result := append([]byte("VMCSTOR1"), nonce...)
	result = aead.Seal(result, nonce, plaintext, []byte(localRecordDomain+filename))
	if len(result) > maxLocalRecordFileBytes {
		zero(result)
		return nil, errors.New("encrypted client record exceeds file limit")
	}
	return result, nil
}

func (store *EncryptedDiskStore) readRecord(path, filename string) (LocalRecord, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > maxLocalRecordFileBytes {
		return LocalRecord{}, errors.New("invalid encrypted client record file")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is a validated entry inside the private client-store directory.
	if err != nil {
		return LocalRecord{}, err
	}
	defer zero(data)
	aead, err := clientStoreAEAD(store.key)
	if err != nil {
		return LocalRecord{}, err
	}
	headerBytes := len("VMCSTOR1") + aead.NonceSize()
	if len(data) <= headerBytes || !bytes.Equal(data[:len("VMCSTOR1")], []byte("VMCSTOR1")) {
		return LocalRecord{}, errors.New("invalid encrypted client record header")
	}
	nonce := data[len("VMCSTOR1"):headerBytes]
	plaintext, err := aead.Open(nil, nonce, data[headerBytes:], []byte(localRecordDomain+filename))
	if err != nil {
		return LocalRecord{}, errors.New("client record authentication failed")
	}
	defer zero(plaintext)
	var record LocalRecord
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return LocalRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		zero(record.Payload)
		return LocalRecord{}, errors.New("client record must contain one JSON value")
	}
	if err := validateLocalRecord(record, time.Now().UTC()); err != nil {
		zero(record.Payload)
		return LocalRecord{}, err
	}
	return record, nil
}

func clientStoreAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("client store AES-256 key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func normalizeLocalRecord(record LocalRecord) LocalRecord {
	record.CreatedAt = record.CreatedAt.UTC().Truncate(time.Millisecond)
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	} else {
		record.UpdatedAt = record.UpdatedAt.UTC().Truncate(time.Millisecond)
	}
	if !record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.ExpiresAt.UTC().Truncate(time.Millisecond)
	}
	record.Payload = append([]byte(nil), record.Payload...)
	return record
}

func validateLocalRecord(record LocalRecord, now time.Time) error {
	if record.Version != ClientStoreVersion || !validLocalRecordID(record.ID) || !validLocalRecordKind(record.Kind) ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) ||
		record.CreatedAt.After(now.Add(5*time.Minute)) || record.UpdatedAt.After(now.Add(5*time.Minute)) ||
		len(record.Payload) == 0 || len(record.Payload) > MaxLocalRecordPayloadBytes {
		return errors.New("invalid local client record")
	}
	if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(record.CreatedAt) {
		return errors.New("invalid local client record expiry")
	}
	switch record.PrunePolicy {
	case PruneNever, PruneOldest:
	case PruneAfterExpiry:
		if record.ExpiresAt.IsZero() {
			return errors.New("expiry-prunable record requires an expiry time")
		}
	default:
		return errors.New("invalid local client prune policy")
	}
	if !safePrunePolicyForKind(record) {
		return errors.New("unsafe prune policy for local client record kind")
	}
	return nil
}

func safePrunePolicyForKind(record LocalRecord) bool {
	switch record.Kind {
	case LocalKindDelivery:
		return record.PrunePolicy == PruneAfterExpiry
	case LocalKindOutbox, LocalKindReplay, LocalKindDeviceEvent:
		return record.PrunePolicy == PruneNever || record.PrunePolicy == PruneAfterExpiry
	case LocalKindGroupState:
		return record.PrunePolicy == PruneNever && record.ExpiresAt.IsZero()
	case LocalKindInbox:
		return record.PrunePolicy == PruneNever || record.PrunePolicy == PruneOldest || record.PrunePolicy == PruneAfterExpiry
	case LocalKindFileCache, LocalKindReputation:
		return record.PrunePolicy == PruneOldest
	default:
		return false
	}
}

func validLocalRecordID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, value := range []byte(id) {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
			value == '-' || value == '_' || value == '.' {
			continue
		}
		return false
	}
	return true
}

func validLocalRecordKind(kind string) bool {
	switch kind {
	case LocalKindDelivery, LocalKindInbox, LocalKindOutbox, LocalKindFileCache,
		LocalKindReplay, LocalKindGroupState, LocalKindDeviceEvent, LocalKindReputation:
		return true
	default:
		return false
	}
}

func validClientStorageLimit(value int64) bool {
	return value >= MinClientStorageBytes && value <= MaxClientStorageBytes
}

func localRecordPrunable(meta localRecordMeta, now time.Time) bool {
	if !meta.ExpiresAt.IsZero() && !meta.ExpiresAt.After(now) {
		return true
	}
	return meta.PrunePolicy == PruneOldest
}

func localRecordFilename(id string) string {
	digest := sha256.Sum256([]byte("veilmesh/client-store-path/v1\x00" + id))
	return hex.EncodeToString(digest[:]) + localRecordSuffix
}

func validLocalRecordFilename(filename string) bool {
	if len(filename) != sha256.Size*2+len(localRecordSuffix) || !strings.HasSuffix(filename, localRecordSuffix) {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimSuffix(filename, localRecordSuffix))
	return err == nil && len(digest) == sha256.Size
}

func localRecordCharge(fileBytes int64) int64 { return fileBytes + localRecordAccountingOverhead }

func metaFromRecord(record LocalRecord, path string, charge int64) localRecordMeta {
	return localRecordMeta{
		ID: record.ID, Kind: record.Kind, CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt,
		PrunePolicy: record.PrunePolicy, Path: path, Charge: charge,
	}
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("client store directory must be a private real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return errors.New("client store directory permissions could not be restricted")
		}
	}
	return nil
}

func writeClientPrivateAtomic(path string, data []byte) (returnErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vmc-private-*")
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
	return syncClientDirectory(directory)
}

func syncClientDirectory(directory string) error {
	handle, err := os.Open(directory) // #nosec G304 -- validated private store directory, opened only for fsync.
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
