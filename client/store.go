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

	"github.com/MacMax-B/propagare/internal/privatefs"
)

const (
	ClientStoreVersion            = 1
	DefaultClientStorageBytes     = int64(10 * 1024 * 1024 * 1024)
	MaxClientStorageBytes         = DefaultClientStorageBytes
	MinClientStorageBytes         = int64(64 * 1024)
	MaxLocalRecordPayloadBytes    = 4 * 1024 * 1024
	MaxClientStoreRecords         = 262_144
	MaxClientStoreListPage        = 1024
	maxLocalRecordFileBytes       = 6 * 1024 * 1024
	maxAbandonedClientTemporaries = 1024
	maxClientLockFileBytes        = 4 * 1024
	localRecordAccountingOverhead = int64(4 * 1024)
	localRecordSuffix             = ".vmc"
	localStoreLockFilename        = ".client-store.lock"
	localRecordDomain             = "enig/client-store/v1\x00"
)

var (
	ErrClientStoreClosed   = errors.New("client store is closed")
	ErrClientStorageFull   = errors.New("client storage limit reached with no safely prunable records")
	ErrLocalRecordExists   = errors.New("local client record already exists")
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
// Put must not return success until the record is durably committed: Core uses
// that return as the barrier before an external storage side effect. ListIDs
// must return at most limit IDs, strictly increasing and unique, all greater
// than afterID and belonging to kind. Core revalidates these requirements so a
// custom implementation fails closed. Production key material must be loaded
// from an OS/hardware-backed SecretVault and supplied to the encrypted
// implementation; it is never written beside the database.
type ClientStore interface {
	Put(ctx context.Context, record LocalRecord, now time.Time) (PruneReport, error)
	Get(ctx context.Context, id string) (LocalRecord, error)
	ListIDs(ctx context.Context, kind, afterID string, limit int) ([]string, error)
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
	mu                   sync.RWMutex
	dir                  string
	key                  []byte
	maxBytes             int64
	used                 int64
	entries              map[string]localRecordMeta
	lockFile             *os.File
	directorySyncPending bool
	syncDirectory        func(string) error
	closed               bool
}

type committedClientWriteError struct{ cause error }

func (err *committedClientWriteError) Error() string {
	return "client record committed but durability sync failed"
}
func (err *committedClientWriteError) Unwrap() error { return err.cause }

func clientWriteCommitted(err error) bool {
	var committed *committedClientWriteError
	return errors.As(err, &committed)
}

func NewEncryptedDiskStore(config DiskClientStoreConfig, now time.Time) (*EncryptedDiskStore, error) {
	return newEncryptedDiskStore(config, now, syncClientDirectory)
}

func newEncryptedDiskStore(config DiskClientStoreConfig, now time.Time, syncDirectory func(string) error) (*EncryptedDiskStore, error) {
	if config.Directory == "" || len(config.Key) != 32 || now.IsZero() {
		return nil, errors.New("client store requires a directory, AES-256 key, and current time")
	}
	if syncDirectory == nil {
		return nil, errors.New("client directory synchronization is unavailable")
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
	resolvedDirectory, err := filepath.EvalSymlinks(config.Directory)
	if err != nil {
		return nil, errors.New("client store directory could not be canonicalized")
	}
	resolvedDirectory, err = filepath.Abs(resolvedDirectory)
	if err != nil {
		return nil, errors.New("client store directory could not be canonicalized")
	}
	config.Directory = filepath.Clean(resolvedDirectory)
	if err := ensurePrivateDirectory(config.Directory); err != nil {
		return nil, err
	}
	lockFile, err := acquireClientStoreLock(config.Directory)
	if err != nil {
		return nil, err
	}
	store := &EncryptedDiskStore{
		dir: config.Directory, key: append([]byte(nil), config.Key...), maxBytes: config.MaxBytes,
		entries: make(map[string]localRecordMeta), lockFile: lockFile, syncDirectory: syncDirectory,
	}
	directory, err := os.Open(config.Directory) // #nosec G304 -- validated private client-store directory.
	if err != nil {
		store.Close()
		return nil, err
	}
	defer directory.Close()
	temporaryPaths := make([]string, 0)
	for {
		entries, readErr := directory.ReadDir(256)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			store.Close()
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.Name() == localStoreLockFilename {
				path := filepath.Join(config.Directory, entry.Name())
				info, infoErr := entry.Info()
				if infoErr != nil || info.Size() < 0 || info.Size() > maxClientLockFileBytes ||
					privatefs.Validate(path, info, privatefs.RegularFile) != nil {
					store.Close()
					return nil, errors.New("client store lock is not a private regular file")
				}
				continue
			}
			if strings.HasPrefix(entry.Name(), ".vmc-private-") {
				path := filepath.Join(config.Directory, entry.Name())
				info, infoErr := entry.Info()
				if infoErr != nil || info.Size() < 0 || info.Size() > maxLocalRecordFileBytes ||
					privatefs.Validate(path, info, privatefs.RegularFile) != nil {
					store.Close()
					return nil, errors.New("client store contains an invalid temporary record")
				}
				if len(temporaryPaths) >= maxAbandonedClientTemporaries {
					store.Close()
					return nil, errors.New("client store contains too many abandoned temporary records")
				}
				temporaryPaths = append(temporaryPaths, path)
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
			if err != nil || !validClientRecordFile(path, info) {
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
			if len(store.entries) >= MaxClientStoreRecords {
				zero(record.Payload)
				store.Close()
				return nil, errors.New("client store record limit exceeded during startup")
			}
			charge := localRecordCharge(info.Size())
			store.entries[record.ID] = metaFromRecord(record, path, charge)
			store.used += charge
			zero(record.Payload)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	// Validate the complete directory before deleting any managed record. A
	// later malformed/unmanaged entry must never make a failed open partially
	// prune otherwise valid client state.
	if store.used > store.maxBytes {
		store.mu.Lock()
		_, err = store.pruneToLocked(context.Background(), store.maxBytes, MaxClientStoreRecords, now, "")
		store.mu.Unlock()
		if err != nil {
			store.Close()
			return nil, err
		}
	}
	for _, path := range temporaryPaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			store.Close()
			return nil, err
		}
	}
	// Always synchronize after a complete authenticated startup scan. This
	// also recovers the durability of a record that was visibly renamed before
	// a previous process lost its directory-fsync result.
	if err := store.syncDirectory(config.Directory); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func (store *EncryptedDiskStore) Put(ctx context.Context, record LocalRecord, now time.Time) (PruneReport, error) {
	return store.put(ctx, record, now, false)
}

// putIfAbsent persists one authenticated record only when its ID has never
// been accepted by this store. The existence test, capacity reservation,
// atomic file publication, and in-memory index commit share the store lock.
// It is intentionally unexported; protocol adapters expose narrower semantics.
func (store *EncryptedDiskStore) putIfAbsent(ctx context.Context, record LocalRecord, now time.Time) (PruneReport, error) {
	return store.put(ctx, record, now, true)
}

func (store *EncryptedDiskStore) put(ctx context.Context, record LocalRecord, now time.Time, onlyIfAbsent bool) (PruneReport, error) {
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
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return PruneReport{}, err
	}
	old := store.entries[record.ID]
	if onlyIfAbsent && old.ID != "" {
		return PruneReport{}, ErrLocalRecordExists
	}
	filename := localRecordFilename(record.ID)
	encoded, err := store.sealRecord(record, filename)
	if err != nil {
		return PruneReport{}, err
	}
	defer zero(encoded)
	newCharge := localRecordCharge(int64(len(encoded)))
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
	writeErr := writeClientPrivateAtomicWithSync(path, encoded, store.syncDirectory)
	if writeErr != nil && !clientWriteCommitted(writeErr) {
		return report, writeErr
	}
	store.used = store.used - old.Charge + newCharge
	store.entries[record.ID] = metaFromRecord(record, path, newCharge)
	store.noteDirectoryWriteResultLocked(writeErr)
	return report, writeErr
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
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return LocalRecord{}, ErrClientStoreClosed
	}
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return LocalRecord{}, err
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

// ListIDs provides bounded, stable pagination without decrypting every record.
// Metadata used for this index exists only in memory after authenticated store
// startup; record filenames remain hashed on disk.
func (store *EncryptedDiskStore) ListIDs(ctx context.Context, kind, afterID string, limit int) ([]string, error) {
	if ctx == nil || !validLocalRecordKind(kind) ||
		(afterID != "" && !validLocalRecordID(afterID)) || limit <= 0 || limit > MaxClientStoreListPage {
		return nil, errors.New("invalid local record listing")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil, ErrClientStoreClosed
	}
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, min(limit, len(store.entries)))
	for id, meta := range store.entries {
		if meta.Kind == kind && (afterID == "" || id > afterID) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids, nil
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
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return err
	}
	meta, ok := store.entries[id]
	if !ok {
		return ErrLocalRecordNotFound
	}
	if err := store.deleteMetaLocked(meta); err != nil {
		return err
	}
	err := store.syncDirectory(store.dir)
	store.noteDirectoryWriteResultLocked(err)
	return err
}

func (store *EncryptedDiskStore) PruneTo(ctx context.Context, targetBytes int64, now time.Time) (PruneReport, error) {
	if ctx == nil || targetBytes < 0 || targetBytes > MaxClientStorageBytes || now.IsZero() {
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
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return PruneReport{}, err
	}
	if targetBytes > store.maxBytes {
		return PruneReport{}, errors.New("invalid client prune target")
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
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return PruneReport{}, err
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
	syncErr := store.ensureDirectoryDurableLocked()
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
	return errors.Join(syncErr, unlockErr, closeErr)
}

func acquireClientStoreLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, localStoreLockFilename)
	created := false
	if info, err := os.Lstat(path); err == nil {
		if info.Size() < 0 || info.Size() > maxClientLockFileBytes ||
			privatefs.Validate(path, info, privatefs.RegularFile) != nil {
			return nil, errors.New("client store lock is not a private regular file")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed file in validated private store directory.
	if err != nil {
		return nil, err
	}
	if created {
		if err := privatefs.Restrict(path, privatefs.RegularFile); err != nil {
			file.Close()
			return nil, err
		}
	}
	if err := privatefs.Validate(path, mustFileInfo(file), privatefs.RegularFile); err != nil {
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
	if err := store.ensureDirectoryDurableLocked(); err != nil {
		return PruneReport{}, err
	}
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
		if err := store.syncDirectory(store.dir); err != nil {
			store.noteDirectoryWriteResultLocked(err)
			return report, err
		}
		store.noteDirectoryWriteResultLocked(nil)
	}
	return report, nil
}

func (store *EncryptedDiskStore) deleteMetaLocked(meta localRecordMeta) error {
	if err := os.Remove(meta.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Mark the directory degraded immediately after each successful namespace
	// mutation. A later cancellation or removal failure in a multi-record prune
	// must not bypass the durability barrier at the end of the batch.
	store.directorySyncPending = true
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
	pathInfo, err := os.Lstat(path)
	if err != nil || !validClientRecordFile(path, pathInfo) {
		return LocalRecord{}, errors.New("invalid encrypted client record file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0) // #nosec G304 -- bounded entry inside the validated private store directory.
	if err != nil {
		return LocalRecord{}, err
	}
	defer file.Close()
	openedInfo, openedErr := file.Stat()
	currentInfo, currentErr := os.Lstat(path)
	if openedErr != nil || currentErr != nil || !validClientRecordFileBasic(openedInfo) ||
		!validClientRecordFile(path, currentInfo) || !os.SameFile(openedInfo, currentInfo) {
		return LocalRecord{}, errors.New("encrypted client record path changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLocalRecordFileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxLocalRecordFileBytes {
		return LocalRecord{}, errors.New("invalid encrypted client record file")
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

func validClientRecordFile(path string, info os.FileInfo) bool {
	return validClientRecordFileBasic(info) && privatefs.Validate(path, info, privatefs.RegularFile) == nil
}

func validClientRecordFileBasic(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maxLocalRecordFileBytes
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
	digest := sha256.Sum256([]byte("enig/client-store-path/v1\x00" + id))
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
	_, initialErr := os.Lstat(path)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("client store directory must be a private real directory")
	}
	if errors.Is(initialErr, os.ErrNotExist) || privateDirectoryIsEmpty(path) {
		if err := privatefs.Restrict(path, privatefs.Directory); err != nil {
			return errors.New("client store directory permissions could not be restricted")
		}
	} else if err := privatefs.Validate(path, info, privatefs.Directory); err != nil {
		return errors.New("client store directory permissions are not private")
	}
	return nil
}

func privateDirectoryIsEmpty(path string) bool {
	handle, err := os.Open(path) // #nosec G304 -- candidate store directory, read only for one entry.
	if err != nil {
		return false
	}
	defer handle.Close()
	entries, err := handle.ReadDir(1)
	return (err == nil || errors.Is(err, io.EOF)) && len(entries) == 0
}

func writeClientPrivateAtomic(path string, data []byte) (returnErr error) {
	return writeClientPrivateAtomicWithSync(path, data, syncClientDirectory)
}

func writeClientPrivateAtomicWithSync(path string, data []byte, syncDirectory func(string) error) (returnErr error) {
	if syncDirectory == nil {
		return errors.New("client directory synchronization is unavailable")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vmc-private-*")
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
		return &committedClientWriteError{cause: err}
	}
	return nil
}

func (store *EncryptedDiskStore) noteDirectoryWriteResultLocked(err error) {
	store.directorySyncPending = err != nil
}

func (store *EncryptedDiskStore) ensureDirectoryDurableLocked() error {
	if !store.directorySyncPending {
		return nil
	}
	if err := store.syncDirectory(store.dir); err != nil {
		return err
	}
	store.directorySyncPending = false
	return nil
}

func mustFileInfo(file *os.File) os.FileInfo {
	info, _ := file.Stat()
	return info
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
