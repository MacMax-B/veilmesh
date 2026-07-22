package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MacMax-B/propagare/internal/privatefs"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

var (
	ErrNotFound      = errors.New("item not found")
	ErrMailboxQuota  = errors.New("route-tag quota exceeded")
	ErrStorageFull   = errors.New("node storage capacity exceeded")
	ErrStoreClosed   = errors.New("node store is closed")
	ErrInvalidItemID = errors.New("invalid item id")
	ErrInvalidLimits = errors.New("invalid store limits")
	ErrItemDeleted   = errors.New("item is covered by a delete tombstone")
	ErrCorruptStore  = errors.New("node store contains an invalid or unmanaged record")
	ErrStoreIdentity = errors.New("node store identity does not match the signing key")
	ErrUnboundStore  = errors.New("non-empty node store has no identity binding")
)

const (
	MaxStoredItems              = 1_000_000
	MaxItemsPerRoute            = 1024
	PerItemAccountingOverhead   = 4 * 1024
	MaxStoredItemEncodingBytes  = protocol.DefaultMaxItemBytes*2 + 64*1024
	MaxDeleteTombstoneBytes     = 16 * 1024
	nodeStoreLockFilename       = ".node-store.lock"
	nodeIdentityBindingFile     = ".node-identity.json"
	nodeIdentityBindingType     = "node-identity-binding"
	nodeIdentityBindingVersion  = 1
	nodeIdentityBindingDomain   = "node-store-identity-binding"
	maxIdentityBindingBytes     = 32 * 1024
	deleteTombstoneRecordType   = "delete-tombstone"
	deleteTombstoneVersion      = 1
	maxSweepBatchRecords        = 256
	maxNodeAbandonedTemporaries = 1024
	maxNodeStartupEntries       = MaxStoredItems + maxNodeAbandonedTemporaries + 2
)

type nodeIdentityBindingUnsigned struct {
	RecordType string                      `json:"record_type"`
	Version    uint8                       `json:"version"`
	Identity   protocol.NodePublicIdentity `json:"identity"`
}

type nodeIdentityBinding struct {
	RecordType string                      `json:"record_type"`
	Version    uint8                       `json:"version"`
	Identity   protocol.NodePublicIdentity `json:"identity"`
	Signature  protocol.HybridSignature    `json:"signature"`
}

type deleteTombstone struct {
	RecordType      string    `json:"record_type"`
	Version         uint8     `json:"version"`
	ItemID          string    `json:"item_id"`
	DeleteTokenHash []byte    `json:"delete_token_hash"`
	DeletedAt       time.Time `json:"deleted_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type committedDelete struct {
	ItemID    string
	DeletedAt time.Time
}

type DiskStore struct {
	mu                   sync.RWMutex
	dir                  string
	items                map[string]protocol.StoredItem
	tombstones           map[string]deleteTombstone
	charges              map[string]int64
	byRoute              map[string]map[string]struct{}
	routeUsed            map[string]int64
	used                 int64
	capacity             int64
	routeQuota           int64
	lockFile             *os.File
	binding              *nodeIdentityBinding
	directorySyncPending bool
	syncDirectory        func(string) error
	closed               bool
}

func NewDiskStore(dir string, capacity, routeQuota int64) (*DiskStore, error) {
	return newDiskStore(dir, capacity, routeQuota, syncPrivateDirectory)
}

func newDiskStore(dir string, capacity, routeQuota int64, syncDirectory func(string) error) (*DiskStore, error) {
	if dir == "" || capacity <= 0 || routeQuota <= 0 || routeQuota > capacity {
		return nil, ErrInvalidLimits
	}
	if syncDirectory == nil {
		return nil, errors.New("node directory synchronization is unavailable")
	}
	if err := ensurePrivateStoreDirectory(dir); err != nil {
		return nil, err
	}
	resolvedDir, err := canonicalConfiguredPath(dir)
	if err != nil {
		return nil, errors.New("node store directory could not be canonicalized")
	}
	dir = resolvedDir
	if err := ensurePrivateStoreDirectory(dir); err != nil {
		return nil, err
	}
	lockFile, err := acquireNodeStoreLock(dir)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*DiskStore, error) {
		_ = unlockNodeStoreFile(lockFile)
		_ = lockFile.Close()
		return nil, cause
	}
	s := &DiskStore{
		dir:           dir,
		items:         make(map[string]protocol.StoredItem),
		tombstones:    make(map[string]deleteTombstone),
		charges:       make(map[string]int64),
		byRoute:       make(map[string]map[string]struct{}),
		routeUsed:     make(map[string]int64),
		capacity:      capacity,
		routeQuota:    routeQuota,
		lockFile:      lockFile,
		syncDirectory: syncDirectory,
	}
	entries, err := readNodeStoreEntriesBounded(dir)
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC()
	expiredPaths := make([]string, 0)
	temporaryPaths := make([]string, 0)
	for _, entry := range entries {
		if entry.Name() == nodeStoreLockFilename {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".propagare-private-") {
			path := filepath.Join(dir, entry.Name())
			info, infoErr := entry.Info()
			if infoErr != nil || info.Size() > MaxStoredItemEncodingBytes ||
				privatefs.Validate(path, info, privatefs.RegularFile) != nil || len(temporaryPaths) >= maxNodeAbandonedTemporaries {
				return fail(fmt.Errorf("%w: invalid abandoned temporary record", ErrCorruptStore))
			}
			temporaryPaths = append(temporaryPaths, path)
			continue
		}
		if entry.Name() == nodeIdentityBindingFile {
			if s.binding != nil || entry.IsDir() {
				return fail(fmt.Errorf("%w: duplicate or invalid identity binding", ErrCorruptStore))
			}
			data, err := readPrivateStoreRecord(filepath.Join(dir, entry.Name()))
			if err != nil || len(data) > maxIdentityBindingBytes {
				return fail(fmt.Errorf("%w: unreadable identity binding", ErrCorruptStore))
			}
			binding, err := decodeNodeIdentityBinding(data)
			if err != nil {
				return fail(fmt.Errorf("%w: invalid identity binding", ErrCorruptStore))
			}
			s.binding = &binding
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return fail(fmt.Errorf("%w: unexpected entry", ErrCorruptStore))
		}
		path := filepath.Join(dir, entry.Name())
		data, err := readPrivateStoreRecord(path)
		if err != nil {
			return fail(fmt.Errorf("%w: unreadable record", ErrCorruptStore))
		}
		var probe struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			return fail(fmt.Errorf("%w: malformed JSON record", ErrCorruptStore))
		}
		switch probe.RecordType {
		case "":
			var item protocol.StoredItem
			if err := decodeStrictJSON(data, &item); err != nil || entry.Name() != item.ItemID+".json" || validateStoredRecord(item, now) != nil {
				return fail(fmt.Errorf("%w: invalid item record", ErrCorruptStore))
			}
			if !item.ExpiresAt.After(now) {
				expiredPaths = append(expiredPaths, path)
				continue
			}
			charge := storedItemCharge(len(data))
			if len(s.items)+len(s.tombstones) >= MaxStoredItems || s.used+charge > capacity {
				return fail(fmt.Errorf("%w while reopening node store", ErrStorageFull))
			}
			if s.routeUsed[item.RouteTag]+charge > routeQuota || len(s.byRoute[item.RouteTag]) >= MaxItemsPerRoute {
				return fail(fmt.Errorf("%w while reopening node store", ErrMailboxQuota))
			}
			s.index(item, charge)
		case deleteTombstoneRecordType:
			var tombstone deleteTombstone
			if len(data) > MaxDeleteTombstoneBytes || decodeStrictJSON(data, &tombstone) != nil ||
				entry.Name() != tombstone.ItemID+".json" || validateDeleteTombstone(tombstone) != nil {
				return fail(fmt.Errorf("%w: invalid delete tombstone", ErrCorruptStore))
			}
			if !tombstone.ExpiresAt.After(now) {
				expiredPaths = append(expiredPaths, path)
				continue
			}
			charge := storedItemCharge(len(data))
			if len(s.items)+len(s.tombstones) >= MaxStoredItems || s.used+charge > capacity {
				return fail(fmt.Errorf("%w while reopening node store", ErrStorageFull))
			}
			s.indexTombstone(tombstone, charge)
		default:
			return fail(fmt.Errorf("%w: unknown record type", ErrCorruptStore))
		}
	}
	// No managed record is touched until the complete scan and all configured
	// limits have succeeded. A failed reopen therefore preserves every record
	// byte-for-byte, including malformed or unmanaged JSON.
	for _, path := range temporaryPaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(errors.New("abandoned temporary store record could not be removed"))
		}
	}
	for _, path := range expiredPaths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(errors.New("expired store record could not be removed"))
		}
	}
	// Always synchronize after the complete startup scan. A prior process may
	// have committed a visible rename but exited before learning whether its
	// directory fsync succeeded; reopening must recover that durability before
	// any idempotent operation can report success.
	if err := s.syncDirectory(dir); err != nil {
		return fail(err)
	}
	return s, nil
}

func readNodeStoreEntriesBounded(directory string) ([]os.DirEntry, error) {
	handle, err := os.Open(directory) // #nosec G304 -- validated private node-store directory.
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	entries := make([]os.DirEntry, 0, 256)
	for {
		batch, readErr := handle.ReadDir(256)
		if len(entries)+len(batch) > maxNodeStartupEntries {
			return nil, fmt.Errorf("%w: node store entry bound exceeded", ErrCorruptStore)
		}
		entries = append(entries, batch...)
		if errors.Is(readErr, io.EOF) {
			return entries, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func decodeNodeIdentityBinding(data []byte) (nodeIdentityBinding, error) {
	var binding nodeIdentityBinding
	if len(data) == 0 || len(data) > maxIdentityBindingBytes || decodeStrictJSON(data, &binding) != nil {
		return nodeIdentityBinding{}, errors.New("invalid node identity binding encoding")
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical, data) {
		return nodeIdentityBinding{}, errors.New("node identity binding is not canonically encoded")
	}
	if binding.RecordType != nodeIdentityBindingType || binding.Version != nodeIdentityBindingVersion ||
		!pqcrypto.ValidPublicIdentity(binding.Identity) {
		return nodeIdentityBinding{}, errors.New("invalid node identity binding fields")
	}
	signingBytes, err := nodeIdentityBindingSigningBytes(binding.Identity)
	if err != nil || !pqcrypto.Verify(binding.Identity, nodeIdentityBindingDomain, signingBytes, binding.Signature) {
		return nodeIdentityBinding{}, errors.New("invalid node identity binding signature")
	}
	binding.Identity = cloneNodeIdentity(binding.Identity)
	binding.Signature.Ed25519 = append([]byte(nil), binding.Signature.Ed25519...)
	binding.Signature.MLDSA65 = append([]byte(nil), binding.Signature.MLDSA65...)
	return binding, nil
}

func nodeIdentityBindingSigningBytes(identity protocol.NodePublicIdentity) ([]byte, error) {
	return json.Marshal(nodeIdentityBindingUnsigned{
		RecordType: nodeIdentityBindingType,
		Version:    nodeIdentityBindingVersion,
		Identity:   identity,
	})
}

func cloneNodeIdentity(identity protocol.NodePublicIdentity) protocol.NodePublicIdentity {
	identity.Ed25519Public = append([]byte(nil), identity.Ed25519Public...)
	identity.MLDSA65Public = append([]byte(nil), identity.MLDSA65Public...)
	return identity
}

func sameNodeIdentity(left, right protocol.NodePublicIdentity) bool {
	return left.ProtocolVersion == right.ProtocolVersion && left.NodeID == right.NodeID &&
		bytes.Equal(left.Ed25519Public, right.Ed25519Public) && bytes.Equal(left.MLDSA65Public, right.MLDSA65Public)
}

// BindIdentity permanently ties this store directory to the node's hybrid
// signing identity. Existing pre-binding stores must be empty so accidentally
// replacing a lost key can never make old retained data appear under a new
// node identity.
func (s *DiskStore) BindIdentity(signer *pqcrypto.HybridSigner) error {
	if signer == nil {
		return ErrStoreIdentity
	}
	identity := signer.PublicIdentity()
	if !pqcrypto.ValidPublicIdentity(identity) {
		return ErrStoreIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if s.binding != nil {
		if !sameNodeIdentity(s.binding.Identity, identity) {
			return ErrStoreIdentity
		}
		return s.ensureDirectoryDurableLocked()
	}
	if len(s.items) != 0 || len(s.tombstones) != 0 {
		return ErrUnboundStore
	}
	signingBytes, err := nodeIdentityBindingSigningBytes(identity)
	if err != nil {
		return err
	}
	signature, err := signer.Sign(nodeIdentityBindingDomain, signingBytes)
	if err != nil {
		return err
	}
	binding := nodeIdentityBinding{
		RecordType: nodeIdentityBindingType,
		Version:    nodeIdentityBindingVersion,
		Identity:   cloneNodeIdentity(identity),
		Signature: protocol.HybridSignature{
			Ed25519: append([]byte(nil), signature.Ed25519...),
			MLDSA65: append([]byte(nil), signature.MLDSA65...),
		},
	}
	encoded, err := json.Marshal(binding)
	if err != nil || len(encoded) > maxIdentityBindingBytes {
		return errors.New("node identity binding exceeds encoding bound")
	}
	writeErr := writePrivateAtomicWithSync(filepath.Join(s.dir, nodeIdentityBindingFile), encoded, s.syncDirectory)
	if writeErr != nil && !privateWriteCommitted(writeErr) {
		return writeErr
	}
	s.binding = &binding
	s.noteDirectoryWriteResultLocked(writeErr)
	return writeErr
}

// BoundIdentity returns the authenticated identity persisted in this store.
func (s *DiskStore) BoundIdentity() (protocol.NodePublicIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.binding == nil {
		return protocol.NodePublicIdentity{}, false
	}
	return cloneNodeIdentity(s.binding.Identity), true
}

// IdentityInitializationAllowed reports whether a fresh identity binding can
// be created without orphaning retained items or tombstones.
func (s *DiskStore) IdentityInitializationAllowed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed && s.binding == nil && len(s.items) == 0 && len(s.tombstones) == 0
}

func readPrivateStoreRecord(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !validPrivateRegularFile(path, pathInfo, int64(MaxStoredItemEncodingBytes)) {
		return nil, errors.New("store record is not a bounded private regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0) // #nosec G304 -- single validated entry in the private store directory.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, openedErr := file.Stat()
	currentInfo, currentErr := os.Lstat(path)
	if openedErr != nil || currentErr != nil || !validPrivateRegularFileBasic(openedInfo, int64(MaxStoredItemEncodingBytes)) ||
		!validPrivateRegularFile(path, currentInfo, int64(MaxStoredItemEncodingBytes)) || !os.SameFile(openedInfo, currentInfo) {
		return nil, errors.New("store record path changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(MaxStoredItemEncodingBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxStoredItemEncodingBytes {
		return nil, errors.New("store record has invalid size")
	}
	return data, nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("record must contain one JSON value")
	}
	return nil
}

func validateStoredRecord(item protocol.StoredItem, now time.Time) error {
	validationTime := now
	if !item.ExpiresAt.After(now) {
		validationTime = item.ExpiresAt.Add(-time.Nanosecond)
	}
	return protocol.ValidateItem(item, validationTime, protocol.DefaultMaxItemBytes)
}

func validateDeleteTombstone(tombstone deleteTombstone) error {
	earliestDelete := tombstone.ExpiresAt.Add(-protocol.FixedItemRetention).Add(-5 * time.Minute)
	if tombstone.RecordType != deleteTombstoneRecordType || tombstone.Version != deleteTombstoneVersion ||
		!validItemID(tombstone.ItemID) || len(tombstone.DeleteTokenHash) != sha256.Size ||
		tombstone.DeletedAt.IsZero() || tombstone.DeletedAt.Before(earliestDelete) || !tombstone.ExpiresAt.After(tombstone.DeletedAt) {
		return errors.New("invalid delete tombstone")
	}
	return nil
}

func ensurePrivateStoreDirectory(path string) error {
	_, initialErr := os.Lstat(path)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("node store directory must be a private real directory")
	}
	if errors.Is(initialErr, os.ErrNotExist) || privateNodeDirectoryIsEmpty(path) {
		if err := privatefs.Restrict(path, privatefs.Directory); err != nil {
			return fmt.Errorf("node store directory permissions could not be restricted: %w", err)
		}
	} else if err := privatefs.Validate(path, info, privatefs.Directory); err != nil {
		return fmt.Errorf("node store directory permissions are not private: %w", err)
	}
	return nil
}

func validItemID(itemID string) bool {
	decoded, err := hex.DecodeString(itemID)
	return err == nil && len(decoded) == 32
}

func (s *DiskStore) path(itemID string) (string, error) {
	if !validItemID(itemID) {
		return "", ErrInvalidItemID
	}
	return filepath.Join(s.dir, itemID+".json"), nil
}

func storedItemCharge(encodedBytes int) int64 {
	if encodedBytes <= 0 {
		return 0
	}
	return int64(encodedBytes + PerItemAccountingOverhead)
}

func cloneStoredItem(item protocol.StoredItem) protocol.StoredItem {
	item.DeleteTokenHash = append([]byte(nil), item.DeleteTokenHash...)
	item.Payload = append([]byte(nil), item.Payload...)
	return item
}

func cloneDeleteTombstone(tombstone deleteTombstone) deleteTombstone {
	tombstone.DeleteTokenHash = append([]byte(nil), tombstone.DeleteTokenHash...)
	return tombstone
}

func (s *DiskStore) index(item protocol.StoredItem, charge int64) {
	item = cloneStoredItem(item)
	s.items[item.ItemID] = item
	s.charges[item.ItemID] = charge
	if s.byRoute[item.RouteTag] == nil {
		s.byRoute[item.RouteTag] = make(map[string]struct{})
	}
	s.byRoute[item.RouteTag][item.ItemID] = struct{}{}
	s.used += charge
	s.routeUsed[item.RouteTag] += charge
}

func (s *DiskStore) indexTombstone(tombstone deleteTombstone, charge int64) {
	tombstone = cloneDeleteTombstone(tombstone)
	s.tombstones[tombstone.ItemID] = tombstone
	s.charges[tombstone.ItemID] = charge
	s.used += charge
}

func (s *DiskStore) unindexItem(item protocol.StoredItem) {
	delete(s.items, item.ItemID)
	charge := s.charges[item.ItemID]
	delete(s.charges, item.ItemID)
	delete(s.byRoute[item.RouteTag], item.ItemID)
	s.routeUsed[item.RouteTag] -= charge
	if len(s.byRoute[item.RouteTag]) == 0 {
		delete(s.byRoute, item.RouteTag)
		delete(s.routeUsed, item.RouteTag)
	}
	s.used -= charge
}

func (s *DiskStore) unindexTombstone(tombstone deleteTombstone) {
	delete(s.tombstones, tombstone.ItemID)
	charge := s.charges[tombstone.ItemID]
	delete(s.charges, tombstone.ItemID)
	s.used -= charge
}

func (s *DiskStore) Put(item protocol.StoredItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := protocol.ValidateItem(item, time.Now(), protocol.DefaultMaxItemBytes); err != nil {
		return err
	}
	if _, ok := s.items[item.ItemID]; ok {
		return s.ensureDirectoryDurableLocked()
	}
	if _, deleted := s.tombstones[item.ItemID]; deleted {
		if err := s.ensureDirectoryDurableLocked(); err != nil {
			return err
		}
		return ErrItemDeleted
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if len(encoded) > MaxStoredItemEncodingBytes {
		return protocol.ErrItemTooLarge
	}
	charge := storedItemCharge(len(encoded))
	if len(s.items)+len(s.tombstones) >= MaxStoredItems || s.capacity > 0 && s.used+charge > s.capacity {
		return ErrStorageFull
	}
	if len(s.byRoute[item.RouteTag]) >= MaxItemsPerRoute ||
		s.routeQuota > 0 && s.routeUsed[item.RouteTag]+charge > s.routeQuota {
		return ErrMailboxQuota
	}
	path, err := s.path(item.ItemID)
	if err != nil {
		return err
	}
	writeErr := writePrivateAtomicWithSync(path, encoded, s.syncDirectory)
	if writeErr != nil && !privateWriteCommitted(writeErr) {
		return writeErr
	}
	s.index(item, charge)
	s.noteDirectoryWriteResultLocked(writeErr)
	return writeErr
}

func (s *DiskStore) Get(itemID string) (protocol.StoredItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return protocol.StoredItem{}, ErrStoreClosed
	}
	if err := s.ensureDirectoryDurableLocked(); err != nil {
		return protocol.StoredItem{}, err
	}
	item, ok := s.items[itemID]
	if !ok || !item.ExpiresAt.After(time.Now()) {
		return protocol.StoredItem{}, ErrNotFound
	}
	return cloneStoredItem(item), nil
}

func (s *DiskStore) FetchLimited(routeTags []string, maxItems int, maxBytes int64) ([]protocol.StoredItem, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, true
	}
	if err := s.ensureDirectoryDurableLocked(); err != nil {
		return nil, true
	}
	if len(routeTags) == 0 || len(routeTags) > protocol.MaxRouteTagsPerFetch || maxItems <= 0 || maxBytes <= 0 {
		return nil, true
	}
	now := time.Now()
	seen := make(map[string]struct{})
	items := make([]protocol.StoredItem, 0)
	var totalBytes int64
	truncated := false
	for _, routeTag := range routeTags {
		for itemID := range s.byRoute[routeTag] {
			item := s.items[itemID]
			if item.ExpiresAt.After(now) {
				if _, exists := seen[itemID]; !exists {
					if len(items) >= maxItems || totalBytes+int64(len(item.Payload)) > maxBytes {
						truncated = true
						break
					}
					items = append(items, cloneStoredItem(item))
					seen[itemID] = struct{}{}
					totalBytes += int64(len(item.Payload))
				}
			}
		}
		if truncated {
			break
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].ItemID < items[j].ItemID
	})
	return items, truncated
}

func (s *DiskStore) deleteWithCapability(itemID string, deleteToken []byte, deletedAt time.Time) (committedDelete, error) {
	if !validItemID(itemID) || len(deleteToken) != protocol.CapabilityBytes || deletedAt.IsZero() {
		return committedDelete{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return committedDelete{}, ErrStoreClosed
	}
	if tombstone, ok := s.tombstones[itemID]; ok {
		if !tombstone.ExpiresAt.After(deletedAt) || !pqcrypto.DeleteTokenMatches(tombstone.DeleteTokenHash, deleteToken) {
			return committedDelete{}, ErrNotFound
		}
		if err := s.ensureDirectoryDurableLocked(); err != nil {
			return committedDelete{}, err
		}
		return committedDelete{ItemID: itemID, DeletedAt: tombstone.DeletedAt}, nil
	}
	item, ok := s.items[itemID]
	if !ok || !item.ExpiresAt.After(deletedAt) || !pqcrypto.DeleteTokenMatches(item.DeleteTokenHash, deleteToken) {
		return committedDelete{}, ErrNotFound
	}
	path, err := s.path(itemID)
	if err != nil {
		return committedDelete{}, err
	}
	tombstone := deleteTombstone{
		RecordType:      deleteTombstoneRecordType,
		Version:         deleteTombstoneVersion,
		ItemID:          itemID,
		DeleteTokenHash: append([]byte(nil), item.DeleteTokenHash...),
		DeletedAt:       deletedAt.UTC().Truncate(time.Millisecond),
		ExpiresAt:       item.ExpiresAt,
	}
	if err := validateDeleteTombstone(tombstone); err != nil {
		return committedDelete{}, err
	}
	encoded, err := json.Marshal(tombstone)
	if err != nil {
		return committedDelete{}, err
	}
	if len(encoded) > MaxDeleteTombstoneBytes {
		return committedDelete{}, errors.New("delete tombstone exceeds encoding bound")
	}
	writeErr := writePrivateAtomicWithSync(path, encoded, s.syncDirectory)
	if writeErr != nil && !privateWriteCommitted(writeErr) {
		return committedDelete{}, writeErr
	}
	s.unindexItem(item)
	s.indexTombstone(tombstone, storedItemCharge(len(encoded)))
	s.noteDirectoryWriteResultLocked(writeErr)
	return committedDelete{ItemID: itemID, DeletedAt: tombstone.DeletedAt}, writeErr
}

func (s *DiskStore) Sweep(now time.Time) error {
	return s.SweepContext(context.Background(), now)
}

// SweepContext removes expired records in bounded batches. The store mutex is
// released between batches so shutdown never waits behind up to
// MaxStoredItems filesystem mutations.
func (s *DiskStore) SweepContext(ctx context.Context, now time.Time) error {
	if ctx == nil || now.IsZero() {
		return errors.New("invalid node store sweep")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := lockStoreForSweep(ctx, &s.mu); err != nil {
			return err
		}
		more, err := s.sweepBatchLocked(ctx, now, maxSweepBatchRecords)
		s.mu.Unlock()
		if err != nil || !more {
			return err
		}
	}
}

func lockStoreForSweep(ctx context.Context, mutex *sync.RWMutex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for !mutex.TryLock() {
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		mutex.Unlock()
		return err
	}
	return nil
}

func (s *DiskStore) sweepBatchLocked(ctx context.Context, now time.Time, limit int) (bool, error) {
	if s.closed {
		return false, ErrStoreClosed
	}
	if err := s.ensureDirectoryDurableLocked(); err != nil {
		return false, err
	}
	removed := false
	removedCount := 0
	scannedCount := 0
	for itemID, item := range s.items {
		scannedCount++
		if scannedCount%maxSweepBatchRecords == 0 {
			if err := ctx.Err(); err != nil {
				return false, errors.Join(s.syncRemovedDirectoryLocked(removed), err)
			}
		}
		if item.ExpiresAt.After(now) {
			continue
		}
		if removedCount >= limit {
			return true, s.syncRemovedDirectoryLocked(removed)
		}
		select {
		case <-ctx.Done():
			return false, errors.Join(s.syncRemovedDirectoryLocked(removed), ctx.Err())
		default:
		}
		path, err := s.path(itemID)
		if err != nil {
			return false, err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("expired store record could not be removed")
		}
		// Set this before any later loop error can return. The batch-level sync
		// clears it only after the directory mutation is durable.
		s.directorySyncPending = true
		s.unindexItem(item)
		removed = true
		removedCount++
	}
	for itemID, tombstone := range s.tombstones {
		scannedCount++
		if scannedCount%maxSweepBatchRecords == 0 {
			if err := ctx.Err(); err != nil {
				return false, errors.Join(s.syncRemovedDirectoryLocked(removed), err)
			}
		}
		if tombstone.ExpiresAt.After(now) {
			continue
		}
		if removedCount >= limit {
			return true, s.syncRemovedDirectoryLocked(removed)
		}
		select {
		case <-ctx.Done():
			return false, errors.Join(s.syncRemovedDirectoryLocked(removed), ctx.Err())
		default:
		}
		path, err := s.path(itemID)
		if err != nil {
			return false, err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("expired store record could not be removed")
		}
		s.directorySyncPending = true
		s.unindexTombstone(tombstone)
		removed = true
		removedCount++
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(s.syncRemovedDirectoryLocked(removed), err)
	}
	return false, s.syncRemovedDirectoryLocked(removed)
}

func (s *DiskStore) syncRemovedDirectoryLocked(removed bool) error {
	if !removed {
		return nil
	}
	err := s.syncDirectory(s.dir)
	s.noteDirectoryWriteResultLocked(err)
	return err
}

func (s *DiskStore) noteDirectoryWriteResultLocked(err error) {
	if err == nil {
		s.directorySyncPending = false
	} else if privateWriteCommitted(err) {
		s.directorySyncPending = true
	} else {
		// Directory sync calls used by sweeps return their raw error after the
		// filesystem mutation, so any error there must also keep the store degraded.
		s.directorySyncPending = true
	}
}

func (s *DiskStore) ensureDirectoryDurableLocked() error {
	if !s.directorySyncPending {
		return nil
	}
	if err := s.syncDirectory(s.dir); err != nil {
		return err
	}
	s.directorySyncPending = false
	return nil
}

func (s *DiskStore) Used() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0
	}
	return s.used
}

func (s *DiskStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	syncErr := s.ensureDirectoryDurableLocked()
	s.closed = true
	var unlockErr, closeErr error
	if s.lockFile != nil {
		unlockErr = unlockNodeStoreFile(s.lockFile)
		closeErr = s.lockFile.Close()
		s.lockFile = nil
	}
	return errors.Join(syncErr, unlockErr, closeErr)
}

func acquireNodeStoreLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, nodeStoreLockFilename)
	created := false
	if info, err := os.Lstat(path); err == nil {
		if info.Size() < 0 || info.Size() > maxNodeLockFileBytes ||
			privatefs.Validate(path, info, privatefs.RegularFile) != nil {
			return nil, errors.New("node store lock is not a private regular file")
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
	openedInfo, openedErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if openedErr != nil || pathErr != nil || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		file.Close()
		return nil, errors.New("node store lock path changed during open")
	}
	if err := lockNodeStoreFile(file); err != nil {
		file.Close()
		return nil, errors.New("node store is already open or cannot be locked")
	}
	return file, nil
}
