package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"veilmesh/protocol"
)

var (
	ErrNotFound      = errors.New("item not found")
	ErrMailboxQuota  = errors.New("route-tag quota exceeded")
	ErrStorageFull   = errors.New("node storage capacity exceeded")
	ErrStoreClosed   = errors.New("node store is closed")
	ErrInvalidItemID = errors.New("invalid item id")
	ErrInvalidLimits = errors.New("invalid store limits")
)

const (
	MaxStoredItems             = 1_000_000
	MaxItemsPerRoute           = 1024
	PerItemAccountingOverhead  = 4 * 1024
	MaxStoredItemEncodingBytes = protocol.DefaultMaxItemBytes*2 + 64*1024
	nodeStoreLockFilename      = ".node-store.lock"
)

type DiskStore struct {
	mu         sync.RWMutex
	dir        string
	items      map[string]protocol.StoredItem
	charges    map[string]int64
	byRoute    map[string]map[string]struct{}
	routeUsed  map[string]int64
	used       int64
	capacity   int64
	routeQuota int64
	lockFile   *os.File
	closed     bool
}

func NewDiskStore(dir string, capacity, routeQuota int64) (*DiskStore, error) {
	if dir == "" || capacity <= 0 || routeQuota <= 0 || routeQuota > capacity {
		return nil, ErrInvalidLimits
	}
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
	if err := cleanupPrivateTemporaries(dir, ""); err != nil {
		return fail(err)
	}
	s := &DiskStore{
		dir:        dir,
		items:      make(map[string]protocol.StoredItem),
		charges:    make(map[string]int64),
		byRoute:    make(map[string]map[string]struct{}),
		routeUsed:  make(map[string]int64),
		capacity:   capacity,
		routeQuota: routeQuota,
		lockFile:   lockFile,
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fail(err)
	}
	now := time.Now()
	removedFiles := false
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
			info.Size() <= 0 || info.Size() > int64(MaxStoredItemEncodingBytes) {
			_ = os.Remove(path)
			removedFiles = true
			continue
		}
		// path is joined from this private directory and a single ReadDir entry;
		// separators cannot be injected and regular-file mode was checked above.
		data, err := os.ReadFile(path) // #nosec G304 -- directory entry is scoped and validated.
		if err != nil {
			return fail(err)
		}
		var item protocol.StoredItem
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			_ = os.Remove(path)
			removedFiles = true
			continue
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			_ = os.Remove(path)
			removedFiles = true
			continue
		}
		if protocol.ValidateItem(item, now, protocol.DefaultMaxRetention, protocol.DefaultMaxItemBytes) != nil ||
			entry.Name() != item.ItemID+".json" {
			_ = os.Remove(path)
			removedFiles = true
			continue
		}
		charge := storedItemCharge(len(data))
		if len(s.items) >= MaxStoredItems || s.used+charge > capacity ||
			s.routeUsed[item.RouteTag]+charge > routeQuota ||
			len(s.byRoute[item.RouteTag]) >= MaxItemsPerRoute {
			_ = os.Remove(path)
			removedFiles = true
			continue
		}
		s.index(item, charge)
	}
	if removedFiles {
		if err := syncPrivateDirectory(dir); err != nil {
			return fail(err)
		}
	}
	return s, nil
}

func ensurePrivateStoreDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("node store directory must be a private real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return errors.New("node store directory permissions could not be restricted")
		}
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

func (s *DiskStore) Put(item protocol.StoredItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := protocol.ValidateItem(item, time.Now(), protocol.DefaultMaxRetention, protocol.DefaultMaxItemBytes); err != nil {
		return err
	}
	if _, ok := s.items[item.ItemID]; ok {
		return nil
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if len(encoded) > MaxStoredItemEncodingBytes {
		return protocol.ErrItemTooLarge
	}
	charge := storedItemCharge(len(encoded))
	if len(s.items) >= MaxStoredItems || s.capacity > 0 && s.used+charge > s.capacity {
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
	if err := writePrivateAtomic(path, encoded); err != nil {
		return err
	}
	s.index(item, charge)
	return nil
}

func (s *DiskStore) Get(itemID string) (protocol.StoredItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return protocol.StoredItem{}, ErrStoreClosed
	}
	item, ok := s.items[itemID]
	if !ok || !item.ExpiresAt.After(time.Now()) {
		return protocol.StoredItem{}, ErrNotFound
	}
	return cloneStoredItem(item), nil
}

func (s *DiskStore) FetchLimited(routeTags []string, maxItems int, maxBytes int64) ([]protocol.StoredItem, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
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
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items, truncated
}

func (s *DiskStore) Delete(itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	item, ok := s.items[itemID]
	if !ok {
		return ErrNotFound
	}
	path, err := s.path(itemID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.items, itemID)
	charge := s.charges[itemID]
	delete(s.charges, itemID)
	delete(s.byRoute[item.RouteTag], itemID)
	s.routeUsed[item.RouteTag] -= charge
	if len(s.byRoute[item.RouteTag]) == 0 {
		delete(s.byRoute, item.RouteTag)
		delete(s.routeUsed, item.RouteTag)
	}
	s.used -= charge
	return syncPrivateDirectory(s.dir)
}

func (s *DiskStore) Sweep(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	removed := false
	for itemID, item := range s.items {
		if item.ExpiresAt.After(now) {
			continue
		}
		path, err := s.path(itemID)
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(s.items, itemID)
		charge := s.charges[itemID]
		delete(s.charges, itemID)
		delete(s.byRoute[item.RouteTag], itemID)
		s.routeUsed[item.RouteTag] -= charge
		if len(s.byRoute[item.RouteTag]) == 0 {
			delete(s.byRoute, item.RouteTag)
			delete(s.routeUsed, item.RouteTag)
		}
		s.used -= charge
		removed = true
	}
	if removed {
		return syncPrivateDirectory(s.dir)
	}
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
	s.closed = true
	var unlockErr, closeErr error
	if s.lockFile != nil {
		unlockErr = unlockNodeStoreFile(s.lockFile)
		closeErr = s.lockFile.Close()
		s.lockFile = nil
	}
	return errors.Join(unlockErr, closeErr)
}

func acquireNodeStoreLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, nodeStoreLockFilename)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("node store lock is not a private regular file")
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
		return nil, errors.New("node store lock path changed during open")
	}
	if err := lockNodeStoreFile(file); err != nil {
		file.Close()
		return nil, errors.New("node store is already open or cannot be locked")
	}
	return file, nil
}
