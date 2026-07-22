package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

func clientStoreKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func localTestRecord(id string, createdAt time.Time, payloadBytes int, policy PrunePolicy) LocalRecord {
	return LocalRecord{
		Version: ClientStoreVersion, ID: id, Kind: LocalKindFileCache,
		CreatedAt: createdAt, UpdatedAt: createdAt, PrunePolicy: policy,
		Payload: bytes.Repeat([]byte{id[0]}, payloadBytes),
	}
}

func TestEncryptedClientStorePrunesOldestAtConfiguredLimit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 100 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for index, id := range []string{"oldest", "middle"} {
		if _, err := store.Put(context.Background(), localTestRecord(id, now.Add(time.Duration(index)*time.Second), 30*1024, PruneOldest), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	report, err := store.Put(context.Background(), localTestRecord("newest", now.Add(2*time.Second), 30*1024, PruneOldest), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.Records != 1 || report.Bytes <= 0 {
		t.Fatalf("unexpected prune report: %+v", report)
	}
	if _, err := store.Get(context.Background(), "oldest"); !errors.Is(err, ErrLocalRecordNotFound) {
		t.Fatal("oldest prunable record was not evicted")
	}
	for _, id := range []string{"middle", "newest"} {
		record, err := store.Get(context.Background(), id)
		if err != nil || len(record.Payload) != 30*1024 {
			t.Fatalf("retained record %s: bytes=%d err=%v", id, len(record.Payload), err)
		}
		zero(record.Payload)
	}
	usage := store.Usage()
	if usage.UsedBytes > usage.MaxBytes || usage.MaxBytes != 100*1024 {
		t.Fatalf("client store exceeded its bound: %+v", usage)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, bytes.Repeat([]byte{'n'}, 64)) {
			t.Fatal("client payload appeared in plaintext on disk")
		}
	}
}

func TestEncryptedClientStoreNeverPrunesProtectedState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 70 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	protected := localTestRecord("protected", now, 30*1024, PruneNever)
	protected.Kind = LocalKindOutbox
	if _, err := store.Put(context.Background(), protected, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), localTestRecord("overflow", now.Add(time.Second), 30*1024, PruneOldest), now.Add(time.Second)); !errors.Is(err, ErrClientStorageFull) {
		t.Fatalf("protected-state overflow returned %v", err)
	}
	if _, err := store.Get(context.Background(), "protected"); err != nil {
		t.Fatalf("protected state was removed: %v", err)
	}
}

func TestEncryptedClientStoreRejectsUnsafePrunePolicies(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for name, record := range map[string]LocalRecord{
		"group-cache": {
			Version: ClientStoreVersion, ID: "group-cache", Kind: LocalKindGroupState,
			CreatedAt: now, UpdatedAt: now, PrunePolicy: PruneOldest, Payload: []byte{1},
		},
		"replay-cache": {
			Version: ClientStoreVersion, ID: "replay-cache", Kind: LocalKindReplay,
			CreatedAt: now, UpdatedAt: now, PrunePolicy: PruneOldest, Payload: []byte{1},
		},
		"unknown-kind": {
			Version: ClientStoreVersion, ID: "unknown-kind", Kind: "plugin_state",
			CreatedAt: now, UpdatedAt: now, PrunePolicy: PruneOldest, Payload: []byte{1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Put(context.Background(), record, now); err == nil {
				t.Fatal("unsafe local prune policy was accepted")
			}
		})
	}
}

func TestEncryptedClientStoreCanLowerLimitAndPruneOldest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 160 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index, id := range []string{"first", "second", "third"} {
		if _, err := store.Put(context.Background(), localTestRecord(id, now.Add(time.Duration(index)*time.Second), 30*1024, PruneOldest), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	report, err := store.SetLimit(context.Background(), 100*1024, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.Records == 0 || store.Usage().UsedBytes > 100*1024 {
		t.Fatalf("lowered limit was not enforced: report=%+v usage=%+v", report, store.Usage())
	}
	if _, err := store.Get(context.Background(), "first"); !errors.Is(err, ErrLocalRecordNotFound) {
		t.Fatal("oldest record survived limit reduction")
	}
}

func TestEncryptedClientStoreListsBoundedStablePages(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, id := range []string{"record-c", "record-a", "record-b"} {
		if _, err := store.Put(context.Background(), localTestRecord(id, now, 128, PruneOldest), now); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ListIDs(context.Background(), LocalKindFileCache, "", 2)
	if err != nil || len(first) != 2 || first[0] != "record-a" || first[1] != "record-b" {
		t.Fatalf("unexpected first list page: %v err=%v", first, err)
	}
	second, err := store.ListIDs(context.Background(), LocalKindFileCache, first[1], 2)
	if err != nil || len(second) != 1 || second[0] != "record-c" {
		t.Fatalf("unexpected second list page: %v err=%v", second, err)
	}
	if _, err := store.ListIDs(context.Background(), LocalKindFileCache, "", MaxClientStoreListPage+1); err == nil {
		t.Fatal("unbounded local record listing was accepted")
	}
}

func TestEncryptedClientStoreConcurrentLimitAndPrune(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 128 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				limit := int64(128 * 1024)
				if (worker+iteration)%2 == 0 {
					limit = 64 * 1024
				}
				_, _ = store.SetLimit(context.Background(), limit, now)
				_, _ = store.PruneTo(context.Background(), 64*1024, now)
			}
		}(worker)
	}
	wait.Wait()
}

func TestEncryptedClientStorePrunesToRecordCountBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index, id := range []string{"record-one", "record-two", "record-three"} {
		if _, err := store.Put(context.Background(), localTestRecord(id, now.Add(time.Duration(index)*time.Second), 1024, PruneOldest), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.Lock()
	report, err := store.pruneToLocked(context.Background(), store.maxBytes, 2, now.Add(time.Minute), "")
	store.mu.Unlock()
	if err != nil || report.Records != 1 {
		t.Fatalf("record-count pruning failed: report=%+v err=%v", report, err)
	}
	if _, err := store.Get(context.Background(), "record-one"); !errors.Is(err, ErrLocalRecordNotFound) {
		t.Fatal("oldest record survived record-count pruning")
	}
}

func TestClientPruneKeepsDurabilityPendingAfterPartialFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for index, id := range []string{"record-one", "record-two"} {
		if _, err := store.Put(context.Background(), localTestRecord(id, now.Add(time.Duration(index)*time.Second), 1024, PruneOldest), now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	blockedPath := filepath.Join(directory, "blocked-removal")
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedPath, "child"), []byte("nonempty"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	second := store.entries["record-two"]
	second.Path = blockedPath
	store.entries["record-two"] = second
	report, pruneErr := store.pruneToLocked(context.Background(), store.maxBytes, 0, now.Add(time.Minute), "")
	pending := store.directorySyncPending
	recoveryErr := store.ensureDirectoryDurableLocked()
	store.mu.Unlock()
	if pruneErr == nil || report.Records != 1 {
		t.Fatalf("partial prune returned report=%+v err=%v", report, pruneErr)
	}
	if !pending {
		t.Fatal("partial prune forgot the already committed directory mutation")
	}
	if recoveryErr != nil {
		t.Fatalf("pending prune durability did not recover: %v", recoveryErr)
	}
}

func TestClientStoreDoesNotExposeNondurableWrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	actualSync := store.syncDirectory
	injected := errors.New("injected client record directory sync failure")
	store.syncDirectory = func(string) error { return injected }
	if _, err := store.Put(context.Background(), localTestRecord("nondurable", now, 1024, PruneOldest), now); !errors.Is(err, injected) {
		t.Fatalf("nondurable write returned %v", err)
	}
	if _, err := store.Get(context.Background(), "nondurable"); !errors.Is(err, injected) {
		t.Fatalf("Get exposed nondurable record: %v", err)
	}
	if _, err := store.ListIDs(context.Background(), LocalKindFileCache, "", 1); !errors.Is(err, injected) {
		t.Fatalf("ListIDs exposed nondurable record: %v", err)
	}
	store.syncDirectory = actualSync
	record, err := store.Get(context.Background(), "nondurable")
	if err != nil || len(record.Payload) != 1024 {
		t.Fatalf("durability recovery did not expose committed record: bytes=%d err=%v", len(record.Payload), err)
	}
	zero(record.Payload)
}

func TestEncryptedClientStoreRejectsTamperingAndWrongKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{Directory: directory, Key: key, MaxBytes: 1024 * 1024}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), localTestRecord("record", now, 1024, PruneOldest), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedDiskStore(DiskClientStoreConfig{Directory: directory, Key: clientStoreKey(t), MaxBytes: 1024 * 1024}, now); err == nil {
		t.Fatal("wrong client-store key authenticated existing data")
	}

	path := filepath.Join(directory, localRecordFilename("record"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedDiskStore(DiskClientStoreConfig{Directory: directory, Key: key, MaxBytes: 1024 * 1024}, now); err == nil {
		t.Fatal("tampered encrypted client record was accepted")
	}
}

func TestEncryptedClientStoreCleansCrashTemporaryAndRejectsUnmanagedFiles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(directory, ".vmc-private-abandoned")
	if err := os.WriteFile(temporary, []byte("sealed temporary"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned temporary record survived restart: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unmanaged"), []byte("not charged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now); err == nil {
		t.Fatal("unmanaged client-store file was ignored")
	}
}

func TestClientStoreValidatesCompleteStartupBeforePruning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), localTestRecord("preserve-cache", now, 128*1024, PruneOldest), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(directory, localRecordFilename("preserve-cache"))
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "zzzz-unmanaged"), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: MinClientStorageBytes,
	}, now); err == nil {
		t.Fatal("startup accepted an unmanaged entry")
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("failed startup pruned a valid record: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed startup modified a valid record before complete validation")
	}
}

func TestEncryptedClientStoreRequiresExclusiveDirectoryOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	first, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now); err == nil {
		t.Fatal("second client store opened the same directory concurrently")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatalf("client store did not reopen after clean close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCorePersistsAndRevalidatesDelivery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	signer, _ := pqcrypto.GenerateHybridSigner()
	node := developmentNodeForTest(signer.PublicIdentity(), nil)
	directory := t.TempDir()
	key := clientStoreKey(t)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{Directory: directory, Key: key, MaxBytes: 1024 * 1024}, now)
	if err != nil {
		t.Fatal(err)
	}
	core, err := New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	item, deleteToken := validClientItem(t)
	now = item.CreatedAt.Add(time.Second)
	payloadHash := sha256.Sum256(item.Payload)
	receipt := protocol.StorageReceipt{
		NodeID: signer.PublicIdentity().NodeID, ItemID: item.ItemID, PayloadHash: payloadHash[:],
		StoredAt: now, ExpiresAt: item.ExpiresAt,
	}
	receipt.Signature, err = signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
	if err != nil {
		t.Fatal(err)
	}
	delivery := Delivery{Item: item, DeleteToken: deleteToken, Receipts: []protocol.StorageReceipt{receipt}}
	if err := core.persistDelivery(context.Background(), delivery, now); err != nil {
		t.Fatal(err)
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewEncryptedDiskStore(DiskClientStoreConfig{Directory: directory, Key: key, MaxBytes: 1024 * 1024}, now)
	if err != nil {
		t.Fatal(err)
	}
	core, err = New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	restored, err := core.LoadDelivery(context.Background(), item.ItemID, now)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Item.ItemID != item.ItemID || !bytes.Equal(restored.DeleteToken, deleteToken) {
		t.Fatal("restored delivery state differs")
	}
	pending, err := core.PendingDeliveries(context.Background(), "", 1, now)
	if err != nil || len(pending) != 1 || pending[0].Item.ItemID != item.ItemID {
		t.Fatalf("restart did not discover pending delivery: pending=%d err=%v", len(pending), err)
	}
	for _, invalidID := range []string{strings.Repeat("z", sha256.Size*2), "A" + strings.Repeat("0", sha256.Size*2-1)} {
		if _, err := core.LoadDelivery(context.Background(), invalidID, now); err == nil {
			t.Fatalf("non-canonical delivery ID %q was accepted", invalidID)
		}
		if _, err := core.PendingDeliveries(context.Background(), invalidID, 1, now); err == nil {
			t.Fatalf("non-canonical pagination ID %q was accepted", invalidID)
		}
	}
}
