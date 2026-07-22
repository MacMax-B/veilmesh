package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"propagare/pqcrypto"
	"propagare/protocol"
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
	node := &HTTPNode{BaseURL: "https://node.invalid", Identity: signer.PublicIdentity(), Client: &http.Client{}}
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
}
