package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
)

func TestNodeStoreIdentityBindingSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	config := DefaultConfig()
	config.DataDir = directory
	config.StorageCapacity = 32 * 1024 * 1024
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDiskStore(directory, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config, store, signer); err != nil {
		t.Fatal(err)
	}
	bound, ok := store.BoundIdentity()
	if !ok || !sameNodeIdentity(bound, signer.PublicIdentity()) {
		t.Fatal("server did not durably bind the store identity")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDiskStore(directory, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := NewServer(config, reopened, signer); err != nil {
		t.Fatalf("same identity did not reopen bound store: %v", err)
	}
	different, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config, reopened, different); !errors.Is(err, ErrStoreIdentity) {
		t.Fatalf("different key returned %v, want identity mismatch", err)
	}
}

func TestNodeStoreRefusesToBindLegacyNonEmptyData(t *testing.T) {
	directory := t.TempDir()
	config := DefaultConfig()
	config.DataDir = directory
	config.StorageCapacity = 32 * 1024 * 1024
	store, err := NewDiskStore(directory, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(storedTestItem(t, mustRouteTag(t), []byte("retained ciphertext"))); err != nil {
		t.Fatal(err)
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config, store, signer); !errors.Is(err, ErrUnboundStore) {
		t.Fatalf("unbound non-empty store returned %v, want fail-closed migration error", err)
	}
	if _, err := os.Stat(filepath.Join(directory, nodeIdentityBindingFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed binding unexpectedly created identity metadata: %v", err)
	}
}

func TestNodeStoreRejectsMalformedAndNonCanonicalIdentityBindings(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	signingBytes, err := nodeIdentityBindingSigningBytes(signer.PublicIdentity())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(nodeIdentityBindingDomain, signingBytes)
	if err != nil {
		t.Fatal(err)
	}
	valid := nodeIdentityBinding{
		RecordType: nodeIdentityBindingType,
		Version:    nodeIdentityBindingVersion,
		Identity:   signer.PublicIdentity(),
		Signature:  signature,
	}
	canonical, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var reordered bytes.Buffer
	if err := json.Indent(&reordered, canonical, "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"non-canonical": reordered.Bytes(),
		"unknown-field": append(canonical[:len(canonical)-1], []byte(`,"extra":true}`)...),
		"bad-signature": bytes.Replace(canonical, []byte(signer.PublicIdentity().NodeID), []byte(bytes.Repeat([]byte{'0'}, 64)), 1),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := ensurePrivateStoreDirectory(directory); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, nodeIdentityBindingFile), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDiskStore(directory, 1024*1024, 1024*1024); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("invalid identity binding returned %v", err)
			}
		})
	}
}

func TestSweepContextReturnsWhileStoreIsBusy(t *testing.T) {
	store, err := NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.SweepContext(ctx, time.Now()) }()
	select {
	case err := <-done:
		store.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("busy sweep returned %v", err)
		}
	case <-time.After(time.Second):
		store.mu.Unlock()
		t.Fatal("busy sweep ignored context cancellation")
	}
}

func TestDiskStoreRetriesDirectoryDurabilityBeforeIdempotentSuccess(t *testing.T) {
	store, err := NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	actualSync := store.syncDirectory
	store.syncDirectory = func(string) error { return errors.New("injected directory sync failure") }
	item := storedTestItem(t, mustRouteTag(t), []byte("opaque ciphertext"))
	if err := store.Put(item); err == nil {
		t.Fatal("post-rename directory sync failure was reported as success")
	}
	if err := store.Put(item); err == nil {
		t.Fatal("idempotent retry succeeded while directory durability was still unknown")
	}
	store.syncDirectory = actualSync
	if err := store.Put(item); err != nil {
		t.Fatalf("idempotent retry did not recover durability: %v", err)
	}
	if store.directorySyncPending {
		t.Fatal("successful durability retry left store degraded")
	}
}

func TestDiskStoreDoesNotExposeNondurableWrite(t *testing.T) {
	store, err := NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	actualSync := store.syncDirectory
	injected := errors.New("injected node record directory sync failure")
	store.syncDirectory = func(string) error { return injected }
	item := storedTestItem(t, mustRouteTag(t), []byte("opaque ciphertext"))
	if err := store.Put(item); !errors.Is(err, injected) {
		t.Fatalf("nondurable node write returned %v", err)
	}
	if _, err := store.Get(item.ItemID); !errors.Is(err, injected) {
		t.Fatalf("Get exposed nondurable node item: %v", err)
	}
	if items, truncated := store.FetchLimited([]string{item.RouteTag}, 1, 1024); !truncated || len(items) != 0 {
		t.Fatalf("Fetch exposed nondurable node item: items=%d truncated=%v", len(items), truncated)
	}
	store.syncDirectory = actualSync
	if _, err := store.Get(item.ItemID); err != nil {
		t.Fatalf("durability recovery did not expose committed node item: %v", err)
	}
}

func TestDiskStoreRecoversDirectoryDurabilityAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	store, err := NewDiskStore(directory, 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	item := storedTestItem(t, mustRouteTag(t), []byte("opaque ciphertext"))
	injected := errors.New("injected node startup directory sync failure")
	store.syncDirectory = func(string) error { return injected }
	if err := store.Put(item); err == nil {
		t.Fatal("post-rename directory sync failure was reported as success")
	}
	if err := store.Close(); !errors.Is(err, injected) {
		t.Fatalf("closing degraded node store returned %v", err)
	}
	if reopened, err := newDiskStore(directory, 1024*1024, 1024*1024, func(string) error { return injected }); err == nil {
		reopened.Close()
		t.Fatal("reopen admitted visible item state without recovering directory durability")
	}
	store, err = NewDiskStore(directory, 1024*1024, 1024*1024)
	if err != nil {
		t.Fatalf("durable reopen failed: %v", err)
	}
	defer store.Close()
	if err := store.Put(item); err != nil {
		t.Fatalf("idempotent retry after startup durability recovery failed: %v", err)
	}
}

func TestSweepContextHonorsAlreadyCanceledContext(t *testing.T) {
	store, err := NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.SweepContext(ctx, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sweep returned %v", err)
	}
}
