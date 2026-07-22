package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/account"
	"github.com/MacMax-B/propagare/pqcrypto"
)

func TestEncryptedSyncReplayStoreIsAtomicAndSurvivesRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	replays, err := NewEncryptedSyncReplayStore(store)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	accountID := account.AccountID(signer.PublicIdentity())
	eventBytes := make([]byte, 32)
	if _, err := rand.Read(eventBytes); err != nil {
		t.Fatal(err)
	}
	eventID := base64.RawURLEncoding.EncodeToString(eventBytes)
	expiresAt := now.Add(time.Hour)

	const attempts = 16
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- replays.Accept(context.Background(), accountID, eventID, expiresAt)
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for reserveErr := range results {
		if reserveErr == nil {
			successes++
			continue
		}
		if !errors.Is(reserveErr, ErrSyncEventReplay) {
			t.Fatalf("unexpected replay reservation error: %v", reserveErr)
		}
	}
	if successes != 1 {
		t.Fatalf("atomic replay reservation admitted %d callers", successes)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: directory, Key: key, MaxBytes: 1024 * 1024,
	}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restartedReplays, err := NewEncryptedSyncReplayStore(reopened)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedReplays.Accept(context.Background(), accountID, eventID, expiresAt); !errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("restart forgot accepted device-sync event: %v", err)
	}
}

func TestEncryptedSyncReplayStoreIntegratesWithDeviceSync(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	local, err := account.Register(context.Background(), &syncTestVault{})
	if err != nil {
		t.Fatal(err)
	}
	profile := local.Profile()
	_, envelopes, err := account.SealSyncEvent(local, profile, profile.Revision, []byte("durable"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	replays, err := NewEncryptedSyncReplayStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.OpenSyncEvent(
		context.Background(), local, profile, profile.Revision, envelopes[0], now, replays,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := account.OpenSyncEvent(
		context.Background(), local, profile, profile.Revision, envelopes[0], now, replays,
	); !errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("durable replay store admitted the same sync event twice: %v", err)
	}
}

func TestSyncReplayReservationRetriesDurabilityBeforeReportingReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := NewEncryptedDiskStore(DiskClientStoreConfig{
		Directory: t.TempDir(), Key: clientStoreKey(t), MaxBytes: 1024 * 1024,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	replays, err := NewEncryptedSyncReplayStore(store)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	eventBytes := make([]byte, 32)
	if _, err := rand.Read(eventBytes); err != nil {
		t.Fatal(err)
	}
	accountID := account.AccountID(signer.PublicIdentity())
	eventID := base64.RawURLEncoding.EncodeToString(eventBytes)
	actualSync := store.syncDirectory
	store.syncDirectory = func(string) error { return errors.New("injected client directory sync failure") }
	if err := replays.Accept(context.Background(), accountID, eventID, now.Add(time.Hour)); err == nil || errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("first nondurable reservation returned %v", err)
	}
	if err := replays.Accept(context.Background(), accountID, eventID, now.Add(time.Hour)); err == nil || errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("retry reported a replay before durability recovery: %v", err)
	}
	store.syncDirectory = actualSync
	if err := replays.Accept(context.Background(), accountID, eventID, now.Add(time.Hour)); !errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("durably recovered reservation returned %v", err)
	}
}

func TestSyncReplayReservationRecoversDurabilityAcrossRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	directory := t.TempDir()
	key := clientStoreKey(t)
	config := DiskClientStoreConfig{Directory: directory, Key: key, MaxBytes: 1024 * 1024}
	store, err := NewEncryptedDiskStore(config, now)
	if err != nil {
		t.Fatal(err)
	}
	replays, err := NewEncryptedSyncReplayStore(store)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	eventBytes := make([]byte, 32)
	if _, err := rand.Read(eventBytes); err != nil {
		t.Fatal(err)
	}
	accountID := account.AccountID(signer.PublicIdentity())
	eventID := base64.RawURLEncoding.EncodeToString(eventBytes)
	injected := errors.New("injected client startup directory sync failure")
	store.syncDirectory = func(string) error { return injected }
	if err := replays.Accept(context.Background(), accountID, eventID, now.Add(time.Hour)); err == nil || errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("first nondurable reservation returned %v", err)
	}
	if err := store.Close(); !errors.Is(err, injected) {
		t.Fatalf("closing degraded replay store returned %v", err)
	}
	if reopened, err := newEncryptedDiskStore(config, now, func(string) error { return injected }); err == nil {
		reopened.Close()
		t.Fatal("reopen admitted visible replay state without recovering directory durability")
	}
	store, err = NewEncryptedDiskStore(config, now)
	if err != nil {
		t.Fatalf("durable reopen failed: %v", err)
	}
	defer store.Close()
	replays, err = NewEncryptedSyncReplayStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := replays.Accept(context.Background(), accountID, eventID, now.Add(time.Hour)); !errors.Is(err, ErrSyncEventReplay) {
		t.Fatalf("recovered reservation returned %v", err)
	}
}

type syncTestVault struct {
	mu     sync.Mutex
	secret []byte
}

func (vault *syncTestVault) Store(_ context.Context, _ string, secret []byte) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.secret = append([]byte(nil), secret...)
	return nil
}

func (vault *syncTestVault) Load(context.Context, string) ([]byte, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	return append([]byte(nil), vault.secret...), nil
}
