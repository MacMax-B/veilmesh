package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/MacMax-B/propagare/account"
	"github.com/MacMax-B/propagare/identity"
)

var ErrSyncEventReplay = errors.New("device-sync event was already accepted")

// EncryptedSyncReplayStore implements account.SyncReplayStore with the same
// authenticated, process-locked disk store used by Core. It does not own the
// underlying store; the caller remains responsible for closing it.
type EncryptedSyncReplayStore struct {
	store *EncryptedDiskStore
}

var _ account.SyncReplayStore = (*EncryptedSyncReplayStore)(nil)

func NewEncryptedSyncReplayStore(store *EncryptedDiskStore) (*EncryptedSyncReplayStore, error) {
	if store == nil {
		return nil, errors.New("encrypted client store is required for device-sync replay protection")
	}
	return &EncryptedSyncReplayStore{store: store}, nil
}

// Accept durably reserves one account/event pair. Concurrent callers and a
// process restarted after the atomic file publication can observe at most one
// successful acceptance.
func (replays *EncryptedSyncReplayStore) Accept(ctx context.Context, accountID, eventID string, expiresAt time.Time) error {
	if replays == nil || replays.store == nil || ctx == nil || !identity.ValidAccountID(accountID) ||
		!validSyncReplayEventID(eventID) || expiresAt.IsZero() {
		return errors.New("invalid device-sync replay reservation")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt = expiresAt.UTC().Truncate(time.Millisecond)
	if !expiresAt.After(now) || expiresAt.After(now.Add(account.MaxSyncEventLifetime+5*time.Minute)) {
		return errors.New("invalid device-sync replay expiry")
	}
	digest := sha256.Sum256([]byte("enig/device-sync-replay/v1\x00" + accountID + "\x00" + eventID))
	record := LocalRecord{
		Version:     ClientStoreVersion,
		ID:          "sync-replay." + hex.EncodeToString(digest[:]),
		Kind:        LocalKindReplay,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   expiresAt,
		PrunePolicy: PruneAfterExpiry,
		Payload:     append([]byte(nil), digest[:]...),
	}
	if _, err := replays.store.putIfAbsent(ctx, record, now); err != nil {
		if errors.Is(err, ErrLocalRecordExists) {
			return ErrSyncEventReplay
		}
		return err
	}
	return nil
}

func validSyncReplayEventID(eventID string) bool {
	if len(eventID) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(eventID)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == eventID
}
