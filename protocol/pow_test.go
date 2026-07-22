package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestSolveAndVerifyWork(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	item := StoredItem{
		Version:         ProtocolVersion,
		RouteTag:        base64.RawURLEncoding.EncodeToString(make([]byte, CapabilityBytes)),
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
		DeleteTokenHash: make([]byte, sha256.Size),
		Payload:         []byte("ciphertext"),
	}
	item.ItemID = ComputeItemID(item)
	proof, err := SolveWork(context.Background(), item, 600, 10)
	if err != nil {
		t.Fatal(err)
	}
	item.Work = proof
	if err := VerifyWork(item, time.Now(), 600, 10); err != nil {
		t.Fatalf("valid work rejected: %v", err)
	}
	item.ItemID = "tampered"
	if err := VerifyWork(item, time.Now(), 600, 10); err == nil {
		t.Fatal("tampered item unexpectedly retained valid work")
	}
}
