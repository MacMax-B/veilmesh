package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func validValidationItem() StoredItem {
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
	return item
}

func TestItemValidationRejectsWeakCapability(t *testing.T) {
	item := validValidationItem()
	if err := ValidateItem(item, item.CreatedAt, DefaultMaxRetention, DefaultMaxItemBytes); err != nil {
		t.Fatalf("valid item rejected: %v", err)
	}
	weak := item
	weak.RouteTag = "predictable-mailbox"
	weak.ItemID = ComputeItemID(weak)
	if err := ValidateItem(weak, weak.CreatedAt, DefaultMaxRetention, DefaultMaxItemBytes); err == nil {
		t.Fatal("weak route capability accepted")
	}
	nonCanonical := item
	nonCanonical.RouteTag = nonCanonical.RouteTag[:len(nonCanonical.RouteTag)-1] + "B"
	nonCanonical.ItemID = ComputeItemID(nonCanonical)
	if err := ValidateItem(nonCanonical, nonCanonical.CreatedAt, DefaultMaxRetention, DefaultMaxItemBytes); err == nil {
		t.Fatal("non-canonical route capability accepted")
	}
}

func TestNodeParameterValidationRejectsResourceAmplification(t *testing.T) {
	parameters := NodeParameters{
		ProtocolVersion: ProtocolVersion,
		Difficulty:      8,
		EpochSeconds:    600,
		MaxItemBytes:    DefaultMaxItemBytes,
		MaxRetention:    DefaultMaxRetention,
		StorageCapacity: 1024,
	}
	if err := ValidateNodeParameters(parameters); err != nil {
		t.Fatalf("valid parameters rejected: %v", err)
	}
	parameters.Difficulty = MaxWorkDifficulty + 1
	if err := ValidateNodeParameters(parameters); err == nil {
		t.Fatal("unbounded proof-of-work difficulty accepted")
	}
	parameters.Difficulty = 8
	parameters.EpochSeconds = 0
	if err := ValidateNodeParameters(parameters); err == nil {
		t.Fatal("zero proof-of-work epoch accepted")
	}
}
