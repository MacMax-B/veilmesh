package protocol

import (
	"testing"
	"time"
)

func FuzzValidateItem(f *testing.F) {
	seed := validValidationItem()
	f.Add(seed.RouteTag, seed.ItemID, seed.DeleteTokenHash, seed.Payload, seed.CreatedAt.UnixNano(), seed.ExpiresAt.UnixNano())
	f.Fuzz(func(t *testing.T, routeTag, itemID string, deleteHash, payload []byte, createdNanos, expiresNanos int64) {
		item := StoredItem{
			Version:         ProtocolVersion,
			ItemID:          itemID,
			RouteTag:        routeTag,
			CreatedAt:       time.Unix(0, createdNanos),
			ExpiresAt:       time.Unix(0, expiresNanos),
			DeleteTokenHash: deleteHash,
			Payload:         payload,
		}
		_ = ValidateItem(item, time.Now(), DefaultMaxRetention, DefaultMaxItemBytes)
	})
}
