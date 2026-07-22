package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrInvalidItem      = errors.New("invalid stored item")
	ErrInvalidRetention = errors.New("item expiry must equal the fixed retention window")
	ErrItemTooLarge     = errors.New("item exceeds node maximum")
)

func writeBytes(buf *bytes.Buffer, value []byte) {
	// Every caller passes a protocol-bounded value (at most one proof sample,
	// route capability, identifier, or fixed-size digest).
	_ = binary.Write(buf, binary.BigEndian, uint32(len(value))) // #nosec G115 -- bounded at all parser boundaries.
	_, _ = buf.Write(value)
}

func writeString(buf *bytes.Buffer, value string) { writeBytes(buf, []byte(value)) }

func writeTime(buf *bytes.Buffer, value time.Time) {
	_ = binary.Write(buf, binary.BigEndian, value.UTC().UnixMilli())
}

func ItemCommitment(item StoredItem) []byte {
	var buf bytes.Buffer
	buf.WriteByte(item.Version)
	writeString(&buf, item.RouteTag)
	writeTime(&buf, item.CreatedAt)
	writeTime(&buf, item.ExpiresAt)
	writeBytes(&buf, item.DeleteTokenHash)
	payloadHash := sha256.Sum256(item.Payload)
	writeBytes(&buf, payloadHash[:])
	return buf.Bytes()
}

func ComputeItemID(item StoredItem) string {
	sum := sha256.Sum256(ItemCommitment(item))
	return hex.EncodeToString(sum[:])
}

func ValidRouteTag(routeTag string) bool {
	if len(routeTag) != base64.RawURLEncoding.EncodedLen(CapabilityBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(routeTag)
	return err == nil && len(decoded) == CapabilityBytes
}

func ValidateItem(item StoredItem, now time.Time, maxBytes int) error {
	if maxBytes <= 0 || maxBytes > DefaultMaxItemBytes {
		return ErrInvalidItem
	}
	if item.Version != ProtocolVersion || !ValidRouteTag(item.RouteTag) ||
		len(item.DeleteTokenHash) != sha256.Size {
		return ErrInvalidItem
	}
	if len(item.Payload) == 0 || len(item.Payload) > maxBytes {
		return ErrItemTooLarge
	}
	if item.CreatedAt.After(now.Add(5*time.Minute)) || !item.ExpiresAt.After(now) {
		return ErrInvalidItem
	}
	// The retention window is fixed by the protocol. A shorter or longer
	// expiry would let senders encode distinguishing metadata into the
	// node-visible lifetime, so exact equality is required.
	if !item.ExpiresAt.Equal(item.CreatedAt.Add(FixedItemRetention)) {
		return ErrInvalidRetention
	}
	if item.ItemID != ComputeItemID(item) {
		return ErrInvalidItem
	}
	return nil
}

func ValidateNodeParameters(parameters NodeParameters) error {
	if parameters.ProtocolVersion != ProtocolVersion ||
		parameters.Difficulty > MaxWorkDifficulty ||
		parameters.EpochSeconds < MinWorkEpochSeconds || parameters.EpochSeconds > MaxWorkEpochSeconds ||
		parameters.MaxItemBytes <= 0 || parameters.MaxItemBytes > DefaultMaxItemBytes ||
		parameters.StorageUsed < 0 || parameters.StorageCapacity <= 0 ||
		parameters.StorageUsed > parameters.StorageCapacity {
		return errors.New("invalid node parameters")
	}
	return nil
}

func ReceiptSigningBytes(receipt StorageReceipt) []byte {
	var buf bytes.Buffer
	writeString(&buf, receipt.NodeID)
	writeString(&buf, receipt.ItemID)
	writeBytes(&buf, receipt.PayloadHash)
	writeTime(&buf, receipt.StoredAt)
	writeTime(&buf, receipt.ExpiresAt)
	return buf.Bytes()
}

func DeleteReceiptSigningBytes(receipt DeleteReceipt) []byte {
	var buf bytes.Buffer
	writeString(&buf, receipt.NodeID)
	writeString(&buf, receipt.ItemID)
	writeTime(&buf, receipt.DeletedAt)
	return buf.Bytes()
}

func ProofSigningBytes(proof StorageProof) []byte {
	var buf bytes.Buffer
	writeString(&buf, proof.NodeID)
	writeString(&buf, proof.ItemID)
	writeBytes(&buf, proof.Nonce)
	_ = binary.Write(&buf, binary.BigEndian, proof.Offset)
	writeBytes(&buf, proof.Sample)
	writeBytes(&buf, proof.PayloadHash)
	writeTime(&buf, proof.ProvedAt)
	return buf.Bytes()
}
