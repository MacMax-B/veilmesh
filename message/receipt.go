package message

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/MacMax-B/propagare/account"
	"github.com/MacMax-B/propagare/identity"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

// DeliveryReceipt proves that a certified recipient device accepted and
// authenticated a specific message. It must itself travel inside the ratchet.
// A storage receipt from a node is not a DeliveryReceipt.
type DeliveryReceipt struct {
	Version                 uint8                     `json:"version"`
	MessageID               string                    `json:"message_id"`
	MessageDigest           []byte                    `json:"message_digest"`
	SenderID                string                    `json:"sender_id"`
	RecipientID             string                    `json:"recipient_id"`
	ReceiverProfileRevision uint64                    `json:"receiver_profile_revision"`
	ReceiverDevice          account.DeviceCertificate `json:"receiver_device"`
	ReceivedAt              time.Time                 `json:"received_at"`
	Signature               protocol.HybridSignature  `json:"signature"`
}

func receiptSigningBytes(receipt DeliveryReceipt) ([]byte, error) {
	receipt.Signature = protocol.HybridSignature{}
	return json.Marshal(receipt)
}

func NewDeliveryReceipt(receiver *account.LocalAccount, verified VerifiedMessage, now time.Time) (DeliveryReceipt, error) {
	message := verified.message
	if receiver == nil || message.MessageID == "" || receiver.ID() != message.RecipientID || now.IsZero() ||
		now.Before(message.CreatedAt.Add(-5*time.Minute)) || now.After(message.ExpiresAt.Add(5*time.Minute)) {
		return DeliveryReceipt{}, errors.New("receipt receiver does not match verified message")
	}
	digest, err := Digest(message)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	receipt := DeliveryReceipt{
		Version:                 Version,
		MessageID:               message.MessageID,
		MessageDigest:           digest,
		SenderID:                receiver.ID(),
		RecipientID:             message.SenderID,
		ReceiverProfileRevision: receiver.Profile().Revision,
		ReceiverDevice:          receiver.DeviceCertificate(),
		ReceivedAt:              now.UTC().Truncate(time.Millisecond),
	}
	encoded, err := receiptSigningBytes(receipt)
	if err != nil {
		return DeliveryReceipt{}, err
	}
	if len(encoded) > MaxReceiptBytes {
		return DeliveryReceipt{}, errors.New("delivery receipt exceeds size limit")
	}
	receipt.Signature, err = receiver.SignDevicePayload("client-delivery-receipt", encoded)
	return receipt, err
}

func VerifyDeliveryReceipt(receiverProfile account.PublicProfile, receipt DeliveryReceipt, original SignedMessage, now time.Time) error {
	if receipt.Version != Version || !validMessageID(receipt.MessageID) || receipt.MessageID != original.MessageID ||
		len(receipt.MessageDigest) != sha256.Size || !identity.ValidAccountID(receipt.SenderID) ||
		!identity.ValidAccountID(receipt.RecipientID) || receipt.SenderID != original.RecipientID ||
		receipt.RecipientID != original.SenderID || receiverProfile.AccountID != receipt.SenderID ||
		receipt.ReceiverProfileRevision == 0 || receiverProfile.Revision < receipt.ReceiverProfileRevision ||
		receipt.ReceiverDevice.AccountID != receipt.SenderID || receipt.ReceivedAt.IsZero() ||
		receipt.ReceivedAt.Before(original.CreatedAt.Add(-5*time.Minute)) ||
		receipt.ReceivedAt.After(original.ExpiresAt.Add(5*time.Minute)) || receipt.ReceivedAt.After(now.Add(5*time.Minute)) {
		return errors.New("invalid delivery receipt")
	}
	if err := account.VerifyPublicProfile(receiverProfile, now); err != nil ||
		!account.VerifyDevice(receiverProfile.AccountPublic, receipt.ReceiverDevice) ||
		!account.ProfileContainsDevice(receiverProfile, receipt.ReceiverDevice) {
		return errors.New("receipt device is not certified by the ENIG account")
	}
	digest, err := Digest(original)
	if err != nil || !bytes.Equal(digest, receipt.MessageDigest) {
		return errors.New("delivery receipt message digest mismatch")
	}
	encoded, err := receiptSigningBytes(receipt)
	if err != nil || len(encoded) > MaxReceiptBytes ||
		!pqcrypto.Verify(receipt.ReceiverDevice.Device.SigningKey, "client-delivery-receipt", encoded, receipt.Signature) {
		return errors.New("invalid delivery receipt signature")
	}
	return nil
}

func EncodeDeliveryReceipt(receipt DeliveryReceipt) ([]byte, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > MaxReceiptBytes {
		return nil, errors.New("delivery receipt size is out of range")
	}
	return encoded, nil
}

func DecodeDeliveryReceipt(encoded []byte) (DeliveryReceipt, error) {
	if len(encoded) == 0 || len(encoded) > MaxReceiptBytes {
		return DeliveryReceipt{}, errors.New("delivery receipt size is out of range")
	}
	var receipt DeliveryReceipt
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return DeliveryReceipt{}, err
	}
	if err := requireEOF(decoder); err != nil {
		return DeliveryReceipt{}, err
	}
	if !validMessageID(receipt.MessageID) || len(receipt.MessageDigest) != sha256.Size {
		return DeliveryReceipt{}, errors.New("invalid delivery receipt structure")
	}
	return receipt, nil
}
