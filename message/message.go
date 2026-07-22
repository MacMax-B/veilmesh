// Package message defines authenticated application messages and client
// delivery receipts. These objects must be encrypted inside an audited ratchet;
// they are not a replacement for a ratchet or metadata-private transport.
package message

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"veilmesh/account"
	"veilmesh/identity"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	Version               = 1
	MaxBodyBytes          = 192 * 1024
	MaxSignedMessageBytes = 300 * 1024
	MaxReceiptBytes       = 64 * 1024
	messageIDBytes        = 32
)

const directKind = "direct"

type SignedMessage struct {
	Version               uint8                     `json:"version"`
	Kind                  string                    `json:"kind"`
	MessageID             string                    `json:"message_id"`
	SenderID              string                    `json:"sender_id"`
	RecipientID           string                    `json:"recipient_id"`
	SenderProfileRevision uint64                    `json:"sender_profile_revision"`
	SenderDevice          account.DeviceCertificate `json:"sender_device"`
	CreatedAt             time.Time                 `json:"created_at"`
	ExpiresAt             time.Time                 `json:"expires_at"`
	Body                  []byte                    `json:"body"`
	Signature             protocol.HybridSignature  `json:"signature"`
}

type VerifiedMessage struct{ message SignedMessage }

func (verified VerifiedMessage) Message() SignedMessage { return cloneMessage(verified.message) }

func randomMessageID() (string, error) {
	value := make([]byte, messageIDBytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validMessageID(messageID string) bool {
	if len(messageID) != base64.RawURLEncoding.EncodedLen(messageIDBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(messageID)
	return err == nil && len(decoded) == messageIDBytes
}

func messageSigningBytes(message SignedMessage) ([]byte, error) {
	message.Signature = protocol.HybridSignature{}
	return json.Marshal(message)
}

func NewDirect(sender *account.LocalAccount, recipientID string, body []byte, now time.Time, retention time.Duration) (SignedMessage, error) {
	if sender == nil || !identity.ValidAccountID(recipientID) || recipientID == sender.ID() ||
		len(body) == 0 || len(body) > MaxBodyBytes || now.IsZero() || retention <= 0 ||
		retention > protocol.DefaultMaxRetention {
		return SignedMessage{}, errors.New("invalid direct message input")
	}
	messageID, err := randomMessageID()
	if err != nil {
		return SignedMessage{}, err
	}
	createdAt := now.UTC().Truncate(time.Millisecond)
	message := SignedMessage{
		Version:               Version,
		Kind:                  directKind,
		MessageID:             messageID,
		SenderID:              sender.ID(),
		RecipientID:           recipientID,
		SenderProfileRevision: sender.Profile().Revision,
		SenderDevice:          sender.DeviceCertificate(),
		CreatedAt:             createdAt,
		ExpiresAt:             createdAt.Add(retention).Truncate(time.Millisecond),
		Body:                  append([]byte(nil), body...),
	}
	encoded, err := messageSigningBytes(message)
	if err != nil {
		return SignedMessage{}, err
	}
	if len(encoded) > MaxSignedMessageBytes {
		return SignedMessage{}, errors.New("signed message exceeds size limit")
	}
	message.Signature, err = sender.SignDevicePayload("client-direct-message", encoded)
	return message, err
}

func validateDirectStructure(message SignedMessage, expectedRecipient string, now time.Time) error {
	if message.Version != Version || message.Kind != directKind || !validMessageID(message.MessageID) ||
		!identity.ValidAccountID(message.SenderID) || !identity.ValidAccountID(message.RecipientID) ||
		message.SenderID == message.RecipientID || message.RecipientID != expectedRecipient ||
		message.SenderProfileRevision == 0 || message.SenderDevice.AccountID != message.SenderID || len(message.Body) == 0 ||
		len(message.Body) > MaxBodyBytes || message.CreatedAt.IsZero() || message.ExpiresAt.IsZero() ||
		message.CreatedAt.After(now.Add(5*time.Minute)) || !message.ExpiresAt.After(message.CreatedAt) ||
		message.ExpiresAt.Sub(message.CreatedAt) > protocol.DefaultMaxRetention || now.After(message.ExpiresAt.Add(5*time.Minute)) {
		return errors.New("invalid direct message")
	}
	return nil
}

func VerifyDirect(senderProfile account.PublicProfile, message SignedMessage, expectedRecipient string, now time.Time) (VerifiedMessage, error) {
	if err := validateDirectStructure(message, expectedRecipient, now); err != nil {
		return VerifiedMessage{}, err
	}
	if senderProfile.AccountID != message.SenderID || senderProfile.Revision < message.SenderProfileRevision ||
		account.VerifyPublicProfile(senderProfile, now) != nil ||
		!account.VerifyDevice(senderProfile.AccountPublic, message.SenderDevice) ||
		!account.ProfileContainsDevice(senderProfile, message.SenderDevice) {
		return VerifiedMessage{}, errors.New("message sender is not certified by the ENIG account")
	}
	encoded, err := messageSigningBytes(message)
	if err != nil || len(encoded) > MaxSignedMessageBytes ||
		!pqcrypto.Verify(message.SenderDevice.Device.SigningKey, "client-direct-message", encoded, message.Signature) {
		return VerifiedMessage{}, errors.New("invalid direct message signature")
	}
	return VerifiedMessage{message: cloneMessage(message)}, nil
}

func Encode(message SignedMessage) ([]byte, error) {
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > MaxSignedMessageBytes {
		return nil, errors.New("signed message size is out of range")
	}
	return encoded, nil
}

func Decode(encoded []byte) (SignedMessage, error) {
	if len(encoded) == 0 || len(encoded) > MaxSignedMessageBytes {
		return SignedMessage{}, errors.New("signed message size is out of range")
	}
	var message SignedMessage
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return SignedMessage{}, err
	}
	if err := requireEOF(decoder); err != nil {
		return SignedMessage{}, err
	}
	if len(message.Body) == 0 || len(message.Body) > MaxBodyBytes {
		return SignedMessage{}, errors.New("message body size is out of range")
	}
	return message, nil
}

func Digest(message SignedMessage) ([]byte, error) {
	encoded, err := Encode(message)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func cloneMessage(message SignedMessage) SignedMessage {
	result := message
	result.Body = append([]byte(nil), message.Body...)
	result.SenderDevice = cloneCertificate(message.SenderDevice)
	result.Signature.Ed25519 = append([]byte(nil), message.Signature.Ed25519...)
	result.Signature.MLDSA65 = append([]byte(nil), message.Signature.MLDSA65...)
	return result
}

func cloneCertificate(certificate account.DeviceCertificate) account.DeviceCertificate {
	result := certificate
	result.Device.HPKEPublicKey = append([]byte(nil), certificate.Device.HPKEPublicKey...)
	result.Device.SigningKey.Ed25519Public = append([]byte(nil), certificate.Device.SigningKey.Ed25519Public...)
	result.Device.SigningKey.MLDSA65Public = append([]byte(nil), certificate.Device.SigningKey.MLDSA65Public...)
	result.Signature.Ed25519 = append([]byte(nil), certificate.Signature.Ed25519...)
	result.Signature.MLDSA65 = append([]byte(nil), certificate.Signature.MLDSA65...)
	return result
}
