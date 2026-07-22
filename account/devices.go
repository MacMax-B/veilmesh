package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/MacMax-B/propagare/identity"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

const (
	// MaxDevicesPerAccount is derived from MaxPublicProfileBytes and the fixed
	// ML-DSA-65, hybrid KEM, and JSON/base64 overhead. A profile containing this
	// many devices must still fit the public-profile wire limit.
	MaxDevicesPerAccount      = 27
	MaxDeviceIDBytes          = 128
	SyncEventVersion          = 1
	MaxSyncEventPayloadBytes  = 128 * 1024
	MaxSignedSyncEventBytes   = 224 * 1024
	MaxSyncEncapsulationBytes = 2 * 1024
	MaxSyncEventLifetime      = protocol.FixedItemRetention
	syncEventIDBytes          = 32
	syncEventDomain           = "device-sync-event"
)

var ErrSyncReplayStoreRequired = errors.New("persistent atomic device-sync replay store required")

type DeviceCertificate struct {
	AccountID string                    `json:"account_id"`
	Device    protocol.DeviceDescriptor `json:"device"`
	Signature protocol.HybridSignature  `json:"signature"`
}

type DeviceSet struct {
	AccountID     string
	AccountPublic protocol.NodePublicIdentity
	Devices       map[string]DeviceCertificate
}

// SignedSyncEvent is authenticated by a currently active sender device before
// it is independently HPKE-encrypted to every currently active account device.
// The event is not valid on its own: receivers must verify it against a current,
// revision-pinned PublicProfile and atomically reserve EventID in durable state.
type SignedSyncEvent struct {
	Version         uint8                    `json:"version"`
	EventID         string                   `json:"event_id"`
	AccountID       string                   `json:"account_id"`
	ProfileRevision uint64                   `json:"profile_revision"`
	SenderDevice    DeviceCertificate        `json:"sender_device"`
	CreatedAt       time.Time                `json:"created_at"`
	ExpiresAt       time.Time                `json:"expires_at"`
	Payload         []byte                   `json:"payload"`
	Signature       protocol.HybridSignature `json:"signature"`
}

type VerifiedSyncEvent struct{ event SignedSyncEvent }

func (verified VerifiedSyncEvent) Event() SignedSyncEvent {
	return cloneSyncEvent(verified.event)
}

// SyncReplayStore must atomically reject an already accepted
// (accountID,eventID) pair and persist it at least until expiresAt. An in-memory
// implementation does not satisfy the production contract.
type SyncReplayStore interface {
	Accept(ctx context.Context, accountID, eventID string, expiresAt time.Time) error
}

func AccountID(public protocol.NodePublicIdentity) string {
	return identity.AccountID(public)
}

func validDeviceID(deviceID string) bool {
	return len(deviceID) <= MaxDeviceIDBytes && identity.ValidDeviceID(deviceID)
}

func validDeviceDescriptor(device protocol.DeviceDescriptor) bool {
	return validDeviceID(device.DeviceID) && identity.ValidAccountID(device.AccountID) &&
		pqcrypto.ValidPublicIdentity(device.SigningKey) &&
		device.DeviceID == identity.DeviceID(device.SigningKey) &&
		pqcrypto.ValidateHybridKEMPublicKey(device.HPKEPublicKey) == nil
}

func certificateBytes(certificate DeviceCertificate) ([]byte, error) {
	unsigned := struct {
		AccountID string                    `json:"account_id"`
		Device    protocol.DeviceDescriptor `json:"device"`
	}{certificate.AccountID, certificate.Device}
	return json.Marshal(unsigned)
}

func SignDevice(accountSigner *pqcrypto.HybridSigner, device protocol.DeviceDescriptor) (DeviceCertificate, error) {
	if accountSigner == nil {
		return DeviceCertificate{}, errors.New("account signer is required")
	}
	accountPublic := accountSigner.PublicIdentity()
	accountID := AccountID(accountPublic)
	if device.AccountID != accountID || !validDeviceDescriptor(device) {
		return DeviceCertificate{}, errors.New("invalid device descriptor")
	}
	certificate := DeviceCertificate{AccountID: accountID, Device: device}
	message, err := certificateBytes(certificate)
	if err != nil {
		return DeviceCertificate{}, err
	}
	certificate.Signature, err = accountSigner.Sign("device-certificate", message)
	return certificate, err
}

func VerifyDevice(accountPublic protocol.NodePublicIdentity, certificate DeviceCertificate) bool {
	if !pqcrypto.ValidPublicIdentity(accountPublic) || certificate.AccountID != AccountID(accountPublic) ||
		certificate.Device.AccountID != certificate.AccountID || !validDeviceDescriptor(certificate.Device) {
		return false
	}
	message, err := certificateBytes(certificate)
	return err == nil && pqcrypto.Verify(accountPublic, "device-certificate", message, certificate.Signature)
}

func randomSyncEventID() (string, error) {
	value := make([]byte, syncEventIDBytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validSyncEventID(eventID string) bool {
	if len(eventID) != base64.RawURLEncoding.EncodedLen(syncEventIDBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(eventID)
	return err == nil && len(decoded) == syncEventIDBytes
}

func syncEventSigningBytes(event SignedSyncEvent) ([]byte, error) {
	event.Signature = protocol.HybridSignature{}
	return json.Marshal(event)
}

func syncEventAAD(accountID, deviceID string) []byte {
	return []byte("enig/device-sync/v2\x00" + accountID + "\x00" + deviceID)
}

func validateSyncEventStructure(event SignedSyncEvent, currentProfile PublicProfile, now time.Time) error {
	if event.Version != SyncEventVersion || !validSyncEventID(event.EventID) ||
		event.AccountID != currentProfile.AccountID || event.ProfileRevision == 0 ||
		event.ProfileRevision != currentProfile.Revision || event.SenderDevice.AccountID != event.AccountID ||
		event.CreatedAt.IsZero() || event.ExpiresAt.IsZero() ||
		event.CreatedAt.After(now.Add(5*time.Minute)) || !event.ExpiresAt.After(event.CreatedAt) ||
		event.ExpiresAt.Sub(event.CreatedAt) > MaxSyncEventLifetime || !event.ExpiresAt.After(now) ||
		len(event.Payload) == 0 || len(event.Payload) > MaxSyncEventPayloadBytes {
		return errors.New("invalid signed device-sync event")
	}
	if !VerifyDevice(currentProfile.AccountPublic, event.SenderDevice) ||
		!ProfileContainsDevice(currentProfile, event.SenderDevice) {
		return errors.New("device-sync sender is not active in the current profile")
	}
	unsigned, err := syncEventSigningBytes(event)
	if err != nil || len(unsigned) > MaxSignedSyncEventBytes ||
		!pqcrypto.Verify(event.SenderDevice.Device.SigningKey, syncEventDomain, unsigned, event.Signature) {
		return errors.New("invalid device-sync event signature")
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxSignedSyncEventBytes {
		return errors.New("signed device-sync event size is out of range")
	}
	return nil
}

// SealSyncEvent signs one event with sender's certified device key and
// encrypts it independently to every active device in currentProfile.
// minimumRevision must come from locally protected state; a directory cannot
// choose it. This prevents a valid historical profile from re-adding revoked
// recipients through rollback.
func SealSyncEvent(sender *LocalAccount, currentProfile PublicProfile, minimumRevision uint64, payload []byte, now time.Time, lifetime time.Duration) (SignedSyncEvent, []protocol.DeviceSyncEnvelope, error) {
	if sender == nil || minimumRevision == 0 || now.IsZero() || lifetime < time.Millisecond || lifetime > MaxSyncEventLifetime ||
		len(payload) == 0 || len(payload) > MaxSyncEventPayloadBytes {
		return SignedSyncEvent{}, nil, errors.New("invalid device-sync input")
	}
	if err := VerifyPublicProfile(currentProfile, now); err != nil {
		return SignedSyncEvent{}, nil, fmt.Errorf("verify current device-sync profile: %w", err)
	}
	senderCertificate := sender.DeviceCertificate()
	if currentProfile.Revision < minimumRevision || sender.ID() != currentProfile.AccountID ||
		!ProfileContainsDevice(currentProfile, senderCertificate) {
		return SignedSyncEvent{}, nil, errors.New("device-sync profile is rolled back or sender is inactive")
	}
	eventID, err := randomSyncEventID()
	if err != nil {
		return SignedSyncEvent{}, nil, err
	}
	createdAt := now.UTC().Truncate(time.Millisecond)
	event := SignedSyncEvent{
		Version:         SyncEventVersion,
		EventID:         eventID,
		AccountID:       currentProfile.AccountID,
		ProfileRevision: currentProfile.Revision,
		SenderDevice:    senderCertificate,
		CreatedAt:       createdAt,
		ExpiresAt:       createdAt.Add(lifetime).Truncate(time.Millisecond),
		Payload:         append([]byte(nil), payload...),
	}
	unsigned, err := syncEventSigningBytes(event)
	if err != nil || len(unsigned) > MaxSignedSyncEventBytes {
		return SignedSyncEvent{}, nil, errors.New("signed device-sync event exceeds size limit")
	}
	event.Signature, err = sender.SignDevicePayload(syncEventDomain, unsigned)
	if err != nil {
		return SignedSyncEvent{}, nil, err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return SignedSyncEvent{}, nil, err
	}
	if len(encoded) == 0 || len(encoded) > MaxSignedSyncEventBytes {
		return SignedSyncEvent{}, nil, errors.New("signed device-sync event exceeds size limit")
	}

	result := make([]protocol.DeviceSyncEnvelope, 0, len(currentProfile.Devices))
	for _, certificate := range currentProfile.Devices {
		aad := syncEventAAD(currentProfile.AccountID, certificate.Device.DeviceID)
		encapsulation, ciphertext, sealErr := pqcrypto.Seal(certificate.Device.HPKEPublicKey, aad, encoded)
		if sealErr != nil {
			return SignedSyncEvent{}, nil, sealErr
		}
		envelope := protocol.DeviceSyncEnvelope{
			DeviceID: certificate.Device.DeviceID,
			Payload: protocol.DirectCiphertext{
				Suite: pqcrypto.HybridHPKESuite, Encapsulation: encapsulation, Ciphertext: ciphertext,
			},
		}
		wire, marshalErr := json.Marshal(envelope)
		if marshalErr != nil || len(wire) > protocol.DefaultMaxItemBytes {
			return SignedSyncEvent{}, nil, errors.New("device-sync envelope exceeds transport item limit")
		}
		result = append(result, envelope)
	}
	return cloneSyncEvent(event), result, nil
}

// OpenSyncEvent decrypts and authenticates an event, requires its exact profile
// revision to remain current, verifies both endpoint devices, and atomically
// reserves its event ID in durable replay state before returning plaintext.
// minimumRevision must come from locally protected state.
func OpenSyncEvent(ctx context.Context, local *LocalAccount, currentProfile PublicProfile, minimumRevision uint64, envelope protocol.DeviceSyncEnvelope, now time.Time, replays SyncReplayStore) (VerifiedSyncEvent, error) {
	if replays == nil {
		return VerifiedSyncEvent{}, ErrSyncReplayStoreRequired
	}
	if ctx == nil || local == nil {
		return VerifiedSyncEvent{}, errors.New("account: invalid sync event opener")
	}
	if minimumRevision == 0 || now.IsZero() || envelope.DeviceID != local.DeviceID() || !validDeviceID(envelope.DeviceID) ||
		envelope.Payload.Suite != pqcrypto.HybridHPKESuite || len(envelope.Payload.Encapsulation) == 0 ||
		len(envelope.Payload.Encapsulation) > MaxSyncEncapsulationBytes || len(envelope.Payload.Ciphertext) == 0 ||
		len(envelope.Payload.Ciphertext) > MaxSignedSyncEventBytes+1024 {
		return VerifiedSyncEvent{}, errors.New("device-sync envelope is out of range")
	}
	if err := VerifyPublicProfile(currentProfile, now); err != nil {
		return VerifiedSyncEvent{}, fmt.Errorf("verify current device-sync profile: %w", err)
	}
	localCertificate := local.DeviceCertificate()
	if currentProfile.Revision < minimumRevision || local.ID() != currentProfile.AccountID ||
		!VerifyDevice(currentProfile.AccountPublic, localCertificate) ||
		!ProfileContainsDevice(currentProfile, localCertificate) {
		return VerifiedSyncEvent{}, errors.New("device-sync profile is rolled back or recipient is inactive")
	}
	plaintext, err := local.OpenDeviceEnvelope(
		envelope.Payload.Encapsulation,
		syncEventAAD(currentProfile.AccountID, envelope.DeviceID),
		envelope.Payload.Ciphertext,
	)
	if err != nil {
		return VerifiedSyncEvent{}, err
	}
	defer zero(plaintext)
	if len(plaintext) == 0 || len(plaintext) > MaxSignedSyncEventBytes {
		return VerifiedSyncEvent{}, errors.New("signed device-sync plaintext is out of range")
	}
	var event SignedSyncEvent
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return VerifiedSyncEvent{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return VerifiedSyncEvent{}, err
	}
	canonical, err := json.Marshal(event)
	if err != nil || !bytes.Equal(canonical, plaintext) {
		return VerifiedSyncEvent{}, errors.New("device-sync event encoding is not canonical")
	}
	if err := validateSyncEventStructure(event, currentProfile, now); err != nil {
		return VerifiedSyncEvent{}, err
	}
	if err := replays.Accept(ctx, event.AccountID, event.EventID, event.ExpiresAt); err != nil {
		return VerifiedSyncEvent{}, fmt.Errorf("reject replayed device-sync event: %w", err)
	}
	return VerifiedSyncEvent{event: cloneSyncEvent(event)}, nil
}

func cloneSyncEvent(event SignedSyncEvent) SignedSyncEvent {
	result := event
	result.SenderDevice = cloneCertificate(event.SenderDevice)
	result.Payload = append([]byte(nil), event.Payload...)
	result.Signature.Ed25519 = append([]byte(nil), event.Signature.Ed25519...)
	result.Signature.MLDSA65 = append([]byte(nil), event.Signature.MLDSA65...)
	return result
}
