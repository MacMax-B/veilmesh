package message

import (
	"context"
	"errors"
	"fmt"
	"time"

	"veilmesh/account"
	"veilmesh/identity"
	"veilmesh/protocol"
)

const MaxRatchetSkippedKeys = 2048

var (
	ErrRatchetProviderRequired          = errors.New("audited PQXDH/Double-or-Triple-Ratchet provider required")
	ErrMetadataPrivateTransportRequired = errors.New("metadata-private mix transport with cover traffic required")
	ErrReplayStoreRequired              = errors.New("persistent atomic message replay store required")
)

type RatchetSecurity struct {
	Protocol               string
	IndependentAudit       string
	ForwardSecrecy         bool
	PostCompromiseSecurity bool
	PostQuantumHandshake   bool
	UniquePerMessageKeys   bool
	DeletesConsumedKeys    bool
	MaxSkippedMessageKeys  int
}

type RoutedCiphertext struct {
	RouteTag  string
	Payload   []byte
	ExpiresAt time.Time
}

// RatchetProvider is a narrow boundary for an audited implementation. The
// provider owns session state, prekeys, skipped-key limits, key deletion, and
// replay handling at the cryptographic layer. VeilMesh does not implement a
// custom ratchet behind this interface.
type RatchetProvider interface {
	Security() RatchetSecurity
	Encrypt(ctx context.Context, peerID, peerDeviceID string, plaintext []byte, expiresAt time.Time) (RoutedCiphertext, error)
	Decrypt(ctx context.Context, item RoutedCiphertext) ([]byte, error)
}

type TransportSecurity struct {
	Protocol                    string
	IndependentAudit            string
	MixLayers                   int
	SenderReceiverUnlinkability bool
	CoverTraffic                bool
	ConstantRate                bool
	Batching                    bool
	AnonymousFetch              bool
	FixedSizePackets            bool
}

// PrivateTransport only receives one-time route capabilities and already
// encrypted, padded payloads. Send must return nil only after validating the
// transport's authenticated storage acknowledgement.
type PrivateTransport interface {
	Security() TransportSecurity
	Send(ctx context.Context, item RoutedCiphertext) error
}

// ReplayStore must atomically reject an already accepted (senderID,messageID)
// pair and persist entries at least until expiresAt.
type ReplayStore interface {
	Accept(ctx context.Context, senderID, messageID string, expiresAt time.Time) error
}

type StrictPipeline struct {
	ratchet   RatchetProvider
	transport PrivateTransport
	replays   ReplayStore
}

func NewStrictPipeline(ratchet RatchetProvider, transport PrivateTransport, replays ReplayStore) (*StrictPipeline, error) {
	if ratchet == nil {
		return nil, ErrRatchetProviderRequired
	}
	ratchetSecurity := ratchet.Security()
	if ratchetSecurity.Protocol == "" || ratchetSecurity.IndependentAudit == "" ||
		!ratchetSecurity.ForwardSecrecy || !ratchetSecurity.PostCompromiseSecurity ||
		!ratchetSecurity.PostQuantumHandshake || !ratchetSecurity.UniquePerMessageKeys ||
		!ratchetSecurity.DeletesConsumedKeys || ratchetSecurity.MaxSkippedMessageKeys <= 0 ||
		ratchetSecurity.MaxSkippedMessageKeys > MaxRatchetSkippedKeys {
		return nil, ErrRatchetProviderRequired
	}
	if transport == nil {
		return nil, ErrMetadataPrivateTransportRequired
	}
	transportSecurity := transport.Security()
	if transportSecurity.Protocol == "" || transportSecurity.IndependentAudit == "" ||
		transportSecurity.MixLayers < 3 || !transportSecurity.SenderReceiverUnlinkability ||
		!transportSecurity.CoverTraffic || !transportSecurity.ConstantRate || !transportSecurity.Batching ||
		!transportSecurity.AnonymousFetch || !transportSecurity.FixedSizePackets {
		return nil, ErrMetadataPrivateTransportRequired
	}
	if replays == nil {
		return nil, ErrReplayStoreRequired
	}
	return &StrictPipeline{ratchet: ratchet, transport: transport, replays: replays}, nil
}

// SendDirect signs once and creates an independent ratchet ciphertext for
// every certified recipient device. The signed sender and recipient IDs remain
// inside the ratchet ciphertext and are never passed to the transport.
func (pipeline *StrictPipeline) SendDirect(ctx context.Context, sender *account.LocalAccount, recipient account.PublicProfile, body []byte, now time.Time, retention time.Duration) (SignedMessage, []RoutedCiphertext, error) {
	if pipeline == nil || pipeline.ratchet == nil || pipeline.transport == nil || sender == nil {
		return SignedMessage{}, nil, errors.New("strict messaging pipeline is unavailable")
	}
	if err := account.VerifyPublicProfile(recipient, now); err != nil {
		return SignedMessage{}, nil, fmt.Errorf("recipient profile: %w", err)
	}
	message, err := NewDirect(sender, recipient.AccountID, body, now, retention)
	if err != nil {
		return SignedMessage{}, nil, err
	}
	plaintext, err := Encode(message)
	if err != nil {
		return SignedMessage{}, nil, err
	}
	routed := make([]RoutedCiphertext, 0, len(recipient.Devices))
	seenRoutes := make(map[string]struct{}, len(recipient.Devices))
	for _, certificate := range recipient.Devices {
		item, encryptErr := pipeline.ratchet.Encrypt(ctx, recipient.AccountID, certificate.Device.DeviceID, plaintext, message.ExpiresAt)
		if encryptErr != nil {
			return message, routed, encryptErr
		}
		if !protocol.ValidRouteTag(item.RouteTag) || len(item.Payload) == 0 ||
			len(item.Payload) > protocol.DefaultMaxItemBytes || !item.ExpiresAt.Equal(message.ExpiresAt) {
			return message, routed, errors.New("ratchet provider returned an invalid routed ciphertext")
		}
		if _, duplicate := seenRoutes[item.RouteTag]; duplicate {
			return message, routed, errors.New("ratchet provider reused a route capability")
		}
		seenRoutes[item.RouteTag] = struct{}{}
		if err := pipeline.transport.Send(ctx, item); err != nil {
			return message, routed, err
		}
		item.Payload = append([]byte(nil), item.Payload...)
		routed = append(routed, item)
	}
	return message, routed, nil
}

// OpenDirect only returns an authenticated message after ratchet decryption,
// ENIG/profile validation, device-signature validation, and atomic replay
// rejection all succeed.
func (pipeline *StrictPipeline) OpenDirect(ctx context.Context, local *account.LocalAccount, sender account.PublicProfile, item RoutedCiphertext, now time.Time) (VerifiedMessage, error) {
	if pipeline == nil || pipeline.ratchet == nil || pipeline.replays == nil || local == nil ||
		!protocol.ValidRouteTag(item.RouteTag) || len(item.Payload) == 0 ||
		len(item.Payload) > protocol.DefaultMaxItemBytes || item.ExpiresAt.IsZero() {
		return VerifiedMessage{}, errors.New("invalid routed ciphertext")
	}
	plaintext, err := pipeline.ratchet.Decrypt(ctx, item)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxSignedMessageBytes {
		return VerifiedMessage{}, errors.New("ratchet plaintext size is out of range")
	}
	message, err := Decode(plaintext)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if !item.ExpiresAt.Equal(message.ExpiresAt) || !identity.ValidAccountID(local.ID()) {
		return VerifiedMessage{}, errors.New("ratchet metadata does not match signed message")
	}
	verified, err := VerifyDirect(sender, message, local.ID(), now)
	if err != nil {
		return VerifiedMessage{}, err
	}
	if err := pipeline.replays.Accept(ctx, message.SenderID, message.MessageID, message.ExpiresAt); err != nil {
		return VerifiedMessage{}, fmt.Errorf("reject replayed message: %w", err)
	}
	return verified, nil
}
