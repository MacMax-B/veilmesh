// Package mixtransport implements the ENIG-Mix v2 moderate constant-rate transport
// orchestration. Cryptographic onion packets are supplied by an independently
// audited provider; this package intentionally does not invent an onion format.
package mixtransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	ProtocolVersion        = 2
	RequestIDBytes         = 32
	MinPacketBytes         = 8 * 1024
	DefaultPacketBytes     = 8 * 1024
	MaxPacketBytes         = 64 * 1024
	MaxCommandPayloadBytes = 2 * 1024
	MaxEncodedCommandBytes = 4 * 1024
	MaxCommandLifetime     = 15 * time.Minute
	MaxQueueEntries        = 4096
)

type CommandKind string

const (
	KindStore            CommandKind = "store"
	KindDirectoryLookup  CommandKind = "directory_lookup"
	KindDirectoryPublish CommandKind = "directory_publish"
	KindDeviceSync       CommandKind = "device_sync"
	KindDelete           CommandKind = "delete"
)

type Command struct {
	Version   uint8       `json:"version"`
	RequestID string      `json:"request_id"`
	Kind      CommandKind `json:"kind"`
	CreatedAt time.Time   `json:"created_at"`
	ExpiresAt time.Time   `json:"expires_at"`
	Payload   []byte      `json:"payload"`
}

func validKind(kind CommandKind) bool {
	switch kind {
	case KindStore, KindDirectoryLookup, KindDirectoryPublish, KindDeviceSync, KindDelete:
		return true
	default:
		return false
	}
}

func validRequestID(requestID string) bool {
	if len(requestID) != base64.RawURLEncoding.EncodedLen(RequestIDBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(requestID)
	return err == nil && len(decoded) == RequestIDBytes
}

func NewCommand(kind CommandKind, payload []byte, now time.Time, lifetime time.Duration) (Command, error) {
	if !validKind(kind) || len(payload) == 0 || len(payload) > MaxCommandPayloadBytes ||
		now.IsZero() || lifetime <= 0 || lifetime > MaxCommandLifetime {
		return Command{}, errors.New("invalid ENIG-Mix command input")
	}
	requestID := make([]byte, RequestIDBytes)
	if _, err := rand.Read(requestID); err != nil {
		return Command{}, err
	}
	createdAt := now.UTC().Truncate(time.Millisecond)
	return Command{
		Version:   ProtocolVersion,
		RequestID: base64.RawURLEncoding.EncodeToString(requestID),
		Kind:      kind,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(lifetime).Truncate(time.Millisecond),
		Payload:   append([]byte(nil), payload...),
	}, nil
}

func ValidateCommand(command Command, now time.Time) error {
	if command.Version != ProtocolVersion || !validRequestID(command.RequestID) || !validKind(command.Kind) ||
		len(command.Payload) == 0 || len(command.Payload) > MaxCommandPayloadBytes ||
		command.CreatedAt.IsZero() || command.ExpiresAt.IsZero() ||
		command.CreatedAt.After(now.Add(5*time.Minute)) || !command.ExpiresAt.After(command.CreatedAt) ||
		command.ExpiresAt.Sub(command.CreatedAt) > MaxCommandLifetime || now.After(command.ExpiresAt) {
		return errors.New("invalid ENIG-Mix command")
	}
	return nil
}

func EncodeCommand(command Command, now time.Time) ([]byte, error) {
	if err := ValidateCommand(command, now); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > MaxEncodedCommandBytes {
		return nil, errors.New("encoded ENIG-Mix command exceeds size limit")
	}
	return encoded, nil
}

func DecodeCommand(encoded []byte, now time.Time) (Command, error) {
	if len(encoded) == 0 || len(encoded) > MaxEncodedCommandBytes {
		return Command{}, errors.New("encoded ENIG-Mix command size is out of range")
	}
	var command Command
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return Command{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Command{}, errors.New("multiple ENIG-Mix JSON values")
		}
		return Command{}, err
	}
	if err := ValidateCommand(command, now); err != nil {
		return Command{}, err
	}
	return command, nil
}

// PacketSecurity describes requirements which the adapter and its independent
// audit must actually establish. These booleans are a fail-closed integration
// guard, not cryptographic evidence of an audit.
type PacketSecurity struct {
	Protocol                 string
	IndependentAudit         string
	MinimumMixHops           int
	FixedLengthPackets       bool
	LayeredMixing            bool
	PerHopAuthentication     bool
	ReplayProtection         bool
	UniformReplies           bool
	PostQuantumHybridOnion   bool
	ForwardSecureRoutingKeys bool
}

type LinkSecurity struct {
	Protocol             string
	IndependentAudit     string
	AuthenticatedEntry   bool
	PersistentConnection bool
	FixedLengthFrames    bool
	PostQuantumHybridKEX bool
	NoRedirects          bool
}

type PreparedPacket struct {
	Packet []byte
}

// PacketProvider owns the audited Sphinx/onion packet format, route selection,
// SURBs, per-hop keys, reply authentication, replay tags, and packet padding.
// Prepare methods must be local-only and must not perform observable network I/O.
type PacketProvider interface {
	Security() PacketSecurity
	PrepareReal(ctx context.Context, encodedCommand []byte, packetBytes int) (PreparedPacket, error)
	PreparePoll(ctx context.Context, packetBytes int) (PreparedPacket, error)
	PrepareCover(ctx context.Context, packetBytes int) (PreparedPacket, error)
}

// PacketSink accepts an already protected fixed-size packet for a persistent,
// authenticated entry connection. It must never log packet bytes or timing
// together with application state.
type PacketSink interface {
	Security() LinkSecurity
	Send(ctx context.Context, packet []byte) error
}
