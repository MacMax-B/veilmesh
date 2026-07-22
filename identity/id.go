// Package identity defines self-certifying, shareable VeilMesh identifiers.
package identity

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	AccountPrefix = "ENIGC1"
	DevicePrefix  = "ENIGD1"
	GroupPrefix   = "ENIGG1"

	GenesisNonceBytes = 32
	digestTextBytes   = 52 // unpadded base32 encoding of SHA-256
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func keyDigest(domain string, public protocol.NodePublicIdentity, extra []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("veilmesh/enig-id/v1\x00"))
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0, public.ProtocolVersion})
	_, _ = hash.Write(public.Ed25519Public)
	_, _ = hash.Write(public.MLDSA65Public)
	_, _ = hash.Write(extra)
	return encoding.EncodeToString(hash.Sum(nil))
}

// AccountID is a stable fingerprint of the account authorization key. Device
// changes therefore do not change the shareable address.
func AccountID(public protocol.NodePublicIdentity) string {
	if !pqcrypto.ValidPublicIdentity(public) {
		return ""
	}
	return AccountPrefix + keyDigest("account", public, nil)
}

// DeviceID binds a device identifier to its signing key.
func DeviceID(public protocol.NodePublicIdentity) string {
	if !pqcrypto.ValidPublicIdentity(public) {
		return ""
	}
	return DevicePrefix + keyDigest("device", public, nil)
}

// GroupID binds a group address to its creator, random genesis nonce, and a
// bounded canonical genesis policy commitment.
func GroupID(creator protocol.NodePublicIdentity, genesisNonce, genesisContext []byte) string {
	if !pqcrypto.ValidPublicIdentity(creator) || len(genesisNonce) != GenesisNonceBytes ||
		len(genesisContext) == 0 || len(genesisContext) > 1024 {
		return ""
	}
	extra := make([]byte, 0, len(genesisNonce)+len(genesisContext))
	extra = append(extra, genesisNonce...)
	extra = append(extra, genesisContext...)
	return GroupPrefix + keyDigest("group", creator, extra)
}

func valid(id, prefix string) bool {
	if len(id) != len(prefix)+digestTextBytes || !strings.HasPrefix(id, prefix) {
		return false
	}
	digest, err := encoding.DecodeString(id[len(prefix):])
	return err == nil && len(digest) == sha256.Size
}

func ValidAccountID(id string) bool { return valid(id, AccountPrefix) }
func ValidDeviceID(id string) bool  { return valid(id, DevicePrefix) }
func ValidGroupID(id string) bool   { return valid(id, GroupPrefix) }

func ValidRecipientID(id string) bool { return ValidAccountID(id) || ValidGroupID(id) }
