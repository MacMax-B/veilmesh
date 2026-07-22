package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"propagare/identity"
	"propagare/pqcrypto"
	"propagare/protocol"
)

const (
	ProfileVersion        = 1
	MaxPublicProfileBytes = 256 * 1024
)

// PublicProfile is the signed response an untrusted directory may return for
// an ENIG account ID. The account signature and self-certifying AccountID must
// both verify locally before any device key is used.
type PublicProfile struct {
	Version       uint8                       `json:"version"`
	AccountID     string                      `json:"account_id"`
	AccountPublic protocol.NodePublicIdentity `json:"account_public"`
	Revision      uint64                      `json:"revision"`
	UpdatedAt     time.Time                   `json:"updated_at"`
	Devices       []DeviceCertificate         `json:"devices"`
	Signature     protocol.HybridSignature    `json:"signature"`
}

func profileSigningBytes(profile PublicProfile) ([]byte, error) {
	profile.Signature = protocol.HybridSignature{}
	return json.Marshal(profile)
}

func SignPublicProfile(accountSigner *pqcrypto.HybridSigner, revision uint64, updatedAt time.Time, devices []DeviceCertificate) (PublicProfile, error) {
	if accountSigner == nil || revision == 0 || updatedAt.IsZero() || len(devices) == 0 || len(devices) > MaxDevicesPerAccount {
		return PublicProfile{}, errors.New("invalid public profile input")
	}
	accountPublic := accountSigner.PublicIdentity()
	profile := PublicProfile{
		Version:       ProfileVersion,
		AccountID:     AccountID(accountPublic),
		AccountPublic: accountPublic,
		Revision:      revision,
		UpdatedAt:     updatedAt.UTC().Truncate(time.Millisecond),
		Devices:       append([]DeviceCertificate(nil), devices...),
	}
	sort.Slice(profile.Devices, func(i, j int) bool {
		return profile.Devices[i].Device.DeviceID < profile.Devices[j].Device.DeviceID
	})
	if err := validateProfileStructure(profile, profile.UpdatedAt.Add(time.Minute)); err != nil {
		return PublicProfile{}, err
	}
	message, err := profileSigningBytes(profile)
	if err != nil {
		return PublicProfile{}, err
	}
	profile.Signature, err = accountSigner.Sign("account-public-profile", message)
	return profile, err
}

func validateProfileStructure(profile PublicProfile, now time.Time) error {
	if profile.Version != ProfileVersion || profile.Revision == 0 ||
		!identity.ValidAccountID(profile.AccountID) || !pqcrypto.ValidPublicIdentity(profile.AccountPublic) ||
		profile.AccountID != AccountID(profile.AccountPublic) || profile.UpdatedAt.IsZero() ||
		profile.UpdatedAt.After(now.Add(5*time.Minute)) || len(profile.Devices) == 0 ||
		len(profile.Devices) > MaxDevicesPerAccount {
		return errors.New("invalid public profile")
	}
	previous := ""
	for _, certificate := range profile.Devices {
		deviceID := certificate.Device.DeviceID
		if deviceID <= previous || !VerifyDevice(profile.AccountPublic, certificate) {
			return errors.New("invalid or unsorted device certificate")
		}
		previous = deviceID
	}
	return nil
}

func VerifyPublicProfile(profile PublicProfile, now time.Time) error {
	if err := validateProfileStructure(profile, now); err != nil {
		return err
	}
	message, err := profileSigningBytes(profile)
	if err != nil || !pqcrypto.Verify(profile.AccountPublic, "account-public-profile", message, profile.Signature) {
		return errors.New("invalid public profile signature")
	}
	return nil
}

func DecodePublicProfile(encoded []byte, now time.Time) (PublicProfile, error) {
	if len(encoded) == 0 || len(encoded) > MaxPublicProfileBytes {
		return PublicProfile{}, errors.New("public profile size is out of range")
	}
	var profile PublicProfile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return PublicProfile{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return PublicProfile{}, err
	}
	if err := VerifyPublicProfile(profile, now); err != nil {
		return PublicProfile{}, err
	}
	return profile, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

type ProfileResolver interface {
	Resolve(ctx context.Context, accountID string) (PublicProfile, error)
}

// ResolveVerified treats the directory as an availability-only component.
// minimumRevision must come from locally protected state and prevents rollback
// to a previously valid profile after the client has observed a newer one.
func ResolveVerified(ctx context.Context, resolver ProfileResolver, accountID string, minimumRevision uint64, now time.Time) (PublicProfile, error) {
	if resolver == nil || !identity.ValidAccountID(accountID) {
		return PublicProfile{}, errors.New("invalid account profile lookup")
	}
	profile, err := resolver.Resolve(ctx, accountID)
	if err != nil {
		return PublicProfile{}, err
	}
	if profile.AccountID != accountID || profile.Revision < minimumRevision {
		return PublicProfile{}, errors.New("directory returned a substituted or rolled-back profile")
	}
	if err := VerifyPublicProfile(profile, now); err != nil {
		return PublicProfile{}, fmt.Errorf("verify resolved profile: %w", err)
	}
	return profile, nil
}

func cloneCertificate(certificate DeviceCertificate) DeviceCertificate {
	result := certificate
	result.Device.HPKEPublicKey = append([]byte(nil), certificate.Device.HPKEPublicKey...)
	result.Device.SigningKey.Ed25519Public = append([]byte(nil), certificate.Device.SigningKey.Ed25519Public...)
	result.Device.SigningKey.MLDSA65Public = append([]byte(nil), certificate.Device.SigningKey.MLDSA65Public...)
	result.Signature.Ed25519 = append([]byte(nil), certificate.Signature.Ed25519...)
	result.Signature.MLDSA65 = append([]byte(nil), certificate.Signature.MLDSA65...)
	return result
}

func cloneProfile(profile PublicProfile) PublicProfile {
	result := profile
	result.AccountPublic.Ed25519Public = append([]byte(nil), profile.AccountPublic.Ed25519Public...)
	result.AccountPublic.MLDSA65Public = append([]byte(nil), profile.AccountPublic.MLDSA65Public...)
	result.Devices = make([]DeviceCertificate, len(profile.Devices))
	for index, certificate := range profile.Devices {
		result.Devices[index] = cloneCertificate(certificate)
	}
	result.Signature.Ed25519 = append([]byte(nil), profile.Signature.Ed25519...)
	result.Signature.MLDSA65 = append([]byte(nil), profile.Signature.MLDSA65...)
	return result
}

// ProfileContainsDevice checks that a certificate is in the profile's current
// active device set, not merely that it was signed by the account at some point.
func ProfileContainsDevice(profile PublicProfile, candidate DeviceCertificate) bool {
	for _, certificate := range profile.Devices {
		if certificate.Device.DeviceID != candidate.Device.DeviceID {
			continue
		}
		left, leftErr := certificateBytes(certificate)
		right, rightErr := certificateBytes(candidate)
		return leftErr == nil && rightErr == nil && bytes.Equal(left, right) &&
			bytes.Equal(certificate.Signature.Ed25519, candidate.Signature.Ed25519) &&
			bytes.Equal(certificate.Signature.MLDSA65, candidate.Signature.MLDSA65)
	}
	return false
}
