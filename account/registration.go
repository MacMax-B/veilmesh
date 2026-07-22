package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/MacMax-B/propagare/identity"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

const (
	privateRecordVersion  = 1
	MaxPrivateRecordBytes = 512 * 1024
)

// SecretVault is a trusted platform boundary. Production adapters must store
// values atomically in an OS keychain, hardware-backed keystore, or equivalent
// encrypted secret store and must never log or sync plaintext secret bytes.
type SecretVault interface {
	Store(ctx context.Context, key string, secret []byte) error
	Load(ctx context.Context, key string) ([]byte, error)
}

type privateRecord struct {
	Version        uint8                           `json:"version"`
	Profile        PublicProfile                   `json:"profile"`
	AccountSigning pqcrypto.PrivateSigningMaterial `json:"account_signing"`
	DeviceSigning  pqcrypto.PrivateSigningMaterial `json:"device_signing"`
	DeviceHPKE     []byte                          `json:"device_hpke"`
}

// LocalAccount owns runtime key handles. Raw private material is only exported
// to the SecretVault during registration and restoration.
type LocalAccount struct {
	profile       PublicProfile
	accountSigner *pqcrypto.HybridSigner
	deviceSigner  *pqcrypto.HybridSigner
	deviceHPKE    []byte
	deviceCert    DeviceCertificate
}

func vaultKey(accountID string) string { return "enig/account/v1/" + accountID }

func Register(ctx context.Context, vault SecretVault) (*LocalAccount, error) {
	if vault == nil {
		return nil, errors.New("protected secret vault is required")
	}
	accountSigner, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		return nil, err
	}
	deviceSigner, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		return nil, err
	}
	deviceKEM, err := pqcrypto.GenerateHybridKEMKeyPair()
	if err != nil {
		return nil, err
	}
	accountID := AccountID(accountSigner.PublicIdentity())
	devicePublic := deviceSigner.PublicIdentity()
	certificate, err := SignDevice(accountSigner, protocol.DeviceDescriptor{
		DeviceID:      identity.DeviceID(devicePublic),
		AccountID:     accountID,
		HPKEPublicKey: deviceKEM.PublicKey,
		SigningKey:    devicePublic,
	})
	if err != nil {
		return nil, err
	}
	profile, err := SignPublicProfile(accountSigner, 1, time.Now().UTC(), []DeviceCertificate{certificate})
	if err != nil {
		return nil, err
	}
	record := privateRecord{
		Version:        privateRecordVersion,
		Profile:        profile,
		AccountSigning: accountSigner.PrivateMaterial(),
		DeviceSigning:  deviceSigner.PrivateMaterial(),
		DeviceHPKE:     append([]byte(nil), deviceKEM.PrivateKey...),
	}
	defer zeroRecord(&record)
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	defer zero(encoded)
	if len(encoded) > MaxPrivateRecordBytes {
		return nil, errors.New("private account record exceeds size limit")
	}
	if err := vault.Store(ctx, vaultKey(accountID), encoded); err != nil {
		return nil, fmt.Errorf("protect account keys: %w", err)
	}
	return newLocalAccount(profile, accountSigner, deviceSigner, deviceKEM.PrivateKey, certificate), nil
}

func Load(ctx context.Context, vault SecretVault, accountID string) (*LocalAccount, error) {
	if vault == nil || !identity.ValidAccountID(accountID) {
		return nil, errors.New("valid account ID and protected secret vault are required")
	}
	encoded, err := vault.Load(ctx, vaultKey(accountID))
	if err != nil {
		return nil, fmt.Errorf("load protected account keys: %w", err)
	}
	defer zero(encoded)
	if len(encoded) == 0 || len(encoded) > MaxPrivateRecordBytes {
		return nil, errors.New("private account record size is out of range")
	}
	var record privateRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	defer zeroRecord(&record)
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	if record.Version != privateRecordVersion || record.Profile.AccountID != accountID {
		return nil, errors.New("private account record identity mismatch")
	}
	if err := VerifyPublicProfile(record.Profile, time.Now().UTC()); err != nil {
		return nil, err
	}
	accountSigner, err := pqcrypto.NewHybridSigner(record.AccountSigning)
	if err != nil {
		return nil, err
	}
	deviceSigner, err := pqcrypto.NewHybridSigner(record.DeviceSigning)
	if err != nil {
		return nil, err
	}
	if AccountID(accountSigner.PublicIdentity()) != accountID {
		return nil, errors.New("account private key does not match public profile")
	}
	deviceID := identity.DeviceID(deviceSigner.PublicIdentity())
	certificate, ok := profileDevice(record.Profile, deviceID)
	if !ok || !sameIdentity(certificate.Device.SigningKey, deviceSigner.PublicIdentity()) {
		return nil, errors.New("device private key does not match public profile")
	}
	publicHPKE, err := pqcrypto.HybridKEMPublicFromPrivate(record.DeviceHPKE)
	if err != nil || !bytes.Equal(publicHPKE, certificate.Device.HPKEPublicKey) {
		return nil, errors.New("device HPKE private key does not match public profile")
	}
	return newLocalAccount(record.Profile, accountSigner, deviceSigner, record.DeviceHPKE, certificate), nil
}

func newLocalAccount(profile PublicProfile, accountSigner, deviceSigner *pqcrypto.HybridSigner, hpke []byte, certificate DeviceCertificate) *LocalAccount {
	return &LocalAccount{
		profile:       cloneProfile(profile),
		accountSigner: accountSigner,
		deviceSigner:  deviceSigner,
		deviceHPKE:    append([]byte(nil), hpke...),
		deviceCert:    cloneCertificate(certificate),
	}
}

func (account *LocalAccount) ID() string { return account.profile.AccountID }

func (account *LocalAccount) DeviceID() string { return account.deviceCert.Device.DeviceID }

func (account *LocalAccount) Profile() PublicProfile { return cloneProfile(account.profile) }

func (account *LocalAccount) DeviceCertificate() DeviceCertificate {
	return cloneCertificate(account.deviceCert)
}

// SignDevicePayload is intentionally scoped by a caller-supplied protocol
// domain. Application packages must use a unique, fixed domain string.
func (account *LocalAccount) SignDevicePayload(domain string, message []byte) (protocol.HybridSignature, error) {
	if account == nil || account.deviceSigner == nil || domain == "" {
		return protocol.HybridSignature{}, errors.New("local device signer is unavailable")
	}
	return account.deviceSigner.Sign(domain, message)
}

func (account *LocalAccount) OpenDeviceEnvelope(encapsulation, aad, ciphertext []byte) ([]byte, error) {
	if account == nil || len(account.deviceHPKE) == 0 {
		return nil, errors.New("local device decryption key is unavailable")
	}
	return pqcrypto.Open(account.deviceHPKE, encapsulation, aad, ciphertext)
}

func profileDevice(profile PublicProfile, deviceID string) (DeviceCertificate, bool) {
	for _, certificate := range profile.Devices {
		if certificate.Device.DeviceID == deviceID {
			return certificate, true
		}
	}
	return DeviceCertificate{}, false
}

func sameIdentity(left, right protocol.NodePublicIdentity) bool {
	return left.NodeID == right.NodeID && left.ProtocolVersion == right.ProtocolVersion &&
		bytes.Equal(left.Ed25519Public, right.Ed25519Public) && bytes.Equal(left.MLDSA65Public, right.MLDSA65Public)
}

func zeroRecord(record *privateRecord) {
	zero(record.AccountSigning.Ed25519Private)
	zero(record.AccountSigning.MLDSA65Private)
	zero(record.DeviceSigning.Ed25519Private)
	zero(record.DeviceSigning.MLDSA65Private)
	zero(record.DeviceHPKE)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
