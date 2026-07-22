package account

import (
	"encoding/json"
	"errors"

	"veilmesh/identity"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	MaxDevicesPerAccount = 32
	MaxDeviceIDBytes     = 128
	MaxSyncEventBytes    = 256 * 1024
)

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

func SealSyncEvent(accountPublic protocol.NodePublicIdentity, devices []DeviceCertificate, event []byte) ([]protocol.DeviceSyncEnvelope, error) {
	if !pqcrypto.ValidPublicIdentity(accountPublic) || len(devices) == 0 || len(devices) > MaxDevicesPerAccount ||
		len(event) == 0 || len(event) > MaxSyncEventBytes {
		return nil, errors.New("invalid device sync input")
	}
	result := make([]protocol.DeviceSyncEnvelope, 0, len(devices))
	seen := make(map[string]struct{}, len(devices))
	for _, certificate := range devices {
		if !VerifyDevice(accountPublic, certificate) {
			return nil, errors.New("unverified device certificate")
		}
		if _, duplicate := seen[certificate.Device.DeviceID]; duplicate {
			return nil, errors.New("duplicate sync device")
		}
		seen[certificate.Device.DeviceID] = struct{}{}
		aad := []byte("veilmesh/device-sync/v1\x00" + certificate.AccountID + "\x00" + certificate.Device.DeviceID)
		encapsulation, ciphertext, err := pqcrypto.Seal(certificate.Device.HPKEPublicKey, aad, event)
		if err != nil {
			return nil, err
		}
		result = append(result, protocol.DeviceSyncEnvelope{
			DeviceID: certificate.Device.DeviceID,
			Payload:  protocol.DirectCiphertext{Suite: pqcrypto.HybridHPKESuite, Encapsulation: encapsulation, Ciphertext: ciphertext},
		})
	}
	return result, nil
}

func OpenSyncEvent(privateHPKEKey []byte, accountID, deviceID string, envelope protocol.DeviceSyncEnvelope) ([]byte, error) {
	if accountID == "" || !validDeviceID(deviceID) || envelope.DeviceID != deviceID ||
		envelope.Payload.Suite != pqcrypto.HybridHPKESuite || len(envelope.Payload.Encapsulation) == 0 ||
		len(envelope.Payload.Ciphertext) == 0 || len(envelope.Payload.Ciphertext) > MaxSyncEventBytes+1024 {
		return nil, errors.New("device sync envelope mismatch")
	}
	aad := []byte("veilmesh/device-sync/v1\x00" + accountID + "\x00" + deviceID)
	return pqcrypto.Open(privateHPKEKey, envelope.Payload.Encapsulation, aad, envelope.Payload.Ciphertext)
}
