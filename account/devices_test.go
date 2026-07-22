package account

import (
	"bytes"
	"testing"

	"veilmesh/identity"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

func TestDeviceCertificateAndEncryptedSync(t *testing.T) {
	accountSigner, _ := pqcrypto.GenerateHybridSigner()
	deviceSigner, _ := pqcrypto.GenerateHybridSigner()
	deviceKEM, err := pqcrypto.GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	accountID := AccountID(accountSigner.PublicIdentity())
	deviceID := identity.DeviceID(deviceSigner.PublicIdentity())
	certificate, err := SignDevice(accountSigner, protocol.DeviceDescriptor{
		DeviceID:      deviceID,
		AccountID:     accountID,
		HPKEPublicKey: deviceKEM.PublicKey,
		SigningKey:    deviceSigner.PublicIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDevice(accountSigner.PublicIdentity(), certificate) {
		t.Fatal("valid device certificate rejected")
	}
	event := []byte("sync this state")
	envelopes, err := SealSyncEvent(accountSigner.PublicIdentity(), []DeviceCertificate{certificate}, event)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenSyncEvent(deviceKEM.PrivateKey, accountID, deviceID, envelopes[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, event) {
		t.Fatal("device sync event differs")
	}
}

func TestSyncRejectsUnverifiedOrDuplicateDevices(t *testing.T) {
	accountSigner, _ := pqcrypto.GenerateHybridSigner()
	deviceSigner, _ := pqcrypto.GenerateHybridSigner()
	deviceKEM, _ := pqcrypto.GenerateHybridKEMKeyPair()
	accountID := AccountID(accountSigner.PublicIdentity())
	deviceID := identity.DeviceID(deviceSigner.PublicIdentity())
	certificate, err := SignDevice(accountSigner, protocol.DeviceDescriptor{
		DeviceID:      deviceID,
		AccountID:     accountID,
		HPKEPublicKey: deviceKEM.PublicKey,
		SigningKey:    deviceSigner.PublicIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := certificate
	tampered.Device.DeviceID = "attacker-device"
	if _, err := SealSyncEvent(accountSigner.PublicIdentity(), []DeviceCertificate{tampered}, []byte("event")); err == nil {
		t.Fatal("tampered device certificate was accepted")
	}
	if _, err := SealSyncEvent(accountSigner.PublicIdentity(), []DeviceCertificate{certificate, certificate}, []byte("event")); err == nil {
		t.Fatal("duplicate device was accepted")
	}
}
