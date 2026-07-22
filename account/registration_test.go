package account

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"veilmesh/identity"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

type memoryVault struct {
	values map[string][]byte
	err    error
}

func TestProfileContainsOnlyCurrentCertifiedDevice(t *testing.T) {
	root, _ := pqcrypto.GenerateHybridSigner()
	first, _ := pqcrypto.GenerateHybridSigner()
	second, _ := pqcrypto.GenerateHybridSigner()
	firstKEM, _ := pqcrypto.GenerateHybridKEMKeyPair()
	secondKEM, _ := pqcrypto.GenerateHybridKEMKeyPair()
	accountID := AccountID(root.PublicIdentity())
	makeCertificate := func(signer *pqcrypto.HybridSigner, publicKey []byte) DeviceCertificate {
		certificate, err := SignDevice(root, protocol.DeviceDescriptor{
			DeviceID: identity.DeviceID(signer.PublicIdentity()), AccountID: accountID,
			HPKEPublicKey: publicKey, SigningKey: signer.PublicIdentity(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	active := makeCertificate(first, firstKEM.PublicKey)
	revoked := makeCertificate(second, secondKEM.PublicKey)
	profile, err := SignPublicProfile(root, 2, time.Now(), []DeviceCertificate{active})
	if err != nil {
		t.Fatal(err)
	}
	if !ProfileContainsDevice(profile, active) || ProfileContainsDevice(profile, revoked) {
		t.Fatal("profile active-device check accepted a non-current certificate")
	}
}

func FuzzDecodePublicProfile(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = DecodePublicProfile(encoded, time.Now())
	})
}

func (vault *memoryVault) Store(_ context.Context, key string, secret []byte) error {
	if vault.err != nil {
		return vault.err
	}
	if vault.values == nil {
		vault.values = make(map[string][]byte)
	}
	vault.values[key] = append([]byte(nil), secret...)
	return nil
}

func (vault *memoryVault) Load(_ context.Context, key string) ([]byte, error) {
	if vault.err != nil {
		return nil, vault.err
	}
	value, ok := vault.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func TestRegisterProtectsAndRestoresENIGAccount(t *testing.T) {
	vault := &memoryVault{}
	registered, err := Register(context.Background(), vault)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(registered.ID(), "ENIGC1") || !strings.HasPrefix(registered.DeviceID(), "ENIGD1") {
		t.Fatal("registration did not produce typed ENIG identifiers")
	}
	if err := VerifyPublicProfile(registered.Profile(), time.Now()); err != nil {
		t.Fatal(err)
	}
	restored, err := Load(context.Background(), vault, registered.ID())
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != registered.ID() || restored.DeviceID() != registered.DeviceID() {
		t.Fatal("restored account identity changed")
	}
}

func TestRegistrationFailsClosedWithoutProtectedVault(t *testing.T) {
	if _, err := Register(context.Background(), nil); err == nil {
		t.Fatal("registration succeeded without a protected vault")
	}
	if _, err := Register(context.Background(), &memoryVault{err: errors.New("vault unavailable")}); err == nil {
		t.Fatal("registration succeeded after vault storage failed")
	}
}

func TestLoadRejectsTamperedPrivateRecord(t *testing.T) {
	vault := &memoryVault{}
	registered, err := Register(context.Background(), vault)
	if err != nil {
		t.Fatal(err)
	}
	key := vaultKey(registered.ID())
	var record privateRecord
	if err := json.Unmarshal(vault.values[key], &record); err != nil {
		t.Fatal(err)
	}
	record.DeviceHPKE[0] ^= 1
	vault.values[key], _ = json.Marshal(record)
	if _, err := Load(context.Background(), vault, registered.ID()); err == nil {
		t.Fatal("mismatched private HPKE key was accepted")
	}
}

func TestProfileRejectsTamperingRollbackAndParserAbuse(t *testing.T) {
	vault := &memoryVault{}
	registered, err := Register(context.Background(), vault)
	if err != nil {
		t.Fatal(err)
	}
	profile := registered.Profile()
	tampered := cloneProfile(profile)
	tampered.Devices[0].Device.HPKEPublicKey[0] ^= 1
	if err := VerifyPublicProfile(tampered, time.Now()); err == nil {
		t.Fatal("tampered profile was accepted")
	}
	resolver := profileResolverFunc(func(context.Context, string) (PublicProfile, error) { return profile, nil })
	if _, err := ResolveVerified(context.Background(), resolver, registered.ID(), profile.Revision+1, time.Now()); err == nil {
		t.Fatal("rolled-back directory profile was accepted")
	}
	encoded, _ := json.Marshal(profile)
	withUnknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := DecodePublicProfile(withUnknown, time.Now()); err == nil {
		t.Fatal("unknown profile field was accepted")
	}
	if _, err := DecodePublicProfile(make([]byte, MaxPublicProfileBytes+1), time.Now()); err == nil {
		t.Fatal("oversized profile was accepted")
	}
}

type profileResolverFunc func(context.Context, string) (PublicProfile, error)

func (resolver profileResolverFunc) Resolve(ctx context.Context, id string) (PublicProfile, error) {
	return resolver(ctx, id)
}
