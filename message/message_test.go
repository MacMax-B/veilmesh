package message

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"propagare/account"
	"propagare/identity"
	"propagare/pqcrypto"
	"propagare/protocol"
)

func TestMessageIDRejectsNonCanonicalBase64(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, messageIDBytes))
	if !validMessageID(canonical) {
		t.Fatal("canonical message ID rejected")
	}
	if validMessageID(canonical[:len(canonical)-1] + "B") {
		t.Fatal("non-canonical message ID accepted")
	}
}

type testVault struct{ values map[string][]byte }

func (vault *testVault) Store(_ context.Context, key string, secret []byte) error {
	if vault.values == nil {
		vault.values = make(map[string][]byte)
	}
	vault.values[key] = append([]byte(nil), secret...)
	return nil
}

func (vault *testVault) Load(_ context.Context, key string) ([]byte, error) {
	value, ok := vault.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func newTestAccount(t *testing.T) *account.LocalAccount {
	t.Helper()
	local, err := account.Register(context.Background(), &testVault{})
	if err != nil {
		t.Fatal(err)
	}
	return local
}

func TestSignedMessageAndClientDeliveryReceipt(t *testing.T) {
	sender := newTestAccount(t)
	receiver := newTestAccount(t)
	now := time.Now().UTC()
	signed, err := NewDirect(sender, receiver.ID(), []byte("authenticated message"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyDirect(sender.Profile(), signed, receiver.ID(), now)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewDeliveryReceipt(receiver, verified, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeliveryReceipt(receiver.Profile(), receipt, signed, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeDeliveryReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeliveryReceipt(encoded)
	if err != nil || decoded.MessageID != signed.MessageID {
		t.Fatal("delivery receipt did not survive strict encoding")
	}
}

func TestMessageAndReceiptTamperingIsRejected(t *testing.T) {
	sender := newTestAccount(t)
	receiver := newTestAccount(t)
	now := time.Now().UTC()
	signed, err := NewDirect(sender, receiver.ID(), []byte("original"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyDirect(sender.Profile(), signed, receiver.ID(), now)
	if err != nil {
		t.Fatal(err)
	}
	tampered := cloneMessage(signed)
	tampered.Body[0] ^= 1
	if _, err := VerifyDirect(sender.Profile(), tampered, receiver.ID(), now); err == nil {
		t.Fatal("tampered signed message was accepted")
	}
	receipt, err := NewDeliveryReceipt(receiver, verified, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt.MessageDigest[0] ^= 1
	if err := VerifyDeliveryReceipt(receiver.Profile(), receipt, signed, now); err == nil {
		t.Fatal("tampered client receipt was accepted")
	}
	encoded, _ := EncodeDeliveryReceipt(receipt)
	withUnknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := DecodeDeliveryReceipt(withUnknown); err == nil {
		t.Fatal("unknown receipt field was accepted")
	}
	if _, err := DecodeDeliveryReceipt(make([]byte, MaxReceiptBytes+1)); err == nil {
		t.Fatal("oversized receipt was accepted")
	}
}

func TestMessageParserAndTimeBounds(t *testing.T) {
	sender := newTestAccount(t)
	receiver := newTestAccount(t)
	now := time.Now().UTC()
	signed, err := NewDirect(sender, receiver.ID(), []byte("bounded"), now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirect(sender.Profile(), signed, receiver.ID(), now.Add(10*time.Minute)); err == nil {
		t.Fatal("expired message was accepted")
	}
	encoded, _ := Encode(signed)
	withUnknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := Decode(withUnknown); err == nil {
		t.Fatal("unknown message field was accepted")
	}
	if _, err := Decode(make([]byte, MaxSignedMessageBytes+1)); err == nil {
		t.Fatal("oversized signed message was accepted")
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
}

type fakeRatchet struct {
	security       RatchetSecurity
	counter        byte
	reuseRoute     bool
	oversize       bool
	malformedRoute bool
}

func secureRatchet() RatchetSecurity {
	return RatchetSecurity{
		Protocol: "test-audited-pqxdh-double-ratchet", IndependentAudit: "test-report",
		ForwardSecrecy: true, PostCompromiseSecurity: true, PostQuantumHandshake: true,
		UniquePerMessageKeys: true, DeletesConsumedKeys: true, MaxSkippedMessageKeys: 128,
	}
}

func (ratchet *fakeRatchet) Security() RatchetSecurity { return ratchet.security }

func (ratchet *fakeRatchet) Encrypt(_ context.Context, _, _ string, plaintext []byte, expiresAt time.Time) (RoutedCiphertext, error) {
	if !ratchet.reuseRoute {
		ratchet.counter++
	}
	route := make([]byte, 32)
	route[0] = ratchet.counter
	item := RoutedCiphertext{RouteTag: base64.RawURLEncoding.EncodeToString(route), Payload: append([]byte(nil), plaintext...), ExpiresAt: expiresAt}
	if ratchet.oversize {
		item.Payload = make([]byte, protocol.DefaultMaxItemBytes+1)
	}
	if ratchet.malformedRoute {
		item.RouteTag = "predictable"
	}
	return item, nil
}

func (ratchet *fakeRatchet) Decrypt(_ context.Context, item RoutedCiphertext) ([]byte, error) {
	return append([]byte(nil), item.Payload...), nil
}

type fakeTransport struct {
	security TransportSecurity
	items    []RoutedCiphertext
}

func secureTransport() TransportSecurity {
	return TransportSecurity{
		Protocol: "test-audited-mixnet", IndependentAudit: "test-report", MixLayers: 3,
		SenderReceiverUnlinkability: true, CoverTraffic: true, ConstantRate: true,
		Batching: true, AnonymousFetch: true, FixedSizePackets: true,
	}
}

func (transport *fakeTransport) Security() TransportSecurity { return transport.security }

func (transport *fakeTransport) Send(_ context.Context, item RoutedCiphertext) error {
	transport.items = append(transport.items, item)
	return nil
}

type replayMemory struct{ seen map[string]struct{} }

func (memory *replayMemory) Accept(_ context.Context, senderID, messageID string, _ time.Time) error {
	if memory.seen == nil {
		memory.seen = make(map[string]struct{})
	}
	key := senderID + "\x00" + messageID
	if _, exists := memory.seen[key]; exists {
		return errors.New("replay")
	}
	memory.seen[key] = struct{}{}
	return nil
}

func TestStrictPipelineSendsPerDeviceAndRejectsReplay(t *testing.T) {
	sender := newTestAccount(t)
	receiver := newTestAccount(t)
	ratchet := &fakeRatchet{security: secureRatchet()}
	transport := &fakeTransport{security: secureTransport()}
	pipeline, err := NewStrictPipeline(ratchet, transport, &replayMemory{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signed, routed, err := pipeline.SendDirect(context.Background(), sender, receiver.Profile(), []byte("strict"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(routed) != 1 || len(transport.items) != 1 {
		t.Fatal("message was not sent once per certified device")
	}
	if _, err := pipeline.OpenDirect(context.Background(), receiver, sender.Profile(), routed[0], now); err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.OpenDirect(context.Background(), receiver, sender.Profile(), routed[0], now); err == nil {
		t.Fatal("replayed message was accepted")
	}
	if routed[0].ExpiresAt != signed.ExpiresAt {
		t.Fatal("signed and routed expiration differ")
	}
}

func TestStrictPipelineRejectsMissingSecurityGuarantees(t *testing.T) {
	validRatchet := &fakeRatchet{security: secureRatchet()}
	validTransport := &fakeTransport{security: secureTransport()}
	replays := &replayMemory{}
	if _, err := NewStrictPipeline(nil, validTransport, replays); !errors.Is(err, ErrRatchetProviderRequired) {
		t.Fatal("missing ratchet provider was accepted")
	}
	weakRatchet := &fakeRatchet{security: secureRatchet()}
	weakRatchet.security.DeletesConsumedKeys = false
	if _, err := NewStrictPipeline(weakRatchet, validTransport, replays); !errors.Is(err, ErrRatchetProviderRequired) {
		t.Fatal("ratchet without key deletion was accepted")
	}
	tweakTransport := &fakeTransport{security: secureTransport()}
	tweakTransport.security.CoverTraffic = false
	if _, err := NewStrictPipeline(validRatchet, tweakTransport, replays); !errors.Is(err, ErrMetadataPrivateTransportRequired) {
		t.Fatal("transport without cover traffic was accepted")
	}
	if _, err := NewStrictPipeline(validRatchet, validTransport, nil); !errors.Is(err, ErrReplayStoreRequired) {
		t.Fatal("missing replay store was accepted")
	}
	tooManySkips := &fakeRatchet{security: secureRatchet()}
	tooManySkips.security.MaxSkippedMessageKeys = MaxRatchetSkippedKeys + 1
	if _, err := NewStrictPipeline(tooManySkips, validTransport, replays); !errors.Is(err, ErrRatchetProviderRequired) {
		t.Fatal("unbounded ratchet skip window was accepted")
	}
}

func TestStrictPipelineRejectsInvalidCiphertextAndRouteReuse(t *testing.T) {
	sender := newTestAccount(t)
	profile := newMultiDeviceProfile(t, 2)
	now := time.Now().UTC()
	for name, ratchet := range map[string]*fakeRatchet{
		"oversize":        {security: secureRatchet(), oversize: true},
		"malformed route": {security: secureRatchet(), malformedRoute: true},
		"route reuse":     {security: secureRatchet(), reuseRoute: true},
	} {
		t.Run(name, func(t *testing.T) {
			pipeline, err := NewStrictPipeline(ratchet, &fakeTransport{security: secureTransport()}, &replayMemory{})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := pipeline.SendDirect(context.Background(), sender, profile, []byte("bounded"), now, time.Hour); err == nil {
				t.Fatal("invalid ratchet output was accepted")
			}
		})
	}
}

func newMultiDeviceProfile(t *testing.T, count int) account.PublicProfile {
	t.Helper()
	root, _ := pqcrypto.GenerateHybridSigner()
	accountID := account.AccountID(root.PublicIdentity())
	certificates := make([]account.DeviceCertificate, 0, count)
	for index := 0; index < count; index++ {
		device, _ := pqcrypto.GenerateHybridSigner()
		kem, _ := pqcrypto.GenerateHybridKEMKeyPair()
		certificate, err := account.SignDevice(root, protocol.DeviceDescriptor{
			DeviceID: identity.DeviceID(device.PublicIdentity()), AccountID: accountID,
			HPKEPublicKey: kem.PublicKey, SigningKey: device.PublicIdentity(),
		})
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, certificate)
	}
	profile, err := account.SignPublicProfile(root, 1, time.Now(), certificates)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func FuzzDecodeSignedMessage(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = Decode(encoded)
	})
}

func FuzzDecodeDeliveryReceipt(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = DecodeDeliveryReceipt(encoded)
	})
}
