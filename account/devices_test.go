package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/identity"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

type syncFixture struct {
	root         *pqcrypto.HybridSigner
	profile      PublicProfile
	locals       []*LocalAccount
	certificates []DeviceCertificate
}

func newSyncFixture(t *testing.T, count int) syncFixture {
	t.Helper()
	root, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	accountID := AccountID(root.PublicIdentity())
	deviceSigners := make([]*pqcrypto.HybridSigner, count)
	privateKEMs := make([][]byte, count)
	certificates := make([]DeviceCertificate, count)
	for index := 0; index < count; index++ {
		deviceSigners[index], err = pqcrypto.GenerateHybridSigner()
		if err != nil {
			t.Fatal(err)
		}
		kem, kemErr := pqcrypto.GenerateHybridKEMKeyPair()
		if kemErr != nil {
			t.Fatal(kemErr)
		}
		privateKEMs[index] = kem.PrivateKey
		public := deviceSigners[index].PublicIdentity()
		certificates[index], err = SignDevice(root, protocol.DeviceDescriptor{
			DeviceID:      identity.DeviceID(public),
			AccountID:     accountID,
			HPKEPublicKey: kem.PublicKey,
			SigningKey:    public,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	profile, err := SignPublicProfile(root, 1, time.Now().UTC(), certificates)
	if err != nil {
		t.Fatal(err)
	}
	locals := make([]*LocalAccount, count)
	for index := range certificates {
		locals[index] = newLocalAccount(profile, root, deviceSigners[index], privateKEMs[index], certificates[index])
	}
	return syncFixture{root: root, profile: profile, locals: locals, certificates: certificates}
}

type syncReplayMemory struct {
	mu      sync.Mutex
	seen    map[string]struct{}
	accepts int
	err     error
}

func (memory *syncReplayMemory) Accept(_ context.Context, accountID, eventID string, _ time.Time) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if memory.err != nil {
		return memory.err
	}
	if memory.seen == nil {
		memory.seen = make(map[string]struct{})
	}
	key := accountID + "\x00" + eventID
	if _, exists := memory.seen[key]; exists {
		return errors.New("replay")
	}
	memory.seen[key] = struct{}{}
	memory.accepts++
	return nil
}

func envelopeForDevice(t *testing.T, envelopes []protocol.DeviceSyncEnvelope, deviceID string) protocol.DeviceSyncEnvelope {
	t.Helper()
	for _, envelope := range envelopes {
		if envelope.DeviceID == deviceID {
			return envelope
		}
	}
	t.Fatalf("missing envelope for device %s", deviceID)
	return protocol.DeviceSyncEnvelope{}
}

func sealRawSyncEvent(t *testing.T, event SignedSyncEvent, aadAccountID string, recipient DeviceCertificate) protocol.DeviceSyncEnvelope {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return sealRawSyncPlaintext(t, encoded, aadAccountID, recipient)
}

func sealRawSyncPlaintext(t *testing.T, plaintext []byte, aadAccountID string, recipient DeviceCertificate) protocol.DeviceSyncEnvelope {
	t.Helper()
	encapsulation, ciphertext, err := pqcrypto.Seal(
		recipient.Device.HPKEPublicKey,
		syncEventAAD(aadAccountID, recipient.Device.DeviceID),
		plaintext,
	)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.DeviceSyncEnvelope{
		DeviceID: recipient.Device.DeviceID,
		Payload: protocol.DirectCiphertext{
			Suite: pqcrypto.HybridHPKESuite, Encapsulation: encapsulation, Ciphertext: ciphertext,
		},
	}
}

func TestDeviceSyncRejectsNonCanonicalOrMalformedPlaintext(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	event, _, err := SealSyncEvent(
		fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("canonical"), now, time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	recipient := fixture.certificates[1]
	duplicate := append(append([]byte(nil), encoded[:len(encoded)-1]...),
		[]byte(`,"event_id":"`+event.EventID+`"}`)...)
	tests := map[string][]byte{
		"duplicate field": duplicate,
		"unknown field": append(append([]byte(nil), encoded[:len(encoded)-1]...),
			[]byte(`,"unknown":true}`)...),
		"trailing value": append(append([]byte(nil), encoded...), []byte(` {}`)...),
	}
	for name, plaintext := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := sealRawSyncPlaintext(t, plaintext, fixture.profile.AccountID, recipient)
			if _, err := OpenSyncEvent(
				context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
				envelope, now, &syncReplayMemory{},
			); err == nil {
				t.Fatal("non-canonical device-sync plaintext was accepted")
			}
		})
	}
}

func TestDeviceSyncRejectsSignedMalformedEventIDAndEnvelopeBounds(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	event, envelopes, err := SealSyncEvent(
		fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("bounded"), now, time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	recipient := fixture.certificates[1]
	malformed := cloneSyncEvent(event)
	malformed.EventID = "not-a-canonical-event-id"
	unsigned, err := syncEventSigningBytes(malformed)
	if err != nil {
		t.Fatal(err)
	}
	malformed.Signature, err = fixture.locals[0].SignDevicePayload(syncEventDomain, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSyncEvent(
		context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
		sealRawSyncEvent(t, malformed, fixture.profile.AccountID, recipient), now, &syncReplayMemory{},
	); err == nil {
		t.Fatal("signed malformed device-sync event ID was accepted")
	}

	valid := envelopeForDevice(t, envelopes, recipient.Device.DeviceID)
	tests := map[string]func(*protocol.DeviceSyncEnvelope){
		"wrong device": func(candidate *protocol.DeviceSyncEnvelope) { candidate.DeviceID = fixture.locals[0].DeviceID() },
		"wrong suite":  func(candidate *protocol.DeviceSyncEnvelope) { candidate.Payload.Suite = "unknown" },
		"empty encapsulation": func(candidate *protocol.DeviceSyncEnvelope) {
			candidate.Payload.Encapsulation = nil
		},
		"oversized encapsulation": func(candidate *protocol.DeviceSyncEnvelope) {
			candidate.Payload.Encapsulation = make([]byte, MaxSyncEncapsulationBytes+1)
		},
		"empty ciphertext": func(candidate *protocol.DeviceSyncEnvelope) { candidate.Payload.Ciphertext = nil },
		"oversized ciphertext": func(candidate *protocol.DeviceSyncEnvelope) {
			candidate.Payload.Ciphertext = make([]byte, MaxSignedSyncEventBytes+1025)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Payload.Encapsulation = append([]byte(nil), valid.Payload.Encapsulation...)
			candidate.Payload.Ciphertext = append([]byte(nil), valid.Payload.Ciphertext...)
			mutate(&candidate)
			if _, err := OpenSyncEvent(
				context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
				candidate, now, &syncReplayMemory{},
			); err == nil {
				t.Fatal("out-of-range device-sync envelope was accepted")
			}
		})
	}
}

func TestDeviceSyncReplayReservationIsConcurrent(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	_, envelopes, err := SealSyncEvent(
		fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("once"), now, time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := envelopeForDevice(t, envelopes, fixture.locals[1].DeviceID())
	replays := &syncReplayMemory{}
	const attempts = 16
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, openErr := OpenSyncEvent(
				context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
				envelope, now, replays,
			)
			results <- openErr
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for openErr := range results {
		if openErr == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent replay reservation admitted %d events", successes)
	}
}

func TestSignedDeviceSyncRoundTripAndReplayRejection(t *testing.T) {
	fixture := newSyncFixture(t, 3)
	now := time.Now().UTC()
	payload := []byte("sync this authenticated state")
	event, envelopes, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision, payload, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if event.ProfileRevision != fixture.profile.Revision || len(envelopes) != len(fixture.profile.Devices) {
		t.Fatal("sync event did not bind the current complete profile")
	}
	envelope := envelopeForDevice(t, envelopes, fixture.locals[1].DeviceID())
	replays := &syncReplayMemory{}
	verified, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision, envelope, now, replays)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified.Event().Payload, payload) {
		t.Fatal("opened device-sync payload differs")
	}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision, envelope, now, replays); err == nil {
		t.Fatal("replayed device-sync event was accepted")
	}
}

func TestDeviceSyncRejectsOutsiderForgeryAndTampering(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	event, envelopes, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("authentic"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recipient := fixture.certificates[1]
	validEnvelope := envelopeForDevice(t, envelopes, recipient.Device.DeviceID)

	outsider, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged := cloneSyncEvent(event)
	unsigned, err := syncEventSigningBytes(forged)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature, err = outsider.Sign(syncEventDomain, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	replays := &syncReplayMemory{}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
		sealRawSyncEvent(t, forged, fixture.profile.AccountID, recipient), now, replays); err == nil {
		t.Fatal("outsider-created HPKE sync event was accepted")
	}
	if replays.accepts != 0 {
		t.Fatal("unauthenticated sync event reached replay state")
	}

	tests := map[string]func(*SignedSyncEvent){
		"account":  func(candidate *SignedSyncEvent) { candidate.AccountID = identity.AccountID(outsider.PublicIdentity()) },
		"revision": func(candidate *SignedSyncEvent) { candidate.ProfileRevision++ },
		"event ID": func(candidate *SignedSyncEvent) {
			candidate.EventID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"created": func(candidate *SignedSyncEvent) { candidate.CreatedAt = candidate.CreatedAt.Add(time.Second) },
		"expires": func(candidate *SignedSyncEvent) { candidate.ExpiresAt = candidate.ExpiresAt.Add(time.Second) },
		"payload": func(candidate *SignedSyncEvent) { candidate.Payload[0] ^= 1 },
		"sender":  func(candidate *SignedSyncEvent) { candidate.SenderDevice = cloneCertificate(recipient) },
		"signature": func(candidate *SignedSyncEvent) {
			candidate.Signature.Ed25519[0] ^= 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneSyncEvent(event)
			mutate(&candidate)
			envelope := sealRawSyncEvent(t, candidate, fixture.profile.AccountID, recipient)
			if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
				envelope, now, &syncReplayMemory{}); err == nil {
				t.Fatal("tampered signed device-sync event was accepted")
			}
		})
	}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
		validEnvelope, now, nil); !errors.Is(err, ErrSyncReplayStoreRequired) {
		t.Fatal("device-sync event opened without a replay store")
	}
}

func TestDeviceSyncRejectsRevokedSenderAndRecipient(t *testing.T) {
	fixture := newSyncFixture(t, 3)
	now := time.Now().UTC()
	event, envelopes, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("revision-bound"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recipientEnvelope := envelopeForDevice(t, envelopes, fixture.locals[1].DeviceID())

	withoutSender, err := SignPublicProfile(fixture.root, 2, now,
		[]DeviceCertificate{fixture.certificates[1], fixture.certificates[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], withoutSender, withoutSender.Revision,
		recipientEnvelope, now, &syncReplayMemory{}); err == nil {
		t.Fatal("sync event from a revoked sender was accepted")
	}
	if _, _, err := SealSyncEvent(fixture.locals[0], withoutSender, withoutSender.Revision, []byte("forbidden"), now, time.Hour); err == nil {
		t.Fatal("revoked sender created a sync event")
	}

	withoutRecipient, err := SignPublicProfile(fixture.root, 2, now,
		[]DeviceCertificate{fixture.certificates[0], fixture.certificates[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], withoutRecipient, withoutRecipient.Revision,
		recipientEnvelope, now, &syncReplayMemory{}); err == nil {
		t.Fatal("revoked recipient opened a sync event")
	}
	_, activeEnvelopes, err := SealSyncEvent(fixture.locals[0], withoutRecipient, withoutRecipient.Revision, []byte("current only"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(activeEnvelopes) != 2 {
		t.Fatal("sync event was not limited to the current active device set")
	}
	for _, envelope := range activeEnvelopes {
		if envelope.DeviceID == fixture.locals[1].DeviceID() {
			t.Fatal("sync event was encrypted to a revoked recipient")
		}
	}
	_ = event
}

func TestDeviceSyncRejectsProfileRollbackAndCrossRevisionEvent(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	_, envelopes, err := SealSyncEvent(
		fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("revision one"), now, time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealSyncEvent(
		fixture.locals[0], fixture.profile, fixture.profile.Revision+1, []byte("rolled back"), now, time.Hour,
	); err == nil {
		t.Fatal("sync was encrypted using a profile below the locally pinned revision")
	}

	current, err := SignPublicProfile(fixture.root, fixture.profile.Revision+1, now, fixture.certificates)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope := envelopeForDevice(t, envelopes, fixture.locals[1].DeviceID())
	if _, err := OpenSyncEvent(
		context.Background(), fixture.locals[1], current, current.Revision, oldEnvelope, now, &syncReplayMemory{},
	); err == nil {
		t.Fatal("device-sync event from an older profile revision was accepted")
	}
	if _, err := OpenSyncEvent(
		context.Background(), fixture.locals[1], current, current.Revision+1, oldEnvelope, now, &syncReplayMemory{},
	); err == nil {
		t.Fatal("device-sync opened with a profile below the locally pinned revision")
	}
}

func TestDeviceSyncBoundsAndTransportFit(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	now := time.Now().UTC()
	payload := make([]byte, MaxSyncEventPayloadBytes)
	event, envelopes, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision, payload, now, MaxSyncEventLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Payload) != MaxSyncEventPayloadBytes {
		t.Fatal("maximum device-sync payload was truncated")
	}
	for _, envelope := range envelopes {
		wire, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if len(wire) > protocol.DefaultMaxItemBytes {
			t.Fatalf("device-sync envelope is not transportable: %d bytes", len(wire))
		}
	}
	if _, _, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision,
		make([]byte, MaxSyncEventPayloadBytes+1), now, time.Hour); err == nil {
		t.Fatal("oversized device-sync payload was accepted")
	}
	if _, _, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision,
		[]byte("too short"), now, time.Nanosecond); err == nil {
		t.Fatal("sub-millisecond device-sync lifetime was accepted")
	}
	shortEvent, shortEnvelopes, err := SealSyncEvent(fixture.locals[0], fixture.profile, fixture.profile.Revision, []byte("short"), now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSyncEvent(context.Background(), fixture.locals[1], fixture.profile, fixture.profile.Revision,
		envelopeForDevice(t, shortEnvelopes, fixture.locals[1].DeviceID()), now.Add(2*time.Second), &syncReplayMemory{}); err == nil {
		t.Fatal("expired device-sync event was accepted")
	}
	_ = shortEvent
}

func TestSyncRejectsUnverifiedOrDuplicateDevices(t *testing.T) {
	fixture := newSyncFixture(t, 2)
	tampered := cloneCertificate(fixture.certificates[0])
	tampered.Device.DeviceID = "attacker-device"
	if VerifyDevice(fixture.profile.AccountPublic, tampered) {
		t.Fatal("tampered device certificate was accepted")
	}
}
