package mixtransport

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeProvider struct {
	security     PacketSecurity
	mu           sync.Mutex
	realCalls    int
	coverCalls   int
	pollCalls    int
	badRealSize  bool
	badCoverSize bool
	badPollSize  bool
}

func securePacketSecurity() PacketSecurity {
	return PacketSecurity{
		Protocol: "test-pq-sphinx", IndependentAudit: "test-audit", MinimumMixHops: 3,
		FixedLengthPackets: true, LayeredMixing: true, PerHopAuthentication: true,
		ReplayProtection: true, UniformReplies: true, PostQuantumHybridOnion: true,
		ForwardSecureRoutingKeys: true,
	}
}

func (provider *fakeProvider) Security() PacketSecurity { return provider.security }

func testPacket(size int, marker byte, badSize bool) PreparedPacket {
	if badSize {
		size--
	}
	packet := make([]byte, size)
	packet[0] = marker
	return PreparedPacket{Packet: packet}
}

func (provider *fakeProvider) PrepareReal(_ context.Context, _ []byte, packetBytes int) (PreparedPacket, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.realCalls++
	return testPacket(packetBytes, 1, provider.badRealSize), nil
}

func (provider *fakeProvider) PreparePoll(_ context.Context, packetBytes int) (PreparedPacket, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.pollCalls++
	return testPacket(packetBytes, 3, provider.badPollSize), nil
}

func (provider *fakeProvider) PrepareCover(_ context.Context, packetBytes int) (PreparedPacket, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.coverCalls++
	return testPacket(packetBytes, 2, provider.badCoverSize), nil
}

type fakeSink struct {
	security LinkSecurity
	mu       sync.Mutex
	packets  [][]byte
	err      error
	delay    time.Duration
	sent     chan struct{}
}

func secureLinkSecurity() LinkSecurity {
	return LinkSecurity{
		Protocol: "test-pq-link", IndependentAudit: "test-audit", AuthenticatedEntry: true,
		PersistentConnection: true, FixedLengthFrames: true, PostQuantumHybridKEX: true,
		NoRedirects: true,
	}
}

func (sink *fakeSink) Security() LinkSecurity { return sink.security }

func (sink *fakeSink) Send(ctx context.Context, packet []byte) error {
	if sink.err != nil {
		return sink.err
	}
	if sink.delay > 0 {
		timer := time.NewTimer(sink.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sink.mu.Lock()
	sink.packets = append(sink.packets, append([]byte(nil), packet...))
	sink.mu.Unlock()
	if sink.sent != nil {
		select {
		case sink.sent <- struct{}{}:
		default:
		}
	}
	return nil
}

func testScheduler(t *testing.T, provider *fakeProvider, sink *fakeSink, maxQueue int) *Scheduler {
	t.Helper()
	scheduler, err := NewScheduler(Config{
		PacketBytes: DefaultPacketBytes, SlotInterval: ReferenceSlotInterval, PollEverySlots: ReferencePollEverySlots,
		MaxQueue: maxQueue, MaxLateness: 100 * time.Millisecond, DispatchBudget: 500 * time.Millisecond,
	}, provider, sink)
	if err != nil {
		t.Fatal(err)
	}
	return scheduler
}

func testCommand(t *testing.T, now time.Time, lifetime time.Duration) Command {
	t.Helper()
	command, err := NewCommand(KindStore, []byte("opaque ratchet ciphertext"), now, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestConstantSlotsUseRealPollAndCoverAtOneFixedSize(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	sink := &fakeSink{security: secureLinkSecurity()}
	scheduler := testScheduler(t, provider, sink, 8)
	now := time.Now().UTC()
	first, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	for slot := 0; slot < 6; slot++ {
		if err := scheduler.dispatchSlot(context.Background(), now.Add(time.Duration(slot)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.packets) != 6 {
		t.Fatalf("got %d packets for six mandatory slots", len(sink.packets))
	}
	for _, packet := range sink.packets {
		if len(packet) != DefaultPacketBytes {
			t.Fatal("observer saw a variable packet size")
		}
	}
	// Test markers are visible only in this fake provider. The audited provider
	// must make these packet classes computationally indistinguishable.
	markers := []byte{sink.packets[0][0], sink.packets[1][0], sink.packets[2][0], sink.packets[3][0], sink.packets[4][0], sink.packets[5][0]}
	if string(markers) != string([]byte{1, 1, 2, 2, 2, 3}) {
		t.Fatalf("unexpected slot classes: %v", markers)
	}
	if result, err := first.Wait(context.Background()); err != nil || result.RequestID == "" {
		t.Fatal("first real packet was not dispatched")
	}
	if _, err := second.Wait(context.Background()); err != nil {
		t.Fatal("second real packet was not dispatched")
	}
	if provider.coverCalls != 6 || provider.pollCalls != 1 {
		t.Fatal("mandatory cover or polling work was skipped")
	}
}

func TestQueueLimitIsEnforcedBeforeProviderWork(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	scheduler := testScheduler(t, provider, &fakeSink{security: secureLinkSecurity()}, 1)
	now := time.Now().UTC()
	if _, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now); !errors.Is(err, ErrQueueFull) {
		t.Fatal("full queue was not rejected")
	}
	if provider.realCalls != 1 {
		t.Fatal("provider performed expensive work after queue limit")
	}
}

func TestExpiredCommandBecomesCoverWithoutTrafficGap(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	sink := &fakeSink{security: secureLinkSecurity()}
	scheduler := testScheduler(t, provider, sink, 4)
	now := time.Now().UTC()
	ticket, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ticket.Wait(context.Background()); !errors.Is(err, ErrCommandExpired) {
		t.Fatal("expired command was dispatched")
	}
	if len(sink.packets) != 1 || sink.packets[0][0] != 2 {
		t.Fatal("expired command created an observable empty slot")
	}
}

func TestSchedulerFailsClosedOnMissingAssurancesAndBadPackets(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	sink := &fakeSink{security: secureLinkSecurity()}
	weakProvider := &fakeProvider{security: securePacketSecurity()}
	weakProvider.security.PostQuantumHybridOnion = false
	if _, err := NewScheduler(Config{}, weakProvider, sink); !errors.Is(err, ErrPacketProviderRequired) {
		t.Fatal("classical-only onion provider was accepted")
	}
	weakSink := &fakeSink{security: secureLinkSecurity()}
	weakSink.security.FixedLengthFrames = false
	if _, err := NewScheduler(Config{}, provider, weakSink); !errors.Is(err, ErrPrivateLinkRequired) {
		t.Fatal("variable-length entry link was accepted")
	}
	badProvider := &fakeProvider{security: securePacketSecurity(), badRealSize: true}
	scheduler := testScheduler(t, badProvider, sink, 4)
	now := time.Now().UTC()
	if _, err := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now); err == nil {
		t.Fatal("wrong-size real packet was accepted")
	}
	badProvider = &fakeProvider{security: securePacketSecurity(), badCoverSize: true}
	scheduler = testScheduler(t, badProvider, sink, 4)
	if err := scheduler.dispatchSlot(context.Background(), now); err == nil {
		t.Fatal("wrong-size cover packet was accepted")
	}
	badProvider = &fakeProvider{security: securePacketSecurity(), badPollSize: true}
	scheduler = testScheduler(t, badProvider, sink, 4)
	if err := scheduler.dispatchSlot(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), now.Add(5*time.Second)); err == nil {
		t.Fatal("wrong-size poll packet was accepted")
	}
	if _, err := NewScheduler(Config{PacketBytes: DefaultPacketBytes * 2}, provider, sink); err == nil {
		t.Fatal("fingerprintable non-reference packet profile was accepted")
	}
	if _, err := NewScheduler(Config{SlotInterval: 2 * time.Second}, provider, sink); err == nil {
		t.Fatal("fingerprintable non-reference timing profile was accepted")
	}
}

func TestRunCancellationTerminatesPendingTrafficAndCannotRestart(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	sink := &fakeSink{security: secureLinkSecurity(), sent: make(chan struct{}, 1)}
	scheduler, err := NewScheduler(Config{
		PacketBytes: DefaultPacketBytes, SlotInterval: ReferenceSlotInterval, PollEverySlots: ReferencePollEverySlots,
		MaxQueue: 4, MaxLateness: 100 * time.Millisecond, DispatchBudget: 250 * time.Millisecond,
	}, provider, sink)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first, _ := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now)
	second, _ := scheduler.Enqueue(context.Background(), testCommand(t, now, time.Minute), now)
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- scheduler.Run(ctx) }()
	select {
	case <-sink.sent:
		cancel()
	case <-time.After(8 * time.Second):
		t.Fatal("constant-rate scheduler did not emit its first slot")
	}
	if _, err := first.Wait(context.Background()); err != nil {
		t.Fatal("first queued packet was not dispatched")
	}
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected scheduler stop: %v", err)
	}
	if _, err := second.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal("pending packet did not inherit terminal scheduler failure")
	}
	if err := scheduler.Run(context.Background()); err == nil {
		t.Fatal("terminated anonymity schedule was silently restarted")
	}
}

func TestDispatchBudgetFailureIsFailClosed(t *testing.T) {
	provider := &fakeProvider{security: securePacketSecurity()}
	sink := &fakeSink{security: secureLinkSecurity(), delay: 100 * time.Millisecond}
	scheduler, err := NewScheduler(Config{
		PacketBytes: DefaultPacketBytes, SlotInterval: ReferenceSlotInterval, PollEverySlots: ReferencePollEverySlots,
		MaxQueue: 4, MaxLateness: 50 * time.Millisecond, DispatchBudget: 25 * time.Millisecond,
	}, provider, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.dispatchSlot(context.Background(), time.Now()); err == nil {
		t.Fatal("slot budget overrun was accepted")
	}
}

func TestCommandParserRejectsTamperingAndLimits(t *testing.T) {
	now := time.Now().UTC()
	command := testCommand(t, now, time.Minute)
	encoded, err := EncodeCommand(command, now)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := DecodeCommand(withUnknown, now); err == nil {
		t.Fatal("unknown command field was accepted")
	}
	if _, err := DecodeCommand(make([]byte, MaxEncodedCommandBytes+1), now); err == nil {
		t.Fatal("oversized command was accepted")
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["kind"] = "invented"
	tampered, _ := json.Marshal(object)
	if _, err := DecodeCommand(tampered, now); err == nil {
		t.Fatal("unknown command kind was accepted")
	}
	object["kind"] = string(KindStore)
	object["request_id"] = "predictable"
	tampered, _ = json.Marshal(object)
	if _, err := DecodeCommand(tampered, now); err == nil {
		t.Fatal("weak request capability was accepted")
	}
	object["request_id"] = command.RequestID[:len(command.RequestID)-1] + "B"
	tampered, _ = json.Marshal(object)
	if _, err := DecodeCommand(tampered, now); err == nil {
		t.Fatal("non-canonical request capability was accepted")
	}
	object["request_id"] = command.RequestID
	object["version"] = float64(1)
	tampered, _ = json.Marshal(object)
	if _, err := DecodeCommand(tampered, now); err == nil {
		t.Fatal("superseded ENIG-Mix v1 command was accepted by v2")
	}
	if _, err := NewCommand(KindStore, make([]byte, MaxCommandPayloadBytes+1), now, time.Minute); err == nil {
		t.Fatal("oversized command payload was accepted")
	}
}

func FuzzDecodeCommand(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = DecodeCommand(encoded, time.Now())
	})
}
