package call

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	"propagare/pqcrypto"
)

const testAudioSDP = "v=0\r\n" +
	"o=- 1 1 IN IP4 0.0.0.0\r\n" +
	"s=-\r\n" +
	"t=0 0\r\n" +
	"a=group:BUNDLE 0\r\n" +
	"a=fingerprint:sha-256 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F\r\n" +
	"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" +
	"c=IN IP4 0.0.0.0\r\n" +
	"a=mid:0\r\n" +
	"a=rtcp-mux\r\n" +
	"a=sendrecv\r\n" +
	"a=ice-ufrag:test\r\n" +
	"a=ice-pwd:0123456789012345678901\r\n" +
	"a=setup:actpass\r\n" +
	"a=rtpmap:111 opus/48000/2\r\n"

func TestSignalAuthenticationExpiryAndBounds(t *testing.T) {
	caller, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	callee, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	callID, err := randomCallID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	signal := Signal{
		Version:     ProtocolVersion,
		CallID:      callID,
		Type:        SignalOffer,
		InitiatorID: caller.PublicIdentity().NodeID,
		ResponderID: callee.PublicIdentity().NodeID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Minute),
		Media:       Media{Audio: true},
		SDP:         testAudioSDP,
	}
	if err := signSignal(caller, &signal); err != nil {
		t.Fatal(err)
	}
	if err := verifySignal(signal, SignalOffer, caller.PublicIdentity(), callee.PublicIdentity().NodeID, now); err != nil {
		t.Fatalf("valid signal rejected: %v", err)
	}

	tampered := signal
	tampered.SDP += "a=x-propagare-tampered:1\r\n"
	if err := verifySignal(tampered, SignalOffer, caller.PublicIdentity(), callee.PublicIdentity().NodeID, now); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("tampered SDP was not rejected: %v", err)
	}
	if err := verifySignal(signal, SignalOffer, callee.PublicIdentity(), callee.PublicIdentity().NodeID, now); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("wrong signer was not rejected: %v", err)
	}
	expired := signal
	expired.CreatedAt = now.Add(-2 * time.Minute)
	expired.ExpiresAt = now.Add(-time.Minute)
	if err := signSignal(caller, &expired); err != nil {
		t.Fatal(err)
	}
	if err := verifySignal(expired, SignalOffer, caller.PublicIdentity(), callee.PublicIdentity().NodeID, now); !errors.Is(err, ErrExpiredSignal) {
		t.Fatalf("expired signal was not rejected: %v", err)
	}
	tooManySections := signal
	tooManySections.SDP += "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:1\r\n"
	if err := signSignal(caller, &tooManySections); err != nil {
		t.Fatal(err)
	}
	if err := verifySignal(tooManySections, SignalOffer, caller.PublicIdentity(), callee.PublicIdentity().NodeID, now); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("duplicate audio section was not rejected: %v", err)
	}
}

func TestCallIDRejectsNonCanonicalBase64(t *testing.T) {
	canonical := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if !validCallID(canonical) {
		t.Fatal("canonical call ID rejected")
	}
	if validCallID(canonical[:len(canonical)-1] + "B") {
		t.Fatal("non-canonical call ID accepted")
	}
}

func TestEndpointReplayAndConcurrencyBounds(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(Config{Signer: signer, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	callID, err := randomCallID()
	if err != nil {
		t.Fatal(err)
	}
	if err := endpoint.acquire(callID); err != nil {
		t.Fatal(err)
	}
	if err := endpoint.acquire(callID); !errors.Is(err, ErrSignalReplay) {
		t.Fatalf("replayed call ID was not rejected: %v", err)
	}
	otherID, _ := randomCallID()
	if err := endpoint.acquire(otherID); !errors.Is(err, ErrCallLimit) {
		t.Fatalf("concurrent call overflow was not rejected: %v", err)
	}
	endpoint.release()
}

func TestDirectCallConnectsAndCarriesAuthenticatedMedia(t *testing.T) {
	callerSigner, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	calleeSigner, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	caller, err := NewEndpoint(Config{Signer: callerSigner, MaxCallDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	callee, err := NewEndpoint(Config{Signer: calleeSigner, MaxCallDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	callerSession, offer, err := caller.Start(ctx, callee.Identity(), Media{Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	defer callerSession.Close()
	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48_000, Channels: 2},
		"audio", "propagare-direct-call",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := callerSession.ReplaceAudioTrack(track); err != nil {
		t.Fatal(err)
	}
	calleeSession, answer, err := callee.Accept(ctx, caller.Identity(), offer)
	if err != nil {
		t.Fatal(err)
	}
	defer calleeSession.Close()
	received := make(chan struct{}, 1)
	calleeSession.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if _, _, readErr := remote.ReadRTP(); readErr == nil {
			select {
			case received <- struct{}{}:
			default:
			}
		}
	})
	if err := callerSession.ApplyAnswer(answer); err != nil {
		t.Fatal(err)
	}

	connected := make(chan struct{}, 1)
	callerSession.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateConnected {
			select {
			case connected <- struct{}{}:
			default:
			}
		}
	})
	if callerSession.ConnectionState() != webrtc.PeerConnectionStateConnected {
		select {
		case <-connected:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for sequence := uint16(1); sequence <= 20; sequence++ {
		if err := track.WriteRTP(&rtp.Packet{
			Header:  rtp.Header{Version: 2, PayloadType: 111, SequenceNumber: sequence, Timestamp: uint32(sequence) * 960, SSRC: 1234},
			Payload: []byte{0xf8, 0xff, 0xfe},
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-received:
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
	t.Fatal("authenticated media was not received")
}
