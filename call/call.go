// Package call provides authenticated direct 1:1 WebRTC calls.
//
// Media is protected end to end by DTLS-SRTP. The complete SDP, including the
// ephemeral DTLS certificate fingerprint and ICE candidates, is hybrid-signed
// by the caller's or callee's existing device identity before it is sent over
// the messaging channel. This prevents a signaling service or storage node
// from substituting a media endpoint.
//
// This package deliberately does not implement SFU/group-call encryption.
// Such calls require an audited RFC 9605 SFrame implementation and an audited
// forward-secure group key manager such as RFC 9420 MLS.
package call

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"

	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	ProtocolVersion       = 1
	MaxSignalBytes        = 96 * 1024
	MaxSDPBytes           = 64 * 1024
	MaxICECandidates      = 64
	MaxICEServers         = 8
	MaxICEURLs            = 16
	MaxConcurrentCalls    = 64
	MaxRememberedCallIDs  = 4096
	DefaultSignalLifetime = 2 * time.Minute
	MaxSignalLifetime     = 5 * time.Minute
	DefaultCallDuration   = time.Hour
	MaxCallDuration       = 24 * time.Hour
	clockSkew             = 2 * time.Minute
	signalDomain          = "direct-call-signal"
)

var (
	ErrInvalidSignal     = errors.New("invalid direct-call signal")
	ErrExpiredSignal     = errors.New("expired direct-call signal")
	ErrSignalReplay      = errors.New("direct-call signal replay")
	ErrCallLimit         = errors.New("concurrent direct-call limit reached")
	ErrAnswerAlreadyUsed = errors.New("call answer was already applied")
)

type SignalType string

const (
	SignalOffer  SignalType = "offer"
	SignalAnswer SignalType = "answer"
)

// Media describes the only media sections accepted by direct-call protocol
// v1. At least one of Audio or Video must be set.
type Media struct {
	Audio bool `json:"audio"`
	Video bool `json:"video"`
}

// Signal is safe to serialize inside an end-to-end encrypted chat message.
// The signature authenticates every field, including all ICE candidates and
// the ephemeral DTLS certificate fingerprint contained in SDP.
type Signal struct {
	Version     uint8                    `json:"version"`
	CallID      string                   `json:"call_id"`
	Type        SignalType               `json:"type"`
	InitiatorID string                   `json:"initiator_id"`
	ResponderID string                   `json:"responder_id"`
	CreatedAt   time.Time                `json:"created_at"`
	ExpiresAt   time.Time                `json:"expires_at"`
	Media       Media                    `json:"media"`
	SDP         string                   `json:"sdp"`
	Signature   protocol.HybridSignature `json:"signature"`
}

type Config struct {
	Signer             *pqcrypto.HybridSigner
	ICEServers         []webrtc.ICEServer
	ICETransportPolicy webrtc.ICETransportPolicy
	SignalLifetime     time.Duration
	MaxCallDuration    time.Duration
	MaxConcurrent      int
}

// Endpoint owns the bounded replay cache and WebRTC configuration for one
// device. A new ephemeral ECDSA certificate is generated for every call.
type Endpoint struct {
	signer         *pqcrypto.HybridSigner
	identity       protocol.NodePublicIdentity
	configuration  webrtc.Configuration
	api            *webrtc.API
	signalLifetime time.Duration
	callDuration   time.Duration
	maxConcurrent  int

	mu     sync.Mutex
	active int
	seen   map[string]time.Time
}

// Session wraps the media-facing part of a direct PeerConnection. Frontends
// can provide platform-specific Pion tracks, but never handle key material.
type Session struct {
	pc             *webrtc.PeerConnection
	callID         string
	localID        string
	remoteIdentity protocol.NodePublicIdentity
	initiator      bool
	audioSender    *webrtc.RTPSender
	videoSender    *webrtc.RTPSender
	release        func()

	mu            sync.Mutex
	answerApplied bool
	closed        bool
	timer         *time.Timer
}

func NewEndpoint(config Config) (*Endpoint, error) {
	if config.Signer == nil {
		return nil, errors.New("call signer is required")
	}
	identity := config.Signer.PublicIdentity()
	if !pqcrypto.ValidPublicIdentity(identity) {
		return nil, errors.New("invalid call signing identity")
	}
	if config.SignalLifetime == 0 {
		config.SignalLifetime = DefaultSignalLifetime
	}
	if config.SignalLifetime <= 0 || config.SignalLifetime > MaxSignalLifetime {
		return nil, errors.New("call signal lifetime is out of range")
	}
	if config.MaxCallDuration == 0 {
		config.MaxCallDuration = DefaultCallDuration
	}
	if config.MaxCallDuration <= 0 || config.MaxCallDuration > MaxCallDuration {
		return nil, errors.New("maximum call duration is out of range")
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 8
	}
	if config.MaxConcurrent < 1 || config.MaxConcurrent > MaxConcurrentCalls {
		return nil, errors.New("concurrent call limit is out of range")
	}
	if err := validateICEServers(config.ICEServers); err != nil {
		return nil, err
	}
	if config.ICETransportPolicy != webrtc.ICETransportPolicyAll &&
		config.ICETransportPolicy != webrtc.ICETransportPolicyRelay {
		return nil, errors.New("invalid ICE transport policy")
	}

	settings := webrtc.SettingEngine{}
	settings.SetDTLSCipherSuites(
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	)
	settings.SetSRTPProtectionProfiles(
		dtls.SRTP_AEAD_AES_256_GCM,
		dtls.SRTP_AEAD_AES_128_GCM,
	)
	settings.SetDTLSExtendedMasterSecret(dtls.RequireExtendedMasterSecret)
	settings.SetDTLSReplayProtectionWindow(128)
	settings.SetSRTPReplayProtectionWindow(256)
	settings.SetSRTCPReplayProtectionWindow(256)
	// Pion authenticates WebRTC's self-signed DTLS certificate against the
	// fingerprint in SDP. The SDP itself is authenticated by our hybrid
	// signature, so no public CA validation is applicable here.
	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelDisabled
	loggerFactory.ScopeLevels = map[string]logging.LogLevel{}
	settings.LoggerFactory = loggerFactory

	return &Endpoint{
		signer:   config.Signer,
		identity: identity,
		configuration: webrtc.Configuration{
			ICEServers:         append([]webrtc.ICEServer(nil), config.ICEServers...),
			ICETransportPolicy: config.ICETransportPolicy,
			BundlePolicy:       webrtc.BundlePolicyMaxBundle,
			RTCPMuxPolicy:      webrtc.RTCPMuxPolicyRequire,
			SDPSemantics:       webrtc.SDPSemanticsUnifiedPlan,
		},
		api:            webrtc.NewAPI(webrtc.WithSettingEngine(settings)),
		signalLifetime: config.SignalLifetime,
		callDuration:   config.MaxCallDuration,
		maxConcurrent:  config.MaxConcurrent,
		seen:           make(map[string]time.Time),
	}, nil
}

func (e *Endpoint) Identity() protocol.NodePublicIdentity { return e.identity }

// Start creates an offer with all gathered ICE candidates. The caller sends
// the returned Signal through the existing encrypted messaging channel.
func (e *Endpoint) Start(ctx context.Context, remote protocol.NodePublicIdentity, media Media) (*Session, Signal, error) {
	if !pqcrypto.ValidPublicIdentity(remote) || remote.NodeID == e.identity.NodeID {
		return nil, Signal{}, errors.New("invalid remote call identity")
	}
	if err := validateMedia(media); err != nil {
		return nil, Signal{}, err
	}
	if err := e.acquire(""); err != nil {
		return nil, Signal{}, err
	}
	releaseOnFailure := true
	defer func() {
		if releaseOnFailure {
			e.release()
		}
	}()

	pc, senders, err := e.newPeerConnection(media, true)
	if err != nil {
		return nil, Signal{}, err
	}
	fail := func(err error) (*Session, Signal, error) {
		_ = pc.Close()
		return nil, Signal{}, err
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fail(err)
	}
	if err := setLocalAndGather(ctx, pc, offer); err != nil {
		return fail(err)
	}
	local := pc.LocalDescription()
	if local == nil {
		return fail(errors.New("WebRTC did not produce a local offer"))
	}
	if err := validateSDP(local.SDP, media); err != nil {
		return fail(fmt.Errorf("generated offer: %w", err))
	}
	callID, err := randomCallID()
	if err != nil {
		return fail(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	signal := Signal{
		Version:     ProtocolVersion,
		CallID:      callID,
		Type:        SignalOffer,
		InitiatorID: e.identity.NodeID,
		ResponderID: remote.NodeID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(e.signalLifetime),
		Media:       media,
		SDP:         local.SDP,
	}
	if err := signSignal(e.signer, &signal); err != nil {
		return fail(err)
	}
	session := e.session(pc, callID, remote, true, senders)
	releaseOnFailure = false
	return session, signal, nil
}

// Accept verifies an offer before parsing SDP or allocating a PeerConnection,
// reserves its call ID against replay, and returns the signed answer.
func (e *Endpoint) Accept(ctx context.Context, remote protocol.NodePublicIdentity, offer Signal) (*Session, Signal, error) {
	now := time.Now().UTC()
	if err := verifySignal(offer, SignalOffer, remote, e.identity.NodeID, now); err != nil {
		return nil, Signal{}, err
	}
	if err := e.acquire(offer.CallID); err != nil {
		return nil, Signal{}, err
	}
	releaseOnFailure := true
	defer func() {
		if releaseOnFailure {
			e.release()
		}
	}()

	pc, senders, err := e.newPeerConnection(offer.Media, false)
	if err != nil {
		return nil, Signal{}, err
	}
	fail := func(err error) (*Session, Signal, error) {
		_ = pc.Close()
		return nil, Signal{}, err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.SDP}); err != nil {
		return fail(fmt.Errorf("set authenticated remote offer: %w", err))
	}
	for _, transceiver := range pc.GetTransceivers() {
		switch transceiver.Kind() {
		case webrtc.RTPCodecTypeAudio:
			senders.audio = transceiver.Sender()
		case webrtc.RTPCodecTypeVideo:
			senders.video = transceiver.Sender()
		}
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fail(err)
	}
	if err := setLocalAndGather(ctx, pc, answer); err != nil {
		return fail(err)
	}
	local := pc.LocalDescription()
	if local == nil {
		return fail(errors.New("WebRTC did not produce a local answer"))
	}
	if err := validateSDP(local.SDP, offer.Media); err != nil {
		return fail(fmt.Errorf("generated answer: %w", err))
	}
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	answerSignal := Signal{
		Version:     ProtocolVersion,
		CallID:      offer.CallID,
		Type:        SignalAnswer,
		InitiatorID: offer.InitiatorID,
		ResponderID: offer.ResponderID,
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt.Add(e.signalLifetime),
		Media:       offer.Media,
		SDP:         local.SDP,
	}
	if err := signSignal(e.signer, &answerSignal); err != nil {
		return fail(err)
	}
	session := e.session(pc, offer.CallID, remote, false, senders)
	releaseOnFailure = false
	return session, answerSignal, nil
}

// ApplyAnswer authenticates the callee and the DTLS fingerprint before Pion
// processes the remote SDP. A session accepts exactly one answer.
func (s *Session) ApplyAnswer(answer Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("call session is closed")
	}
	if !s.initiator || s.answerApplied {
		return ErrAnswerAlreadyUsed
	}
	if answer.CallID != s.callID || answer.InitiatorID != s.localID {
		return ErrInvalidSignal
	}
	if err := verifySignal(answer, SignalAnswer, s.remoteIdentity, s.localID, time.Now().UTC()); err != nil {
		return err
	}
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer.SDP}); err != nil {
		return fmt.Errorf("set authenticated remote answer: %w", err)
	}
	s.answerApplied = true
	return nil
}

func (s *Session) CallID() string { return s.callID }

func (s *Session) ConnectionState() webrtc.PeerConnectionState { return s.pc.ConnectionState() }

func (s *Session) OnConnectionStateChange(handler func(webrtc.PeerConnectionState)) {
	s.pc.OnConnectionStateChange(handler)
}

func (s *Session) OnTrack(handler func(*webrtc.TrackRemote, *webrtc.RTPReceiver)) {
	s.pc.OnTrack(handler)
}

func (s *Session) ReplaceAudioTrack(track webrtc.TrackLocal) error {
	if s.audioSender == nil {
		return errors.New("audio was not negotiated for this call")
	}
	return s.audioSender.ReplaceTrack(track)
}

func (s *Session) ReplaceVideoTrack(track webrtc.TrackLocal) error {
	if s.videoSender == nil {
		return errors.New("video was not negotiated for this call")
	}
	return s.videoSender.ReplaceTrack(track)
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	release := s.release
	s.release = nil
	s.mu.Unlock()
	err := s.pc.Close()
	if release != nil {
		release()
	}
	return err
}

type mediaSenders struct {
	audio *webrtc.RTPSender
	video *webrtc.RTPSender
}

func (e *Endpoint) newPeerConnection(media Media, addTransceivers bool) (*webrtc.PeerConnection, mediaSenders, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, mediaSenders{}, err
	}
	certificate, err := webrtc.GenerateCertificate(privateKey)
	if err != nil {
		return nil, mediaSenders{}, err
	}
	configuration := e.configuration
	configuration.Certificates = []webrtc.Certificate{*certificate}
	pc, err := e.api.NewPeerConnection(configuration)
	if err != nil {
		return nil, mediaSenders{}, err
	}
	senders := mediaSenders{}
	if !addTransceivers {
		return pc, senders, nil
	}
	add := func(kind webrtc.RTPCodecType) (*webrtc.RTPSender, error) {
		transceiver, err := pc.AddTransceiverFromKind(kind, webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendrecv,
		})
		if err != nil {
			return nil, err
		}
		return transceiver.Sender(), nil
	}
	if media.Audio {
		senders.audio, err = add(webrtc.RTPCodecTypeAudio)
		if err != nil {
			_ = pc.Close()
			return nil, mediaSenders{}, err
		}
	}
	if media.Video {
		senders.video, err = add(webrtc.RTPCodecTypeVideo)
		if err != nil {
			_ = pc.Close()
			return nil, mediaSenders{}, err
		}
	}
	return pc, senders, nil
}

func (e *Endpoint) session(pc *webrtc.PeerConnection, callID string, remote protocol.NodePublicIdentity, initiator bool, senders mediaSenders) *Session {
	s := &Session{
		pc:             pc,
		callID:         callID,
		localID:        e.identity.NodeID,
		remoteIdentity: remote,
		initiator:      initiator,
		audioSender:    senders.audio,
		videoSender:    senders.video,
		release:        e.release,
	}
	s.timer = time.AfterFunc(e.callDuration, func() { _ = s.Close() })
	return s
}

func (e *Endpoint) acquire(callID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for id, expiresAt := range e.seen {
		if !expiresAt.After(now) {
			delete(e.seen, id)
		}
	}
	if callID != "" {
		if _, exists := e.seen[callID]; exists {
			return ErrSignalReplay
		}
		if len(e.seen) >= MaxRememberedCallIDs {
			return ErrCallLimit
		}
	}
	if e.active >= e.maxConcurrent {
		return ErrCallLimit
	}
	if callID != "" {
		e.seen[callID] = now.Add(MaxSignalLifetime + clockSkew)
	}
	e.active++
	return nil
}

func (e *Endpoint) release() {
	e.mu.Lock()
	if e.active > 0 {
		e.active--
	}
	e.mu.Unlock()
}

func setLocalAndGather(ctx context.Context, pc *webrtc.PeerConnection, description webrtc.SessionDescription) error {
	complete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(description); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-complete:
		return nil
	}
}

func randomCallID() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func validCallID(callID string) bool {
	if len(callID) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(callID)
	return err == nil && len(decoded) == 32
}

func signalBytes(signal Signal) ([]byte, error) {
	unsigned := signal
	unsigned.Signature = protocol.HybridSignature{}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxSignalBytes {
		return nil, ErrInvalidSignal
	}
	return encoded, nil
}

func signSignal(signer *pqcrypto.HybridSigner, signal *Signal) error {
	encoded, err := signalBytes(*signal)
	if err != nil {
		return err
	}
	signal.Signature, err = signer.Sign(signalDomain, encoded)
	return err
}

func verifySignal(signal Signal, expectedType SignalType, signer protocol.NodePublicIdentity, localID string, now time.Time) error {
	if !pqcrypto.ValidPublicIdentity(signer) || signal.Version != ProtocolVersion ||
		signal.Type != expectedType || !validCallID(signal.CallID) ||
		signal.InitiatorID == "" || signal.ResponderID == "" ||
		signal.InitiatorID == signal.ResponderID {
		return ErrInvalidSignal
	}
	expectedSigner := signal.InitiatorID
	if expectedType == SignalAnswer {
		expectedSigner = signal.ResponderID
	}
	if signer.NodeID != expectedSigner ||
		(expectedType == SignalOffer && localID != signal.ResponderID) ||
		(expectedType == SignalAnswer && localID != signal.InitiatorID) {
		return ErrInvalidSignal
	}
	if signal.CreatedAt.After(now.Add(clockSkew)) || !signal.ExpiresAt.After(now) ||
		!signal.ExpiresAt.After(signal.CreatedAt) || signal.ExpiresAt.Sub(signal.CreatedAt) > MaxSignalLifetime {
		return ErrExpiredSignal
	}
	if err := validateMedia(signal.Media); err != nil {
		return ErrInvalidSignal
	}
	if len(signal.SDP) == 0 || len(signal.SDP) > MaxSDPBytes || strings.IndexByte(signal.SDP, 0) >= 0 {
		return ErrInvalidSignal
	}
	encoded, err := signalBytes(signal)
	if err != nil || !pqcrypto.Verify(signer, signalDomain, encoded, signal.Signature) {
		return ErrInvalidSignal
	}
	if err := validateSDP(signal.SDP, signal.Media); err != nil {
		return ErrInvalidSignal
	}
	return nil
}

func validateMedia(media Media) error {
	if !media.Audio && !media.Video {
		return errors.New("a direct call requires audio or video")
	}
	return nil
}

func validateSDP(raw string, media Media) error {
	if len(raw) == 0 || len(raw) > MaxSDPBytes || strings.IndexByte(raw, 0) >= 0 {
		return ErrInvalidSignal
	}
	var description sdp.SessionDescription
	if err := description.Unmarshal([]byte(raw)); err != nil {
		return ErrInvalidSignal
	}
	audio, video, candidates := 0, 0, 0
	fingerprint := false
	for _, attribute := range description.Attributes {
		if attribute.Key == "fingerprint" && validSHA256Fingerprint(attribute.Value) {
			fingerprint = true
		}
		if attribute.Key == "candidate" {
			candidates++
		}
	}
	for _, section := range description.MediaDescriptions {
		switch section.MediaName.Media {
		case "audio":
			audio++
		case "video":
			video++
		default:
			return ErrInvalidSignal
		}
		for _, attribute := range section.Attributes {
			if attribute.Key == "fingerprint" && validSHA256Fingerprint(attribute.Value) {
				fingerprint = true
			}
			if attribute.Key == "candidate" {
				candidates++
			}
		}
	}
	if !fingerprint || candidates > MaxICECandidates || audio > 1 || video > 1 ||
		(media.Audio != (audio == 1)) || (media.Video != (video == 1)) {
		return ErrInvalidSignal
	}
	return nil
}

func validSHA256Fingerprint(value string) bool {
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "sha-256") {
		return false
	}
	compact := strings.ReplaceAll(fields[1], ":", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 32 && strings.Count(fields[1], ":") == 31
}

func validateICEServers(servers []webrtc.ICEServer) error {
	if len(servers) > MaxICEServers {
		return errors.New("too many ICE servers")
	}
	totalURLs := 0
	for _, server := range servers {
		totalURLs += len(server.URLs)
		if len(server.Username) > 256 {
			return errors.New("ICE username is too long")
		}
		if password, ok := server.Credential.(string); ok && len(password) > 1024 {
			return errors.New("ICE credential is too long")
		}
		for _, rawURL := range server.URLs {
			if len(rawURL) == 0 || len(rawURL) > 2048 {
				return errors.New("ICE server URL is out of range")
			}
		}
	}
	if totalURLs > MaxICEURLs {
		return errors.New("too many ICE server URLs")
	}
	return nil
}
