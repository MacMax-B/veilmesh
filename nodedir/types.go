// Package nodedir implements VeilMesh's bounded, signed IP node directory.
//
// The directory is a discovery and availability mechanism, not an anonymity
// mechanism. Node endpoints are intentionally public. Membership is admitted
// only through locally pinned seed identities and short-lived signed leases.
package nodedir

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

const (
	ProtocolVersion      = 1
	ChallengeBytes       = 32
	MaxDirectoryNodes    = 512
	MaxAttestations      = 16
	MaxSnapshotBytes     = 16 * 1024 * 1024
	MaxRegistrationBytes = 256 * 1024
	MinLease             = 10 * time.Minute
	MaxLease             = 2 * time.Hour
	MaxClockSkew         = 5 * time.Minute
)

const (
	announcementDomain = "node-directory-announcement"
	attestationDomain  = "node-directory-attestation"
	snapshotDomain     = "node-directory-snapshot"
	challengeDomain    = "node-directory-challenge"
)

type Endpoint struct {
	Scheme string `json:"scheme"`
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
}

func (endpoint Endpoint) BaseURL() string {
	return endpoint.Scheme + "://" + net.JoinHostPort(endpoint.IP, strconv.Itoa(int(endpoint.Port)))
}

type PinnedNode struct {
	Identity protocol.NodePublicIdentity `json:"identity"`
	Endpoint Endpoint                    `json:"endpoint"`
}

type Announcement struct {
	Version   uint8                       `json:"version"`
	Identity  protocol.NodePublicIdentity `json:"identity"`
	Endpoint  Endpoint                    `json:"endpoint"`
	Sequence  uint64                      `json:"sequence"`
	IssuedAt  time.Time                   `json:"issued_at"`
	ExpiresAt time.Time                   `json:"expires_at"`
	Signature protocol.HybridSignature    `json:"signature"`
}

type Attestation struct {
	Version          uint8                    `json:"version"`
	AuthorityID      string                   `json:"authority_id"`
	AnnouncementHash []byte                   `json:"announcement_hash"`
	ObservedAt       time.Time                `json:"observed_at"`
	ExpiresAt        time.Time                `json:"expires_at"`
	Signature        protocol.HybridSignature `json:"signature"`
}

type Record struct {
	Announcement Announcement  `json:"announcement"`
	Attestations []Attestation `json:"attestations"`
}

type Snapshot struct {
	Version     uint8                       `json:"version"`
	Publisher   protocol.NodePublicIdentity `json:"publisher"`
	GeneratedAt time.Time                   `json:"generated_at"`
	Records     []Record                    `json:"records"`
	Signature   protocol.HybridSignature    `json:"signature"`
}

type RegistrationRequest struct {
	Record Record `json:"record"`
}

type ChallengeRequest struct {
	Nonce []byte `json:"nonce"`
}

type ChallengeResponse struct {
	Version   uint8                    `json:"version"`
	NodeID    string                   `json:"node_id"`
	Nonce     []byte                   `json:"nonce"`
	CreatedAt time.Time                `json:"created_at"`
	Signature protocol.HybridSignature `json:"signature"`
}

type Signer interface {
	PublicIdentity() protocol.NodePublicIdentity
	Sign(domain string, message []byte) (protocol.HybridSignature, error)
}

type Policy struct {
	Seeds           []PinnedNode
	AuthorityQuorum int
	AllowPrivateIPs bool
	MaxNodes        int
}

func NewPolicy(seeds []PinnedNode, authorityQuorum int, allowPrivateIPs bool, maxNodes int) (Policy, error) {
	if len(seeds) == 0 || len(seeds) > MaxAttestations || authorityQuorum <= 0 || authorityQuorum > len(seeds) {
		return Policy{}, errors.New("invalid directory seed quorum")
	}
	if maxNodes == 0 {
		maxNodes = MaxDirectoryNodes
	}
	if maxNodes <= 0 || maxNodes > MaxDirectoryNodes {
		return Policy{}, errors.New("invalid directory node limit")
	}
	seen := make(map[string]struct{}, len(seeds))
	copySeeds := make([]PinnedNode, len(seeds))
	for index, seed := range seeds {
		if !pqcrypto.ValidPublicIdentity(seed.Identity) {
			return Policy{}, errors.New("invalid pinned seed identity")
		}
		canonical, err := validateEndpoint(seed.Endpoint, allowPrivateIPs)
		if err != nil || canonical != seed.Endpoint {
			return Policy{}, errors.New("invalid or non-canonical pinned seed endpoint")
		}
		if _, duplicate := seen[seed.Identity.NodeID]; duplicate {
			return Policy{}, errors.New("duplicate pinned seed identity")
		}
		seen[seed.Identity.NodeID] = struct{}{}
		copySeeds[index] = clonePinnedNode(seed)
	}
	return Policy{Seeds: copySeeds, AuthorityQuorum: authorityQuorum, AllowPrivateIPs: allowPrivateIPs, MaxNodes: maxNodes}, nil
}

func validateEndpoint(endpoint Endpoint, allowPrivate bool) (Endpoint, error) {
	if endpoint.Scheme != "https" && endpoint.Scheme != "http" || endpoint.Port == 0 {
		return Endpoint{}, errors.New("invalid node endpoint transport")
	}
	address, err := netip.ParseAddr(endpoint.IP)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return Endpoint{}, errors.New("node endpoint must contain a usable literal IP")
	}
	address = address.Unmap()
	if endpoint.Scheme == "http" && !(allowPrivate && (address.IsPrivate() || address.IsLoopback())) {
		return Endpoint{}, errors.New("plain HTTP is restricted to private development endpoints")
	}
	if !allowPrivate && !publicRoutable(address) {
		return Endpoint{}, errors.New("private node endpoint is disabled")
	}
	return Endpoint{Scheme: endpoint.Scheme, IP: address.String(), Port: endpoint.Port}, nil
}

func publicRoutable(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func SignAnnouncement(signer Signer, endpoint Endpoint, sequence uint64, now time.Time, lease time.Duration, allowPrivate bool) (Announcement, error) {
	if signer == nil || sequence == 0 || now.IsZero() || lease < MinLease || lease > MaxLease {
		return Announcement{}, errors.New("invalid node announcement input")
	}
	canonical, err := validateEndpoint(endpoint, allowPrivate)
	if err != nil || canonical != endpoint {
		return Announcement{}, errors.New("node endpoint is not canonical")
	}
	announcement := Announcement{
		Version: ProtocolVersion, Identity: signer.PublicIdentity(), Endpoint: endpoint, Sequence: sequence,
		IssuedAt: now.UTC().Truncate(time.Millisecond), ExpiresAt: now.UTC().Add(lease).Truncate(time.Millisecond),
	}
	if !pqcrypto.ValidPublicIdentity(announcement.Identity) {
		return Announcement{}, errors.New("invalid node signing identity")
	}
	announcement.Signature, err = signer.Sign(announcementDomain, announcementSigningBytes(announcement))
	if err != nil {
		return Announcement{}, err
	}
	return announcement, nil
}

func VerifyAnnouncement(announcement Announcement, now time.Time, allowPrivate bool) error {
	canonical, endpointErr := validateEndpoint(announcement.Endpoint, allowPrivate)
	if announcement.Version != ProtocolVersion || !pqcrypto.ValidPublicIdentity(announcement.Identity) ||
		endpointErr != nil || canonical != announcement.Endpoint || announcement.Sequence == 0 ||
		announcement.IssuedAt.IsZero() || announcement.ExpiresAt.IsZero() ||
		announcement.IssuedAt.After(now.Add(MaxClockSkew)) || !announcement.ExpiresAt.After(now) ||
		announcement.ExpiresAt.Sub(announcement.IssuedAt) < MinLease ||
		announcement.ExpiresAt.Sub(announcement.IssuedAt) > MaxLease {
		return errors.New("invalid node announcement")
	}
	if !pqcrypto.Verify(announcement.Identity, announcementDomain, announcementSigningBytes(announcement), announcement.Signature) {
		return errors.New("invalid node announcement signature")
	}
	return nil
}

func AnnouncementHash(announcement Announcement) []byte {
	digest := sha256.Sum256(append(announcementSigningBytes(announcement), signatureBytes(announcement.Signature)...))
	return digest[:]
}

func SignAttestation(signer Signer, announcement Announcement, now time.Time) (Attestation, error) {
	if signer == nil || now.IsZero() || now.After(announcement.ExpiresAt) {
		return Attestation{}, errors.New("invalid node attestation input")
	}
	attestation := Attestation{
		Version: ProtocolVersion, AuthorityID: signer.PublicIdentity().NodeID,
		AnnouncementHash: AnnouncementHash(announcement), ObservedAt: now.UTC().Truncate(time.Millisecond),
		ExpiresAt: announcement.ExpiresAt.UTC().Truncate(time.Millisecond),
	}
	var err error
	attestation.Signature, err = signer.Sign(attestationDomain, attestationSigningBytes(attestation))
	if err != nil {
		return Attestation{}, err
	}
	return attestation, nil
}

func VerifyRecord(policy Policy, record Record, now time.Time) error {
	valid, err := verifyRecordAttestations(policy, record, now)
	if err != nil {
		return err
	}
	if policy.isPinned(record.Announcement) {
		return nil
	}
	if valid < policy.AuthorityQuorum {
		return errors.New("node record does not meet the pinned authority quorum")
	}
	return nil
}

func verifyPartialRecord(policy Policy, record Record, now time.Time) error {
	_, err := verifyRecordAttestations(policy, record, now)
	return err
}

func verifyRecordAttestations(policy Policy, record Record, now time.Time) (int, error) {
	if len(policy.Seeds) == 0 || len(policy.Seeds) > MaxAttestations || policy.AuthorityQuorum <= 0 ||
		policy.AuthorityQuorum > len(policy.Seeds) || policy.MaxNodes <= 0 || policy.MaxNodes > MaxDirectoryNodes {
		return 0, errors.New("invalid node directory policy")
	}
	if len(record.Attestations) > MaxAttestations {
		return 0, errors.New("node record has too many attestations")
	}
	if err := VerifyAnnouncement(record.Announcement, now, policy.AllowPrivateIPs); err != nil {
		return 0, err
	}
	expectedHash := AnnouncementHash(record.Announcement)
	authorities := policy.authorities()
	seen := make(map[string]struct{}, len(record.Attestations))
	valid := 0
	for _, attestation := range record.Attestations {
		identity, trusted := authorities[attestation.AuthorityID]
		if !trusted || attestation.Version != ProtocolVersion || len(attestation.AnnouncementHash) != sha256.Size ||
			!bytes.Equal(attestation.AnnouncementHash, expectedHash) || attestation.ObservedAt.IsZero() ||
			attestation.ObservedAt.After(now.Add(MaxClockSkew)) || attestation.ObservedAt.Before(record.Announcement.IssuedAt.Add(-MaxClockSkew)) ||
			!attestation.ExpiresAt.Equal(record.Announcement.ExpiresAt) {
			return 0, errors.New("invalid node attestation")
		}
		if _, duplicate := seen[attestation.AuthorityID]; duplicate {
			return 0, errors.New("duplicate node attestation")
		}
		if !pqcrypto.Verify(identity, attestationDomain, attestationSigningBytes(attestation), attestation.Signature) {
			return 0, errors.New("invalid node attestation signature")
		}
		seen[attestation.AuthorityID] = struct{}{}
		valid++
	}
	return valid, nil
}

func NewChallenge() ([]byte, error) {
	nonce := make([]byte, ChallengeBytes)
	_, err := rand.Read(nonce)
	return nonce, err
}

func SignChallenge(signer Signer, nonce []byte, now time.Time) (ChallengeResponse, error) {
	if signer == nil || len(nonce) != ChallengeBytes || now.IsZero() {
		return ChallengeResponse{}, errors.New("invalid node challenge")
	}
	response := ChallengeResponse{Version: ProtocolVersion, NodeID: signer.PublicIdentity().NodeID, Nonce: append([]byte(nil), nonce...), CreatedAt: now.UTC().Truncate(time.Millisecond)}
	var err error
	response.Signature, err = signer.Sign(challengeDomain, challengeSigningBytes(response))
	return response, err
}

func VerifyChallenge(identity protocol.NodePublicIdentity, nonce []byte, response ChallengeResponse, now time.Time) error {
	if response.Version != ProtocolVersion || response.NodeID != identity.NodeID || len(nonce) != ChallengeBytes ||
		!bytes.Equal(nonce, response.Nonce) || response.CreatedAt.Before(now.Add(-MaxClockSkew)) ||
		response.CreatedAt.After(now.Add(MaxClockSkew)) ||
		!pqcrypto.Verify(identity, challengeDomain, challengeSigningBytes(response), response.Signature) {
		return errors.New("invalid node reachability proof")
	}
	return nil
}

func (policy Policy) authorities() map[string]protocol.NodePublicIdentity {
	result := make(map[string]protocol.NodePublicIdentity, len(policy.Seeds))
	for _, seed := range policy.Seeds {
		result[seed.Identity.NodeID] = seed.Identity
	}
	return result
}

func (policy Policy) Authority(identity protocol.NodePublicIdentity) bool {
	pinned, ok := policy.pinned(identity.NodeID)
	return ok && sameIdentity(pinned.Identity, identity)
}

func (policy Policy) isPinned(announcement Announcement) bool {
	pinned, ok := policy.pinned(announcement.Identity.NodeID)
	return ok && sameIdentity(pinned.Identity, announcement.Identity) && pinned.Endpoint == announcement.Endpoint
}

func (policy Policy) pinned(nodeID string) (PinnedNode, bool) {
	for _, seed := range policy.Seeds {
		if seed.Identity.NodeID == nodeID {
			return seed, true
		}
	}
	return PinnedNode{}, false
}

func sameIdentity(left, right protocol.NodePublicIdentity) bool {
	return left.NodeID == right.NodeID && left.ProtocolVersion == right.ProtocolVersion &&
		bytes.Equal(left.Ed25519Public, right.Ed25519Public) && bytes.Equal(left.MLDSA65Public, right.MLDSA65Public)
}

func appendAttestation(record Record, attestation Attestation) Record {
	result := cloneRecord(record)
	for index, existing := range result.Attestations {
		if existing.AuthorityID == attestation.AuthorityID {
			result.Attestations[index] = cloneAttestation(attestation)
			sort.Slice(result.Attestations, func(i, j int) bool { return result.Attestations[i].AuthorityID < result.Attestations[j].AuthorityID })
			return result
		}
	}
	result.Attestations = append(result.Attestations, cloneAttestation(attestation))
	sort.Slice(result.Attestations, func(i, j int) bool { return result.Attestations[i].AuthorityID < result.Attestations[j].AuthorityID })
	return result
}

func writeBytes(buffer *bytes.Buffer, value []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value))) // #nosec G115 -- all inputs are bounded by their parser.
	_, _ = buffer.Write(value)
}

func writeString(buffer *bytes.Buffer, value string) { writeBytes(buffer, []byte(value)) }
func writeTime(buffer *bytes.Buffer, value time.Time) {
	_ = binary.Write(buffer, binary.BigEndian, value.UTC().UnixMilli())
}

func writeIdentity(buffer *bytes.Buffer, identity protocol.NodePublicIdentity) {
	writeString(buffer, identity.NodeID)
	writeBytes(buffer, identity.Ed25519Public)
	writeBytes(buffer, identity.MLDSA65Public)
	buffer.WriteByte(identity.ProtocolVersion)
}

func signatureBytes(signature protocol.HybridSignature) []byte {
	var buffer bytes.Buffer
	writeBytes(&buffer, signature.Ed25519)
	writeBytes(&buffer, signature.MLDSA65)
	return buffer.Bytes()
}

func announcementSigningBytes(announcement Announcement) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(announcement.Version)
	writeIdentity(&buffer, announcement.Identity)
	writeString(&buffer, announcement.Endpoint.Scheme)
	writeString(&buffer, announcement.Endpoint.IP)
	_ = binary.Write(&buffer, binary.BigEndian, announcement.Endpoint.Port)
	_ = binary.Write(&buffer, binary.BigEndian, announcement.Sequence)
	writeTime(&buffer, announcement.IssuedAt)
	writeTime(&buffer, announcement.ExpiresAt)
	return buffer.Bytes()
}

func attestationSigningBytes(attestation Attestation) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(attestation.Version)
	writeString(&buffer, attestation.AuthorityID)
	writeBytes(&buffer, attestation.AnnouncementHash)
	writeTime(&buffer, attestation.ObservedAt)
	writeTime(&buffer, attestation.ExpiresAt)
	return buffer.Bytes()
}

func challengeSigningBytes(response ChallengeResponse) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(response.Version)
	writeString(&buffer, response.NodeID)
	writeBytes(&buffer, response.Nonce)
	writeTime(&buffer, response.CreatedAt)
	return buffer.Bytes()
}

func clonePinnedNode(value PinnedNode) PinnedNode {
	value.Identity.Ed25519Public = append([]byte(nil), value.Identity.Ed25519Public...)
	value.Identity.MLDSA65Public = append([]byte(nil), value.Identity.MLDSA65Public...)
	return value
}

func cloneAttestation(value Attestation) Attestation {
	value.AnnouncementHash = append([]byte(nil), value.AnnouncementHash...)
	value.Signature.Ed25519 = append([]byte(nil), value.Signature.Ed25519...)
	value.Signature.MLDSA65 = append([]byte(nil), value.Signature.MLDSA65...)
	return value
}

func cloneRecord(value Record) Record {
	value.Announcement.Identity = clonePinnedNode(PinnedNode{Identity: value.Announcement.Identity}).Identity
	value.Announcement.Signature.Ed25519 = append([]byte(nil), value.Announcement.Signature.Ed25519...)
	value.Announcement.Signature.MLDSA65 = append([]byte(nil), value.Announcement.Signature.MLDSA65...)
	value.Attestations = append([]Attestation(nil), value.Attestations...)
	for index := range value.Attestations {
		value.Attestations[index] = cloneAttestation(value.Attestations[index])
	}
	return value
}
