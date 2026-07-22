package pqcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/MacMax-B/propagare/protocol"
)

const (
	signatureContext        = "enig-v1"
	MaxSignatureDomainBytes = 128
)

type HybridSigner struct {
	edPrivate ed25519.PrivateKey
	pqPrivate *mldsa65.PrivateKey
}

type PrivateSigningMaterial struct {
	Ed25519Private []byte `json:"ed25519_private"`
	MLDSA65Private []byte `json:"ml_dsa_65_private"`
}

func GenerateHybridSigner() (*HybridSigner, error) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, pqPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &HybridSigner{edPrivate: edPrivate, pqPrivate: pqPrivate}, nil
}

func NewHybridSigner(material PrivateSigningMaterial) (*HybridSigner, error) {
	if len(material.Ed25519Private) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	var pqPrivate mldsa65.PrivateKey
	if err := pqPrivate.UnmarshalBinary(material.MLDSA65Private); err != nil {
		return nil, err
	}
	return &HybridSigner{
		edPrivate: append(ed25519.PrivateKey(nil), material.Ed25519Private...),
		pqPrivate: &pqPrivate,
	}, nil
}

func (s *HybridSigner) PrivateMaterial() PrivateSigningMaterial {
	return PrivateSigningMaterial{
		Ed25519Private: append([]byte(nil), s.edPrivate...),
		MLDSA65Private: s.pqPrivate.Bytes(),
	}
}

func (s *HybridSigner) PublicIdentity() protocol.NodePublicIdentity {
	edPublic := s.edPrivate.Public().(ed25519.PublicKey)
	pqPublic := s.pqPrivate.Public().(*mldsa65.PublicKey)
	identity := protocol.NodePublicIdentity{
		Ed25519Public:   append([]byte(nil), edPublic...),
		MLDSA65Public:   pqPublic.Bytes(),
		ProtocolVersion: protocol.ProtocolVersion,
	}
	identity.NodeID = NodeID(identity)
	return identity
}

func NodeID(identity protocol.NodePublicIdentity) string {
	h := sha256.New()
	_, _ = h.Write([]byte("enig/node-id/v1"))
	_, _ = h.Write(identity.Ed25519Public)
	_, _ = h.Write(identity.MLDSA65Public)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidPublicIdentity rejects malformed or cross-version identities before
// they reach expensive signature verification.
func ValidPublicIdentity(identity protocol.NodePublicIdentity) bool {
	if identity.ProtocolVersion != protocol.ProtocolVersion ||
		len(identity.Ed25519Public) != ed25519.PublicKeySize ||
		len(identity.MLDSA65Public) != mldsa65.PublicKeySize ||
		identity.NodeID != NodeID(identity) {
		return false
	}
	var pqPublic mldsa65.PublicKey
	return pqPublic.UnmarshalBinary(identity.MLDSA65Public) == nil
}

func domainMessage(domain string, message []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("enig/signature/v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(message)
	return h.Sum(nil)
}

func validSignatureDomain(domain string) bool {
	return len(domain) > 0 && len(domain) <= MaxSignatureDomainBytes && strings.IndexByte(domain, 0) < 0
}

func (s *HybridSigner) Sign(domain string, message []byte) (protocol.HybridSignature, error) {
	if !validSignatureDomain(domain) {
		return protocol.HybridSignature{}, errors.New("invalid signature domain")
	}
	digest := domainMessage(domain, message)
	pqSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.pqPrivate, digest, []byte(signatureContext), true, pqSignature); err != nil {
		return protocol.HybridSignature{}, err
	}
	return protocol.HybridSignature{
		Ed25519: ed25519.Sign(s.edPrivate, digest),
		MLDSA65: pqSignature,
	}, nil
}

func Verify(identity protocol.NodePublicIdentity, domain string, message []byte, signature protocol.HybridSignature) bool {
	if !validSignatureDomain(domain) || !ValidPublicIdentity(identity) || len(signature.Ed25519) != ed25519.SignatureSize ||
		len(signature.MLDSA65) != mldsa65.SignatureSize {
		return false
	}
	var pqPublic mldsa65.PublicKey
	if err := pqPublic.UnmarshalBinary(identity.MLDSA65Public); err != nil {
		return false
	}
	digest := domainMessage(domain, message)
	edOK := ed25519.Verify(ed25519.PublicKey(identity.Ed25519Public), digest, signature.Ed25519)
	pqOK := mldsa65.Verify(&pqPublic, digest, []byte(signatureContext), signature.MLDSA65)
	return edOK && pqOK
}

func DeleteTokenHash(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

func DeleteTokenMatches(expectedHash, token []byte) bool {
	actual := DeleteTokenHash(token)
	return len(expectedHash) == len(actual) && subtle.ConstantTimeCompare(expectedHash, actual) == 1
}
