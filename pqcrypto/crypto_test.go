package pqcrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/protocol"
)

func TestHybridHPKERoundTrip(t *testing.T) {
	keyPair, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("associated metadata")
	plaintext := []byte("secret message")
	encapsulation, ciphertext, err := Seal(keyPair.PublicKey, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(keyPair.PrivateKey, encapsulation, aad, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("opened plaintext differs")
	}
	if _, err := Open(keyPair.PrivateKey, encapsulation, []byte("wrong aad"), ciphertext); err == nil {
		t.Fatal("wrong associated data was accepted")
	}
}

func TestLargestPaddingBucketFitsDirectCiphertextWireLimit(t *testing.T) {
	keyPair, err := GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, MaxPaddedMessageBytes-4)
	padded, err := PadMessage(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != MaxPaddedMessageBytes {
		t.Fatalf("unexpected largest padding bucket: %d", len(padded))
	}
	encapsulation, ciphertext, err := Seal(keyPair.PublicKey, []byte("bounded-wire-test"), padded)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(protocol.DirectCiphertext{
		Suite: HybridHPKESuite, Encapsulation: encapsulation, Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > protocol.DefaultMaxItemBytes {
		t.Fatalf("largest padded direct ciphertext exceeds item limit: %d > %d", len(wire), protocol.DefaultMaxItemBytes)
	}
	if _, err := PadMessage(make([]byte, MaxPaddedMessageBytes-3)); err == nil {
		t.Fatal("plaintext above the largest transportable padding bucket was accepted")
	}
}

func TestUnpadMessageRejectsNonProtocolBucket(t *testing.T) {
	padded := make([]byte, 2048)
	binary.BigEndian.PutUint32(padded[:4], 1)
	padded[4] = 1
	if _, err := UnpadMessage(padded); err == nil {
		t.Fatal("non-protocol padding bucket was accepted")
	}
}

func TestHybridSignaturesRequireBothAlgorithms(t *testing.T) {
	signer, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("signed statement")
	signature, err := signer.Sign("test", message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(signer.PublicIdentity(), "test", message, signature) {
		t.Fatal("valid hybrid signature rejected")
	}
	signature.Ed25519[0] ^= 1
	if Verify(signer.PublicIdentity(), "test", message, signature) {
		t.Fatal("signature with invalid classical component accepted")
	}
}

func TestSignatureDomainsRejectAmbiguousOrUnboundedValues(t *testing.T) {
	signer, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign("a", []byte("\x00b"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(signer.PublicIdentity(), "a", []byte("\x00b"), signature) {
		t.Fatal("valid NUL-free signature domain was rejected")
	}
	// The legacy delimiter encoding produces the same digest for these two
	// pairs. Rejecting NUL in domains prevents the alternate interpretation
	// without changing any existing NUL-free signature bytes.
	if !bytes.Equal(domainMessage("a", []byte("\x00b")), domainMessage("a\x00", []byte("b"))) {
		t.Fatal("test inputs no longer demonstrate the delimiter ambiguity")
	}
	if Verify(signer.PublicIdentity(), "a\x00", []byte("b"), signature) {
		t.Fatal("signature verified under an ambiguous NUL-containing domain")
	}
	for name, domain := range map[string]string{
		"empty":     "",
		"NUL":       "a\x00b",
		"oversized": string(bytes.Repeat([]byte{'a'}, MaxSignatureDomainBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signer.Sign(domain, []byte("message")); err == nil {
				t.Fatal("invalid signature domain was accepted")
			}
			if Verify(signer.PublicIdentity(), domain, []byte("message"), signature) {
				t.Fatal("invalid signature domain reached verification")
			}
		})
	}
}

func TestMalformedHybridInputsAreRejected(t *testing.T) {
	signer, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	identity := signer.PublicIdentity()
	identity.MLDSA65Public = append(identity.MLDSA65Public, 0)
	if ValidPublicIdentity(identity) {
		t.Fatal("oversized ML-DSA public key was accepted")
	}
	if err := ValidateHybridKEMPublicKey(make([]byte, 32)); err == nil {
		t.Fatal("wrong-sized hybrid KEM key was accepted")
	}
}

func TestTransportCertificateUsesNodeSigningKey(t *testing.T) {
	signer, err := GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	certificate, err := signer.TransportCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := certificate.Leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, signer.PublicIdentity().Ed25519Public) {
		t.Fatal("transport certificate is not bound to the node signing identity")
	}
	if certificate.Leaf.IsCA || certificate.Leaf.NotAfter.Sub(now) != NodeTransportCertificateLifetime {
		t.Fatal("transport certificate has unsafe constraints")
	}
	if _, err := (*HybridSigner)(nil).TransportCertificate(now); err == nil {
		t.Fatal("nil signer produced a transport certificate")
	}
	if _, err := (&HybridSigner{}).TransportCertificate(now); err == nil {
		t.Fatal("empty signer produced a transport certificate")
	}
	if _, err := signer.TransportCertificate(time.Time{}); err == nil {
		t.Fatal("zero time produced a transport certificate")
	}
}
