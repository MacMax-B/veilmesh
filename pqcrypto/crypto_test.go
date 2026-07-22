package pqcrypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
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
