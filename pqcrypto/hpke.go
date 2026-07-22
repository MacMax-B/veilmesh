package pqcrypto

import (
	"crypto/hpke"
	"errors"
)

const (
	HybridHPKESuite = "HPKE-MLKEM768-X25519-HKDFSHA256-CHACHA20POLY1305"
	hpkeInfo        = "veilmesh/direct-envelope/v1"
)

type HybridKEMKeyPair struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

func GenerateHybridKEMKeyPair() (HybridKEMKeyPair, error) {
	kem := hpke.MLKEM768X25519()
	privateKey, err := kem.GenerateKey()
	if err != nil {
		return HybridKEMKeyPair{}, err
	}
	privateBytes, err := privateKey.Bytes()
	if err != nil {
		return HybridKEMKeyPair{}, err
	}
	return HybridKEMKeyPair{
		PrivateKey: privateBytes,
		PublicKey:  privateKey.PublicKey().Bytes(),
	}, nil
}

// ValidateHybridKEMPublicKey parses a key with the standard-library hybrid
// KEM without performing encapsulation or allocating from attacker-controlled
// length fields.
func ValidateHybridKEMPublicKey(publicKey []byte) error {
	_, err := hpke.MLKEM768X25519().NewPublicKey(publicKey)
	return err
}

// HybridKEMPublicFromPrivate parses private key material and derives its
// public key. It is used while restoring a locally protected account to reject
// mismatched or corrupted vault records.
func HybridKEMPublicFromPrivate(privateKey []byte) ([]byte, error) {
	private, err := hpke.MLKEM768X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return private.PublicKey().Bytes(), nil
}

func Seal(publicKey, aad, plaintext []byte) (encapsulation, ciphertext []byte, err error) {
	kem := hpke.MLKEM768X25519()
	public, err := kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	encapsulation, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(hpkeInfo))
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err = sender.Seal(aad, plaintext)
	return encapsulation, ciphertext, err
}

func Open(privateKey, encapsulation, aad, ciphertext []byte) ([]byte, error) {
	if len(encapsulation) == 0 || len(ciphertext) == 0 {
		return nil, errors.New("empty HPKE envelope")
	}
	kem := hpke.MLKEM768X25519()
	private, err := kem.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(encapsulation, private, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(hpkeInfo))
	if err != nil {
		return nil, err
	}
	return recipient.Open(aad, ciphertext)
}
