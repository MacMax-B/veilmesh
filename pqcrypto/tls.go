package pqcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

const NodeTransportCertificateLifetime = 366 * 24 * time.Hour

// TransportCertificate creates a self-signed certificate container for the
// signer's existing Ed25519 public key. Its self-signature is an integrity and
// possession check, not a trust root: clients pin the key through the complete
// hybrid-signed Node identity instead of trusting a CA.
func (s *HybridSigner) TransportCertificate(now time.Time) (tls.Certificate, error) {
	if s == nil || len(s.edPrivate) != ed25519.PrivateKeySize || s.pqPrivate == nil || now.IsZero() {
		return tls.Certificate{}, errors.New("invalid node transport certificate input")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	public := s.edPrivate.Public()
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              now.UTC().Add(NodeTransportCertificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, public, s.edPrivate)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(encoded)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{encoded},
		PrivateKey:  s.edPrivate,
		Leaf:        leaf,
	}, nil
}
