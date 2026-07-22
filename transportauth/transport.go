// Package transportauth provides CA-PKI-free node transport authentication.
// Node public keys are pinned from hybrid-signed directory identities; TLS is
// used only as the standardized authenticated key-exchange and record layer.
package transportauth

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"propagare/pqcrypto"
	"propagare/protocol"
)

const transportCertificateRenewBefore = 30 * 24 * time.Hour

type certificateSource struct {
	mu          sync.Mutex
	signer      *pqcrypto.HybridSigner
	currentTime func() time.Time
	certificate tls.Certificate
}

// ServerTLSConfigForSigner creates the production server profile and renews
// its self-signed certificate container before expiry without changing the
// pinned Node public key.
func ServerTLSConfigForSigner(signer *pqcrypto.HybridSigner) (*tls.Config, error) {
	return rotatingServerTLSConfig(signer, time.Now)
}

func rotatingServerTLSConfig(signer *pqcrypto.HybridSigner, currentTime func() time.Time) (*tls.Config, error) {
	if signer == nil || currentTime == nil {
		return nil, errors.New("node transport signer is unavailable")
	}
	source := &certificateSource{signer: signer, currentTime: currentTime}
	certificate, err := source.get()
	if err != nil {
		return nil, err
	}
	config, err := serverTLSConfigAt(certificate, currentTime().UTC())
	if err != nil {
		return nil, err
	}
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		certificate, err := source.get()
		if err != nil {
			return nil, err
		}
		next, err := serverTLSConfigAt(certificate, currentTime().UTC())
		if err != nil {
			return nil, err
		}
		next.NextProtos = append([]string(nil), config.NextProtos...)
		return next, nil
	}
	return config, nil
}

func (source *certificateSource) get() (tls.Certificate, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	now := source.currentTime().UTC()
	if source.certificate.Leaf != nil && !now.Before(source.certificate.Leaf.NotBefore) &&
		now.Before(source.certificate.Leaf.NotAfter.Add(-transportCertificateRenewBefore)) {
		return source.certificate, nil
	}
	certificate, err := source.signer.TransportCertificate(now)
	if err != nil {
		return tls.Certificate{}, err
	}
	source.certificate = certificate
	return certificate, nil
}

func ServerTLSConfig(certificate tls.Certificate) (*tls.Config, error) {
	return serverTLSConfigAt(certificate, time.Now().UTC())
}

func serverTLSConfigAt(certificate tls.Certificate, now time.Time) (*tls.Config, error) {
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil {
		return nil, errors.New("node transport certificate is unavailable")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, errors.New("node transport certificate is malformed")
		}
	}
	public, publicOK := leaf.PublicKey.(ed25519.PublicKey)
	private, privateOK := certificate.PrivateKey.(ed25519.PrivateKey)
	if !publicOK || !privateOK || subtle.ConstantTimeCompare(public, private.Public().(ed25519.PublicKey)) != 1 ||
		leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) ||
		!allowsServerAuthentication(leaf.ExtKeyUsage) ||
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		return nil, errors.New("node transport certificate has unsafe constraints")
	}
	certificate.Leaf = leaf
	return &tls.Config{
		Certificates:           []tls.Certificate{certificate},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	}, nil
}

// PinnedHTTPClient clones a conventional HTTP transport and replaces public
// CA/hostname validation with exact Node-identity key pinning. The TLS 1.3
// handshake is required to use the hybrid X25519+ML-KEM-768 key exchange.
func PinnedHTTPClient(base *http.Client, identity protocol.NodePublicIdentity) (*http.Client, error) {
	if !pqcrypto.ValidPublicIdentity(identity) {
		return nil, errors.New("invalid pinned node identity")
	}
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	result := *base
	var transport *http.Transport
	switch candidate := base.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = candidate.Clone()
	default:
		return nil, errors.New("pinned node transport requires an HTTP transport")
	}
	if transport.DialTLS != nil || transport.DialTLSContext != nil {
		return nil, errors.New("custom TLS dialers cannot enforce node identity pinning")
	}
	expected := append(ed25519.PublicKey(nil), identity.Ed25519Public...)
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true, // #nosec G402 -- CA verification is intentionally replaced by VerifyConnection identity pinning.
		VerifyConnection: func(state tls.ConnectionState) error {
			// VerifyConnection runs before HandshakeComplete is published on the
			// client connection, so the negotiated version and group are the
			// authoritative handshake checks here.
			if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 ||
				len(state.PeerCertificates) != 1 {
				return errors.New("node did not negotiate the required hybrid TLS transport")
			}
			certificate := state.PeerCertificates[0]
			public, ok := certificate.PublicKey.(ed25519.PublicKey)
			now := time.Now().UTC()
			if !ok || subtle.ConstantTimeCompare(public, expected) != 1 || certificate.IsCA ||
				certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
				now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) ||
				!allowsServerAuthentication(certificate.ExtKeyUsage) ||
				certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
				return errors.New("node transport certificate does not match the pinned identity")
			}
			return nil
		},
	}
	if transport.TLSClientConfig != nil {
		tlsConfig.NextProtos = append([]string(nil), transport.TLSClientConfig.NextProtos...)
	}
	transport.TLSClientConfig = tlsConfig
	transport.ForceAttemptHTTP2 = true
	result.Transport = transport
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &result, nil
}

func allowsServerAuthentication(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}
