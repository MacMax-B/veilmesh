package transportauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"veilmesh/pqcrypto"
)

func TestPinnedPKIFreeHybridTransport(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := ServerTLSConfigForSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverConfig
	server.StartTLS()
	defer server.Close()

	client, err := PinnedHTTPClient(&http.Client{Timeout: time.Second}, signer.PublicIdentity())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("pinned transport returned %d", response.StatusCode)
	}

	wrongSigner, _ := pqcrypto.GenerateHybridSigner()
	wrongClient, err := PinnedHTTPClient(&http.Client{Timeout: time.Second}, wrongSigner.PublicIdentity())
	if err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if _, err := wrongClient.Do(request); err == nil {
		t.Fatal("transport accepted a certificate outside the pinned node identity")
	}
}

func TestServerTransportRenewsContainerWithoutChangingPinnedKey(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	config, err := rotatingServerTLSConfig(signer, clock)
	if err != nil {
		t.Fatal(err)
	}
	before := config.Certificates[0]
	now = now.Add(pqcrypto.NodeTransportCertificateLifetime - transportCertificateRenewBefore + time.Second)
	renewedConfig, err := config.GetConfigForClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	after := renewedConfig.Certificates[0]
	if bytes.Equal(before.Certificate[0], after.Certificate[0]) {
		t.Fatal("expiring transport certificate container was not renewed")
	}
	beforePublic := before.Leaf.PublicKey.(ed25519.PublicKey)
	afterPublic := after.Leaf.PublicKey.(ed25519.PublicKey)
	if !bytes.Equal(beforePublic, afterPublic) || !bytes.Equal(afterPublic, signer.PublicIdentity().Ed25519Public) {
		t.Fatal("certificate renewal changed the pinned node key")
	}
}

func TestPinnedTransportRejectsUnenforceableInputs(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PinnedHTTPClient(&http.Client{Transport: roundTripper{}}, signer.PublicIdentity()); err == nil {
		t.Fatal("custom round tripper bypass was accepted")
	}
	if _, err := PinnedHTTPClient(&http.Client{Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") },
	}}, signer.PublicIdentity()); err == nil {
		t.Fatal("custom TLS dialer bypass was accepted")
	}
	if _, err := ServerTLSConfig(tls.Certificate{}); err == nil {
		t.Fatal("empty server certificate was accepted")
	}
	if _, err := ServerTLSConfigForSigner(nil); err == nil {
		t.Fatal("nil server signer was accepted")
	}
	certificate, err := signer.TransportCertificate(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	malformed := certificate
	malformed.Leaf = nil
	malformed.Certificate = [][]byte{append([]byte(nil), certificate.Certificate[0]...)}
	malformed.Certificate[0][0] ^= 1
	if _, err := ServerTLSConfig(malformed); err == nil {
		t.Fatal("malformed server certificate was accepted")
	}
	wrongSigner, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := certificate
	wrongKey.PrivateKey = ed25519.PrivateKey(wrongSigner.PrivateMaterial().Ed25519Private)
	if _, err := ServerTLSConfig(wrongKey); err == nil {
		t.Fatal("server certificate with a different private key was accepted")
	}
}

type roundTripper struct{}

func (roundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}
