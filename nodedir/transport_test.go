package nodedir

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/transportauth"
)

func TestDirectoryHTTPSPinsPublisherAndChallengeIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	signer := testSigner(t)
	snapshot, err := SignSnapshot(signer, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/nodes":
			_ = json.NewEncoder(response).Encode(snapshot)
		case "/v1/nodes/challenge":
			var challenge ChallengeRequest
			if err := json.NewDecoder(request.Body).Decode(&challenge); err != nil {
				http.Error(response, "bad request", http.StatusBadRequest)
				return
			}
			result, signErr := SignChallenge(signer, challenge.Nonce, time.Now().UTC())
			if signErr != nil {
				http.Error(response, "internal error", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(response).Encode(result)
		default:
			http.NotFound(response, request)
		}
	})
	serverTLS, err := transportauth.ServerTLSConfigForSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := Endpoint{Scheme: "https", IP: host, Port: uint16(port)}
	baseClient := &http.Client{Timeout: time.Second}
	if _, err := FetchSnapshot(context.Background(), baseClient, endpoint, signer.PublicIdentity(), now, MaxDirectoryNodes); err != nil {
		t.Fatal(err)
	}
	announcement := Announcement{Identity: signer.PublicIdentity(), Endpoint: endpoint}
	if err := (&HTTPProber{Client: baseClient}).Verify(context.Background(), announcement); err != nil {
		t.Fatal(err)
	}
	wrongSigner := testSigner(t)
	if _, err := FetchSnapshot(context.Background(), baseClient, endpoint, wrongSigner.PublicIdentity(), now, MaxDirectoryNodes); err == nil {
		t.Fatal("directory fetch accepted a transport key outside the pinned publisher identity")
	}
	announcement.Identity = wrongSigner.PublicIdentity()
	if err := (&HTTPProber{Client: baseClient}).Verify(context.Background(), announcement); err == nil {
		t.Fatal("reachability callback accepted a transport key outside the announced identity")
	}
}
