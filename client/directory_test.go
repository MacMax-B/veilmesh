package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/nodedir"
	"github.com/MacMax-B/propagare/pqcrypto"
)

type directoryRoundTrip func(*http.Request) (*http.Response, error)

func (function directoryRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientReconcilesMultiplePinnedDirectoryViews(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	first, _ := pqcrypto.GenerateHybridSigner()
	second, _ := pqcrypto.GenerateHybridSigner()
	member, _ := pqcrypto.GenerateHybridSigner()
	seeds := []nodedir.PinnedNode{
		{Identity: first.PublicIdentity(), Endpoint: nodedir.Endpoint{Scheme: "http", IP: "10.2.0.1", Port: 8787}},
		{Identity: second.PublicIdentity(), Endpoint: nodedir.Endpoint{Scheme: "http", IP: "10.2.0.2", Port: 8787}},
	}
	announcement, _ := nodedir.SignAnnouncement(member, nodedir.Endpoint{Scheme: "http", IP: "10.2.0.3", Port: 8787}, 1, now, nodedir.MinLease, true)
	firstAttestation, _ := nodedir.SignAttestation(first, announcement, now)
	secondAttestation, _ := nodedir.SignAttestation(second, announcement, now)
	record := nodedir.Record{Announcement: announcement, Attestations: []nodedir.Attestation{firstAttestation, secondAttestation}}
	firstSnapshot, _ := nodedir.SignSnapshot(first, []nodedir.Record{record}, now)
	secondSnapshot, _ := nodedir.SignSnapshot(second, []nodedir.Record{record}, now)
	encoded := make(map[string][]byte)
	encoded["10.2.0.1:8787"], _ = json.Marshal(firstSnapshot)
	encoded["10.2.0.2:8787"], _ = json.Marshal(secondSnapshot)
	httpClient := &http.Client{Transport: directoryRoundTrip(func(request *http.Request) (*http.Response, error) {
		body, exists := encoded[request.URL.Host]
		if !exists {
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	directory, err := FetchNodeDirectory(context.Background(), DirectoryBootstrap{
		Seeds: seeds, AuthorityQuorum: 2, MinSeedResponses: 2, AllowPrivateIPs: true, MaxNodes: 16,
	}, httpClient, now)
	if err != nil {
		t.Fatal(err)
	}
	records := directory.Records()
	if len(records) != 1 || records[0].Announcement.Identity.NodeID != member.PublicIdentity().NodeID {
		t.Fatal("client did not obtain the complete admitted node view")
	}
	records[0].Announcement.Identity.Ed25519Public[0] ^= 1
	identityBody, _ := json.Marshal(member.PublicIdentity())
	encoded["10.2.0.3:8787"] = identityBody
	if _, err := ConnectDirectoryRecords(context.Background(), directory, 1, httpClient); err == nil {
		t.Fatal("production directory connection implicitly downgraded to plain HTTP")
	}
	nodes, err := ConnectDirectoryRecordsForDevelopment(context.Background(), directory, 1, httpClient)
	if err != nil || len(nodes) != 1 || nodes[0].Identity().NodeID != member.PublicIdentity().NodeID {
		t.Fatalf("defensive directory copy changed trusted connection state: nodes=%d err=%v", len(nodes), err)
	}
	if _, err := ConnectDirectoryRecords(context.Background(), VerifiedDirectory{}, 1, httpClient); err == nil {
		t.Fatal("manually constructed empty directory handle was accepted")
	}
	tampered := directory
	tampered.records = cloneDirectoryRecords(directory.records)
	tampered.records[0].Announcement.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := ConnectDirectoryRecordsForDevelopment(context.Background(), tampered, 1, httpClient); err == nil {
		t.Fatal("directory record was not reverified immediately before dialing")
	}
	delete(encoded, "10.2.0.2:8787")
	if _, err := FetchNodeDirectory(context.Background(), DirectoryBootstrap{
		Seeds: seeds, AuthorityQuorum: 2, MinSeedResponses: 2, AllowPrivateIPs: true, MaxNodes: 16,
	}, httpClient, now); err == nil {
		t.Fatal("client accepted fewer seed views than configured")
	}
}
