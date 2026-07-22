package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/client"
	"github.com/MacMax-B/propagare/nodedir"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

func testServer(t *testing.T, mutate func(*Config)) (*Server, *DiskStore) {
	t.Helper()
	config := DefaultConfig()
	config.DataDir = t.TempDir()
	config.StorageCapacity = 32 * 1024 * 1024
	if mutate != nil {
		mutate(&config)
	}
	store, err := NewDiskStore(config.DataDir, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(config, store, signer)
	if err != nil {
		t.Fatal(err)
	}
	return server, store
}

func storedTestItem(t *testing.T, routeTag string, payload []byte) protocol.StoredItem {
	t.Helper()
	token, err := client.RandomDeleteToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	item := protocol.StoredItem{
		Version:         protocol.ProtocolVersion,
		RouteTag:        routeTag,
		CreatedAt:       now,
		ExpiresAt:       now.Add(protocol.FixedItemRetention),
		DeleteTokenHash: pqcrypto.DeleteTokenHash(token),
		Payload:         payload,
	}
	item.ItemID = protocol.ComputeItemID(item)
	return item
}

func postJSON(t *testing.T, handler http.Handler, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestFetchAndDeleteBoundsAreEnforcedBeforeWork(t *testing.T) {
	server, store := testServer(t, func(config *Config) {
		config.MaxFetchBytes = 100
	})
	routeTag, err := client.RandomCapability()
	if err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		payload := bytes.Repeat([]byte{byte(index + 1)}, 60)
		if err := store.Put(storedTestItem(t, routeTag, payload)); err != nil {
			t.Fatal(err)
		}
	}

	response := postJSON(t, server.Handler(), "/v1/fetch", protocol.FetchRequest{RouteTags: []string{routeTag}})
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized fetch returned %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
	response = postJSON(t, server.Handler(), "/v1/fetch", protocol.FetchRequest{RouteTags: []string{"predictable"}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("weak route tag returned %d, want %d", response.Code, http.StatusBadRequest)
	}
	response = postJSON(t, server.Handler(), "/v1/delete", protocol.DeleteRequest{
		ItemID:      string(bytes.Repeat([]byte{'0'}, sha256.Size*2)),
		DeleteToken: make([]byte, protocol.CapabilityBytes-1),
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("short delete capability returned %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestProofRejectsTruncatedSampleWindow(t *testing.T) {
	server, store := testServer(t, nil)
	item := storedTestItem(t, mustRouteTag(t), bytes.Repeat([]byte{1}, 32))
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	response := postJSON(t, server.Handler(), "/v1/proof", protocol.ProofRequest{
		ItemID: item.ItemID, Nonce: bytes.Repeat([]byte{2}, 32), Offset: 31, Length: 2,
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("truncated proof window returned %d", response.Code)
	}
}

func TestProofReportsStoreFailureAsInternalError(t *testing.T) {
	server, store := testServer(t, nil)
	item := storedTestItem(t, mustRouteTag(t), []byte("ciphertext"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	response := postJSON(t, server.Handler(), "/v1/proof", protocol.ProofRequest{
		ItemID: item.ItemID, Nonce: bytes.Repeat([]byte{2}, 32), Offset: 0, Length: 1,
	})
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("closed store proof returned %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestJSONParserRejectsUnknownTrailingAndWrongContentType(t *testing.T) {
	server, _ := testServer(t, nil)
	for name, body := range map[string]string{
		"unknown":  `{"route_tags":[],"extra":true}`,
		"trailing": `{"route_tags":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/fetch", bytes.NewBufferString(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("parser returned %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/fetch", bytes.NewBufferString(`{"route_tags":[]}`))
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("wrong content type returned %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestConfigurationRejectsDifficultyOverflow(t *testing.T) {
	config := DefaultConfig()
	config.BaseDifficulty = protocol.MaxWorkDifficulty
	if err := config.Validate(); err == nil {
		t.Fatal("difficulty that could overflow under load was accepted")
	}
}

type acceptingDirectoryProber struct{}

func (acceptingDirectoryProber) Verify(context.Context, nodedir.Announcement) error { return nil }

func TestDirectoryRegistrationRequiresSourceIPAndPublishesSignedLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	config := DefaultConfig()
	config.DataDir = t.TempDir()
	config.StorageCapacity = 32 * 1024 * 1024
	store, err := NewDiskStore(config.DataDir, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	authority, _ := pqcrypto.GenerateHybridSigner()
	seed := nodedir.PinnedNode{Identity: authority.PublicIdentity(), Endpoint: nodedir.Endpoint{Scheme: "http", IP: "10.0.0.1", Port: 8787}}
	policy, err := nodedir.NewPolicy([]nodedir.PinnedNode{seed}, 1, true, 16)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := nodedir.NewAgent(policy, seed.Endpoint, authority, nodedir.MinLease, nil, acceptingDirectoryProber{}, now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(config, store, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.EnableDirectory(agent); err != nil {
		t.Fatal(err)
	}

	member, _ := pqcrypto.GenerateHybridSigner()
	announcement, _ := nodedir.SignAnnouncement(member, nodedir.Endpoint{Scheme: "http", IP: "10.0.0.3", Port: 8787}, 1, now, nodedir.MinLease, true)
	body, _ := json.Marshal(nodedir.RegistrationRequest{Record: nodedir.Record{Announcement: announcement}})
	request := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "10.0.0.3:45000"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid registration returned %d: %s", response.Code, response.Body.String())
	}
	var admitted nodedir.Record
	if err := json.Unmarshal(response.Body.Bytes(), &admitted); err != nil {
		t.Fatal(err)
	}
	if err := nodedir.VerifyRecord(policy, admitted, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "10.0.0.4:45000"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("source-IP mismatch returned %d, want %d", response.Code, http.StatusForbidden)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)
	request.RemoteAddr = "10.0.0.5:45000"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("directory fetch returned %d", response.Code)
	}
	var snapshot nodedir.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := nodedir.VerifySnapshotHeader(snapshot, authority.PublicIdentity().NodeID, time.Now().UTC(), 16); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Records) != 2 {
		t.Fatalf("directory published %d records, want seed plus admitted member", len(snapshot.Records))
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/nodes/challenge", bytes.NewBufferString(`{"nonce":"AQ==","unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "10.0.0.6:45000"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed directory challenge returned %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestDirectoryAgentMustMatchServerIdentity(t *testing.T) {
	server, _ := testServer(t, nil)
	authority, _ := pqcrypto.GenerateHybridSigner()
	policy, _ := nodedir.NewPolicy([]nodedir.PinnedNode{{
		Identity: authority.PublicIdentity(), Endpoint: nodedir.Endpoint{Scheme: "http", IP: "127.0.0.1", Port: 8787},
	}}, 1, true, 8)
	agent, _ := nodedir.NewAgent(policy, policy.Seeds[0].Endpoint, authority, nodedir.MinLease, nil, acceptingDirectoryProber{}, time.Now().UTC())
	// The test server has a different identity; attaching it must fail closed.
	if err := server.EnableDirectory(agent); err == nil {
		t.Fatal("directory agent with a different server identity was accepted")
	}
}
