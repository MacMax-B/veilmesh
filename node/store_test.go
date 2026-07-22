package node

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MacMax-B/propagare/client"
)

func TestDiskStoreChargesEncodedRecordAndFixedOverhead(t *testing.T) {
	item := storedTestItem(t, mustRouteTag(t), []byte{1})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	charge := storedItemCharge(len(encoded))
	store, err := NewDiskStore(t.TempDir(), charge-1, charge-1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(item); !errors.Is(err, ErrStorageFull) {
		t.Fatalf("under-accounted tiny item returned %v", err)
	}

	store, err = NewDiskStore(t.TempDir(), charge*2, charge-1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(item); !errors.Is(err, ErrMailboxQuota) {
		t.Fatalf("under-accounted route quota returned %v", err)
	}
}

func TestDiskStoreClonesMutableItemBytes(t *testing.T) {
	payload := []byte("immutable ciphertext")
	expected := string(payload)
	item := storedTestItem(t, mustRouteTag(t), payload)
	store, err := NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	item.Payload[0] ^= 1
	first, err := store.Get(item.ItemID)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Payload) != expected {
		t.Fatal("caller mutation changed stored payload")
	}
	first.Payload[0] ^= 1
	second, err := store.Get(item.ItemID)
	if err != nil || string(second.Payload) != expected {
		t.Fatal("Get returned mutable store-owned bytes")
	}
}

func TestDiskStoreFailsClosedWithoutDeletingMismatchedRecord(t *testing.T) {
	directory := t.TempDir()
	if err := ensurePrivateStoreDirectory(directory); err != nil {
		t.Fatal(err)
	}
	item := storedTestItem(t, mustRouteTag(t), []byte("ciphertext"))
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(directory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
	if err := os.WriteFile(wrongPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(directory, 1024*1024, 1024*1024); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("mismatched record returned %v, want fail-closed corruption error", err)
	}
	preserved, err := os.ReadFile(wrongPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved) != string(encoded) {
		t.Fatal("mismatched record was modified during failed reopen")
	}
}

func TestDiskStoreCleansAbandonedPrivateTemporary(t *testing.T) {
	directory := t.TempDir()
	if err := ensurePrivateStoreDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, ".propagare-private-abandoned")
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewDiskStore(directory, 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned private temporary survived startup: %v", err)
	}
}

func TestDiskStoreRequiresExclusiveDirectoryOwnership(t *testing.T) {
	directory := t.TempDir()
	first, err := NewDiskStore(directory, 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(directory, 1024*1024, 1024*1024); err == nil {
		t.Fatal("second node store opened the same directory concurrently")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewDiskStore(directory, 1024*1024, 1024*1024)
	if err != nil {
		t.Fatalf("node store did not reopen after clean close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerTransportRequiresTLSOutsideExplicitPrivateDevelopment(t *testing.T) {
	if err := ValidateServerTransport("127.0.0.1:8787", false, false); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServerTransport("10.0.0.2:8787", false, false); err == nil {
		t.Fatal("private cleartext listener did not require an explicit switch")
	}
	if err := ValidateServerTransport("10.0.0.2:8787", false, true); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:8787", "203.0.113.20:8787", ":8787"} {
		if err := ValidateServerTransport(address, false, true); err == nil {
			t.Fatalf("unsafe cleartext listener %q was accepted", address)
		}
	}
	if err := ValidateServerTransport("0.0.0.0:8787", true, false); err != nil {
		t.Fatalf("TLS listener was rejected: %v", err)
	}
}

func TestInternalServerErrorsDoNotExposeDetails(t *testing.T) {
	response := httptest.NewRecorder()
	writeError(response, http.StatusInternalServerError, errors.New("/secret/path/delete-token"))
	if response.Body.String() != "{\"error\":\"request failed\"}\n" {
		t.Fatalf("internal error detail leaked: %s", response.Body.String())
	}
}

func TestServerRejectsWorkBeyondConcurrencyBound(t *testing.T) {
	server, _ := testServer(t, func(config *Config) { config.MaxConcurrentRequests = 1 })
	server.requestWork <- struct{}{}
	defer func() { <-server.requestWork }()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("overloaded server returned %d", response.Code)
	}
}

func mustRouteTag(t *testing.T) string {
	t.Helper()
	routeTag, err := client.RandomCapability()
	if err != nil {
		t.Fatal(err)
	}
	return routeTag
}
