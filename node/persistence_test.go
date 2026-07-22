package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/client"
	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

func TestDiskStoreReopenLimitFailurePreservesValidItemBytes(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		limits func(charge int64) (int64, int64)
		want   error
	}{
		{name: "capacity", limits: func(charge int64) (int64, int64) { return charge - 1, charge - 1 }, want: ErrStorageFull},
		{name: "route quota", limits: func(charge int64) (int64, int64) { return charge * 2, charge - 1 }, want: ErrMailboxQuota},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			item := storedTestItem(t, mustRouteTag(t), []byte("opaque ciphertext"))
			store, err := NewDiskStore(directory, 8*1024*1024, 8*1024*1024)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(item); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, item.ItemID+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			capacity, routeQuota := testCase.limits(storedItemCharge(len(before)))
			if _, err := NewDiskStore(directory, capacity, routeQuota); !errors.Is(err, testCase.want) {
				t.Fatalf("reopen returned %v, want %v", err, testCase.want)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed reopen modified a valid unexpired item")
			}
			reopened, err := NewDiskStore(directory, 8*1024*1024, 8*1024*1024)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, err := reopened.Get(item.ItemID); err != nil {
				t.Fatalf("preserved item did not reopen: %v", err)
			}
		})
	}
}

func TestDiskStoreDoesNotDeleteUnmanagedJSON(t *testing.T) {
	directory := t.TempDir()
	if err := ensurePrivateStoreDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "operator-notes.json")
	before := []byte(`{"do_not_delete":true}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(directory, 1024*1024, 1024*1024); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("unmanaged JSON returned %v, want fail-closed corruption error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unmanaged JSON was changed or deleted")
	}
}

func TestDiskStoreOversizedRecordFailsClosedWithoutDeletion(t *testing.T) {
	directory := t.TempDir()
	if err := ensurePrivateStoreDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
	before := bytes.Repeat([]byte{'x'}, MaxStoredItemEncodingBytes+1)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(directory, 2*int64(len(before)), int64(len(before))); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("oversized record returned %v, want fail-closed corruption error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("oversized record was changed or deleted")
	}
}

func TestConfigRejectsEmptyAndOverlappingStorePaths(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(config *Config) { config.DataDir = "" },
		func(config *Config) { config.KeyFile = " \t " },
	} {
		config := DefaultConfig()
		mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatal("empty configured path was accepted")
		}
	}

	root := t.TempDir()
	for _, paths := range [][2]string{
		{filepath.Join(root, "state"), filepath.Join(root, "state", "node-key.json")},
		{filepath.Join(root, "same"), filepath.Join(root, "same")},
		{filepath.Join(root, "node-key.json", "state"), filepath.Join(root, "node-key.json")},
	} {
		config := DefaultConfig()
		config.DataDir, config.KeyFile = paths[0], paths[1]
		if err := config.Validate(); err == nil {
			t.Fatalf("overlapping paths %q and %q were accepted", config.DataDir, config.KeyFile)
		}
	}

	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDirectory, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is unavailable")
		}
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.DataDir = realDirectory
	config.KeyFile = filepath.Join(alias, "node-key.json")
	if err := config.Validate(); err == nil {
		t.Fatal("symlink-hidden path overlap was accepted")
	}

	config.DataDir = filepath.Join(root, "data")
	config.KeyFile = filepath.Join(root, "keys", "node-key.json")
	if err := config.Validate(); err != nil {
		t.Fatalf("disjoint paths were rejected: %v", err)
	}
}

func TestLoadOrCreateSignerConcurrentFirstStartUsesOneIdentity(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node-key.json")
	const callers = 12
	start := make(chan struct{})
	identities := make(chan string, callers)
	errorsFound := make(chan error, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			signer, err := LoadOrCreateSigner(keyPath)
			if err != nil {
				errorsFound <- err
				return
			}
			identities <- signer.PublicIdentity().NodeID
		}()
	}
	close(start)
	workers.Wait()
	close(errorsFound)
	close(identities)
	for err := range errorsFound {
		t.Fatalf("parallel signer creation failed: %v", err)
	}
	var expected string
	count := 0
	for identity := range identities {
		count++
		if expected == "" {
			expected = identity
		}
		if identity != expected {
			t.Fatalf("parallel first starts created different identities: %q and %q", expected, identity)
		}
	}
	if count != callers {
		t.Fatalf("got %d signers, want %d", count, callers)
	}
	info, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !validPrivateRegularFile(keyPath, info, maxNodeSigningKeyBytes) {
		t.Fatalf("key was published with mode %v", info.Mode())
	}
}

func TestNodeSignerLeaseIsExclusiveForProcessLifetime(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node-key.json")
	if _, err := LoadOrCreateSigner(keyPath); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireNodeSigner(keyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireNodeSigner(keyPath, false); err == nil {
		t.Fatal("second running process acquired the same node identity")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireNodeSigner(keyPath, false)
	if err != nil {
		t.Fatalf("node identity could not be reacquired after shutdown: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireNodeSignerWithoutCreatePreservesMissingKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "missing.json")
	if _, err := AcquireNodeSigner(keyPath, false); !errors.Is(err, ErrNodeSigningKeyMissing) {
		t.Fatalf("missing key returned %v", err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("load-only signer acquisition created a key: %v", err)
	}
}

func TestLoadOrCreateSignerRejectsUnsafeParentAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission and symlink invariants")
	}
	t.Run("writable parent", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(directory, 0o700)
		if err := os.WriteFile(filepath.Join(directory, "unmanaged"), []byte("not a key directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateSigner(filepath.Join(directory, "key.json")); err == nil {
			t.Fatal("group/world-writable key parent was accepted")
		}
	})
	t.Run("symlink parent", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(realDirectory, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateSigner(filepath.Join(alias, "key.json")); err == nil {
			t.Fatal("symlink key parent was accepted")
		}
	})
	t.Run("symlink key", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "key.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateSigner(link); err == nil {
			t.Fatal("symlink key file was accepted")
		}
	})
}

func TestLoadOrCreateSignerRejectsOversizedKeyBeforeDecode(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node-key.json")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{'x'}, maxNodeSigningKeyBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSigner(keyPath); err == nil {
		t.Fatal("oversized key file was accepted")
	}
}

type droppingResponseWriter struct {
	header http.Header
	status int
}

func (writer *droppingResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *droppingResponseWriter) WriteHeader(status int) { writer.status = status }

func (*droppingResponseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestDeleteTombstoneSurvivesDroppedResponseAndRestart(t *testing.T) {
	directory := t.TempDir()
	config := DefaultConfig()
	config.DataDir = directory
	config.StorageCapacity = 32 * 1024 * 1024
	store, err := NewDiskStore(directory, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(config, store, signer)
	if err != nil {
		t.Fatal(err)
	}
	deleteToken, err := client.RandomDeleteToken()
	if err != nil {
		t.Fatal(err)
	}
	item := storedTestItemForDelete(t, deleteToken)
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}

	requestBody := protocol.DeleteRequest{ItemID: item.ItemID, DeleteToken: deleteToken}
	encodedRequest, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/delete", bytes.NewReader(encodedRequest))
	request.Header.Set("Content-Type", "application/json")
	dropped := &droppingResponseWriter{}
	server.Handler().ServeHTTP(dropped, request)
	if dropped.status != http.StatusOK {
		t.Fatalf("delete before response drop returned %d", dropped.status)
	}
	if err := store.Put(item); !errors.Is(err, ErrItemDeleted) {
		t.Fatalf("deleted item was resurrected before restart: %v", err)
	}
	tombstonePath := filepath.Join(directory, item.ItemID+".json")
	encodedTombstone, err := os.ReadFile(tombstonePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedTombstone) > MaxDeleteTombstoneBytes || !bytes.Contains(encodedTombstone, []byte(deleteTombstoneRecordType)) {
		t.Fatal("delete did not persist a bounded tombstone")
	}
	deletedAt := store.tombstones[item.ItemID].DeletedAt
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDiskStore(directory, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restartedServer, err := NewServer(config, reopened, signer)
	if err != nil {
		t.Fatal(err)
	}
	wrongToken, err := client.RandomDeleteToken()
	if err != nil {
		t.Fatal(err)
	}
	wrongResponse := postJSON(t, restartedServer.Handler(), "/v1/delete", protocol.DeleteRequest{ItemID: item.ItemID, DeleteToken: wrongToken})
	if wrongResponse.Code != http.StatusNotFound {
		t.Fatalf("wrong tombstone capability returned %d, want 404", wrongResponse.Code)
	}

	retryResponse := postJSON(t, restartedServer.Handler(), "/v1/delete", requestBody)
	if retryResponse.Code != http.StatusOK {
		t.Fatalf("delete retry returned %d: %s", retryResponse.Code, retryResponse.Body.String())
	}
	var receipt protocol.DeleteReceipt
	if err := json.Unmarshal(retryResponse.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ItemID != item.ItemID || !receipt.DeletedAt.Equal(deletedAt) ||
		!pqcrypto.Verify(signer.PublicIdentity(), deleteReceiptDomain, protocol.DeleteReceiptSigningBytes(receipt), receipt.Signature) {
		t.Fatal("retry did not return a verifiable receipt for the committed deletion")
	}
	if err := reopened.Put(item); !errors.Is(err, ErrItemDeleted) {
		t.Fatalf("deleted item was resurrected after restart: %v", err)
	}
	if err := reopened.Sweep(item.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tombstonePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired tombstone was not removed: %v", err)
	}
	postExpiry := postJSON(t, restartedServer.Handler(), "/v1/delete", requestBody)
	if postExpiry.Code != http.StatusNotFound {
		t.Fatalf("expired tombstone replay returned %d, want 404", postExpiry.Code)
	}
}

func TestDeletedItemRetryWaitsForTombstoneDurability(t *testing.T) {
	store, err := NewDiskStore(t.TempDir(), 8*1024*1024, 8*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	deleteToken, err := client.RandomDeleteToken()
	if err != nil {
		t.Fatal(err)
	}
	item := storedTestItemForDelete(t, deleteToken)
	if err := store.Put(item); err != nil {
		t.Fatal(err)
	}
	actualSync := store.syncDirectory
	injected := errors.New("injected tombstone directory sync failure")
	store.syncDirectory = func(string) error { return injected }
	if _, err := store.deleteWithCapability(item.ItemID, deleteToken, time.Now().UTC()); !errors.Is(err, injected) {
		t.Fatalf("nondurable tombstone delete returned %v", err)
	}
	if err := store.Put(item); !errors.Is(err, injected) {
		t.Fatalf("retry trusted a nondurable tombstone: %v", err)
	}
	store.syncDirectory = actualSync
	if err := store.Put(item); !errors.Is(err, ErrItemDeleted) {
		t.Fatalf("durably recovered tombstone retry returned %v", err)
	}
	if store.directorySyncPending {
		t.Fatal("tombstone durability recovery left the store degraded")
	}
}

func storedTestItemForDelete(t *testing.T, deleteToken []byte) protocol.StoredItem {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	item := protocol.StoredItem{
		Version:         protocol.ProtocolVersion,
		RouteTag:        mustRouteTag(t),
		CreatedAt:       now,
		ExpiresAt:       now.Add(protocol.FixedItemRetention),
		DeleteTokenHash: pqcrypto.DeleteTokenHash(deleteToken),
		Payload:         []byte("opaque ciphertext"),
	}
	item.ItemID = protocol.ComputeItemID(item)
	return item
}
