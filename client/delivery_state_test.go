package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

type memoryClientStore struct {
	mu       sync.RWMutex
	records  map[string]LocalRecord
	putErr   error
	listHook func(kind, afterID string, limit int) ([]string, error)
}

func newMemoryClientStore() *memoryClientStore {
	return &memoryClientStore{records: make(map[string]LocalRecord)}
}

func cloneLocalRecord(record LocalRecord) LocalRecord {
	record.Payload = append([]byte(nil), record.Payload...)
	return record
}

func (store *memoryClientStore) Put(_ context.Context, record LocalRecord, _ time.Time) (PruneReport, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.putErr != nil {
		return PruneReport{}, store.putErr
	}
	store.records[record.ID] = cloneLocalRecord(record)
	return PruneReport{}, nil
}

func (store *memoryClientStore) Get(_ context.Context, id string) (LocalRecord, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	record, ok := store.records[id]
	if !ok {
		return LocalRecord{}, ErrLocalRecordNotFound
	}
	return cloneLocalRecord(record), nil
}

func (store *memoryClientStore) ListIDs(_ context.Context, kind, afterID string, limit int) ([]string, error) {
	store.mu.RLock()
	hook := store.listHook
	if hook == nil {
		ids := make([]string, 0, len(store.records))
		for id, record := range store.records {
			if record.Kind == kind && id > afterID {
				ids = append(ids, id)
			}
		}
		store.mu.RUnlock()
		sort.Strings(ids)
		if len(ids) > limit {
			ids = ids[:limit]
		}
		return ids, nil
	}
	store.mu.RUnlock()
	return hook(kind, afterID, limit)
}

func (store *memoryClientStore) Delete(_ context.Context, id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.records[id]; !ok {
		return ErrLocalRecordNotFound
	}
	delete(store.records, id)
	return nil
}

func (*memoryClientStore) PruneTo(context.Context, int64, time.Time) (PruneReport, error) {
	return PruneReport{}, nil
}
func (*memoryClientStore) SetLimit(context.Context, int64, time.Time) (PruneReport, error) {
	return PruneReport{}, nil
}
func (store *memoryClientStore) Usage() ClientStorageUsage {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return ClientStorageUsage{Records: len(store.records), MaxRecords: MaxClientStoreRecords}
}
func (*memoryClientStore) Close() error { return nil }

func signedClientStorageReceipt(t *testing.T, signer *pqcrypto.HybridSigner, item protocol.StoredItem, storedAt time.Time) protocol.StorageReceipt {
	t.Helper()
	payloadHash := sha256.Sum256(item.Payload)
	receipt := protocol.StorageReceipt{
		NodeID: signer.PublicIdentity().NodeID, ItemID: item.ItemID, PayloadHash: payloadHash[:],
		StoredAt: storedAt.UTC().Truncate(time.Millisecond), ExpiresAt: item.ExpiresAt,
	}
	var err error
	receipt.Signature, err = signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func signedClientDeleteReceipt(t *testing.T, signer *pqcrypto.HybridSigner, itemID string) protocol.DeleteReceipt {
	t.Helper()
	receipt := protocol.DeleteReceipt{
		NodeID: signer.PublicIdentity().NodeID, ItemID: itemID,
		DeletedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	var err error
	receipt.Signature, err = signer.Sign(deleteReceiptDomain, protocol.DeleteReceiptSigningBytes(receipt))
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func clientNodeParametersResponse(t *testing.T) *http.Response {
	t.Helper()
	return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
		ProtocolVersion: protocol.ProtocolVersion, EpochSeconds: protocol.MinWorkEpochSeconds,
		MaxItemBytes: protocol.DefaultMaxItemBytes, StorageCapacity: 1 << 30,
	})
}

func TestStoreReplicatedPersistsAttemptBeforeExternalWrite(t *testing.T) {
	store := newMemoryClientStore()
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	item, deleteToken := validClientItem(t)
	inspection := make(chan error, 1)
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/parameters":
			return clientNodeParametersResponse(t), nil
		case "/v1/items":
			record, getErr := store.Get(context.Background(), deliveryRecordID(item.ItemID))
			if getErr != nil {
				inspection <- getErr
				return nil, errors.New("simulated lost response")
			}
			var state persistedDeliveryState
			decodeErr := decodeStrictJSON(record.Payload, &state)
			if decodeErr == nil && (!sameStringSlice(state.AttemptedNodeIDs, []string{signer.PublicIdentity().NodeID}) || len(state.Delivery.Receipts) != 0 || !bytes.Equal(state.Delivery.DeleteToken, deleteToken)) {
				decodeErr = errors.New("pending capability state was incomplete before Store")
			}
			inspection <- decodeErr
			return nil, errors.New("simulated lost response")
		default:
			return nil, errors.New("unexpected request")
		}
	}))
	core, err := New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := core.StoreReplicated(context.Background(), item, deleteToken)
	if err == nil || len(delivery.Receipts) != 0 {
		t.Fatalf("lost response did not remain a zero-receipt pending delivery: receipts=%d err=%v", len(delivery.Receipts), err)
	}
	if inspectErr := <-inspection; inspectErr != nil {
		t.Fatal(inspectErr)
	}
	restored, err := core.LoadDelivery(context.Background(), item.ItemID, time.Now().UTC())
	if err != nil || !bytes.Equal(restored.DeleteToken, deleteToken) || len(restored.Receipts) != 0 {
		t.Fatalf("zero-receipt capability was not recoverable: receipts=%d err=%v", len(restored.Receipts), err)
	}
}

func TestStoreReplicatedNeverWritesWhenPendingPersistenceFails(t *testing.T) {
	store := newMemoryClientStore()
	store.putErr = errors.New("durability failure")
	signer, _ := pqcrypto.GenerateHybridSigner()
	var writes atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/parameters" {
			return clientNodeParametersResponse(t), nil
		}
		if request.URL.Path == "/v1/items" {
			writes.Add(1)
		}
		return nil, errors.New("unexpected request")
	}))
	core, err := New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	item, token := validClientItem(t)
	if _, err := core.StoreReplicated(context.Background(), item, token); err == nil {
		t.Fatal("StoreReplicated accepted a failed pending-state write")
	}
	if writes.Load() != 0 {
		t.Fatal("external Store ran before pending state became durable")
	}
}

func TestLoadDeliverySurvivesNodeMembershipDrift(t *testing.T) {
	store := newMemoryClientStore()
	oldSigner, _ := pqcrypto.GenerateHybridSigner()
	newSigner, _ := pqcrypto.GenerateHybridSigner()
	oldNode := developmentNodeForTest(oldSigner.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("old node must not be contacted")
	}))
	oldCore, err := New(Config{Nodes: []*HTTPNode{oldNode}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	item, token := validClientItem(t)
	receipt := signedClientStorageReceipt(t, oldSigner, item, time.Now())
	delivery := Delivery{Item: item, DeleteToken: token, Receipts: []protocol.StorageReceipt{receipt}}
	if err := oldCore.persistDelivery(context.Background(), delivery, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var unexpectedDeletes atomic.Int32
	newNode := developmentNodeForTest(newSigner.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		unexpectedDeletes.Add(1)
		return nil, errors.New("unrelated node must not be contacted")
	}))
	newCore, err := New(Config{Nodes: []*HTTPNode{newNode}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := newCore.LoadDelivery(context.Background(), item.ItemID, time.Now().UTC())
	if err != nil || len(restored.Receipts) != 1 || restored.Receipts[0].NodeID != oldSigner.PublicIdentity().NodeID {
		t.Fatalf("pinned old receipt did not survive membership drift: %+v err=%v", restored.Receipts, err)
	}
	results := newCore.Delete(context.Background(), restored)
	if !errors.Is(results[oldSigner.PublicIdentity().NodeID], ErrDeliveryNodeUnavailable) {
		t.Fatalf("unconfigured pinned node was not retained safely: %v", results)
	}
	if _, err := store.Get(context.Background(), deliveryRecordID(item.ItemID)); err != nil {
		t.Fatalf("membership drift removed recoverable local state: %v", err)
	}
	if unexpectedDeletes.Load() != 0 {
		t.Fatal("deletion was redirected to a different directory member")
	}
}

func TestDeleteUsesCanonicalReceiptSetAndRejectsForgery(t *testing.T) {
	store := newMemoryClientStore()
	item, token := validClientItem(t)
	signers := make([]*pqcrypto.HybridSigner, 2)
	nodes := make([]*HTTPNode, 2)
	deleteCalls := make([]atomic.Int32, 2)
	receipts := make([]protocol.StorageReceipt, 2)
	for index := range signers {
		signers[index], _ = pqcrypto.GenerateHybridSigner()
		receipts[index] = signedClientStorageReceipt(t, signers[index], item, time.Now())
		index := index
		nodes[index] = developmentNodeForTest(signers[index].PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/v1/delete" {
				return nil, errors.New("unexpected request")
			}
			deleteCalls[index].Add(1)
			return jsonResponse(t, http.StatusOK, signedClientDeleteReceipt(t, signers[index], item.ItemID)), nil
		}))
	}
	core, err := New(Config{Nodes: nodes, Replicas: 2, WriteQuorum: 2, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	full := Delivery{Item: item, DeleteToken: token, Receipts: receipts}
	if err := core.persistDelivery(context.Background(), full, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	forged := cloneStorageReceipt(receipts[1])
	forged.Signature.Ed25519[0] ^= 1
	forgedInput := Delivery{Item: item, DeleteToken: token, Receipts: []protocol.StorageReceipt{receipts[0], forged}}
	if result := core.Delete(context.Background(), forgedInput); !errors.Is(result[deliveryAuditStateKey], ErrInvalidDeliveryState) {
		t.Fatalf("forged receipt did not fail closed: %v", result)
	}
	if deleteCalls[0].Load()+deleteCalls[1].Load() != 0 {
		t.Fatal("delete side effect occurred before receipt authentication")
	}
	staleSubset := Delivery{Item: item, DeleteToken: token, Receipts: []protocol.StorageReceipt{receipts[0]}}
	results := core.Delete(context.Background(), staleSubset)
	if results[signers[0].PublicIdentity().NodeID] != nil || results[signers[1].PublicIdentity().NodeID] != nil {
		t.Fatalf("canonical deletion failed: %v", results)
	}
	if deleteCalls[0].Load() != 1 || deleteCalls[1].Load() != 1 {
		t.Fatalf("stale subset deleted %d/%d canonical replicas", deleteCalls[0].Load(), deleteCalls[1].Load())
	}
	if _, err := store.Get(context.Background(), deliveryRecordID(item.ItemID)); !errors.Is(err, ErrLocalRecordNotFound) {
		t.Fatalf("fully deleted canonical state remained: %v", err)
	}
}

func TestAuditAndRepairMergesOldAndNewReceipts(t *testing.T) {
	store := newMemoryClientStore()
	item, token := validClientItem(t)
	oldSigner, _ := pqcrypto.GenerateHybridSigner()
	repairSigner, _ := pqcrypto.GenerateHybridSigner()
	oldReceipt := signedClientStorageReceipt(t, oldSigner, item, time.Now())
	oldNode := developmentNodeForTest(oldSigner.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusInternalServerError, map[string]string{"error": "unavailable"}), nil
	}))
	var repairStores atomic.Int32
	repairNode := developmentNodeForTest(repairSigner.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/parameters":
			return clientNodeParametersResponse(t), nil
		case "/v1/items":
			repairStores.Add(1)
			var stored protocol.StoredItem
			if err := json.NewDecoder(request.Body).Decode(&stored); err != nil {
				return nil, err
			}
			return jsonResponse(t, http.StatusCreated, signedClientStorageReceipt(t, repairSigner, stored, time.Now())), nil
		default:
			return nil, errors.New("unexpected repair-node request")
		}
	}))
	core, err := New(Config{Nodes: []*HTTPNode{oldNode, repairNode}, Replicas: 2, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	original := Delivery{Item: item, DeleteToken: token, Receipts: []protocol.StorageReceipt{oldReceipt}}
	if err := core.persistDelivery(context.Background(), original, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	repaired, audit, err := core.AuditAndRepair(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	if audit[oldSigner.PublicIdentity().NodeID] == nil || repairStores.Load() != 1 || len(repaired.Receipts) != 2 {
		t.Fatalf("repair did not preserve old receipt and add a new one: receipts=%d stores=%d audit=%v", len(repaired.Receipts), repairStores.Load(), audit)
	}
	restored, err := core.LoadDelivery(context.Background(), item.ItemID, time.Now().UTC())
	if err != nil || len(restored.Receipts) != 2 {
		t.Fatalf("merged repair state was not durable: receipts=%d err=%v", len(restored.Receipts), err)
	}
}

func TestConcurrentAuditAndRepairSerializesOneItem(t *testing.T) {
	store := newMemoryClientStore()
	item, token := validClientItem(t)
	signer, _ := pqcrypto.GenerateHybridSigner()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var storeCalls atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/parameters":
			return clientNodeParametersResponse(t), nil
		case "/v1/items":
			storeCalls.Add(1)
			entered <- struct{}{}
			<-release
			return jsonResponse(t, http.StatusCreated, signedClientStorageReceipt(t, signer, item, time.Now())), nil
		case "/v1/proof":
			var proofRequest protocol.ProofRequest
			if err := json.NewDecoder(request.Body).Decode(&proofRequest); err != nil {
				return nil, err
			}
			payloadHash := sha256.Sum256(item.Payload)
			end := proofRequest.Offset + int64(proofRequest.Length)
			proof := protocol.StorageProof{
				NodeID: signer.PublicIdentity().NodeID, ItemID: item.ItemID, Nonce: append([]byte(nil), proofRequest.Nonce...),
				Offset: proofRequest.Offset, Sample: append([]byte(nil), item.Payload[proofRequest.Offset:end]...),
				PayloadHash: payloadHash[:], ProvedAt: time.Now().UTC().Truncate(time.Millisecond),
			}
			var err error
			proof.Signature, err = signer.Sign(proofDomain, protocol.ProofSigningBytes(proof))
			if err != nil {
				return nil, err
			}
			return jsonResponse(t, http.StatusOK, proof), nil
		default:
			return nil, errors.New("unexpected request")
		}
	}))
	core, err := New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	resultErrors := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, _, callErr := core.AuditAndRepair(context.Background(), Delivery{Item: item, DeleteToken: token})
			resultErrors <- callErr
		}()
	}
	close(start)
	<-entered
	select {
	case <-entered:
		t.Fatal("same-item Store calls overlapped before the first state commit")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if err := <-resultErrors; err != nil {
			t.Fatal(err)
		}
	}
	if storeCalls.Load() != 1 {
		t.Fatalf("serialized retry performed %d external writes", storeCalls.Load())
	}
}

func deliveryTestItemAt(t *testing.T, createdAt time.Time) (protocol.StoredItem, []byte) {
	t.Helper()
	routeTag, _ := RandomCapability()
	token, _ := RandomDeleteToken()
	item := protocol.StoredItem{
		Version: protocol.ProtocolVersion, RouteTag: routeTag, CreatedAt: createdAt.UTC().Truncate(time.Millisecond),
		ExpiresAt:       createdAt.UTC().Truncate(time.Millisecond).Add(protocol.FixedItemRetention),
		DeleteTokenHash: pqcrypto.DeleteTokenHash(token), Payload: []byte("encrypted pending delivery"),
	}
	item.ItemID = protocol.ComputeItemID(item)
	return item, token
}

func TestPendingDeliveriesSkipsExpiredAndValidatesCustomIndex(t *testing.T) {
	store := newMemoryClientStore()
	signer, _ := pqcrypto.GenerateHybridSigner()
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	core, err := New(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	var expiredItem, activeItem protocol.StoredItem
	var expiredToken, activeToken []byte
	for {
		expiredItem, expiredToken = deliveryTestItemAt(t, now.Add(-protocol.FixedItemRetention-time.Hour))
		activeItem, activeToken = deliveryTestItemAt(t, now.Add(-time.Hour))
		if expiredItem.ItemID < activeItem.ItemID {
			break
		}
	}
	if err := core.persistDelivery(context.Background(), Delivery{Item: expiredItem, DeleteToken: expiredToken}, expiredItem.CreatedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := core.persistDelivery(context.Background(), Delivery{Item: activeItem, DeleteToken: activeToken}, now); err != nil {
		t.Fatal(err)
	}
	pending, err := core.PendingDeliveries(context.Background(), "", 1, now)
	if err != nil || len(pending) != 1 || pending[0].Item.ItemID != activeItem.ItemID {
		t.Fatalf("expired cursor entry blocked active delivery: pending=%v err=%v", pending, err)
	}

	activeRecordID := deliveryRecordID(activeItem.ItemID)
	expiredRecordID := deliveryRecordID(expiredItem.ItemID)
	validAscending := []string{expiredRecordID, activeRecordID}
	for name, test := range map[string]struct {
		after string
		ids   []string
	}{
		"oversized":  {ids: make([]string, MaxPendingDeliveryPage+1)},
		"duplicate":  {ids: []string{activeRecordID, activeRecordID}},
		"descending": {ids: []string{validAscending[1], validAscending[0]}},
		"at-cursor":  {after: activeItem.ItemID, ids: []string{activeRecordID}},
		"malformed":  {ids: []string{"delivery.not-an-item"}},
	} {
		t.Run(name, func(t *testing.T) {
			ids := append([]string(nil), test.ids...)
			store.mu.Lock()
			store.listHook = func(string, string, int) ([]string, error) { return ids, nil }
			store.mu.Unlock()
			if _, err := core.PendingDeliveries(context.Background(), test.after, 1, now); err == nil {
				t.Fatal("malformed custom ClientStore index was accepted")
			}
		})
	}
	store.mu.Lock()
	store.listHook = nil
	record := cloneLocalRecord(store.records[activeRecordID])
	store.mu.Unlock()
	record.Payload = []byte(strings.Replace(string(record.Payload), `{"version":1,`, `{"version":1,"version":1,`, 1))
	if _, err := store.Put(context.Background(), record, now); err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadDelivery(context.Background(), activeItem.ItemID, now); !errors.Is(err, ErrInvalidDeliveryState) {
		t.Fatalf("non-canonical duplicate delivery JSON was accepted: %v", err)
	}
}
