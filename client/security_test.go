package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func developmentNodeForTest(identity protocol.NodePublicIdentity, transport http.RoundTripper) *HTTPNode {
	return &HTTPNode{
		baseURL: "http://127.0.0.1:8787", identity: cloneNodeIdentity(identity),
		client: &http.Client{Transport: transport}, mode: nodeConnectionPrivateDevelopment,
	}
}

func jsonResponse(t *testing.T, status int, value any) *http.Response {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
}

func validClientItem(t *testing.T) (protocol.StoredItem, []byte) {
	t.Helper()
	routeTag, err := RandomCapability()
	if err != nil {
		t.Fatal(err)
	}
	deleteToken, err := RandomDeleteToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	item := protocol.StoredItem{
		Version:         protocol.ProtocolVersion,
		RouteTag:        routeTag,
		CreatedAt:       now,
		ExpiresAt:       now.Add(protocol.FixedItemRetention),
		DeleteTokenHash: pqcrypto.DeleteTokenHash(deleteToken),
		Payload:         []byte("opaque ciphertext"),
	}
	item.ItemID = protocol.ComputeItemID(item)
	return item, deleteToken
}

func TestStorageReceiptMustBindPayloadAndExpiry(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	item, _ := validClientItem(t)
	payloadHash := sha256.Sum256(item.Payload)
	baseReceipt := protocol.StorageReceipt{
		NodeID:      signer.PublicIdentity().NodeID,
		ItemID:      item.ItemID,
		PayloadHash: payloadHash[:],
		StoredAt:    time.Now().UTC().Truncate(time.Millisecond),
		ExpiresAt:   item.ExpiresAt,
	}
	for name, mutate := range map[string]func(*protocol.StorageReceipt){
		"payload": func(receipt *protocol.StorageReceipt) { receipt.PayloadHash[0] ^= 1 },
		"expiry":  func(receipt *protocol.StorageReceipt) { receipt.ExpiresAt = receipt.ExpiresAt.Add(time.Second) },
		"stored-after-expiry": func(receipt *protocol.StorageReceipt) {
			receipt.StoredAt = receipt.ExpiresAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt := baseReceipt
			receipt.PayloadHash = append([]byte(nil), baseReceipt.PayloadHash...)
			mutate(&receipt)
			receipt.Signature, err = signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
			if err != nil {
				t.Fatal(err)
			}
			node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(t, http.StatusCreated, receipt), nil
			}))
			if _, err := node.Store(context.Background(), item); err == nil {
				t.Fatal("cryptographically signed but mismatched receipt was accepted")
			}
		})
	}
}

func TestDiscoveryRejectsRedirectsAndInvalidParameters(t *testing.T) {
	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Status:     "307 Temporary Redirect",
			Header:     http.Header{"Location": []string{"http://127.0.0.1/internal"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    request,
		}, nil
	})}
	if _, err := DiscoverHTTPNode(context.Background(), "https://node.invalid", client); err == nil {
		t.Fatal("node discovery followed or accepted a redirect")
	}
	if requests.Load() != 1 {
		t.Fatalf("redirect triggered %d requests, want 1", requests.Load())
	}

	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
			ProtocolVersion: protocol.ProtocolVersion,
			Difficulty:      protocol.MaxWorkDifficulty + 1,
			EpochSeconds:    600,
			MaxItemBytes:    protocol.DefaultMaxItemBytes,
			StorageCapacity: 1,
		}), nil
	}))
	if _, err := node.Parameters(context.Background()); err == nil {
		t.Fatal("malicious proof-of-work difficulty was accepted")
	}
}

func TestSignedEndpointResponsesUseTightSizeLimits(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxStorageProofResponseBytes+1))),
		}, nil
	}))
	item, deleteToken := validClientItem(t)
	proofRequest := protocol.ProofRequest{
		ItemID: item.ItemID, Nonce: bytes.Repeat([]byte{1}, 32), Offset: 0, Length: 1,
	}
	tests := map[string]func() error{
		"storage-receipt": func() error {
			_, err := node.Store(context.Background(), item)
			return err
		},
		"storage-proof": func() error {
			_, err := node.Prove(context.Background(), proofRequest)
			return err
		},
		"delete-receipt": func() error {
			_, err := node.Delete(context.Background(), protocol.DeleteRequest{ItemID: item.ItemID, DeleteToken: deleteToken})
			return err
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrNodeResponseTooLarge) {
				t.Fatalf("oversized signed response returned %v", err)
			}
		})
	}
}

func TestPlainHTTPDiscoveryRequiresExplicitPrivateDevelopment(t *testing.T) {
	signer, _ := pqcrypto.GenerateHybridSigner()
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusOK, signer.PublicIdentity()), nil
	})
	client := &http.Client{Transport: transport}
	if _, err := DiscoverHTTPNode(context.Background(), "http://127.0.0.1:8787", client); err == nil {
		t.Fatal("production discovery accepted plain HTTP")
	}
	if _, err := DiscoverHTTPNodeForDevelopment(context.Background(), "http://203.0.113.10:8787", client); err == nil {
		t.Fatal("development discovery accepted a public HTTP endpoint")
	}
	if _, err := DiscoverHTTPNodeForDevelopment(context.Background(), "http://127.0.0.1:8787", client); err != nil {
		t.Fatalf("explicit loopback development discovery failed: %v", err)
	}
	secret := "delete-token-must-not-escape"
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(secret))}, nil
	}))
	_, err := node.Delete(context.Background(), protocol.DeleteRequest{ItemID: strings.Repeat("0", 64), DeleteToken: make([]byte, 32)})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("untrusted response body escaped through error: %v", err)
	}
}

func TestHTTPNodeTrustStateAndCoreCopiesAreEnforced(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := DiscoverHTTPNode(context.Background(), "https://node.invalid", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusOK, signer.PublicIdentity()), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discovered.Parameters(context.Background()); !errors.Is(err, ErrUntrustedNodeTransport) {
		t.Fatalf("unpinned discovery became operational: %v", err)
	}
	if _, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{discovered}}); err == nil {
		t.Fatal("core accepted an unpinned discovery descriptor")
	}
	if _, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{{}}}); err == nil {
		t.Fatal("core accepted a manually constructed zero node")
	}

	routeTag, _ := RandomCapability()
	item, _ := validClientItem(t)
	item.RouteTag = routeTag
	item.ItemID = protocol.ComputeItemID(item)
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusOK, protocol.FetchResponse{Items: []protocol.StoredItem{item}}), nil
	}))
	if _, err := New(Config{Nodes: []*HTTPNode{node}}); err == nil {
		t.Fatal("production constructor accepted a missing client store")
	}
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}})
	if err != nil {
		t.Fatal(err)
	}
	identityCopy := node.Identity()
	identityCopy.Ed25519Public[0] ^= 1
	if sameNodeIdentity(identityCopy, node.Identity()) {
		t.Fatal("identity accessor exposed mutable node state")
	}
	// Mutating the source descriptor after construction cannot redirect or
	// re-identify the copy retained by Core.
	node.baseURL = "http://10.0.0.9:9999"
	node.identity.Ed25519Public[0] ^= 1
	node.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("mutated source transport")
	})
	items, err := core.Fetch(context.Background(), []string{routeTag})
	if err != nil || len(items) != 1 || items[0].ItemID != item.ItemID {
		t.Fatalf("core did not retain a secure node copy: items=%d err=%v", len(items), err)
	}
}

func TestRemoteDecodeErrorsCannotReflectCapabilities(t *testing.T) {
	signer, _ := pqcrypto.GenerateHybridSigner()
	secret, _ := RandomCapability()
	fetchMalformed := []byte(fmt.Sprintf(`{"items":[],%q:true}`, secret))
	parametersMalformed := []byte(fmt.Sprintf(`{"protocol_version":1,"difficulty":0,"epoch_seconds":60,"max_item_bytes":327680,"storage_used":0,"storage_capacity":1,%q:true}`, secret))
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := fetchMalformed
		if request.URL.Path == "/v1/parameters" {
			body = parametersMalformed
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(body)),
		}, nil
	}))
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Fetch(context.Background(), []string{secret}); !errors.Is(err, ErrInvalidNodeResponse) || strings.Contains(err.Error(), secret) {
		t.Fatalf("remote JSON field escaped through fetch error: %v", err)
	}
	item, token := validClientItem(t)
	delivery, err := core.StoreReplicated(context.Background(), item, token)
	if err == nil {
		t.Fatal("malformed parameter response was accepted")
	}
	if len(delivery.FailedNodes) != 1 {
		t.Fatalf("parameter failure was not retained: %+v", delivery.FailedNodes)
	}
	for _, failure := range delivery.FailedNodes {
		if strings.Contains(failure, secret) {
			t.Fatalf("remote JSON field escaped through failed nodes: %q", failure)
		}
	}
	for _, score := range core.Reputation() {
		if strings.Contains(score.LastFailure, secret) {
			t.Fatalf("remote JSON field escaped through reputation: %q", score.LastFailure)
		}
	}
}

func TestFetchRejectsPerNodeAndFairlyBoundsCombinedItemAmplification(t *testing.T) {
	routeTag, _ := RandomCapability()
	now := time.Now().UTC().Truncate(time.Millisecond)
	makeItems := func(start, count int) []protocol.StoredItem {
		items := make([]protocol.StoredItem, 0, count)
		for index := start; index < start+count; index++ {
			tokenHash := sha256.Sum256([]byte(fmt.Sprintf("token-%d", index)))
			item := protocol.StoredItem{
				Version: protocol.ProtocolVersion, RouteTag: routeTag, CreatedAt: now,
				ExpiresAt: now.Add(protocol.FixedItemRetention), DeleteTokenHash: tokenHash[:], Payload: []byte{byte(index)},
			}
			item.ItemID = protocol.ComputeItemID(item)
			items = append(items, item)
		}
		return items
	}
	newNode := func(items []protocol.StoredItem) *HTTPNode {
		signer, _ := pqcrypto.GenerateHybridSigner()
		return developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, http.StatusOK, protocol.FetchResponse{Items: items}), nil
		}))
	}
	if _, err := newNode(makeItems(0, protocol.DefaultMaxFetchItems+1)).Fetch(context.Background(), []string{routeTag}); err == nil {
		t.Fatal("per-node item amplification was accepted")
	}
	budgetFillingNode := newNode(makeItems(0, protocol.DefaultMaxFetchItems))
	honestItem := makeItems(10_000, 1)[0]
	honestNode := newNode([]protocol.StoredItem{honestItem})
	orders := [][]*HTTPNode{{budgetFillingNode, honestNode}, {honestNode, budgetFillingNode}}
	var firstOrder []string
	for orderIndex, nodes := range orders {
		core, err := NewEphemeralForDevelopment(Config{Nodes: nodes, Replicas: 2, WriteQuorum: 2})
		if err != nil {
			t.Fatal(err)
		}
		items, err := core.Fetch(context.Background(), []string{routeTag})
		if err != nil {
			t.Fatalf("fair combined fetch failed: %v", err)
		}
		if len(items) != protocol.DefaultMaxFetchItems {
			t.Fatalf("combined result has %d items, want bounded %d", len(items), protocol.DefaultMaxFetchItems)
		}
		var bytes int64
		foundHonest := false
		ids := make([]string, len(items))
		for index, item := range items {
			bytes += int64(len(item.Payload))
			ids[index] = item.ItemID
			foundHonest = foundHonest || item.ItemID == honestItem.ItemID
		}
		if bytes > protocol.DefaultMaxFetchBytes || !foundHonest {
			t.Fatalf("combined fetch was not fairly bounded: bytes=%d honest=%v", bytes, foundHonest)
		}
		if orderIndex == 0 {
			firstOrder = ids
			continue
		}
		for index := range ids {
			if ids[index] != firstOrder[index] {
				t.Fatalf("result changed with configuration order at index %d", index)
			}
		}
	}
}

func TestFetchFairMergeEnforcesCombinedByteBudget(t *testing.T) {
	routeTag, _ := RandomCapability()
	now := time.Now().UTC().Truncate(time.Millisecond)
	makeItem := func(index, payloadBytes int) protocol.StoredItem {
		tokenHash := sha256.Sum256([]byte(fmt.Sprintf("byte-budget-token-%d", index)))
		item := protocol.StoredItem{
			Version: protocol.ProtocolVersion, RouteTag: routeTag, CreatedAt: now,
			ExpiresAt: now.Add(protocol.FixedItemRetention), DeleteTokenHash: tokenHash[:],
			Payload: bytes.Repeat([]byte{byte(index)}, payloadBytes),
		}
		item.ItemID = protocol.ComputeItemID(item)
		return item
	}
	budgetItems := make([]protocol.StoredItem, 0, 26)
	remaining := int64(protocol.DefaultMaxFetchBytes)
	for index := 0; remaining > 0; index++ {
		payloadBytes := min(int64(protocol.DefaultMaxItemBytes), remaining)
		budgetItems = append(budgetItems, makeItem(index, int(payloadBytes)))
		remaining -= payloadBytes
	}
	honestItem := makeItem(10_000, 32)
	newNode := func(items []protocol.StoredItem) *HTTPNode {
		signer, _ := pqcrypto.GenerateHybridSigner()
		return developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, http.StatusOK, protocol.FetchResponse{Items: items}), nil
		}))
	}
	budgetNode := newNode(budgetItems)
	honestNode := newNode([]protocol.StoredItem{honestItem})
	for _, nodes := range [][]*HTTPNode{{budgetNode, honestNode}, {honestNode, budgetNode}} {
		core, err := NewEphemeralForDevelopment(Config{Nodes: nodes, Replicas: 2, WriteQuorum: 2})
		if err != nil {
			t.Fatal(err)
		}
		items, err := core.Fetch(context.Background(), []string{routeTag})
		if err != nil {
			t.Fatalf("byte-bounded fair fetch failed: %v", err)
		}
		var resultBytes int64
		foundHonest := false
		for _, item := range items {
			resultBytes += int64(len(item.Payload))
			foundHonest = foundHonest || item.ItemID == honestItem.ItemID
		}
		if resultBytes > protocol.DefaultMaxFetchBytes || !foundHonest {
			t.Fatalf("byte merge exceeded or crowded the honest node: bytes=%d honest=%v", resultBytes, foundHonest)
		}
	}
}

func TestFetchLocalCancellationDoesNotDamageNodeReputation(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		cancel()
		return nil, context.Canceled
	}))
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}})
	if err != nil {
		t.Fatal(err)
	}
	routeTag, _ := RandomCapability()
	if _, err := core.Fetch(ctx, []string{routeTag}); !errors.Is(err, context.Canceled) {
		t.Fatalf("fetch cancellation returned %v", err)
	}
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	if _, err := core.Fetch(deadlineCtx, []string{routeTag}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fetch deadline returned %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expired local deadline performed a node request; calls=%d", calls.Load())
	}
	if scores := core.Reputation(); len(scores) != 0 {
		t.Fatalf("local context termination damaged node reputation: %+v", scores)
	}
}

func TestFetchFailsWhenEveryNodeIsExcluded(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("excluded node must not be contacted")
	}))
	reputation := NewReputation()
	reputation.Exclude(signer.PublicIdentity().NodeID, time.Hour, errors.New("local exclusion"))
	before := reputation.Snapshot()[0]
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}, Reputation: reputation})
	if err != nil {
		t.Fatal(err)
	}
	routeTag, _ := RandomCapability()
	if _, err := core.Fetch(context.Background(), []string{routeTag}); !errors.Is(err, ErrNoAllowedNodes) {
		t.Fatalf("fetch without an allowed node returned %v", err)
	}
	after := reputation.Snapshot()[0]
	if calls.Load() != 0 || after.Failures != before.Failures || after.ConsecutiveFails != before.ConsecutiveFails {
		t.Fatalf("excluded fetch contacted or penalized the node: calls=%d before=%+v after=%+v", calls.Load(), before, after)
	}
}

func TestOversizedNodeFetchCannotDisplaceHonestReplicaInEitherOrder(t *testing.T) {
	routeTag, _ := RandomCapability()
	now := time.Now().UTC().Truncate(time.Millisecond)
	makeItem := func(index int, payloadBytes int) protocol.StoredItem {
		tokenHash := sha256.Sum256([]byte(fmt.Sprintf("oversized-token-%d", index)))
		item := protocol.StoredItem{
			Version: protocol.ProtocolVersion, RouteTag: routeTag, CreatedAt: now,
			ExpiresAt: now.Add(protocol.FixedItemRetention), DeleteTokenHash: tokenHash[:],
			Payload: bytes.Repeat([]byte{byte(index)}, payloadBytes),
		}
		item.ItemID = protocol.ComputeItemID(item)
		return item
	}
	honestItem := makeItem(1000, 32)
	oversized := make([]protocol.StoredItem, 0, 26)
	for index := 0; index < 26; index++ {
		oversized = append(oversized, makeItem(index, protocol.DefaultMaxItemBytes))
	}
	newNode := func(items []protocol.StoredItem) *HTTPNode {
		signer, _ := pqcrypto.GenerateHybridSigner()
		return developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, http.StatusOK, protocol.FetchResponse{Items: items}), nil
		}))
	}
	for _, maliciousFirst := range []bool{true, false} {
		name := "malicious-last"
		nodes := []*HTTPNode{newNode([]protocol.StoredItem{honestItem}), newNode(oversized)}
		if maliciousFirst {
			name = "malicious-first"
			nodes[0], nodes[1] = nodes[1], nodes[0]
		}
		t.Run(name, func(t *testing.T) {
			core, err := NewEphemeralForDevelopment(Config{Nodes: nodes, Replicas: 2, WriteQuorum: 2})
			if err != nil {
				t.Fatal(err)
			}
			items, err := core.Fetch(context.Background(), []string{routeTag})
			if err != nil || len(items) != 1 || items[0].ItemID != honestItem.ItemID {
				t.Fatalf("oversized response displaced honest item: items=%d err=%v", len(items), err)
			}
		})
	}
}

func TestAuditRejectsUntrustedStateAndRepairsZeroReceipts(t *testing.T) {
	signer, _ := pqcrypto.GenerateHybridSigner()
	var stores atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/parameters":
			return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
				ProtocolVersion: protocol.ProtocolVersion, EpochSeconds: protocol.MinWorkEpochSeconds,
				MaxItemBytes: protocol.DefaultMaxItemBytes, StorageCapacity: 1 << 30,
			}), nil
		case "/v1/items":
			stores.Add(1)
			var item protocol.StoredItem
			if err := json.NewDecoder(request.Body).Decode(&item); err != nil {
				t.Fatal(err)
			}
			payloadHash := sha256.Sum256(item.Payload)
			receipt := protocol.StorageReceipt{
				NodeID: signer.PublicIdentity().NodeID, ItemID: item.ItemID, PayloadHash: payloadHash[:],
				StoredAt: time.Now().UTC().Truncate(time.Millisecond), ExpiresAt: item.ExpiresAt,
			}
			var err error
			receipt.Signature, err = signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
			if err != nil {
				t.Fatal(err)
			}
			return jsonResponse(t, http.StatusCreated, receipt), nil
		default:
			t.Fatalf("unexpected audit repair request %s", request.URL.Path)
			return nil, nil
		}
	}))
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}, Replicas: 1, WriteQuorum: 1})
	if err != nil {
		t.Fatal(err)
	}
	item, token := validClientItem(t)
	repaired, audit, err := core.AuditAndRepair(context.Background(), Delivery{Item: item, DeleteToken: token})
	if err != nil || audit[deliveryAuditStateKey] == nil || len(repaired.Receipts) != 1 || stores.Load() != 1 {
		t.Fatalf("zero-receipt state was not repaired: receipts=%d stores=%d audit=%v err=%v", len(repaired.Receipts), stores.Load(), audit, err)
	}
	validReceipt := repaired.Receipts[0]
	for name, delivery := range map[string]Delivery{
		"duplicate": {Item: repaired.Item, DeleteToken: token, Receipts: []protocol.StorageReceipt{validReceipt, validReceipt}},
		"unknown": func() Delivery {
			unknown := validReceipt
			unknown.NodeID = strings.Repeat("f", sha256.Size*2)
			return Delivery{Item: repaired.Item, DeleteToken: token, Receipts: []protocol.StorageReceipt{unknown}}
		}(),
		"forged": func() Delivery {
			forged := validReceipt
			forged.Signature.Ed25519 = append([]byte(nil), forged.Signature.Ed25519...)
			forged.Signature.Ed25519[0] ^= 1
			return Delivery{Item: repaired.Item, DeleteToken: token, Receipts: []protocol.StorageReceipt{forged}}
		}(),
		"bad-capability": {Item: repaired.Item, DeleteToken: bytes.Repeat([]byte{1}, protocol.CapabilityBytes), Receipts: []protocol.StorageReceipt{validReceipt}},
	} {
		t.Run(name, func(t *testing.T) {
			result := core.Audit(context.Background(), delivery)
			if !errors.Is(result[deliveryAuditStateKey], ErrInvalidDeliveryState) {
				t.Fatalf("untrusted delivery state was accepted: %v", result)
			}
		})
	}
}

func TestProofOffsetIncludesFinalWindow(t *testing.T) {
	offset, err := randomProofOffset(bytes.NewReader([]byte{1}), 4097, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 1 {
		t.Fatalf("proof offset=%d, want final window start 1", offset)
	}
}

func TestStorageProofRequiresTheEntireRequestedSample(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.ProofRequest{
		ItemID: strings.Repeat("0", sha256.Size*2), Nonce: bytes.Repeat([]byte{1}, 32),
		Offset: 0, Length: 32,
	}
	proof := protocol.StorageProof{
		NodeID: signer.PublicIdentity().NodeID, ItemID: request.ItemID, Nonce: request.Nonce,
		Offset: request.Offset, Sample: []byte{1}, PayloadHash: make([]byte, sha256.Size),
		ProvedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	proof.Signature, err = signer.Sign(proofDomain, protocol.ProofSigningBytes(proof))
	if err != nil {
		t.Fatal(err)
	}
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(t, http.StatusOK, proof), nil
	}))
	if _, err := node.Prove(context.Background(), request); err == nil {
		t.Fatal("partial storage proof sample was accepted")
	}
}

func TestItemIDParsersRequireCanonicalLowercaseSHA256Hex(t *testing.T) {
	signer, _ := pqcrypto.GenerateHybridSigner()
	var calls atomic.Int32
	node := developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("request should not be sent")
	}))
	core, err := NewEphemeralForDevelopment(Config{Nodes: []*HTTPNode{node}})
	if err != nil {
		t.Fatal(err)
	}
	for _, itemID := range []string{strings.Repeat("z", sha256.Size*2), "A" + strings.Repeat("0", sha256.Size*2-1)} {
		request := protocol.ProofRequest{ItemID: itemID, Nonce: bytes.Repeat([]byte{1}, 32), Length: 1}
		if _, err := node.Prove(context.Background(), request); err == nil {
			t.Fatalf("proof accepted non-canonical item ID %q", itemID)
		}
		if _, err := node.Delete(context.Background(), protocol.DeleteRequest{ItemID: itemID, DeleteToken: make([]byte, protocol.CapabilityBytes)}); err == nil {
			t.Fatalf("delete accepted non-canonical item ID %q", itemID)
		}
		results := core.DeleteItemEverywhere(context.Background(), itemID, make([]byte, protocol.CapabilityBytes))
		if len(results) != 1 {
			t.Fatalf("delete-everywhere did not reject item ID %q", itemID)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid item IDs triggered %d network requests", calls.Load())
	}
}

func TestMaliciousDifficultyOutlierCannotAmplifyProofOfWork(t *testing.T) {
	difficulties := []uint8{8, 8, protocol.MaxWorkDifficulty}
	nodes := make([]*HTTPNode, 0, len(difficulties))
	storeCalls := make([]atomic.Int32, len(difficulties))
	for index, difficulty := range difficulties {
		signer, err := pqcrypto.GenerateHybridSigner()
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, developmentNodeForTest(signer.PublicIdentity(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case "/v1/parameters":
				return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
					ProtocolVersion: protocol.ProtocolVersion,
					Difficulty:      difficulty,
					EpochSeconds:    600,
					MaxItemBytes:    protocol.DefaultMaxItemBytes,
					StorageCapacity: 1 << 30,
				}), nil
			case "/v1/items":
				storeCalls[index].Add(1)
				var item protocol.StoredItem
				if err := json.NewDecoder(request.Body).Decode(&item); err != nil {
					t.Fatal(err)
				}
				if item.Work.Difficulty != 8 {
					t.Fatalf("outlier raised solved difficulty to %d", item.Work.Difficulty)
				}
				hash := sha256.Sum256(item.Payload)
				receipt := protocol.StorageReceipt{
					NodeID:      signer.PublicIdentity().NodeID,
					ItemID:      item.ItemID,
					PayloadHash: hash[:],
					StoredAt:    time.Now().UTC().Truncate(time.Millisecond),
					ExpiresAt:   item.ExpiresAt,
				}
				signature, signErr := signer.Sign(receiptDomain, protocol.ReceiptSigningBytes(receipt))
				if signErr != nil {
					t.Fatal(signErr)
				}
				receipt.Signature = signature
				return jsonResponse(t, http.StatusCreated, receipt), nil
			default:
				t.Fatalf("unexpected request path %s", request.URL.Path)
				return nil, nil
			}
		})))
	}
	core, err := NewEphemeralForDevelopment(Config{Nodes: nodes, Replicas: 3, WriteQuorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	item, deleteToken := validClientItem(t)
	delivery, err := core.StoreReplicated(context.Background(), item, deleteToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Receipts) != 2 || storeCalls[2].Load() != 0 {
		t.Fatalf("outlier participated: receipts=%d malicious_calls=%d", len(delivery.Receipts), storeCalls[2].Load())
	}
}
