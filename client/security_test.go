package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

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
		ExpiresAt:       now.Add(time.Hour),
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
			node := &HTTPNode{
				BaseURL:  "https://node.invalid",
				Identity: signer.PublicIdentity(),
				Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return jsonResponse(t, http.StatusCreated, receipt), nil
				})},
			}
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
	node := &HTTPNode{
		BaseURL:  "https://node.invalid",
		Identity: signer.PublicIdentity(),
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
				ProtocolVersion: protocol.ProtocolVersion,
				Difficulty:      protocol.MaxWorkDifficulty + 1,
				EpochSeconds:    600,
				MaxItemBytes:    protocol.DefaultMaxItemBytes,
				MaxRetention:    protocol.DefaultMaxRetention,
				StorageCapacity: 1,
			}), nil
		})},
	}
	if _, err := node.Parameters(context.Background()); err == nil {
		t.Fatal("malicious proof-of-work difficulty was accepted")
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
	node := &HTTPNode{
		BaseURL: "https://node.invalid", Identity: signer.PublicIdentity(),
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(secret))}, nil
		})},
	}
	_, err := node.Delete(context.Background(), protocol.DeleteRequest{ItemID: strings.Repeat("0", 64), DeleteToken: make([]byte, 32)})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("untrusted response body escaped through error: %v", err)
	}
}

func TestFetchRejectsPerNodeAndCombinedItemAmplification(t *testing.T) {
	routeTag, _ := RandomCapability()
	now := time.Now().UTC().Truncate(time.Millisecond)
	makeItems := func(start, count int) []protocol.StoredItem {
		items := make([]protocol.StoredItem, 0, count)
		for index := start; index < start+count; index++ {
			tokenHash := sha256.Sum256([]byte(fmt.Sprintf("token-%d", index)))
			item := protocol.StoredItem{
				Version: protocol.ProtocolVersion, RouteTag: routeTag, CreatedAt: now,
				ExpiresAt: now.Add(time.Hour), DeleteTokenHash: tokenHash[:], Payload: []byte{byte(index)},
			}
			item.ItemID = protocol.ComputeItemID(item)
			items = append(items, item)
		}
		return items
	}
	newNode := func(items []protocol.StoredItem) *HTTPNode {
		signer, _ := pqcrypto.GenerateHybridSigner()
		return &HTTPNode{
			BaseURL: "https://node.invalid", Identity: signer.PublicIdentity(),
			Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(t, http.StatusOK, protocol.FetchResponse{Items: items}), nil
			})},
		}
	}
	if _, err := newNode(makeItems(0, protocol.DefaultMaxFetchItems+1)).Fetch(context.Background(), []string{routeTag}); err == nil {
		t.Fatal("per-node item amplification was accepted")
	}
	core, err := New(Config{Nodes: []*HTTPNode{newNode(makeItems(0, 300)), newNode(makeItems(300, 300))}, Replicas: 2, WriteQuorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Fetch(context.Background(), []string{routeTag}); err == nil {
		t.Fatal("combined item amplification was accepted")
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
	node := &HTTPNode{
		BaseURL: "https://node.invalid", Identity: signer.PublicIdentity(),
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, http.StatusOK, proof), nil
		})},
	}
	if _, err := node.Prove(context.Background(), request); err == nil {
		t.Fatal("partial storage proof sample was accepted")
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
		nodes = append(nodes, &HTTPNode{
			BaseURL:  "https://node.invalid",
			Identity: signer.PublicIdentity(),
			Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Path {
				case "/v1/parameters":
					return jsonResponse(t, http.StatusOK, protocol.NodeParameters{
						ProtocolVersion: protocol.ProtocolVersion,
						Difficulty:      difficulty,
						EpochSeconds:    600,
						MaxItemBytes:    protocol.DefaultMaxItemBytes,
						MaxRetention:    protocol.DefaultMaxRetention,
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
			})},
		})
	}
	core, err := New(Config{Nodes: nodes, Replicas: 3, WriteQuorum: 2})
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
