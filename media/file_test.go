package media

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"propagare/client"
	"propagare/pqcrypto"
	"propagare/protocol"
)

type mediaRoundTripFunc func(*http.Request) (*http.Response, error)

func (function mediaRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestEncryptedFileRoundTripAndPadding(t *testing.T) {
	plaintext := make([]byte, 190_123)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptFile("picture.jpg", "image/jpeg", plaintext, 1_000_000, 64*1024)
	if err != nil {
		t.Fatal(err)
	}
	chunks := make(map[int][]byte)
	var size int
	for _, chunk := range encrypted.Chunks {
		chunks[chunk.Metadata.Index] = chunk.Payload
		if size == 0 {
			size = len(chunk.Payload)
		} else if len(chunk.Payload) != size {
			t.Fatal("encrypted chunks do not use a constant padded size")
		}
	}
	opened, err := DecryptFile(encrypted.Secret, encrypted.Manifest, chunks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("reconstructed file differs")
	}
}

func TestDecryptRejectsManifestReorderingAndOversize(t *testing.T) {
	encrypted, err := EncryptFile("file.bin", "application/octet-stream", bytes.Repeat([]byte{1}, 40_000), 1_000_000, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	chunks := make(map[int][]byte, len(encrypted.Chunks))
	for _, chunk := range encrypted.Chunks {
		chunks[chunk.Metadata.Index] = chunk.Payload
	}
	tampered := encrypted.Manifest
	tampered.Chunks = append([]protocol.FileChunk(nil), encrypted.Manifest.Chunks...)
	tampered.Chunks[0].Index = 1
	if _, err := DecryptFile(encrypted.Secret, tampered, chunks); err == nil {
		t.Fatal("reordered manifest index was accepted")
	}
	tampered = encrypted.Manifest
	tampered.PlaintextBytes = protocol.DefaultMaxFileBytes + 1
	if _, err := DecryptFile(encrypted.Secret, tampered, chunks); err == nil {
		t.Fatal("oversized manifest was accepted")
	}
	nonCanonicalManifest := encrypted.Manifest
	nonCanonicalSecret := encrypted.Secret
	nonCanonicalID := encrypted.Manifest.FileID[:len(encrypted.Manifest.FileID)-1] + "B"
	nonCanonicalManifest.FileID = nonCanonicalID
	nonCanonicalSecret.FileID = nonCanonicalID
	if err := validateManifest(nonCanonicalSecret, nonCanonicalManifest); err == nil {
		t.Fatal("non-canonical file capability was accepted")
	}
}

func FuzzValidateManifestFileID(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")
	f.Fuzz(func(t *testing.T, fileID string) {
		secret := FileSecret{FileID: fileID, Key: make([]byte, 32), DeleteTokens: []FileChunkSecret{{Index: 0, DeleteToken: make([]byte, protocol.CapabilityBytes)}}}
		manifest := protocol.FileManifest{
			Version: protocol.ProtocolVersion, FileID: fileID, Name: "file.bin", MediaType: "application/octet-stream",
			PlaintextBytes: 1, ChunkSize: 16 * 1024,
			Chunks: []protocol.FileChunk{{Index: 0, RouteTag: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", CipherHash: make([]byte, 32), CipherSize: 16*1024 + 32}},
		}
		_ = validateManifest(secret, manifest)
	})
}

func TestRetrieveBatchesFilesBeyondSingleFetchLimits(t *testing.T) {
	plaintext := bytes.Repeat([]byte("large authenticated file"), (8*1024*1024)/len("large authenticated file")+1)
	plaintext = plaintext[:8*1024*1024]
	encrypted, err := EncryptFile("large.bin", "application/octet-stream", plaintext, protocol.DefaultMaxFileBytes, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted.Manifest.Chunks) <= protocol.MaxRouteTagsPerFetch {
		t.Fatal("test file did not exceed the single-fetch route limit")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	byRoute := make(map[string]protocol.StoredItem, len(encrypted.Chunks))
	for _, chunk := range encrypted.Chunks {
		item := protocol.StoredItem{
			Version: protocol.ProtocolVersion, RouteTag: chunk.Metadata.RouteTag,
			CreatedAt: now, ExpiresAt: now.Add(protocol.FixedItemRetention),
			DeleteTokenHash: pqcrypto.DeleteTokenHash(chunk.DeleteToken), Payload: chunk.Payload,
		}
		item.ItemID = protocol.ComputeItemID(item)
		byRoute[item.RouteTag] = item
	}
	signer, _ := pqcrypto.GenerateHybridSigner()
	requests := 0
	node := &client.HTTPNode{
		BaseURL: "https://node.invalid", Identity: signer.PublicIdentity(),
		Client: &http.Client{Transport: mediaRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			var fetch protocol.FetchRequest
			if err := json.NewDecoder(request.Body).Decode(&fetch); err != nil {
				t.Fatal(err)
			}
			items := make([]protocol.StoredItem, 0, len(fetch.RouteTags))
			for _, routeTag := range fetch.RouteTags {
				items = append(items, byRoute[routeTag])
			}
			body, err := json.Marshal(protocol.FetchResponse{Items: items})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
				Body: io.NopCloser(bytes.NewReader(body)), Request: request,
			}, nil
		})},
	}
	core, err := client.New(client.Config{Nodes: []*client.HTTPNode{node}, Replicas: 1, WriteQuorum: 1})
	if err != nil {
		t.Fatal(err)
	}
	opened, _, err := Retrieve(context.Background(), core, encrypted.Secret, encrypted.Manifest, false)
	if err != nil {
		t.Fatal(err)
	}
	if requests < 2 || !bytes.Equal(opened, plaintext) {
		t.Fatalf("batched retrieval: requests=%d equal=%v", requests, bytes.Equal(opened, plaintext))
	}
}
