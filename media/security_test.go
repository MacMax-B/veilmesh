package media

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestEncryptFileRejectsUnsafeMetadata(t *testing.T) {
	t.Parallel()

	invalidNames := []string{
		"",
		".",
		"..",
		"../secret",
		`..\secret`,
		"line\nfeed",
		"nul\x00byte",
		string([]byte{0xff}),
		strings.Repeat("a", MaxFileNameBytes+1),
	}
	for _, name := range invalidNames {
		name := name
		t.Run("name", func(t *testing.T) {
			t.Parallel()
			if _, err := EncryptFile(name, "application/octet-stream", []byte{1}, 1, 16*1024); err == nil {
				t.Fatalf("unsafe file name %q was accepted", name)
			}
		})
	}

	invalidMediaTypes := []string{"", "text/plain\nX-Injected: true", string([]byte{0xff}), strings.Repeat("a", MaxMediaTypeBytes+1)}
	for _, mediaType := range invalidMediaTypes {
		mediaType := mediaType
		t.Run("media-type", func(t *testing.T) {
			t.Parallel()
			if _, err := EncryptFile("file.bin", mediaType, []byte{1}, 1, 16*1024); err == nil {
				t.Fatalf("unsafe media type %q was accepted", mediaType)
			}
		})
	}
}

func TestStorePreflightsPayloadBeforeNetworkUse(t *testing.T) {
	t.Parallel()

	encrypted, err := EncryptFile("file.bin", "application/octet-stream", bytes.Repeat([]byte{1}, 32), 32, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	encrypted.Chunks[0].Payload[0] ^= 0xff
	if _, err := Store(context.Background(), nil, encrypted); err == nil || !strings.Contains(err.Error(), "payload hash") {
		t.Fatalf("tampered payload was not rejected during preflight: %v", err)
	}
}

func TestMediaOperationsRejectNilCore(t *testing.T) {
	t.Parallel()

	encrypted, err := EncryptFile("file.bin", "application/octet-stream", []byte{1}, 1, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Store(context.Background(), nil, encrypted); err == nil {
		t.Fatal("Store accepted a nil client core")
	}
	if _, _, err := Retrieve(context.Background(), nil, encrypted.Secret, encrypted.Manifest, false); err == nil {
		t.Fatal("Retrieve accepted a nil client core")
	}
}
