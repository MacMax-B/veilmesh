package media

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/MacMax-B/propagare/client"
	"github.com/MacMax-B/propagare/protocol"
)

type FileSecret struct {
	FileID       string            `json:"file_id"`
	Key          []byte            `json:"key"`
	DeleteTokens []FileChunkSecret `json:"delete_tokens"`
}

type FileChunkSecret struct {
	Index       int    `json:"index"`
	DeleteToken []byte `json:"delete_token"`
}

type EncryptedChunk struct {
	Metadata    protocol.FileChunk `json:"metadata"`
	Payload     []byte             `json:"payload"`
	DeleteToken []byte             `json:"delete_token"`
}

type EncryptedFile struct {
	Secret   FileSecret            `json:"secret"`
	Manifest protocol.FileManifest `json:"manifest"`
	Chunks   []EncryptedChunk      `json:"chunks"`
}

const (
	MaxFileNameBytes  = 255
	MaxMediaTypeBytes = 255
)

func EncryptFile(name, mediaType string, plaintext []byte, maxBytes, chunkSize int) (EncryptedFile, error) {
	if maxBytes <= 0 {
		maxBytes = protocol.DefaultMaxFileBytes
	}
	if maxBytes > protocol.DefaultMaxFileBytes {
		return EncryptedFile{}, errors.New("configured file limit exceeds protocol maximum")
	}
	if chunkSize <= 0 {
		chunkSize = protocol.DefaultFileChunkSize
	}
	if len(plaintext) == 0 || len(plaintext) > maxBytes {
		return EncryptedFile{}, errors.New("file size is outside configured limits")
	}
	if !validPortableFileName(name) || !validMediaType(mediaType) {
		return EncryptedFile{}, errors.New("invalid file metadata")
	}
	if chunkSize < 16*1024 || chunkSize > protocol.DefaultMaxItemBytes-1024 {
		return EncryptedFile{}, errors.New("invalid encrypted file chunk size")
	}
	key := make([]byte, 32)
	fileIDRaw := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return EncryptedFile{}, err
	}
	if _, err := rand.Read(fileIDRaw); err != nil {
		return EncryptedFile{}, err
	}
	fileID := base64.RawURLEncoding.EncodeToString(fileIDRaw)
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedFile{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedFile{}, err
	}
	result := EncryptedFile{
		Secret: FileSecret{FileID: fileID, Key: key},
		Manifest: protocol.FileManifest{
			Version:        protocol.ProtocolVersion,
			FileID:         fileID,
			Name:           name,
			MediaType:      mediaType,
			PlaintextBytes: int64(len(plaintext)),
			ChunkSize:      chunkSize,
		},
	}
	for index, start := 0, 0; start < len(plaintext); index, start = index+1, start+chunkSize {
		end := min(start+chunkSize, len(plaintext))
		padded := make([]byte, chunkSize+4)
		binary.BigEndian.PutUint32(padded[:4], uint32(end-start)) // #nosec G115 -- chunkSize is bounded below 320 KiB.
		copy(padded[4:], plaintext[start:end])
		if _, err := rand.Read(padded[4+(end-start):]); err != nil {
			wipe(padded)
			return EncryptedFile{}, err
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return EncryptedFile{}, err
		}
		aad := []byte(fmt.Sprintf("enig/file/v1\x00%s\x00%d", fileID, index))
		ciphertext := append(nonce, aead.Seal(nil, nonce, padded, aad)...)
		wipe(padded)
		routeTag, err := client.RandomCapability()
		if err != nil {
			return EncryptedFile{}, err
		}
		deleteToken, err := client.RandomDeleteToken()
		if err != nil {
			return EncryptedFile{}, err
		}
		hash := sha256.Sum256(ciphertext)
		metadata := protocol.FileChunk{Index: index, RouteTag: routeTag, CipherHash: hash[:], CipherSize: len(ciphertext)}
		result.Manifest.Chunks = append(result.Manifest.Chunks, metadata)
		result.Chunks = append(result.Chunks, EncryptedChunk{Metadata: metadata, Payload: ciphertext, DeleteToken: deleteToken})
		result.Secret.DeleteTokens = append(result.Secret.DeleteTokens, FileChunkSecret{Index: index, DeleteToken: append([]byte(nil), deleteToken...)})
	}
	return result, nil
}

func DecryptFile(secret FileSecret, manifest protocol.FileManifest, chunks map[int][]byte) ([]byte, error) {
	if err := validateManifest(secret, manifest); err != nil {
		return nil, err
	}
	if len(chunks) != len(manifest.Chunks) {
		return nil, errors.New("encrypted chunk set does not match manifest")
	}
	if manifest.FileID != secret.FileID || len(secret.Key) != 32 {
		return nil, errors.New("file secret does not match manifest")
	}
	block, err := aes.NewCipher(secret.Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	for _, metadata := range manifest.Chunks {
		ciphertext, ok := chunks[metadata.Index]
		if !ok {
			return nil, fmt.Errorf("missing encrypted chunk %d", metadata.Index)
		}
		hash := sha256.Sum256(ciphertext)
		if !bytes.Equal(hash[:], metadata.CipherHash) || len(ciphertext) != metadata.CipherSize || len(ciphertext) < aead.NonceSize() {
			return nil, fmt.Errorf("invalid encrypted chunk %d", metadata.Index)
		}
		nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
		aad := []byte(fmt.Sprintf("enig/file/v1\x00%s\x00%d", manifest.FileID, metadata.Index))
		padded, err := aead.Open(nil, nonce, body, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", metadata.Index, err)
		}
		if len(padded) != manifest.ChunkSize+4 {
			wipe(padded)
			return nil, errors.New("invalid padded chunk size")
		}
		length := int(binary.BigEndian.Uint32(padded[:4]))
		if length < 0 || length > manifest.ChunkSize {
			wipe(padded)
			return nil, errors.New("invalid plaintext chunk length")
		}
		_, _ = output.Write(padded[4 : 4+length])
		wipe(padded)
	}
	if int64(output.Len()) != manifest.PlaintextBytes {
		return nil, errors.New("reconstructed file size does not match manifest")
	}
	return output.Bytes(), nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func Store(ctx context.Context, core *client.Core, encrypted EncryptedFile) ([]client.Delivery, error) {
	if err := validateManifest(encrypted.Secret, encrypted.Manifest); err != nil {
		return nil, err
	}
	if len(encrypted.Chunks) != len(encrypted.Manifest.Chunks) {
		return nil, errors.New("encrypted chunks do not match manifest")
	}
	// Validate the complete immutable upload set before the first network side
	// effect. Otherwise a malformed later chunk could leave an avoidable partial
	// upload, and metadata could claim a hash different from the stored bytes.
	for index, chunk := range encrypted.Chunks {
		expected := encrypted.Manifest.Chunks[index]
		if chunk.Metadata.Index != index || chunk.Metadata.RouteTag != expected.RouteTag ||
			chunk.Metadata.CipherSize != expected.CipherSize || !bytes.Equal(chunk.Metadata.CipherHash, expected.CipherHash) ||
			len(chunk.Payload) != expected.CipherSize || len(chunk.DeleteToken) != protocol.CapabilityBytes ||
			!bytes.Equal(chunk.DeleteToken, encrypted.Secret.DeleteTokens[index].DeleteToken) {
			return nil, errors.New("encrypted chunk metadata mismatch")
		}
		digest := sha256.Sum256(chunk.Payload)
		if !bytes.Equal(digest[:], expected.CipherHash) {
			return nil, errors.New("encrypted chunk payload hash mismatch")
		}
	}
	if core == nil {
		return nil, errors.New("client core is required")
	}
	deliveries := make([]client.Delivery, 0, len(encrypted.Chunks))
	for _, chunk := range encrypted.Chunks {
		delivery, err := core.StoreOpaque(ctx, chunk.Metadata.RouteTag, chunk.Payload, chunk.DeleteToken)
		if err != nil {
			return deliveries, fmt.Errorf("store encrypted chunk %d: %w", chunk.Metadata.Index, err)
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}

// Retrieve downloads every fixed-size encrypted chunk, authenticates and
// reconstructs the file, and only then requests deletion from all nodes.
func Retrieve(ctx context.Context, core *client.Core, secret FileSecret, manifest protocol.FileManifest, deleteAfterSuccess bool) ([]byte, map[string]error, error) {
	if err := validateManifest(secret, manifest); err != nil {
		return nil, nil, err
	}
	if core == nil {
		return nil, nil, errors.New("client core is required")
	}
	routeTags := make([]string, 0, len(manifest.Chunks))
	metadataByHash := make(map[string]protocol.FileChunk)
	for _, metadata := range manifest.Chunks {
		routeTags = append(routeTags, metadata.RouteTag)
		metadataByHash[string(metadata.CipherHash)] = metadata
	}
	chunks := make(map[int][]byte)
	itemByIndex := make(map[int]protocol.StoredItem)
	maxTagsPerBatch := protocol.DefaultMaxFetchBytes / int64(manifest.Chunks[0].CipherSize)
	if maxTagsPerBatch <= 0 {
		return nil, nil, errors.New("encrypted file chunk exceeds fetch byte limit")
	}
	batchSize := min(protocol.MaxRouteTagsPerFetch, int(maxTagsPerBatch))
	for start := 0; start < len(routeTags); start += batchSize {
		end := min(start+batchSize, len(routeTags))
		items, err := core.Fetch(ctx, routeTags[start:end])
		if err != nil {
			return nil, nil, fmt.Errorf("fetch encrypted chunks %d-%d: %w", start, end-1, err)
		}
		for _, item := range items {
			hash := sha256.Sum256(item.Payload)
			metadata, ok := metadataByHash[string(hash[:])]
			if !ok || metadata.RouteTag != item.RouteTag {
				continue
			}
			chunks[metadata.Index] = item.Payload
			itemByIndex[metadata.Index] = item
		}
	}
	plaintext, err := DecryptFile(secret, manifest, chunks)
	if err != nil {
		return nil, nil, err
	}
	deletionReport := make(map[string]error)
	if deleteAfterSuccess {
		for _, chunkSecret := range secret.DeleteTokens {
			item, ok := itemByIndex[chunkSecret.Index]
			if ok {
				for nodeID, deleteErr := range core.DeleteItemEverywhere(ctx, item.ItemID, chunkSecret.DeleteToken) {
					deletionReport[fmt.Sprintf("chunk-%d/%s", chunkSecret.Index, nodeID)] = deleteErr
				}
			}
		}
	}
	return plaintext, deletionReport, nil
}

func validateManifest(secret FileSecret, manifest protocol.FileManifest) error {
	fileID, err := base64.RawURLEncoding.Strict().DecodeString(manifest.FileID)
	if err != nil || len(fileID) != protocol.CapabilityBytes || manifest.Version != protocol.ProtocolVersion ||
		manifest.FileID != secret.FileID || len(secret.Key) != 32 || manifest.PlaintextBytes <= 0 ||
		manifest.PlaintextBytes > protocol.DefaultMaxFileBytes || manifest.ChunkSize < 16*1024 ||
		manifest.ChunkSize > protocol.DefaultMaxItemBytes-1024 || !validPortableFileName(manifest.Name) ||
		!validMediaType(manifest.MediaType) {
		return errors.New("invalid file manifest")
	}
	expectedChunks := (manifest.PlaintextBytes + int64(manifest.ChunkSize) - 1) / int64(manifest.ChunkSize)
	if expectedChunks <= 0 || expectedChunks > int64(protocol.DefaultMaxFileBytes/(16*1024)+1) ||
		int64(len(manifest.Chunks)) != expectedChunks || len(secret.DeleteTokens) != len(manifest.Chunks) {
		return errors.New("invalid file chunk count")
	}
	expectedCipherSize := manifest.ChunkSize + 4 + 12 + 16
	seenRoutes := make(map[string]struct{}, len(manifest.Chunks))
	seenHashes := make(map[string]struct{}, len(manifest.Chunks))
	for index, metadata := range manifest.Chunks {
		if metadata.Index != index || !protocol.ValidRouteTag(metadata.RouteTag) ||
			len(metadata.CipherHash) != sha256.Size || metadata.CipherSize != expectedCipherSize ||
			secret.DeleteTokens[index].Index != index ||
			len(secret.DeleteTokens[index].DeleteToken) != protocol.CapabilityBytes {
			return errors.New("invalid file chunk metadata")
		}
		if _, duplicate := seenRoutes[metadata.RouteTag]; duplicate {
			return errors.New("duplicate file chunk route")
		}
		if _, duplicate := seenHashes[string(metadata.CipherHash)]; duplicate {
			return errors.New("duplicate file chunk hash")
		}
		seenRoutes[metadata.RouteTag] = struct{}{}
		seenHashes[string(metadata.CipherHash)] = struct{}{}
	}
	return nil
}

func validPortableFileName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > MaxFileNameBytes || !utf8.ValidString(name) ||
		strings.ContainsAny(name, "/\\\x00\r\n") {
		return false
	}
	for _, value := range name {
		if value < 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func validMediaType(mediaType string) bool {
	if mediaType == "" || len(mediaType) > MaxMediaTypeBytes || !utf8.ValidString(mediaType) {
		return false
	}
	for _, value := range mediaType {
		if value < 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}
