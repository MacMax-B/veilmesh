package protocol

import "time"

const (
	ProtocolVersion      = 1
	DefaultMaxRetention  = 60 * 24 * time.Hour
	DefaultMaxItemBytes  = 320 * 1024
	DefaultMaxFileBytes  = 64 * 1024 * 1024
	DefaultFileChunkSize = 256 * 1024
	CapabilityBytes      = 32
	MaxRouteTagsPerFetch = 256
	DefaultMaxFetchItems = 512
	DefaultMaxFetchBytes = 8 * 1024 * 1024
	MinWorkEpochSeconds  = 60
	MaxWorkEpochSeconds  = 24 * 60 * 60
	MaxWorkDifficulty    = 24
	MaxProofSampleBytes  = 16 * 1024
)

type WorkProof struct {
	Epoch      int64  `json:"epoch"`
	Nonce      uint64 `json:"nonce"`
	Difficulty uint8  `json:"difficulty"`
}

// StoredItem contains opaque ciphertext. RouteTag is a one-time capability,
// not an account or user identifier. DeleteTokenHash authorizes deletion
// without disclosing an identity to the node.
type StoredItem struct {
	Version         uint8     `json:"version"`
	ItemID          string    `json:"item_id"`
	RouteTag        string    `json:"route_tag"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	DeleteTokenHash []byte    `json:"delete_token_hash"`
	Payload         []byte    `json:"payload"`
	Work            WorkProof `json:"work"`
}

type NodePublicIdentity struct {
	NodeID          string `json:"node_id"`
	Ed25519Public   []byte `json:"ed25519_public"`
	MLDSA65Public   []byte `json:"ml_dsa_65_public"`
	ProtocolVersion uint8  `json:"protocol_version"`
}

type HybridSignature struct {
	Ed25519 []byte `json:"ed25519"`
	MLDSA65 []byte `json:"ml_dsa_65"`
}

type StorageReceipt struct {
	NodeID      string          `json:"node_id"`
	ItemID      string          `json:"item_id"`
	PayloadHash []byte          `json:"payload_hash"`
	StoredAt    time.Time       `json:"stored_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Signature   HybridSignature `json:"signature"`
}

type DeleteRequest struct {
	ItemID      string `json:"item_id"`
	DeleteToken []byte `json:"delete_token"`
}

type DeleteReceipt struct {
	NodeID    string          `json:"node_id"`
	ItemID    string          `json:"item_id"`
	DeletedAt time.Time       `json:"deleted_at"`
	Signature HybridSignature `json:"signature"`
}

type FetchRequest struct {
	RouteTags []string `json:"route_tags"`
}

type FetchResponse struct {
	Items []StoredItem `json:"items"`
}

type ProofRequest struct {
	ItemID string `json:"item_id"`
	Nonce  []byte `json:"nonce"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
}

type StorageProof struct {
	NodeID      string          `json:"node_id"`
	ItemID      string          `json:"item_id"`
	Nonce       []byte          `json:"nonce"`
	Offset      int64           `json:"offset"`
	Sample      []byte          `json:"sample"`
	PayloadHash []byte          `json:"payload_hash"`
	ProvedAt    time.Time       `json:"proved_at"`
	Signature   HybridSignature `json:"signature"`
}

type NodeParameters struct {
	ProtocolVersion uint8         `json:"protocol_version"`
	Difficulty      uint8         `json:"difficulty"`
	EpochSeconds    int64         `json:"epoch_seconds"`
	MaxItemBytes    int           `json:"max_item_bytes"`
	MaxRetention    time.Duration `json:"max_retention"`
	StorageUsed     int64         `json:"storage_used"`
	StorageCapacity int64         `json:"storage_capacity"`
}

type DirectCiphertext struct {
	Suite         string `json:"suite"`
	Encapsulation []byte `json:"encapsulation"`
	Ciphertext    []byte `json:"ciphertext"`
}

type FileManifest struct {
	Version        uint8       `json:"version"`
	FileID         string      `json:"file_id"`
	Name           string      `json:"name"`
	MediaType      string      `json:"media_type"`
	PlaintextBytes int64       `json:"plaintext_bytes"`
	ChunkSize      int         `json:"chunk_size"`
	Chunks         []FileChunk `json:"chunks"`
}

type FileChunk struct {
	Index      int    `json:"index"`
	RouteTag   string `json:"route_tag"`
	CipherHash []byte `json:"cipher_hash"`
	CipherSize int    `json:"cipher_size"`
}

type DeviceDescriptor struct {
	DeviceID      string             `json:"device_id"`
	AccountID     string             `json:"account_id"`
	HPKEPublicKey []byte             `json:"hpke_public_key"`
	SigningKey    NodePublicIdentity `json:"signing_key"`
}

type DeviceSyncEnvelope struct {
	DeviceID string           `json:"device_id"`
	Payload  DirectCiphertext `json:"payload"`
}
