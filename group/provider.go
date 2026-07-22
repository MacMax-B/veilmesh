package group

import (
	"context"
	"errors"
)

var ErrMLSProviderRequired = errors.New("an audited RFC 9420 MLS/TreeKEM provider is required")

// MLSProvider keeps authorization separate from group encryption. A provider
// implementation should use RFC 9420 MLS and map every successful State action
// to the corresponding Add/Remove/Update proposal and Commit.
//
// Hybrid post-quantum MLS ciphersuites are intentionally not implemented here:
// they are still IETF drafts. This boundary lets an audited provider replace
// the transport without changing frontends or node APIs.
type MLSProvider interface {
	Create(ctx context.Context, groupID string, creatorCredential []byte) ([]byte, error)
	Add(ctx context.Context, state []byte, keyPackage []byte) (newState, commit, welcome []byte, err error)
	Remove(ctx context.Context, state []byte, leafIndex uint32) (newState, commit []byte, err error)
	Encrypt(ctx context.Context, state, plaintext []byte) (newState, ciphertext []byte, err error)
	Decrypt(ctx context.Context, state, ciphertext []byte) (newState, plaintext []byte, err error)
}
