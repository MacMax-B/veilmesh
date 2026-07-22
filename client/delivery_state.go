package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

const (
	deliveryStateVersion       = 1
	maxDeliveryNodes           = 384
	maxDeliveryFailureTextByte = 256
)

var (
	ErrDeliveryExpired         = errors.New("persisted delivery has expired")
	ErrDeliveryNodeUnavailable = errors.New("a pinned delivery node is not configured")
	ErrDeliveryStateChanged    = errors.New("persisted delivery state changed during the operation")
)

// persistedDeliveryState stores the identities needed to authenticate old
// receipts after directory membership changes. AttemptedNodeIDs is written
// before the corresponding external Store call, so a crash or a lost response
// never loses the set of nodes that might hold the ciphertext.
type persistedDeliveryState struct {
	Version          uint8                         `json:"version"`
	Delivery         Delivery                      `json:"delivery"`
	NodeIdentities   []protocol.NodePublicIdentity `json:"node_identities"`
	AttemptedNodeIDs []string                      `json:"attempted_node_ids"`
}

func (c *Core) lockDelivery(itemID string) func() {
	digest := sha256.Sum256([]byte("enig/client-delivery-lock/v1\x00" + itemID))
	stripe := int(digest[0]) % len(c.deliveryLocks)
	c.deliveryLocks[stripe].Lock()
	return c.deliveryLocks[stripe].Unlock
}

func cloneStoredItem(item protocol.StoredItem) protocol.StoredItem {
	item.DeleteTokenHash = append([]byte(nil), item.DeleteTokenHash...)
	item.Payload = append([]byte(nil), item.Payload...)
	return item
}

func cloneStorageReceipt(receipt protocol.StorageReceipt) protocol.StorageReceipt {
	receipt.PayloadHash = append([]byte(nil), receipt.PayloadHash...)
	receipt.Signature.Ed25519 = append([]byte(nil), receipt.Signature.Ed25519...)
	receipt.Signature.MLDSA65 = append([]byte(nil), receipt.Signature.MLDSA65...)
	return receipt
}

func cloneDelivery(delivery Delivery) Delivery {
	result := Delivery{
		Item:        cloneStoredItem(delivery.Item),
		DeleteToken: append([]byte(nil), delivery.DeleteToken...),
		Receipts:    make([]protocol.StorageReceipt, 0, len(delivery.Receipts)),
	}
	for _, receipt := range delivery.Receipts {
		result.Receipts = append(result.Receipts, cloneStorageReceipt(receipt))
	}
	if len(delivery.FailedNodes) > 0 {
		result.FailedNodes = make(map[string]string, len(delivery.FailedNodes))
		for nodeID, failure := range delivery.FailedNodes {
			result.FailedNodes[nodeID] = failure
		}
	}
	return result
}

func clonePersistedDeliveryState(state persistedDeliveryState) persistedDeliveryState {
	result := persistedDeliveryState{
		Version:          state.Version,
		Delivery:         cloneDelivery(state.Delivery),
		NodeIdentities:   make([]protocol.NodePublicIdentity, 0, len(state.NodeIdentities)),
		AttemptedNodeIDs: append([]string(nil), state.AttemptedNodeIDs...),
	}
	for _, identity := range state.NodeIdentities {
		result.NodeIdentities = append(result.NodeIdentities, cloneNodeIdentity(identity))
	}
	return result
}

func wipeDeliveryState(state *persistedDeliveryState) {
	if state == nil {
		return
	}
	zero(state.Delivery.DeleteToken)
	zero(state.Delivery.Item.Payload)
	for index := range state.NodeIdentities {
		zero(state.NodeIdentities[index].Ed25519Public)
		zero(state.NodeIdentities[index].MLDSA65Public)
	}
}

func deliveryIdentityMap(state persistedDeliveryState) map[string]protocol.NodePublicIdentity {
	identities := make(map[string]protocol.NodePublicIdentity, len(state.NodeIdentities))
	for _, identity := range state.NodeIdentities {
		identities[identity.NodeID] = identity
	}
	return identities
}

func (c *Core) currentIdentity(nodeID string) (protocol.NodePublicIdentity, bool) {
	node := c.nodeByID(nodeID)
	if node == nil {
		return protocol.NodePublicIdentity{}, false
	}
	return cloneNodeIdentity(node.identity), true
}

func addDeliveryIdentity(state *persistedDeliveryState, identity protocol.NodePublicIdentity) error {
	if state == nil || !pqcrypto.ValidPublicIdentity(identity) {
		return ErrInvalidDeliveryState
	}
	for _, existing := range state.NodeIdentities {
		if existing.NodeID != identity.NodeID {
			continue
		}
		if !sameNodeIdentity(existing, identity) {
			return ErrInvalidDeliveryState
		}
		return nil
	}
	if len(state.NodeIdentities) >= maxDeliveryNodes {
		return ErrInvalidDeliveryState
	}
	state.NodeIdentities = append(state.NodeIdentities, cloneNodeIdentity(identity))
	sort.Slice(state.NodeIdentities, func(i, j int) bool {
		return state.NodeIdentities[i].NodeID < state.NodeIdentities[j].NodeID
	})
	return nil
}

func addDeliveryAttempt(state *persistedDeliveryState, identity protocol.NodePublicIdentity) error {
	if err := addDeliveryIdentity(state, identity); err != nil {
		return err
	}
	index := sort.SearchStrings(state.AttemptedNodeIDs, identity.NodeID)
	if index < len(state.AttemptedNodeIDs) && state.AttemptedNodeIDs[index] == identity.NodeID {
		return nil
	}
	if len(state.AttemptedNodeIDs) >= maxDeliveryNodes {
		return ErrInvalidDeliveryState
	}
	state.AttemptedNodeIDs = append(state.AttemptedNodeIDs, "")
	copy(state.AttemptedNodeIDs[index+1:], state.AttemptedNodeIDs[index:])
	state.AttemptedNodeIDs[index] = identity.NodeID
	return nil
}

func addDeliveryReceipt(state *persistedDeliveryState, identity protocol.NodePublicIdentity, receipt protocol.StorageReceipt, now time.Time) error {
	if err := addDeliveryIdentity(state, identity); err != nil {
		return err
	}
	if err := verifyStorageReceipt(identity, state.Delivery.Item, receipt, now); err != nil {
		return ErrInvalidDeliveryState
	}
	index := sort.Search(len(state.Delivery.Receipts), func(index int) bool {
		return state.Delivery.Receipts[index].NodeID >= receipt.NodeID
	})
	if index < len(state.Delivery.Receipts) && state.Delivery.Receipts[index].NodeID == receipt.NodeID {
		if receipt.StoredAt.After(state.Delivery.Receipts[index].StoredAt) {
			state.Delivery.Receipts[index] = cloneStorageReceipt(receipt)
		}
		return nil
	}
	if len(state.Delivery.Receipts) >= maxDeliveryNodes {
		return ErrInvalidDeliveryState
	}
	state.Delivery.Receipts = append(state.Delivery.Receipts, protocol.StorageReceipt{})
	copy(state.Delivery.Receipts[index+1:], state.Delivery.Receipts[index:])
	state.Delivery.Receipts[index] = cloneStorageReceipt(receipt)
	return nil
}

func validateDeliveryItemAndCapability(delivery Delivery, now time.Time, requireActive bool) error {
	if now.IsZero() || protocol.ValidateItem(delivery.Item, delivery.Item.CreatedAt, protocol.DefaultMaxItemBytes) != nil ||
		len(delivery.DeleteToken) != protocol.CapabilityBytes ||
		!bytes.Equal(delivery.Item.DeleteTokenHash, pqcrypto.DeleteTokenHash(delivery.DeleteToken)) {
		return ErrInvalidDeliveryState
	}
	if requireActive && !delivery.Item.ExpiresAt.After(now) {
		return ErrDeliveryExpired
	}
	if requireActive && delivery.Item.CreatedAt.After(now.Add(5*time.Minute)) {
		return ErrInvalidDeliveryState
	}
	return nil
}

func validatePersistedDeliveryState(record LocalRecord, state persistedDeliveryState, now time.Time, requireActive bool) error {
	if record.Version != ClientStoreVersion || record.ID != deliveryRecordID(state.Delivery.Item.ItemID) ||
		record.Kind != LocalKindDelivery || record.PrunePolicy != PruneAfterExpiry || state.Version != deliveryStateVersion ||
		len(state.NodeIdentities) > maxDeliveryNodes || len(state.AttemptedNodeIDs) > maxDeliveryNodes ||
		len(state.Delivery.Receipts) > maxDeliveryNodes || len(state.Delivery.FailedNodes) > MaxClientNodes {
		return ErrInvalidDeliveryState
	}
	if err := validateDeliveryItemAndCapability(state.Delivery, now, requireActive); err != nil {
		return err
	}
	createdAt := state.Delivery.Item.CreatedAt.UTC().Truncate(time.Millisecond)
	expiresAt := state.Delivery.Item.ExpiresAt.UTC().Truncate(time.Millisecond)
	if !record.CreatedAt.Equal(createdAt) || !record.ExpiresAt.Equal(expiresAt) {
		return ErrInvalidDeliveryState
	}
	identities := make(map[string]protocol.NodePublicIdentity, len(state.NodeIdentities))
	previous := ""
	for _, identity := range state.NodeIdentities {
		if !pqcrypto.ValidPublicIdentity(identity) || (previous != "" && identity.NodeID <= previous) {
			return ErrInvalidDeliveryState
		}
		previous = identity.NodeID
		identities[identity.NodeID] = identity
	}
	previous = ""
	for _, nodeID := range state.AttemptedNodeIDs {
		if (previous != "" && nodeID <= previous) || identities[nodeID].NodeID == "" {
			return ErrInvalidDeliveryState
		}
		previous = nodeID
	}
	previous = ""
	for _, receipt := range state.Delivery.Receipts {
		identity, ok := identities[receipt.NodeID]
		if !ok || (previous != "" && receipt.NodeID <= previous) ||
			verifyStorageReceipt(identity, state.Delivery.Item, receipt, now) != nil {
			return ErrInvalidDeliveryState
		}
		previous = receipt.NodeID
	}
	for nodeID, failure := range state.Delivery.FailedNodes {
		if identities[nodeID].NodeID == "" || len(failure) == 0 || len(failure) > maxDeliveryFailureTextByte {
			return ErrInvalidDeliveryState
		}
	}
	return nil
}

func (c *Core) mergeDeliveryIntoState(state *persistedDeliveryState, delivery Delivery, now time.Time) error {
	if state == nil {
		return ErrInvalidDeliveryState
	}
	if err := validateDeliveryItemAndCapability(delivery, now, true); err != nil {
		return err
	}
	if state.Version == 0 {
		state.Version = deliveryStateVersion
		state.Delivery = cloneDelivery(delivery)
		state.Delivery.Receipts = nil
		state.Delivery.FailedNodes = nil
	} else if state.Version != deliveryStateVersion || state.Delivery.Item.ItemID != delivery.Item.ItemID ||
		!bytes.Equal(state.Delivery.DeleteToken, delivery.DeleteToken) {
		return ErrInvalidDeliveryState
	}
	seen := make(map[string]struct{}, len(delivery.Receipts))
	identities := deliveryIdentityMap(*state)
	for _, receipt := range delivery.Receipts {
		if _, duplicate := seen[receipt.NodeID]; duplicate {
			return ErrInvalidDeliveryState
		}
		seen[receipt.NodeID] = struct{}{}
		identity, ok := identities[receipt.NodeID]
		if !ok {
			identity, ok = c.currentIdentity(receipt.NodeID)
		}
		if !ok {
			return ErrInvalidDeliveryState
		}
		if err := addDeliveryReceipt(state, identity, receipt, now); err != nil {
			return err
		}
		identities[identity.NodeID] = identity
	}
	return nil
}

func (c *Core) persistDeliveryState(ctx context.Context, state persistedDeliveryState, now time.Time) error {
	if c.store == nil {
		return nil
	}
	if ctx == nil || now.IsZero() {
		return ErrInvalidDeliveryState
	}
	state = clonePersistedDeliveryState(state)
	defer wipeDeliveryState(&state)
	// Validate against the exact record metadata before exposing any external
	// Store side effect. The encrypted store validates it again.
	record := LocalRecord{
		Version: ClientStoreVersion, ID: deliveryRecordID(state.Delivery.Item.ItemID), Kind: LocalKindDelivery,
		CreatedAt: state.Delivery.Item.CreatedAt.UTC().Truncate(time.Millisecond),
		UpdatedAt: now.UTC().Truncate(time.Millisecond), ExpiresAt: state.Delivery.Item.ExpiresAt.UTC().Truncate(time.Millisecond),
		PrunePolicy: PruneAfterExpiry,
	}
	if record.UpdatedAt.Before(record.CreatedAt) {
		record.UpdatedAt = record.CreatedAt
	}
	if err := validatePersistedDeliveryState(record, state, now, true); err != nil {
		return err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer zero(encoded)
	record.Payload = encoded
	_, err = c.store.Put(ctx, record, now)
	return err
}

func (c *Core) loadDeliveryState(ctx context.Context, itemID string, now time.Time, requireActive bool) (persistedDeliveryState, error) {
	if c == nil || c.store == nil || ctx == nil || !validItemID(itemID) || now.IsZero() {
		return persistedDeliveryState{}, errors.New("persistent client store is unavailable")
	}
	record, err := c.store.Get(ctx, deliveryRecordID(itemID))
	if err != nil {
		return persistedDeliveryState{}, err
	}
	defer zero(record.Payload)
	if err := validateLocalRecord(record, now); err != nil {
		return persistedDeliveryState{}, ErrInvalidDeliveryState
	}
	var state persistedDeliveryState
	if err := decodeStrictJSON(record.Payload, &state); err != nil {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, err
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, err
	}
	canonicalEncoding := bytes.Equal(canonical, record.Payload)
	zero(canonical)
	if !canonicalEncoding {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, ErrInvalidDeliveryState
	}
	if state.Delivery.Item.ItemID != itemID {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, ErrInvalidDeliveryState
	}
	if err := validatePersistedDeliveryState(record, state, now, requireActive); err != nil {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, err
	}
	return state, nil
}

func validateDeliveryStateInMemory(state persistedDeliveryState, now time.Time, requireActive bool) error {
	record := LocalRecord{
		Version: ClientStoreVersion, ID: deliveryRecordID(state.Delivery.Item.ItemID), Kind: LocalKindDelivery,
		CreatedAt: state.Delivery.Item.CreatedAt.UTC().Truncate(time.Millisecond),
		UpdatedAt: now.UTC().Truncate(time.Millisecond), ExpiresAt: state.Delivery.Item.ExpiresAt.UTC().Truncate(time.Millisecond),
		PrunePolicy: PruneAfterExpiry,
	}
	if record.UpdatedAt.Before(record.CreatedAt) {
		record.UpdatedAt = record.CreatedAt
	}
	return validatePersistedDeliveryState(record, state, now, requireActive)
}

// deliveryStateForOperationLocked always starts from the authenticated local
// record when one exists, then adds (but never removes) valid receipts supplied
// by a caller. Production callers persist that merged canonical state before
// any proof, repair, or deletion request leaves the process.
func (c *Core) deliveryStateForOperationLocked(ctx context.Context, delivery Delivery, now time.Time, persist bool) (persistedDeliveryState, error) {
	if c == nil || ctx == nil {
		return persistedDeliveryState{}, ErrInvalidDeliveryState
	}
	var state persistedDeliveryState
	if c.store != nil {
		loaded, err := c.loadDeliveryState(ctx, delivery.Item.ItemID, now, true)
		if err == nil {
			state = loaded
		} else if !errors.Is(err, ErrLocalRecordNotFound) {
			return persistedDeliveryState{}, err
		}
	}
	if err := c.mergeDeliveryIntoState(&state, delivery, now); err != nil {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, err
	}
	identities := deliveryIdentityMap(state)
	for _, receipt := range state.Delivery.Receipts {
		identity := identities[receipt.NodeID]
		if err := addDeliveryAttempt(&state, identity); err != nil {
			wipeDeliveryState(&state)
			return persistedDeliveryState{}, err
		}
	}
	if err := validateDeliveryStateInMemory(state, now, true); err != nil {
		wipeDeliveryState(&state)
		return persistedDeliveryState{}, err
	}
	if persist && c.store != nil {
		if err := c.persistDeliveryState(ctx, state, now); err != nil {
			wipeDeliveryState(&state)
			return persistedDeliveryState{}, err
		}
	}
	return state, nil
}

func deliveryTargetNodeIDs(state persistedDeliveryState) []string {
	targets := append([]string(nil), state.AttemptedNodeIDs...)
	for _, receipt := range state.Delivery.Receipts {
		index := sort.SearchStrings(targets, receipt.NodeID)
		if index < len(targets) && targets[index] == receipt.NodeID {
			continue
		}
		targets = append(targets, "")
		copy(targets[index+1:], targets[index:])
		targets[index] = receipt.NodeID
	}
	return targets
}

func pruneUnreferencedDeliveryIdentities(state *persistedDeliveryState) {
	if state == nil {
		return
	}
	referenced := make(map[string]struct{}, len(state.AttemptedNodeIDs)+len(state.Delivery.Receipts)+len(state.Delivery.FailedNodes))
	for _, nodeID := range state.AttemptedNodeIDs {
		referenced[nodeID] = struct{}{}
	}
	for _, receipt := range state.Delivery.Receipts {
		referenced[receipt.NodeID] = struct{}{}
	}
	for nodeID := range state.Delivery.FailedNodes {
		referenced[nodeID] = struct{}{}
	}
	identities := state.NodeIdentities[:0]
	for _, identity := range state.NodeIdentities {
		if _, keep := referenced[identity.NodeID]; keep {
			identities = append(identities, identity)
		} else {
			zero(identity.Ed25519Public)
			zero(identity.MLDSA65Public)
		}
	}
	state.NodeIdentities = identities
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameReceiptSet(left, right []protocol.StorageReceipt) bool {
	if len(left) != len(right) {
		return false
	}
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	defer zero(leftJSON)
	defer zero(rightJSON)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func cloneNodeIDSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for nodeID := range source {
		result[nodeID] = struct{}{}
	}
	return result
}

func boundedDeliveryFailure(err error) string {
	if err == nil {
		return "node operation failed"
	}
	message := err.Error()
	if len(message) == 0 || len(message) > maxDeliveryFailureTextByte {
		return "node operation failed"
	}
	return message
}
