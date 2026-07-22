package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"sync"
	"time"

	"propagare/pqcrypto"
	"propagare/protocol"
)

type Config struct {
	Nodes       []*HTTPNode
	Replicas    int
	WriteQuorum int
	Reputation  *Reputation
	Store       ClientStore
}

const MaxClientNodes = 64

type Core struct {
	nodes       []*HTTPNode
	replicas    int
	writeQuorum int
	reputation  *Reputation
	store       ClientStore
}

type Delivery struct {
	Item        protocol.StoredItem       `json:"item"`
	DeleteToken []byte                    `json:"delete_token"`
	Receipts    []protocol.StorageReceipt `json:"receipts"`
	FailedNodes map[string]string         `json:"failed_nodes,omitempty"`
}

func New(config Config) (*Core, error) {
	if len(config.Nodes) == 0 || len(config.Nodes) > MaxClientNodes {
		return nil, errors.New("at least one node is required")
	}
	seenNodes := make(map[string]struct{}, len(config.Nodes))
	for _, candidate := range config.Nodes {
		if candidate == nil || candidate.Client == nil || !pqcrypto.ValidPublicIdentity(candidate.Identity) {
			return nil, errors.New("invalid node descriptor")
		}
		if _, duplicate := seenNodes[candidate.Identity.NodeID]; duplicate {
			return nil, errors.New("duplicate node identity")
		}
		seenNodes[candidate.Identity.NodeID] = struct{}{}
	}
	if config.Replicas <= 0 || config.Replicas > len(config.Nodes) {
		config.Replicas = len(config.Nodes)
	}
	if config.WriteQuorum <= 0 {
		config.WriteQuorum = config.Replicas/2 + 1
	}
	if config.WriteQuorum > config.Replicas {
		return nil, errors.New("write quorum exceeds replica count")
	}
	if config.Reputation == nil {
		config.Reputation = NewReputation()
	}
	return &Core{
		nodes:       append([]*HTTPNode(nil), config.Nodes...),
		replicas:    config.Replicas,
		writeQuorum: config.WriteQuorum,
		reputation:  config.Reputation,
		store:       config.Store,
	}, nil
}

func RandomCapability() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func RandomDeleteToken() ([]byte, error) {
	value := make([]byte, 32)
	_, err := rand.Read(value)
	return value, err
}

func directAAD(routeTag string, createdAt, expiresAt time.Time) []byte {
	return []byte(fmt.Sprintf("enig/direct/v1\x00%s\x00%d\x00%d", routeTag, createdAt.UTC().UnixMilli(), expiresAt.UTC().UnixMilli()))
}

// SendDirect is a development/bootstrap envelope. It does not provide a
// message ratchet, forward secrecy, post-compromise security, or metadata
// anonymity. Production messaging must use message.StrictPipeline with audited
// providers. Every stored item lives for exactly the fixed protocol retention
// window; earlier removal requires the delete capability.
func (c *Core) SendDirect(ctx context.Context, recipientHPKEPublicKey []byte, routeTag string, plaintext []byte) (Delivery, error) {
	if routeTag == "" {
		var err error
		routeTag, err = RandomCapability()
		if err != nil {
			return Delivery{}, err
		}
	}
	if !protocol.ValidRouteTag(routeTag) {
		return Delivery{}, errors.New("invalid route capability")
	}
	if err := pqcrypto.ValidateHybridKEMPublicKey(recipientHPKEPublicKey); err != nil {
		return Delivery{}, errors.New("invalid recipient HPKE public key")
	}
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt := createdAt.Add(protocol.FixedItemRetention)
	padded, err := pqcrypto.PadMessage(plaintext)
	if err != nil {
		return Delivery{}, err
	}
	defer zero(padded)
	encapsulation, ciphertext, err := pqcrypto.Seal(recipientHPKEPublicKey, directAAD(routeTag, createdAt, expiresAt), padded)
	if err != nil {
		return Delivery{}, err
	}
	payload, err := json.Marshal(protocol.DirectCiphertext{
		Suite:         pqcrypto.HybridHPKESuite,
		Encapsulation: encapsulation,
		Ciphertext:    ciphertext,
	})
	if err != nil {
		return Delivery{}, err
	}
	deleteToken, err := RandomDeleteToken()
	if err != nil {
		return Delivery{}, err
	}
	item := protocol.StoredItem{
		Version:         protocol.ProtocolVersion,
		RouteTag:        routeTag,
		CreatedAt:       createdAt,
		ExpiresAt:       expiresAt,
		DeleteTokenHash: pqcrypto.DeleteTokenHash(deleteToken),
		Payload:         payload,
	}
	item.ItemID = protocol.ComputeItemID(item)
	return c.StoreReplicated(ctx, item, deleteToken)
}

// StoreOpaque stores data that is already end-to-end encrypted, for example a
// fixed-size encrypted file chunk. The node never receives the delete token.
// The item expires exactly after the fixed protocol retention window.
func (c *Core) StoreOpaque(ctx context.Context, routeTag string, encryptedPayload, deleteToken []byte) (Delivery, error) {
	if !protocol.ValidRouteTag(routeTag) || len(encryptedPayload) == 0 ||
		len(encryptedPayload) > protocol.DefaultMaxItemBytes || len(deleteToken) != protocol.CapabilityBytes {
		return Delivery{}, errors.New("invalid opaque item capabilities")
	}
	createdAt := time.Now().UTC().Truncate(time.Millisecond)
	item := protocol.StoredItem{
		Version:         protocol.ProtocolVersion,
		RouteTag:        routeTag,
		CreatedAt:       createdAt,
		ExpiresAt:       createdAt.Add(protocol.FixedItemRetention),
		DeleteTokenHash: pqcrypto.DeleteTokenHash(deleteToken),
		Payload:         append([]byte(nil), encryptedPayload...),
	}
	item.ItemID = protocol.ComputeItemID(item)
	return c.StoreReplicated(ctx, item, deleteToken)
}

func OpenDirectItem(privateHPKEKey []byte, item protocol.StoredItem) ([]byte, error) {
	if err := protocol.ValidateItem(item, item.CreatedAt, protocol.DefaultMaxItemBytes); err != nil {
		return nil, protocol.ErrInvalidItem
	}
	var sealed protocol.DirectCiphertext
	if err := decodeStrictJSON(item.Payload, &sealed); err != nil {
		return nil, err
	}
	if sealed.Suite != pqcrypto.HybridHPKESuite || len(sealed.Encapsulation) == 0 ||
		len(sealed.Ciphertext) == 0 || len(sealed.Ciphertext) > protocol.DefaultMaxItemBytes {
		return nil, errors.New("unsupported direct-message cipher suite")
	}
	padded, err := pqcrypto.Open(privateHPKEKey, sealed.Encapsulation, directAAD(item.RouteTag, item.CreatedAt, item.ExpiresAt), sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	return pqcrypto.UnpadMessage(padded)
}

func (c *Core) StoreReplicated(ctx context.Context, item protocol.StoredItem, deleteToken []byte) (Delivery, error) {
	now := time.Now().UTC()
	if err := protocol.ValidateItem(item, now, protocol.DefaultMaxItemBytes); err != nil {
		return Delivery{}, err
	}
	if len(deleteToken) != protocol.CapabilityBytes ||
		!bytes.Equal(item.DeleteTokenHash, pqcrypto.DeleteTokenHash(deleteToken)) {
		return Delivery{}, errors.New("delete capability does not match item")
	}
	candidates := c.allowedNodes()
	if len(candidates) < c.writeQuorum {
		return Delivery{}, errors.New("not enough non-excluded nodes for write quorum")
	}
	delivery := Delivery{DeleteToken: append([]byte(nil), deleteToken...), FailedNodes: make(map[string]string)}
	type nodeParameters struct {
		node       *HTTPNode
		parameters protocol.NodeParameters
	}
	groups := make(map[int64][]nodeParameters)
	type parameterResult struct {
		node       *HTTPNode
		parameters protocol.NodeParameters
		err        error
	}
	parameterResults := make(chan parameterResult, len(candidates))
	var parameterWG sync.WaitGroup
	for _, n := range candidates {
		parameterWG.Add(1)
		go func(node *HTTPNode) {
			defer parameterWG.Done()
			parameters, err := node.Parameters(ctx)
			parameterResults <- parameterResult{node: node, parameters: parameters, err: err}
		}(n)
	}
	parameterWG.Wait()
	close(parameterResults)
	for result := range parameterResults {
		n, parameters, err := result.node, result.parameters, result.err
		if err != nil {
			c.reputation.Failure(n.Identity.NodeID, err)
			delivery.FailedNodes[n.Identity.NodeID] = err.Error()
			continue
		}
		if len(item.Payload) > parameters.MaxItemBytes {
			err := errors.New("item violates node limits")
			delivery.FailedNodes[n.Identity.NodeID] = err.Error()
			continue
		}
		groups[parameters.EpochSeconds] = append(groups[parameters.EpochSeconds], nodeParameters{node: n, parameters: parameters})
	}
	var selected []nodeParameters
	var epochSeconds int64
	var selectedThreshold uint8
	for epoch, group := range groups {
		if len(group) < c.writeQuorum {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].parameters.Difficulty == group[j].parameters.Difficulty {
				return group[i].node.Identity.NodeID < group[j].node.Identity.NodeID
			}
			return group[i].parameters.Difficulty < group[j].parameters.Difficulty
		})
		threshold := group[c.writeQuorum-1].parameters.Difficulty
		if len(group) > len(selected) || (len(group) == len(selected) && (selected == nil || threshold < selectedThreshold)) {
			selected = group
			epochSeconds = epoch
			selectedThreshold = threshold
		}
	}
	if len(selected) < c.writeQuorum {
		return Delivery{}, errors.New("could not obtain node parameters")
	}
	usable := make([]*HTTPNode, 0, len(selected))
	for _, candidate := range selected {
		if candidate.parameters.Difficulty <= selectedThreshold {
			usable = append(usable, candidate.node)
		}
	}
	work, err := protocol.SolveWork(ctx, item, epochSeconds, selectedThreshold)
	if err != nil {
		return Delivery{}, err
	}
	item.Work = work
	delivery.Item = item

	type result struct {
		node    *HTTPNode
		receipt protocol.StorageReceipt
		err     error
	}
	primaryCount := min(c.replicas, len(usable))
	primary := usable[:primaryCount]
	results := make(chan result, len(primary))
	var wg sync.WaitGroup
	for _, n := range primary {
		wg.Add(1)
		go func(node *HTTPNode) {
			defer wg.Done()
			receipt, err := node.Store(ctx, item)
			results <- result{node: node, receipt: receipt, err: err}
		}(n)
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			c.reputation.Failure(result.node.Identity.NodeID, result.err)
			delivery.FailedNodes[result.node.Identity.NodeID] = result.err.Error()
			continue
		}
		c.reputation.Success(result.node.Identity.NodeID, false)
		delivery.Receipts = append(delivery.Receipts, result.receipt)
	}
	// Failed primary nodes are replaced by later candidates. This is the core
	// repair behavior: a signed receipt is required before a replica counts.
	for _, n := range usable[primaryCount:] {
		if len(delivery.Receipts) >= c.replicas {
			break
		}
		receipt, err := n.Store(ctx, item)
		if err != nil {
			c.reputation.Failure(n.Identity.NodeID, err)
			delivery.FailedNodes[n.Identity.NodeID] = err.Error()
			continue
		}
		c.reputation.Success(n.Identity.NodeID, false)
		delivery.Receipts = append(delivery.Receipts, receipt)
	}
	if len(delivery.Receipts) < c.writeQuorum {
		writeErr := fmt.Errorf("write quorum not reached: got %d of %d receipts", len(delivery.Receipts), c.writeQuorum)
		if len(delivery.Receipts) > 0 {
			if persistErr := c.persistDelivery(ctx, delivery, time.Now().UTC()); persistErr != nil {
				writeErr = errors.Join(writeErr, persistErr)
			}
		}
		return delivery, writeErr
	}
	if err := c.persistDelivery(ctx, delivery, time.Now().UTC()); err != nil {
		return delivery, fmt.Errorf("persist delivery state: %w", err)
	}
	return delivery, nil
}

func (c *Core) Fetch(ctx context.Context, routeTags []string) ([]protocol.StoredItem, error) {
	if len(routeTags) == 0 || len(routeTags) > protocol.MaxRouteTagsPerFetch {
		return nil, errors.New("route tag count out of range")
	}
	requested := make(map[string]struct{}, len(routeTags))
	for _, routeTag := range routeTags {
		if !protocol.ValidRouteTag(routeTag) {
			return nil, errors.New("invalid route tag")
		}
		if _, duplicate := requested[routeTag]; duplicate {
			return nil, errors.New("duplicate route tag")
		}
		requested[routeTag] = struct{}{}
	}
	seen := make(map[string]protocol.StoredItem)
	var totalBytes int64
	var lastErr error
	var successfulFetch bool
	for _, n := range c.allowedNodes() {
		items, err := n.Fetch(ctx, routeTags)
		if err != nil {
			c.reputation.Failure(n.Identity.NodeID, err)
			lastErr = err
			continue
		}
		responseValid := true
		if len(items) > protocol.DefaultMaxFetchItems {
			lastErr = errors.New("node returned too many fetch items")
			c.reputation.Failure(n.Identity.NodeID, lastErr)
			continue
		}
		for _, item := range items {
			if _, asked := requested[item.RouteTag]; !asked ||
				protocol.ValidateItem(item, time.Now(), protocol.DefaultMaxItemBytes) != nil {
				responseValid = false
				continue
			}
			if _, duplicate := seen[item.ItemID]; !duplicate {
				if len(seen) >= protocol.DefaultMaxFetchItems {
					return nil, errors.New("combined fetch result exceeds item limit")
				}
				if totalBytes+int64(len(item.Payload)) > protocol.DefaultMaxFetchBytes {
					return nil, errors.New("combined fetch result exceeds size limit")
				}
				seen[item.ItemID] = item
				totalBytes += int64(len(item.Payload))
			}
		}
		if responseValid {
			successfulFetch = true
		} else {
			lastErr = errors.New("node returned an invalid fetch item")
			c.reputation.Failure(n.Identity.NodeID, lastErr)
		}
	}
	result := make([]protocol.StoredItem, 0, len(seen))
	for _, item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	if !successfulFetch && lastErr != nil {
		return nil, lastErr
	}
	return result, nil
}

func (c *Core) Audit(ctx context.Context, delivery Delivery) map[string]error {
	results := make(map[string]error)
	payloadHash := sha256.Sum256(delivery.Item.Payload)
	for _, receipt := range delivery.Receipts {
		n := c.nodeByID(receipt.NodeID)
		if n == nil {
			continue
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			results[n.Identity.NodeID] = err
			continue
		}
		sampleLength := min(4096, len(delivery.Item.Payload))
		offset, err := randomProofOffset(rand.Reader, len(delivery.Item.Payload), sampleLength)
		if err != nil {
			results[n.Identity.NodeID] = err
			continue
		}
		request := protocol.ProofRequest{ItemID: delivery.Item.ItemID, Nonce: nonce, Offset: offset, Length: sampleLength}
		proof, err := n.Prove(ctx, request)
		if err == nil {
			end := offset + int64(len(proof.Sample))
			if end > int64(len(delivery.Item.Payload)) || !bytes.Equal(proof.Sample, delivery.Item.Payload[offset:end]) || !bytes.Equal(proof.PayloadHash, payloadHash[:]) {
				err = errors.New("node returned incorrect stored bytes")
				c.reputation.Exclude(n.Identity.NodeID, 24*time.Hour, err)
			}
		}
		results[n.Identity.NodeID] = err
		if err != nil {
			if c.reputation.Allowed(n.Identity.NodeID, time.Now()) {
				c.reputation.Failure(n.Identity.NodeID, err)
			}
		} else {
			c.reputation.Success(n.Identity.NodeID, true)
		}
	}
	return results
}

func randomProofOffset(reader io.Reader, payloadBytes, sampleBytes int) (int64, error) {
	if reader == nil || payloadBytes <= 0 || sampleBytes <= 0 || sampleBytes > payloadBytes {
		return 0, errors.New("invalid proof sample bounds")
	}
	maxStart := int64(payloadBytes - sampleBytes)
	if maxStart == 0 {
		return 0, nil
	}
	value, err := rand.Int(reader, big.NewInt(maxStart+1))
	if err != nil {
		return 0, err
	}
	return value.Int64(), nil
}

// AuditAndRepair verifies each acknowledged replica and rewrites the same
// ciphertext to replacement nodes when any replica no longer proves storage.
// The caller must persist the returned Delivery because it contains the new
// receipt set and a fresh proof-of-work epoch.
func (c *Core) AuditAndRepair(ctx context.Context, delivery Delivery) (Delivery, map[string]error, error) {
	audit := c.Audit(ctx, delivery)
	needsRepair := false
	for _, err := range audit {
		if err != nil {
			needsRepair = true
			break
		}
	}
	if !needsRepair {
		return delivery, audit, nil
	}
	repaired, err := c.StoreReplicated(ctx, delivery.Item, delivery.DeleteToken)
	return repaired, audit, err
}

func (c *Core) Delete(ctx context.Context, delivery Delivery) map[string]error {
	results := make(map[string]error)
	if len(delivery.DeleteToken) != protocol.CapabilityBytes ||
		!bytes.Equal(delivery.Item.DeleteTokenHash, pqcrypto.DeleteTokenHash(delivery.DeleteToken)) {
		err := errors.New("invalid delete capability")
		for _, receipt := range delivery.Receipts {
			results[receipt.NodeID] = err
		}
		return results
	}
	allDeleted := len(delivery.Receipts) > 0
	for _, receipt := range delivery.Receipts {
		n := c.nodeByID(receipt.NodeID)
		if n == nil {
			allDeleted = false
			continue
		}
		_, err := n.Delete(ctx, protocol.DeleteRequest{ItemID: delivery.Item.ItemID, DeleteToken: delivery.DeleteToken})
		results[n.Identity.NodeID] = err
		if err != nil {
			allDeleted = false
			c.reputation.Failure(n.Identity.NodeID, err)
		}
	}
	if allDeleted && c.store != nil {
		if err := c.store.Delete(ctx, deliveryRecordID(delivery.Item.ItemID)); err != nil && !errors.Is(err, ErrLocalRecordNotFound) {
			results["local-client-store"] = err
		}
	}
	return results
}

func (c *Core) DeleteItemEverywhere(ctx context.Context, itemID string, deleteToken []byte) map[string]error {
	results := make(map[string]error)
	if len(deleteToken) != protocol.CapabilityBytes || len(itemID) != sha256.Size*2 {
		err := errors.New("invalid delete request")
		for _, n := range c.nodes {
			results[n.Identity.NodeID] = err
		}
		return results
	}
	for _, n := range c.nodes {
		_, err := n.Delete(ctx, protocol.DeleteRequest{ItemID: itemID, DeleteToken: deleteToken})
		results[n.Identity.NodeID] = err
	}
	return results
}

func (c *Core) allowedNodes() []*HTTPNode {
	now := time.Now()
	result := make([]*HTTPNode, 0, len(c.nodes))
	for _, n := range c.nodes {
		if c.reputation.Allowed(n.Identity.NodeID, now) {
			result = append(result, n)
		}
	}
	return result
}

func (c *Core) nodeByID(nodeID string) *HTTPNode {
	for _, n := range c.nodes {
		if n.Identity.NodeID == nodeID {
			return n
		}
	}
	return nil
}

func (c *Core) Reputation() []NodeScore { return c.reputation.Snapshot() }

func deliveryRecordID(itemID string) string { return "delivery." + itemID }

func (c *Core) persistDelivery(ctx context.Context, delivery Delivery, now time.Time) error {
	if c.store == nil {
		return nil
	}
	encoded, err := json.Marshal(delivery)
	if err != nil {
		return err
	}
	defer zero(encoded)
	updatedAt := now
	if updatedAt.Before(delivery.Item.CreatedAt) {
		updatedAt = delivery.Item.CreatedAt
	}
	_, err = c.store.Put(ctx, LocalRecord{
		Version: ClientStoreVersion, ID: deliveryRecordID(delivery.Item.ItemID), Kind: LocalKindDelivery,
		CreatedAt: delivery.Item.CreatedAt, UpdatedAt: updatedAt, ExpiresAt: delivery.Item.ExpiresAt,
		PrunePolicy: PruneAfterExpiry, Payload: encoded,
	}, now)
	return err
}

// LoadDelivery restores authenticated repair/deletion state after a restart.
// The encrypted local record and every hybrid node receipt are verified again
// before the delete capability is returned to the caller.
func (c *Core) LoadDelivery(ctx context.Context, itemID string, now time.Time) (Delivery, error) {
	if c == nil || c.store == nil || len(itemID) != sha256.Size*2 || now.IsZero() {
		return Delivery{}, errors.New("persistent client store is unavailable")
	}
	record, err := c.store.Get(ctx, deliveryRecordID(itemID))
	if err != nil {
		return Delivery{}, err
	}
	defer zero(record.Payload)
	if record.Version != ClientStoreVersion || record.ID != deliveryRecordID(itemID) ||
		record.Kind != LocalKindDelivery || record.PrunePolicy != PruneAfterExpiry {
		return Delivery{}, errors.New("invalid persisted delivery record")
	}
	var delivery Delivery
	wipeDelivery := func() {
		zero(delivery.DeleteToken)
		zero(delivery.Item.Payload)
	}
	if err := decodeStrictJSON(record.Payload, &delivery); err != nil {
		wipeDelivery()
		return Delivery{}, err
	}
	if delivery.Item.ItemID != itemID ||
		protocol.ValidateItem(delivery.Item, now, protocol.DefaultMaxItemBytes) != nil ||
		!record.CreatedAt.Equal(delivery.Item.CreatedAt) || !record.ExpiresAt.Equal(delivery.Item.ExpiresAt) ||
		len(delivery.DeleteToken) != protocol.CapabilityBytes ||
		!bytes.Equal(delivery.Item.DeleteTokenHash, pqcrypto.DeleteTokenHash(delivery.DeleteToken)) {
		wipeDelivery()
		return Delivery{}, errors.New("invalid persisted delivery state")
	}
	seen := make(map[string]struct{}, len(delivery.Receipts))
	for _, receipt := range delivery.Receipts {
		node := c.nodeByID(receipt.NodeID)
		if node == nil {
			wipeDelivery()
			return Delivery{}, errors.New("persisted receipt references an unknown node")
		}
		if _, duplicate := seen[receipt.NodeID]; duplicate {
			wipeDelivery()
			return Delivery{}, errors.New("persisted delivery contains duplicate receipts")
		}
		seen[receipt.NodeID] = struct{}{}
		if err := verifyStorageReceipt(node.Identity, delivery.Item, receipt, now); err != nil {
			wipeDelivery()
			return Delivery{}, err
		}
	}
	return delivery, nil
}

func (c *Core) ClientStorageUsage() (ClientStorageUsage, bool) {
	if c == nil || c.store == nil {
		return ClientStorageUsage{}, false
	}
	return c.store.Usage(), true
}

func (c *Core) SetClientStorageLimit(ctx context.Context, maxBytes int64, now time.Time) (PruneReport, error) {
	if c == nil || c.store == nil {
		return PruneReport{}, errors.New("persistent client store is unavailable")
	}
	return c.store.SetLimit(ctx, maxBytes, now)
}

func (c *Core) PruneClientStorage(ctx context.Context, targetBytes int64, now time.Time) (PruneReport, error) {
	if c == nil || c.store == nil {
		return PruneReport{}, errors.New("persistent client store is unavailable")
	}
	return c.store.PruneTo(ctx, targetBytes, now)
}

func (c *Core) Close() error {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.Close()
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON input must contain exactly one value")
	}
	return nil
}
