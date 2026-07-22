package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
)

type Config struct {
	Nodes       []*HTTPNode
	Replicas    int
	WriteQuorum int
	Reputation  *Reputation
	Store       ClientStore
}

const MaxClientNodes = 64

const (
	MaxPendingDeliveryPage = 256
	deliveryAuditStateKey  = "delivery-state"
)

var (
	ErrInvalidDeliveryState = errors.New("invalid delivery state")
	ErrNoAllowedNodes       = errors.New("no non-excluded node is available")
)

type Core struct {
	nodes         []*HTTPNode
	replicas      int
	writeQuorum   int
	reputation    *Reputation
	store         ClientStore
	deliveryLocks [64]sync.Mutex
}

type Delivery struct {
	Item        protocol.StoredItem       `json:"item"`
	DeleteToken []byte                    `json:"delete_token"`
	Receipts    []protocol.StorageReceipt `json:"receipts"`
	FailedNodes map[string]string         `json:"failed_nodes,omitempty"`
}

func New(config Config) (*Core, error) {
	if config.Store == nil {
		return nil, errors.New("persistent client store is required")
	}
	return newCore(config, false)
}

// NewEphemeralForDevelopment explicitly opts out of durable repair and delete
// capability recovery. It is intended only for tests and private development.
func NewEphemeralForDevelopment(config Config) (*Core, error) {
	if config.Store != nil {
		return nil, errors.New("ephemeral development core does not accept a persistent store")
	}
	return newCore(config, true)
}

func newCore(config Config, ephemeral bool) (*Core, error) {
	if len(config.Nodes) == 0 || len(config.Nodes) > MaxClientNodes {
		return nil, errors.New("at least one node is required")
	}
	if !ephemeral && config.Store == nil {
		return nil, errors.New("persistent client store is required")
	}
	seenNodes := make(map[string]struct{}, len(config.Nodes))
	nodes := make([]*HTTPNode, 0, len(config.Nodes))
	for _, candidate := range config.Nodes {
		copyNode, err := cloneOperationalHTTPNode(candidate)
		if err != nil {
			return nil, errors.New("invalid node descriptor")
		}
		if _, duplicate := seenNodes[copyNode.identity.NodeID]; duplicate {
			return nil, errors.New("duplicate node identity")
		}
		seenNodes[copyNode.identity.NodeID] = struct{}{}
		nodes = append(nodes, copyNode)
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
		nodes:       nodes,
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
	if c == nil || ctx == nil {
		return Delivery{}, errors.New("client core and context are required")
	}
	if err := protocol.ValidateItem(item, now, protocol.DefaultMaxItemBytes); err != nil {
		return Delivery{}, err
	}
	if len(deleteToken) != protocol.CapabilityBytes ||
		!bytes.Equal(item.DeleteTokenHash, pqcrypto.DeleteTokenHash(deleteToken)) {
		return Delivery{}, errors.New("delete capability does not match item")
	}
	unlock := c.lockDelivery(item.ItemID)
	defer unlock()
	return c.storeReplicatedLocked(ctx, item, deleteToken, nil, nil)
}

func (c *Core) storeReplicatedLocked(
	ctx context.Context,
	item protocol.StoredItem,
	deleteToken []byte,
	baseState *persistedDeliveryState,
	countedReceiptNodes map[string]struct{},
) (Delivery, error) {
	now := time.Now().UTC()
	var state persistedDeliveryState
	if baseState != nil {
		state = clonePersistedDeliveryState(*baseState)
	} else if c.store != nil {
		loaded, err := c.loadDeliveryState(ctx, item.ItemID, now, true)
		if err == nil {
			state = loaded
		} else if !errors.Is(err, ErrLocalRecordNotFound) {
			return Delivery{}, err
		}
	}
	defer wipeDeliveryState(&state)
	if err := c.mergeDeliveryIntoState(&state, Delivery{Item: item, DeleteToken: deleteToken}, now); err != nil {
		return Delivery{}, err
	}
	state.Delivery.FailedNodes = make(map[string]string)
	pruneUnreferencedDeliveryIdentities(&state)
	if countedReceiptNodes == nil {
		countedReceiptNodes = make(map[string]struct{}, len(state.Delivery.Receipts))
		for _, receipt := range state.Delivery.Receipts {
			countedReceiptNodes[receipt.NodeID] = struct{}{}
		}
	} else {
		countedReceiptNodes = cloneNodeIDSet(countedReceiptNodes)
	}
	if len(countedReceiptNodes) >= c.replicas {
		if err := c.persistDeliveryState(ctx, state, now); err != nil {
			return cloneDelivery(state.Delivery), err
		}
		return cloneDelivery(state.Delivery), nil
	}
	candidates := c.allowedNodes()
	requiredNew := c.writeQuorum - len(countedReceiptNodes)
	if requiredNew < 1 {
		requiredNew = 1
	}
	if len(candidates) < requiredNew {
		return cloneDelivery(state.Delivery), errors.New("not enough non-excluded nodes for write quorum")
	}
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
			if localContextTermination(ctx, err) {
				return cloneDelivery(state.Delivery), ctx.Err()
			}
			c.reputation.Failure(n.identity.NodeID, err)
			if identityErr := addDeliveryIdentity(&state, n.identity); identityErr != nil {
				return cloneDelivery(state.Delivery), identityErr
			}
			state.Delivery.FailedNodes[n.identity.NodeID] = boundedDeliveryFailure(err)
			continue
		}
		if len(item.Payload) > parameters.MaxItemBytes {
			err := errors.New("item violates node limits")
			if identityErr := addDeliveryIdentity(&state, n.identity); identityErr != nil {
				return cloneDelivery(state.Delivery), identityErr
			}
			state.Delivery.FailedNodes[n.identity.NodeID] = boundedDeliveryFailure(err)
			continue
		}
		if _, alreadyCounted := countedReceiptNodes[n.identity.NodeID]; alreadyCounted {
			continue
		}
		groups[parameters.EpochSeconds] = append(groups[parameters.EpochSeconds], nodeParameters{node: n, parameters: parameters})
	}
	var selected []nodeParameters
	var epochSeconds int64
	var selectedThreshold uint8
	for epoch, group := range groups {
		if len(group) < requiredNew {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].parameters.Difficulty == group[j].parameters.Difficulty {
				return group[i].node.identity.NodeID < group[j].node.identity.NodeID
			}
			return group[i].parameters.Difficulty < group[j].parameters.Difficulty
		})
		threshold := group[requiredNew-1].parameters.Difficulty
		if len(group) > len(selected) ||
			(len(group) == len(selected) && (selected == nil || threshold < selectedThreshold ||
				(threshold == selectedThreshold && epoch < epochSeconds))) {
			selected = group
			epochSeconds = epoch
			selectedThreshold = threshold
		}
	}
	if len(selected) < requiredNew {
		return cloneDelivery(state.Delivery), errors.New("could not obtain node parameters")
	}
	usable := make([]*HTTPNode, 0, len(selected))
	for _, candidate := range selected {
		if candidate.parameters.Difficulty <= selectedThreshold {
			usable = append(usable, candidate.node)
		}
	}
	if len(usable) < requiredNew {
		return cloneDelivery(state.Delivery), errors.New("could not obtain enough independent node parameters")
	}
	work, err := protocol.SolveWork(ctx, item, epochSeconds, selectedThreshold)
	if err != nil {
		return cloneDelivery(state.Delivery), err
	}
	item.Work = work
	state.Delivery.Item = cloneStoredItem(item)

	type result struct {
		node    *HTTPNode
		receipt protocol.StorageReceipt
		err     error
	}
	neededReplicas := c.replicas - len(countedReceiptNodes)
	primaryCount := min(neededReplicas, len(usable))
	primary := usable[:primaryCount]
	// Persist both the capability and every potential target before launching
	// concurrent Store calls. A crash or lost response can therefore be safely
	// recovered even when no receipt reached the caller.
	for _, node := range primary {
		if err := addDeliveryAttempt(&state, node.identity); err != nil {
			return cloneDelivery(state.Delivery), err
		}
	}
	if err := c.persistDeliveryState(ctx, state, time.Now().UTC()); err != nil {
		return cloneDelivery(state.Delivery), fmt.Errorf("persist pending delivery before store: %w", err)
	}
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
			if localContextTermination(ctx, result.err) {
				return cloneDelivery(state.Delivery), ctx.Err()
			}
			c.reputation.Failure(result.node.identity.NodeID, result.err)
			state.Delivery.FailedNodes[result.node.identity.NodeID] = boundedDeliveryFailure(result.err)
			continue
		}
		if err := addDeliveryReceipt(&state, result.node.identity, result.receipt, time.Now().UTC()); err != nil {
			return cloneDelivery(state.Delivery), err
		}
		if err := c.persistDeliveryState(ctx, state, time.Now().UTC()); err != nil {
			return cloneDelivery(state.Delivery), fmt.Errorf("persist storage receipt: %w", err)
		}
		c.reputation.Success(result.node.identity.NodeID, false)
		countedReceiptNodes[result.node.identity.NodeID] = struct{}{}
	}
	// Failed primary nodes are replaced by later candidates. This is the core
	// repair behavior: a signed receipt is required before a replica counts.
	for _, n := range usable[primaryCount:] {
		if len(countedReceiptNodes) >= c.replicas {
			break
		}
		if err := addDeliveryAttempt(&state, n.identity); err != nil {
			return cloneDelivery(state.Delivery), err
		}
		if err := c.persistDeliveryState(ctx, state, time.Now().UTC()); err != nil {
			return cloneDelivery(state.Delivery), fmt.Errorf("persist pending replacement before store: %w", err)
		}
		receipt, err := n.Store(ctx, item)
		if err != nil {
			if localContextTermination(ctx, err) {
				return cloneDelivery(state.Delivery), ctx.Err()
			}
			c.reputation.Failure(n.identity.NodeID, err)
			state.Delivery.FailedNodes[n.identity.NodeID] = boundedDeliveryFailure(err)
			continue
		}
		if err := addDeliveryReceipt(&state, n.identity, receipt, time.Now().UTC()); err != nil {
			return cloneDelivery(state.Delivery), err
		}
		if err := c.persistDeliveryState(ctx, state, time.Now().UTC()); err != nil {
			return cloneDelivery(state.Delivery), fmt.Errorf("persist replacement receipt: %w", err)
		}
		c.reputation.Success(n.identity.NodeID, false)
		countedReceiptNodes[n.identity.NodeID] = struct{}{}
	}
	if err := c.persistDeliveryState(ctx, state, time.Now().UTC()); err != nil {
		return cloneDelivery(state.Delivery), fmt.Errorf("persist delivery state: %w", err)
	}
	if len(countedReceiptNodes) < c.writeQuorum {
		return cloneDelivery(state.Delivery), fmt.Errorf("write quorum not reached: got %d of %d receipts", len(countedReceiptNodes), c.writeQuorum)
	}
	return cloneDelivery(state.Delivery), nil
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
	type nodeFetch struct {
		nodeID string
		items  []protocol.StoredItem
	}
	nodes := c.allowedNodes()
	if len(nodes) == 0 {
		return nil, ErrNoAllowedNodes
	}
	// Node order is configuration-dependent. Sort it before both collection and
	// fair merge so the same signed responses always produce the same result.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].identity.NodeID < nodes[j].identity.NodeID })
	responses := make([]nodeFetch, 0, len(nodes))
	var lastErr error
	now := time.Now().UTC()
	for _, n := range nodes {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		items, err := n.Fetch(ctx, routeTags)
		if err != nil {
			if localContextTermination(ctx, err) {
				return nil, ctx.Err()
			}
			c.reputation.Failure(n.identity.NodeID, err)
			lastErr = err
			continue
		}
		responseValid := len(items) <= protocol.DefaultMaxFetchItems
		responseItems := make(map[string]protocol.StoredItem, len(items))
		var responseBytes int64
		if len(items) > protocol.DefaultMaxFetchItems {
			responseValid = false
		}
		for _, item := range items {
			if _, asked := requested[item.RouteTag]; !asked ||
				protocol.ValidateItem(item, now, protocol.DefaultMaxItemBytes) != nil {
				responseValid = false
			}
			responseBytes += int64(len(item.Payload))
			if responseBytes > protocol.DefaultMaxFetchBytes {
				responseValid = false
			}
			if _, duplicate := responseItems[item.ItemID]; duplicate {
				responseValid = false
			} else {
				responseItems[item.ItemID] = item
			}
		}
		if !responseValid {
			lastErr = ErrInvalidNodeResponse
			c.reputation.Failure(n.identity.NodeID, lastErr)
			continue
		}
		items = items[:0]
		for _, item := range responseItems {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool {
			if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
				return items[i].CreatedAt.Before(items[j].CreatedAt)
			}
			return items[i].ItemID < items[j].ItemID
		})
		responses = append(responses, nodeFetch{nodeID: n.identity.NodeID, items: items})
	}
	if len(responses) == 0 && lastErr != nil {
		return nil, lastErr
	}
	sort.Slice(responses, func(i, j int) bool { return responses[i].nodeID < responses[j].nodeID })

	// Merge one candidate per successful node and round. The retained response
	// slices are each independently bounded by HTTPNode.Fetch, and the emitted
	// union is bounded before every append. This prevents a valid but
	// budget-filling response from crowding every other node out.
	result := make([]protocol.StoredItem, 0, protocol.DefaultMaxFetchItems)
	seen := make(map[string]struct{}, protocol.DefaultMaxFetchItems)
	indexes := make([]int, len(responses))
	var resultBytes int64
	for len(result) < protocol.DefaultMaxFetchItems {
		hadCandidate := false
		for responseIndex := range responses {
			itemIndex := indexes[responseIndex]
			if itemIndex >= len(responses[responseIndex].items) {
				continue
			}
			hadCandidate = true
			item := responses[responseIndex].items[itemIndex]
			indexes[responseIndex]++
			if _, duplicate := seen[item.ItemID]; duplicate {
				continue
			}
			seen[item.ItemID] = struct{}{}
			itemBytes := int64(len(item.Payload))
			if resultBytes+itemBytes > protocol.DefaultMaxFetchBytes {
				continue
			}
			result = append(result, item)
			resultBytes += itemBytes
			if len(result) == protocol.DefaultMaxFetchItems {
				break
			}
		}
		if !hadCandidate {
			break
		}
	}
	return result, nil
}

func localContextTermination(ctx context.Context, err error) bool {
	return ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())
}

func (c *Core) Audit(ctx context.Context, delivery Delivery) map[string]error {
	results := make(map[string]error)
	if c == nil || ctx == nil || !validItemID(delivery.Item.ItemID) {
		results[deliveryAuditStateKey] = ErrInvalidDeliveryState
		return results
	}
	unlock := c.lockDelivery(delivery.Item.ItemID)
	defer unlock()
	now := time.Now().UTC()
	state, err := c.deliveryStateForOperationLocked(ctx, delivery, now, true)
	if err != nil {
		results[deliveryAuditStateKey] = err
		return results
	}
	defer wipeDeliveryState(&state)
	return c.auditDeliveryState(ctx, state)
}

func (c *Core) auditDeliveryState(ctx context.Context, state persistedDeliveryState) map[string]error {
	results := make(map[string]error)
	if len(state.Delivery.Receipts) < c.replicas {
		results[deliveryAuditStateKey] = ErrInvalidDeliveryState
	}
	payloadHash := sha256.Sum256(state.Delivery.Item.Payload)
	identities := deliveryIdentityMap(state)
	for _, receipt := range state.Delivery.Receipts {
		n := c.nodeByID(receipt.NodeID)
		if n == nil || !sameNodeIdentity(n.identity, identities[receipt.NodeID]) {
			results[receipt.NodeID] = ErrDeliveryNodeUnavailable
			continue
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			results[n.identity.NodeID] = err
			continue
		}
		sampleLength := min(4096, len(state.Delivery.Item.Payload))
		offset, err := randomProofOffset(rand.Reader, len(state.Delivery.Item.Payload), sampleLength)
		if err != nil {
			results[n.identity.NodeID] = err
			continue
		}
		request := protocol.ProofRequest{ItemID: state.Delivery.Item.ItemID, Nonce: nonce, Offset: offset, Length: sampleLength}
		proof, err := n.Prove(ctx, request)
		if localContextTermination(ctx, err) {
			results[n.identity.NodeID] = ctx.Err()
			continue
		}
		if err == nil {
			end := offset + int64(len(proof.Sample))
			if end > int64(len(state.Delivery.Item.Payload)) || !bytes.Equal(proof.Sample, state.Delivery.Item.Payload[offset:end]) || !bytes.Equal(proof.PayloadHash, payloadHash[:]) {
				err = errors.New("node returned incorrect stored bytes")
				c.reputation.Exclude(n.identity.NodeID, 24*time.Hour, err)
			}
		}
		results[n.identity.NodeID] = err
		if err != nil {
			if c.reputation.Allowed(n.identity.NodeID, time.Now()) {
				c.reputation.Failure(n.identity.NodeID, err)
			}
		} else {
			c.reputation.Success(n.identity.NodeID, true)
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
// Valid old receipts are retained and merged with new repair receipts. The
// operation is serialized per item and the merged state is persisted before
// any repair Store request is sent.
func (c *Core) AuditAndRepair(ctx context.Context, delivery Delivery) (Delivery, map[string]error, error) {
	if c == nil || ctx == nil || !validItemID(delivery.Item.ItemID) {
		audit := map[string]error{deliveryAuditStateKey: ErrInvalidDeliveryState}
		return Delivery{}, audit, ErrInvalidDeliveryState
	}
	unlock := c.lockDelivery(delivery.Item.ItemID)
	defer unlock()
	state, err := c.deliveryStateForOperationLocked(ctx, delivery, time.Now().UTC(), true)
	if err != nil {
		audit := map[string]error{deliveryAuditStateKey: err}
		return Delivery{}, audit, err
	}
	defer wipeDeliveryState(&state)
	audit := c.auditDeliveryState(ctx, state)
	counted := make(map[string]struct{}, len(state.Delivery.Receipts))
	for _, receipt := range state.Delivery.Receipts {
		if audit[receipt.NodeID] == nil {
			counted[receipt.NodeID] = struct{}{}
		}
	}
	if len(counted) >= c.replicas && audit[deliveryAuditStateKey] == nil {
		return cloneDelivery(state.Delivery), audit, nil
	}
	repaired, repairErr := c.storeReplicatedLocked(ctx, state.Delivery.Item, state.Delivery.DeleteToken, &state, counted)
	return repaired, audit, repairErr
}

func (c *Core) Delete(ctx context.Context, delivery Delivery) map[string]error {
	results := make(map[string]error)
	if c == nil || ctx == nil || !validItemID(delivery.Item.ItemID) {
		results[deliveryAuditStateKey] = ErrInvalidDeliveryState
		return results
	}
	unlock := c.lockDelivery(delivery.Item.ItemID)
	defer unlock()
	state, err := c.deliveryStateForOperationLocked(ctx, delivery, time.Now().UTC(), true)
	if err != nil {
		results[deliveryAuditStateKey] = err
		return results
	}
	defer wipeDeliveryState(&state)
	identities := deliveryIdentityMap(state)
	targets := deliveryTargetNodeIDs(state)
	allDeleted := len(targets) > 0
	for _, nodeID := range targets {
		n := c.nodeByID(nodeID)
		if n == nil || !sameNodeIdentity(n.identity, identities[nodeID]) {
			results[nodeID] = ErrDeliveryNodeUnavailable
			allDeleted = false
			continue
		}
		_, err := n.Delete(ctx, protocol.DeleteRequest{ItemID: state.Delivery.Item.ItemID, DeleteToken: state.Delivery.DeleteToken})
		results[n.identity.NodeID] = err
		if err != nil {
			allDeleted = false
			if !localContextTermination(ctx, err) {
				c.reputation.Failure(n.identity.NodeID, err)
			}
		}
	}
	if allDeleted && c.store != nil {
		latest, err := c.loadDeliveryState(ctx, state.Delivery.Item.ItemID, time.Now().UTC(), true)
		if err != nil {
			results["local-client-store"] = err
			return results
		}
		defer wipeDeliveryState(&latest)
		if !sameReceiptSet(state.Delivery.Receipts, latest.Delivery.Receipts) ||
			!sameStringSlice(deliveryTargetNodeIDs(state), deliveryTargetNodeIDs(latest)) ||
			!bytes.Equal(state.Delivery.DeleteToken, latest.Delivery.DeleteToken) {
			results["local-client-store"] = ErrDeliveryStateChanged
			return results
		}
		if err := c.store.Delete(ctx, deliveryRecordID(state.Delivery.Item.ItemID)); err != nil && !errors.Is(err, ErrLocalRecordNotFound) {
			results["local-client-store"] = err
		}
	}
	return results
}

func (c *Core) DeleteItemEverywhere(ctx context.Context, itemID string, deleteToken []byte) map[string]error {
	results := make(map[string]error)
	if len(deleteToken) != protocol.CapabilityBytes || !validItemID(itemID) {
		err := errors.New("invalid delete request")
		for _, n := range c.nodes {
			results[n.identity.NodeID] = err
		}
		return results
	}
	for _, n := range c.nodes {
		_, err := n.Delete(ctx, protocol.DeleteRequest{ItemID: itemID, DeleteToken: deleteToken})
		results[n.identity.NodeID] = err
	}
	return results
}

func (c *Core) allowedNodes() []*HTTPNode {
	now := time.Now()
	result := make([]*HTTPNode, 0, len(c.nodes))
	for _, n := range c.nodes {
		if c.reputation.Allowed(n.identity.NodeID, now) {
			result = append(result, n)
		}
	}
	return result
}

func (c *Core) nodeByID(nodeID string) *HTTPNode {
	for _, n := range c.nodes {
		if n.identity.NodeID == nodeID {
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
	if ctx == nil || !validItemID(delivery.Item.ItemID) || now.IsZero() {
		return ErrInvalidDeliveryState
	}
	unlock := c.lockDelivery(delivery.Item.ItemID)
	defer unlock()
	state, err := c.deliveryStateForOperationLocked(ctx, delivery, now, false)
	if err != nil {
		return err
	}
	defer wipeDeliveryState(&state)
	return c.persistDeliveryState(ctx, state, now)
}

// LoadDelivery restores authenticated repair/deletion state after a restart.
// The encrypted local record and every hybrid node receipt are verified again
// before the delete capability is returned to the caller.
func (c *Core) LoadDelivery(ctx context.Context, itemID string, now time.Time) (Delivery, error) {
	state, err := c.loadDeliveryState(ctx, itemID, now, true)
	if err != nil {
		return Delivery{}, err
	}
	defer wipeDeliveryState(&state)
	return cloneDelivery(state.Delivery), nil
}

// PendingDeliveries returns one bounded, stable page of persisted delivery
// state. Passing the final ItemID from the previous page resumes after it, so a
// restarted client can discover repair and deletion capabilities without
// already knowing every item identifier.
func (c *Core) PendingDeliveries(ctx context.Context, afterItemID string, limit int, now time.Time) ([]Delivery, error) {
	if c == nil || c.store == nil || ctx == nil || now.IsZero() || limit <= 0 || limit > MaxPendingDeliveryPage ||
		(afterItemID != "" && !validItemID(afterItemID)) {
		return nil, errors.New("invalid pending delivery listing")
	}
	scanAfter := ""
	if afterItemID != "" {
		scanAfter = deliveryRecordID(afterItemID)
	}
	deliveries := make([]Delivery, 0, limit)
	scanned := 0
	for {
		ids, err := c.store.ListIDs(ctx, LocalKindDelivery, scanAfter, MaxPendingDeliveryPage)
		if err != nil {
			return nil, err
		}
		if len(ids) > MaxPendingDeliveryPage {
			return nil, errors.New("invalid persisted delivery index page size")
		}
		previous := scanAfter
		for _, id := range ids {
			if id <= previous || !strings.HasPrefix(id, "delivery.") ||
				!validItemID(strings.TrimPrefix(id, "delivery.")) {
				return nil, errors.New("invalid persisted delivery index")
			}
			previous = id
		}
		for _, id := range ids {
			scanned++
			if scanned > MaxClientStoreRecords {
				return nil, errors.New("persisted delivery index exceeds record bound")
			}
			itemID := strings.TrimPrefix(id, "delivery.")
			state, loadErr := c.loadDeliveryState(ctx, itemID, now, false)
			if errors.Is(loadErr, ErrLocalRecordNotFound) {
				continue
			}
			if loadErr != nil {
				return nil, loadErr
			}
			active := state.Delivery.Item.ExpiresAt.After(now)
			if active {
				deliveries = append(deliveries, cloneDelivery(state.Delivery))
			}
			wipeDeliveryState(&state)
			if len(deliveries) == limit {
				return deliveries, nil
			}
		}
		if len(ids) < MaxPendingDeliveryPage {
			return deliveries, nil
		}
		if previous == scanAfter {
			return nil, errors.New("persisted delivery index did not advance")
		}
		scanAfter = previous
	}
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

func validItemID(itemID string) bool {
	if len(itemID) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(itemID)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == itemID
}
