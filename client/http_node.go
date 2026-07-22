package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
	"github.com/MacMax-B/propagare/protocol"
	"github.com/MacMax-B/propagare/transportauth"
)

const (
	receiptDomain       = "storage-receipt"
	proofDomain         = "storage-proof"
	deleteReceiptDomain = "delete-receipt"

	maxIdentityResponseBytes       int64 = 64 * 1024
	maxParametersResponseBytes           = 16 * 1024
	maxStorageReceiptResponseBytes       = 16 * 1024
	maxStorageProofResponseBytes         = 32 * 1024
	maxDeleteReceiptResponseBytes        = 16 * 1024
	maxFetchResponseBytes                = 12 * 1024 * 1024
)

var (
	ErrUntrustedNodeTransport = errors.New("node transport is not authenticated")
	ErrNodeTransport          = errors.New("node transport failed")
	ErrNodeHTTPStatus         = errors.New("node returned an HTTP error")
	ErrInvalidNodeResponse    = errors.New("node returned an invalid response")
	ErrNodeResponseTooLarge   = errors.New("node response exceeds size limit")
)

type nodeConnectionMode uint8

const (
	nodeConnectionInvalid nodeConnectionMode = iota
	nodeConnectionDiscovery
	nodeConnectionPinned
	nodeConnectionPrivateDevelopment
)

// HTTPNode deliberately has no exported mutable fields. A production-capable
// instance can only be created by ConnectPinnedHTTPNode. Discovery returns an
// informational descriptor, while the explicitly named development constructor
// permits operational plain HTTP only to literal private or loopback addresses.
type HTTPNode struct {
	baseURL  string
	identity protocol.NodePublicIdentity
	client   *http.Client
	mode     nodeConnectionMode
}

func (n *HTTPNode) BaseURL() string {
	if n == nil {
		return ""
	}
	return n.baseURL
}

func (n *HTTPNode) Identity() protocol.NodePublicIdentity {
	if n == nil {
		return protocol.NodePublicIdentity{}
	}
	return cloneNodeIdentity(n.identity)
}

func DiscoverHTTPNode(ctx context.Context, baseURL string, httpClient *http.Client) (*HTTPNode, error) {
	return discoverHTTPNode(ctx, baseURL, httpClient, nodeConnectionDiscovery)
}

// DiscoverHTTPNodeForDevelopment permits plain HTTP only for literal loopback
// or private addresses. Production directory callers use ConnectPinnedHTTPNode
// so route capabilities and delete tokens are encrypted without relying on a
// public certificate authority.
func DiscoverHTTPNodeForDevelopment(ctx context.Context, baseURL string, httpClient *http.Client) (*HTTPNode, error) {
	return discoverHTTPNode(ctx, baseURL, httpClient, nodeConnectionPrivateDevelopment)
}

// ConnectPinnedHTTPNode establishes a CA-PKI-free TLS 1.3 channel whose server
// key must match the hybrid-signed Node identity supplied by a pinned seed or
// verified directory record.
func ConnectPinnedHTTPNode(ctx context.Context, baseURL string, identity protocol.NodePublicIdentity, httpClient *http.Client) (*HTTPNode, error) {
	if !pqcrypto.ValidPublicIdentity(identity) {
		return nil, errors.New("invalid pinned node identity")
	}
	parsed, err := validNodeBaseURL(baseURL)
	if err != nil || parsed.Scheme != "https" {
		return nil, errors.New("pinned node transport requires HTTPS framing")
	}
	pinnedClient, err := transportauth.PinnedHTTPClient(httpClient, identity)
	if err != nil {
		return nil, err
	}
	node, err := discoverHTTPNode(ctx, baseURL, pinnedClient, nodeConnectionPinned)
	if err != nil {
		return nil, err
	}
	if !sameNodeIdentity(node.identity, identity) {
		return nil, errors.New("node identity endpoint does not match the pinned identity")
	}
	return node, nil
}

func discoverHTTPNode(ctx context.Context, baseURL string, httpClient *http.Client, mode nodeConnectionMode) (*HTTPNode, error) {
	if ctx == nil {
		return nil, errors.New("node discovery context is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	parsed, err := validNodeBaseURL(baseURL)
	if err != nil {
		return nil, errors.New("invalid node base URL")
	}
	switch mode {
	case nodeConnectionDiscovery, nodeConnectionPinned:
		if parsed.Scheme != "https" {
			return nil, errors.New("production node discovery requires HTTPS framing")
		}
	case nodeConnectionPrivateDevelopment:
		if parsed.Scheme != "http" || !privateDevelopmentHost(parsed.Hostname()) {
			return nil, errors.New("development node discovery requires a private plain HTTP endpoint")
		}
	default:
		return nil, errors.New("invalid node connection mode")
	}
	safeClient := *httpClient
	safeClient.Jar = nil
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	n := &HTTPNode{baseURL: strings.TrimRight(baseURL, "/"), client: &safeClient, mode: mode}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.baseURL+"/v1/identity", nil)
	if err != nil {
		return nil, ErrNodeTransport
	}
	response, err := n.client.Do(request)
	if err != nil {
		return nil, sanitizeNodeTransportError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, responseError(response)
	}
	if err := decodeResponseJSON(response.Body, maxIdentityResponseBytes, &n.identity); err != nil {
		return nil, err
	}
	if !pqcrypto.ValidPublicIdentity(n.identity) {
		return nil, ErrInvalidNodeResponse
	}
	n.identity = cloneNodeIdentity(n.identity)
	return n, nil
}

func validNodeBaseURL(baseURL string) (*url.URL, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid node base URL")
	}
	return parsed, nil
}

func sameNodeIdentity(left, right protocol.NodePublicIdentity) bool {
	return left.NodeID == right.NodeID && left.ProtocolVersion == right.ProtocolVersion &&
		bytes.Equal(left.Ed25519Public, right.Ed25519Public) && bytes.Equal(left.MLDSA65Public, right.MLDSA65Public)
}

func cloneNodeIdentity(identity protocol.NodePublicIdentity) protocol.NodePublicIdentity {
	identity.Ed25519Public = append([]byte(nil), identity.Ed25519Public...)
	identity.MLDSA65Public = append([]byte(nil), identity.MLDSA65Public...)
	return identity
}

func (n *HTTPNode) operational() error {
	if n == nil || n.client == nil || !pqcrypto.ValidPublicIdentity(n.identity) {
		return ErrUntrustedNodeTransport
	}
	parsed, err := validNodeBaseURL(n.baseURL)
	if err != nil {
		return ErrUntrustedNodeTransport
	}
	switch n.mode {
	case nodeConnectionPinned:
		if parsed.Scheme != "https" {
			return ErrUntrustedNodeTransport
		}
	case nodeConnectionPrivateDevelopment:
		if parsed.Scheme != "http" || !privateDevelopmentHost(parsed.Hostname()) {
			return ErrUntrustedNodeTransport
		}
	default:
		return ErrUntrustedNodeTransport
	}
	return nil
}

func cloneOperationalHTTPNode(n *HTTPNode) (*HTTPNode, error) {
	if err := n.operational(); err != nil {
		return nil, err
	}
	clientCopy := *n.client
	clientCopy.Jar = nil
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if transport, ok := n.client.Transport.(*http.Transport); ok {
		clientCopy.Transport = transport.Clone()
	}
	return &HTTPNode{
		baseURL: n.baseURL, identity: cloneNodeIdentity(n.identity), client: &clientCopy, mode: n.mode,
	}, nil
}

func (n *HTTPNode) Parameters(ctx context.Context) (protocol.NodeParameters, error) {
	var parameters protocol.NodeParameters
	err := n.getJSON(ctx, "/v1/parameters", &parameters, maxParametersResponseBytes)
	if err == nil {
		err = protocol.ValidateNodeParameters(parameters)
	}
	return parameters, err
}

func (n *HTTPNode) Store(ctx context.Context, item protocol.StoredItem) (protocol.StorageReceipt, error) {
	var receipt protocol.StorageReceipt
	if err := n.postJSON(ctx, "/v1/items", item, &receipt, maxStorageReceiptResponseBytes); err != nil {
		return receipt, err
	}
	now := time.Now()
	if err := verifyStorageReceipt(n.identity, item, receipt, now); err != nil {
		return protocol.StorageReceipt{}, err
	}
	return receipt, nil
}

func verifyStorageReceipt(identity protocol.NodePublicIdentity, item protocol.StoredItem, receipt protocol.StorageReceipt, now time.Time) error {
	payloadHash := sha256.Sum256(item.Payload)
	if receipt.NodeID != identity.NodeID || receipt.ItemID != item.ItemID ||
		!bytes.Equal(receipt.PayloadHash, payloadHash[:]) || !receipt.ExpiresAt.Equal(item.ExpiresAt) ||
		receipt.StoredAt.Before(item.CreatedAt.Add(-5*time.Minute)) || receipt.StoredAt.After(now.Add(5*time.Minute)) ||
		receipt.StoredAt.After(receipt.ExpiresAt) ||
		!pqcrypto.Verify(identity, receiptDomain, protocol.ReceiptSigningBytes(receipt), receipt.Signature) {
		return errors.New("invalid storage receipt")
	}
	return nil
}

func (n *HTTPNode) Fetch(ctx context.Context, routeTags []string) ([]protocol.StoredItem, error) {
	var response protocol.FetchResponse
	if err := n.postJSON(ctx, "/v1/fetch", protocol.FetchRequest{RouteTags: routeTags}, &response, maxFetchResponseBytes); err != nil {
		return nil, err
	}
	if len(response.Items) > protocol.DefaultMaxFetchItems {
		return nil, ErrNodeResponseTooLarge
	}
	var responseBytes int64
	for _, item := range response.Items {
		responseBytes += int64(len(item.Payload))
		if responseBytes > protocol.DefaultMaxFetchBytes {
			return nil, ErrNodeResponseTooLarge
		}
	}
	return response.Items, nil
}

func (n *HTTPNode) Prove(ctx context.Context, request protocol.ProofRequest) (protocol.StorageProof, error) {
	var proof protocol.StorageProof
	if !validItemID(request.ItemID) || len(request.Nonce) < 16 || len(request.Nonce) > 64 ||
		request.Offset < 0 || request.Length <= 0 || request.Length > protocol.MaxProofSampleBytes {
		return proof, errors.New("invalid storage proof request")
	}
	if err := n.postJSON(ctx, "/v1/proof", request, &proof, maxStorageProofResponseBytes); err != nil {
		return proof, err
	}
	if proof.NodeID != n.identity.NodeID || proof.ItemID != request.ItemID ||
		!bytes.Equal(proof.Nonce, request.Nonce) || proof.Offset != request.Offset ||
		len(proof.Sample) != request.Length || len(proof.PayloadHash) != sha256.Size ||
		proof.ProvedAt.Before(time.Now().Add(-5*time.Minute)) || proof.ProvedAt.After(time.Now().Add(5*time.Minute)) ||
		!pqcrypto.Verify(n.identity, proofDomain, protocol.ProofSigningBytes(proof), proof.Signature) {
		return protocol.StorageProof{}, errors.New("invalid storage proof signature")
	}
	return proof, nil
}

func (n *HTTPNode) Delete(ctx context.Context, request protocol.DeleteRequest) (protocol.DeleteReceipt, error) {
	var receipt protocol.DeleteReceipt
	if !validItemID(request.ItemID) || len(request.DeleteToken) != protocol.CapabilityBytes {
		return receipt, errors.New("invalid delete request")
	}
	if err := n.postJSON(ctx, "/v1/delete", request, &receipt, maxDeleteReceiptResponseBytes); err != nil {
		return receipt, err
	}
	if receipt.NodeID != n.identity.NodeID || receipt.ItemID != request.ItemID ||
		receipt.DeletedAt.Before(time.Now().Add(-5*time.Minute)) || receipt.DeletedAt.After(time.Now().Add(5*time.Minute)) ||
		!pqcrypto.Verify(n.identity, deleteReceiptDomain, protocol.DeleteReceiptSigningBytes(receipt), receipt.Signature) {
		return protocol.DeleteReceipt{}, errors.New("invalid delete receipt")
	}
	return receipt, nil
}

func (n *HTTPNode) getJSON(ctx context.Context, path string, destination any, responseLimit int64) error {
	if err := n.operational(); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.baseURL+path, nil)
	if err != nil {
		return ErrNodeTransport
	}
	response, err := n.client.Do(request)
	if err != nil {
		return sanitizeNodeTransportError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	return decodeResponseJSON(response.Body, responseLimit, destination)
}

func (n *HTTPNode) postJSON(ctx context.Context, path string, source, destination any, responseLimit int64) error {
	if err := n.operational(); err != nil {
		return err
	}
	body, err := json.Marshal(source)
	if err != nil {
		return ErrNodeTransport
	}
	defer zero(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return ErrNodeTransport
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return sanitizeNodeTransportError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	if destination == nil {
		return nil
	}
	return decodeResponseJSON(response.Body, responseLimit, destination)
}

func decodeResponseJSON(reader io.Reader, limit int64, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return ErrNodeTransport
	}
	if int64(len(data)) > limit {
		return ErrNodeResponseTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidNodeResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidNodeResponse
	}
	return nil
}

func responseError(response *http.Response) error {
	// Response bodies are controlled by an untrusted node and may reflect route
	// tags, fetch lists, ciphertext, or delete capabilities. Never propagate them
	// into application errors, reputation state, logs, or crash reports.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
	return ErrNodeHTTPStatus
}

func sanitizeNodeTransportError(ctx context.Context, _ error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrNodeTransport
}

func privateDevelopmentHost(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && (address.IsLoopback() || address.IsPrivate())
}
