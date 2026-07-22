package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"propagare/pqcrypto"
	"propagare/protocol"
	"propagare/transportauth"
)

const (
	receiptDomain       = "storage-receipt"
	proofDomain         = "storage-proof"
	deleteReceiptDomain = "delete-receipt"
)

type HTTPNode struct {
	BaseURL  string
	Identity protocol.NodePublicIdentity
	Client   *http.Client
}

func DiscoverHTTPNode(ctx context.Context, baseURL string, httpClient *http.Client) (*HTTPNode, error) {
	return discoverHTTPNode(ctx, baseURL, httpClient, false)
}

// DiscoverHTTPNodeForDevelopment permits plain HTTP only for literal loopback
// or private addresses. Production directory callers use ConnectPinnedHTTPNode
// so route capabilities and delete tokens are encrypted without relying on a
// public certificate authority.
func DiscoverHTTPNodeForDevelopment(ctx context.Context, baseURL string, httpClient *http.Client) (*HTTPNode, error) {
	return discoverHTTPNode(ctx, baseURL, httpClient, true)
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
	node, err := discoverHTTPNode(ctx, baseURL, pinnedClient, false)
	if err != nil {
		return nil, err
	}
	if !sameNodeIdentity(node.Identity, identity) {
		return nil, errors.New("node identity endpoint does not match the pinned identity")
	}
	return node, nil
}

func discoverHTTPNode(ctx context.Context, baseURL string, httpClient *http.Client, allowPrivateHTTP bool) (*HTTPNode, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	parsed, err := validNodeBaseURL(baseURL)
	if err != nil {
		return nil, errors.New("invalid node base URL")
	}
	if parsed.Scheme == "http" && (!allowPrivateHTTP || !privateDevelopmentHost(parsed.Hostname())) {
		return nil, errors.New("plain HTTP node discovery is restricted to explicit private development")
	}
	safeClient := *httpClient
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	n := &HTTPNode{BaseURL: strings.TrimRight(baseURL, "/"), Client: &safeClient}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.BaseURL+"/v1/identity", nil)
	if err != nil {
		return nil, err
	}
	response, err := n.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, responseError(response)
	}
	if err := decodeResponseJSON(response.Body, 64*1024, &n.Identity); err != nil {
		return nil, err
	}
	if !pqcrypto.ValidPublicIdentity(n.Identity) {
		return nil, errors.New("node identity is internally inconsistent")
	}
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

func (n *HTTPNode) Parameters(ctx context.Context) (protocol.NodeParameters, error) {
	var parameters protocol.NodeParameters
	err := n.getJSON(ctx, "/v1/parameters", &parameters)
	if err == nil {
		err = protocol.ValidateNodeParameters(parameters)
	}
	return parameters, err
}

func (n *HTTPNode) Store(ctx context.Context, item protocol.StoredItem) (protocol.StorageReceipt, error) {
	var receipt protocol.StorageReceipt
	if err := n.postJSON(ctx, "/v1/items", item, &receipt); err != nil {
		return receipt, err
	}
	now := time.Now()
	if err := verifyStorageReceipt(n.Identity, item, receipt, now); err != nil {
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
	if err := n.postJSON(ctx, "/v1/fetch", protocol.FetchRequest{RouteTags: routeTags}, &response); err != nil {
		return nil, err
	}
	if len(response.Items) > protocol.DefaultMaxFetchItems {
		return nil, errors.New("node returned too many fetch items")
	}
	return response.Items, nil
}

func (n *HTTPNode) Prove(ctx context.Context, request protocol.ProofRequest) (protocol.StorageProof, error) {
	var proof protocol.StorageProof
	if len(request.ItemID) != sha256.Size*2 || len(request.Nonce) < 16 || len(request.Nonce) > 64 ||
		request.Offset < 0 || request.Length <= 0 || request.Length > protocol.MaxProofSampleBytes {
		return proof, errors.New("invalid storage proof request")
	}
	if err := n.postJSON(ctx, "/v1/proof", request, &proof); err != nil {
		return proof, err
	}
	if proof.NodeID != n.Identity.NodeID || proof.ItemID != request.ItemID ||
		!bytes.Equal(proof.Nonce, request.Nonce) || proof.Offset != request.Offset ||
		len(proof.Sample) != request.Length || len(proof.PayloadHash) != sha256.Size ||
		proof.ProvedAt.Before(time.Now().Add(-5*time.Minute)) || proof.ProvedAt.After(time.Now().Add(5*time.Minute)) ||
		!pqcrypto.Verify(n.Identity, proofDomain, protocol.ProofSigningBytes(proof), proof.Signature) {
		return protocol.StorageProof{}, errors.New("invalid storage proof signature")
	}
	return proof, nil
}

func (n *HTTPNode) Delete(ctx context.Context, request protocol.DeleteRequest) (protocol.DeleteReceipt, error) {
	var receipt protocol.DeleteReceipt
	if err := n.postJSON(ctx, "/v1/delete", request, &receipt); err != nil {
		return receipt, err
	}
	if receipt.NodeID != n.Identity.NodeID || receipt.ItemID != request.ItemID ||
		receipt.DeletedAt.Before(time.Now().Add(-5*time.Minute)) || receipt.DeletedAt.After(time.Now().Add(5*time.Minute)) ||
		!pqcrypto.Verify(n.Identity, deleteReceiptDomain, protocol.DeleteReceiptSigningBytes(receipt), receipt.Signature) {
		return protocol.DeleteReceipt{}, errors.New("invalid delete receipt")
	}
	return receipt, nil
}

func (n *HTTPNode) getJSON(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, n.BaseURL+path, nil)
	if err != nil {
		return err
	}
	response, err := n.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	return decodeResponseJSON(response.Body, 2*1024*1024, destination)
}

func (n *HTTPNode) postJSON(ctx context.Context, path string, source, destination any) error {
	body, err := json.Marshal(source)
	if err != nil {
		return err
	}
	defer zero(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response)
	}
	if destination == nil {
		return nil
	}
	return decodeResponseJSON(response.Body, 12*1024*1024, destination)
}

func decodeResponseJSON(reader io.Reader, limit int64, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("node response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("node response must contain one JSON value")
	}
	return nil
}

func responseError(response *http.Response) error {
	// Response bodies are controlled by an untrusted node and may reflect route
	// tags, fetch lists, ciphertext, or delete capabilities. Never propagate them
	// into application errors, reputation state, logs, or crash reports.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
	return fmt.Errorf("node returned HTTP status %d", response.StatusCode)
}

func privateDevelopmentHost(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && (address.IsLoopback() || address.IsPrivate())
}
