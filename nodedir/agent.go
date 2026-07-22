package nodedir

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"propagare/pqcrypto"
	"propagare/protocol"
	"propagare/transportauth"
)

type ReachabilityProber interface {
	Verify(ctx context.Context, announcement Announcement) error
}

type HTTPProber struct {
	Client *http.Client
}

type Agent struct {
	registry *Registry
	policy   Policy
	signer   Signer
	endpoint Endpoint
	lease    time.Duration
	client   *http.Client
	prober   ReachabilityProber

	mu       sync.RWMutex
	self     Record
	sequence uint64
}

func NewAgent(policy Policy, endpoint Endpoint, signer Signer, lease time.Duration, client *http.Client, prober ReachabilityProber, now time.Time) (*Agent, error) {
	registry, err := NewRegistry(policy)
	if err != nil {
		return nil, err
	}
	if signer == nil || lease < MinLease || lease > MaxLease {
		return nil, errors.New("invalid node directory agent configuration")
	}
	canonical, err := validateEndpoint(endpoint, policy.AllowPrivateIPs)
	if err != nil || canonical != endpoint {
		return nil, errors.New("invalid advertised node endpoint")
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if prober == nil {
		prober = &HTTPProber{Client: &safeClient}
	}
	agent := &Agent{registry: registry, policy: registry.Policy(), signer: signer, endpoint: endpoint, lease: lease, client: &safeClient, prober: prober}
	if err := agent.renew(now); err != nil {
		return nil, err
	}
	return agent, nil
}

func (agent *Agent) Registry() *Registry { return agent.registry }

func (agent *Agent) IdentityID() string { return agent.signer.PublicIdentity().NodeID }

func (agent *Agent) Active(now time.Time) []Record { return agent.registry.Active(now) }

func (agent *Agent) Snapshot(now time.Time) (Snapshot, error) {
	return SignSnapshot(agent.signer, agent.registry.Active(now), now)
}

func (agent *Agent) Challenge(nonce []byte, now time.Time) (ChallengeResponse, error) {
	return SignChallenge(agent.signer, nonce, now)
}

func (agent *Agent) renew(now time.Time) error {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if !agent.self.Announcement.ExpiresAt.IsZero() && agent.self.Announcement.ExpiresAt.After(now.Add(agent.lease/2)) {
		return nil
	}
	sequence := uint64(now.UTC().UnixMilli()) // #nosec G115 -- positive current protocol time checked below.
	if now.UnixMilli() <= 0 {
		return errors.New("node directory requires a positive wall clock")
	}
	if sequence <= agent.sequence {
		sequence = agent.sequence + 1
	}
	announcement, err := SignAnnouncement(agent.signer, agent.endpoint, sequence, now, agent.lease, agent.policy.AllowPrivateIPs)
	if err != nil {
		return err
	}
	agent.sequence = sequence
	agent.self = Record{Announcement: announcement}
	if agent.policy.isPinned(announcement) {
		return agent.registry.Merge(agent.self, now)
	}
	return nil
}

func (agent *Agent) selfRecord() Record {
	agent.mu.RLock()
	defer agent.mu.RUnlock()
	return cloneRecord(agent.self)
}

// AcceptRegistration proves that the request's TCP source owns the advertised
// IP, then performs a bounded callback challenge to the same IP and advertised
// port. Only a locally pinned seed identity can issue an admission attestation.
func (agent *Agent) AcceptRegistration(ctx context.Context, remoteIP netip.Addr, request RegistrationRequest, now time.Time) (Record, error) {
	if agent == nil || !agent.policy.Authority(agent.signer.PublicIdentity()) {
		return Record{}, errors.New("this node is not a pinned directory authority")
	}
	if err := verifyPartialRecord(agent.policy, request.Record, now); err != nil {
		return Record{}, err
	}
	advertised, err := netip.ParseAddr(request.Record.Announcement.Endpoint.IP)
	if err != nil || remoteIP.Unmap() != advertised.Unmap() {
		return Record{}, errors.New("advertised IP does not match the registration source")
	}
	if err := agent.prober.Verify(ctx, request.Record.Announcement); err != nil {
		return Record{}, fmt.Errorf("node reachability proof failed: %w", err)
	}
	attestation, err := SignAttestation(agent.signer, request.Record.Announcement, now)
	if err != nil {
		return Record{}, err
	}
	result := appendAttestation(request.Record, attestation)
	if err := VerifyRecord(agent.policy, result, now); err == nil {
		if err := agent.registry.Merge(result, now); err != nil {
			return Record{}, err
		}
	}
	return result, nil
}

func (agent *Agent) SyncOnce(ctx context.Context, now time.Time) error {
	if agent == nil {
		return errors.New("node directory agent is unavailable")
	}
	if err := agent.renew(now); err != nil {
		return err
	}
	var failures []error
	self := agent.selfRecord()
	for _, seed := range agent.policy.Seeds {
		if seed.Identity.NodeID == agent.IdentityID() {
			continue
		}
		result, err := postRegistration(ctx, agent.client, seed, self)
		if err != nil {
			failures = append(failures, fmt.Errorf("register with %s: %w", seed.Identity.NodeID, err))
			continue
		}
		if !bytes.Equal(AnnouncementHash(result.Announcement), AnnouncementHash(self.Announcement)) ||
			verifyPartialRecord(agent.policy, result, now) != nil {
			failures = append(failures, fmt.Errorf("register with %s: invalid attested record", seed.Identity.NodeID))
			continue
		}
		self = mergePartial(self, result)
		agent.mu.Lock()
		agent.self = cloneRecord(self)
		agent.mu.Unlock()
	}
	if err := VerifyRecord(agent.policy, self, now); err == nil {
		if err := agent.registry.Merge(self, now); err != nil {
			failures = append(failures, err)
		}
	}

	successfulPulls := 0
	for _, seed := range agent.policy.Seeds {
		snapshot, err := FetchSnapshot(ctx, agent.client, seed.Endpoint, seed.Identity, now, agent.policy.MaxNodes)
		if err != nil {
			failures = append(failures, fmt.Errorf("pull from %s: %w", seed.Identity.NodeID, err))
			continue
		}
		if err := agent.registry.MergeSnapshot(snapshot, seed.Identity.NodeID, now); err != nil {
			failures = append(failures, fmt.Errorf("merge from %s: %w", seed.Identity.NodeID, err))
			continue
		}
		successfulPulls++
	}
	agent.registry.Sweep(now)
	if successfulPulls == 0 {
		return errors.Join(failures...)
	}
	return nil
}

func (agent *Agent) Run(ctx context.Context, interval time.Duration) error {
	if interval < time.Minute || interval > MaxLease/2 {
		return errors.New("invalid node directory synchronization interval")
	}
	if err := agent.SyncOnce(ctx, time.Now().UTC()); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			_ = agent.SyncOnce(ctx, now.UTC())
		}
	}
}

func (prober *HTTPProber) Verify(ctx context.Context, announcement Announcement) error {
	if prober == nil || prober.Client == nil {
		return errors.New("node reachability prober is unavailable")
	}
	nonce, err := NewChallenge()
	if err != nil {
		return err
	}
	var response ChallengeResponse
	safeClient, err := endpointClient(prober.Client, announcement.Endpoint, announcement.Identity)
	if err != nil {
		return err
	}
	if err := postJSON(ctx, safeClient, announcement.Endpoint.BaseURL()+"/v1/nodes/challenge", ChallengeRequest{Nonce: nonce}, MaxRegistrationBytes, &response); err != nil {
		return err
	}
	return VerifyChallenge(announcement.Identity, nonce, response, time.Now().UTC())
}

func FetchSnapshot(ctx context.Context, client *http.Client, endpoint Endpoint, expectedPublisher protocol.NodePublicIdentity, now time.Time, maxNodes int) (Snapshot, error) {
	if client == nil {
		return Snapshot{}, errors.New("HTTP client is required")
	}
	if !pqcrypto.ValidPublicIdentity(expectedPublisher) {
		return Snapshot{}, errors.New("invalid expected directory publisher identity")
	}
	safeClient, err := endpointClient(client, endpoint, expectedPublisher)
	if err != nil {
		return Snapshot{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.BaseURL()+"/v1/nodes", nil)
	if err != nil {
		return Snapshot{}, err
	}
	response, err := safeClient.Do(request)
	if err != nil {
		return Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, responseStatusError(response)
	}
	var snapshot Snapshot
	if err := decodeLimited(response.Body, MaxSnapshotBytes, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := VerifySnapshotHeader(snapshot, expectedPublisher.NodeID, now, maxNodes); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func noRedirectClient(client *http.Client) *http.Client {
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &safe
}

func endpointClient(client *http.Client, endpoint Endpoint, identity protocol.NodePublicIdentity) (*http.Client, error) {
	if client == nil {
		return nil, errors.New("HTTP client is required")
	}
	if endpoint.Scheme == "https" {
		return transportauth.PinnedHTTPClient(client, identity)
	}
	if endpoint.Scheme != "http" {
		return nil, errors.New("unsupported node endpoint transport")
	}
	return noRedirectClient(client), nil
}

func postRegistration(ctx context.Context, client *http.Client, seed PinnedNode, record Record) (Record, error) {
	safeClient, err := endpointClient(client, seed.Endpoint, seed.Identity)
	if err != nil {
		return Record{}, err
	}
	var result Record
	if err := postJSON(ctx, safeClient, seed.Endpoint.BaseURL()+"/v1/nodes/register", RegistrationRequest{Record: record}, MaxRegistrationBytes, &result); err != nil {
		return Record{}, err
	}
	return result, nil
}

func postJSON(ctx context.Context, client *http.Client, url string, source any, limit int64, destination any) error {
	body, err := json.Marshal(source)
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("directory request exceeds size limit")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseStatusError(response)
	}
	return decodeLimited(response.Body, limit, destination)
}

func decodeLimited(reader io.Reader, limit int64, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("directory response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("directory response must contain one JSON value")
	}
	return nil
}

func responseStatusError(response *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 2048))
	return fmt.Errorf("node returned HTTP status %d", response.StatusCode)
}

func mergePartial(left, right Record) Record {
	result := cloneRecord(left)
	for _, attestation := range right.Attestations {
		result = appendAttestation(result, attestation)
	}
	sort.Slice(result.Attestations, func(i, j int) bool { return result.Attestations[i].AuthorityID < result.Attestations[j].AuthorityID })
	return result
}
