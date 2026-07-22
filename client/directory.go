package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MacMax-B/propagare/nodedir"
)

type DirectoryBootstrap struct {
	Seeds            []nodedir.PinnedNode
	AuthorityQuorum  int
	MinSeedResponses int
	AllowPrivateIPs  bool
	MaxNodes         int
}

// VerifiedDirectory can only be populated by FetchNodeDirectory outside this
// package. Its records and trust policy are kept private so callers cannot
// substitute unsigned records between verification and connection.
type VerifiedDirectory struct {
	records    []nodedir.Record
	policy     nodedir.Policy
	verifiedAt time.Time
}

// Records returns defensive copies for display and node selection UIs. Mutating
// them cannot affect the records later consumed by ConnectDirectoryRecords.
func (directory VerifiedDirectory) Records() []nodedir.Record {
	return cloneDirectoryRecords(directory.records)
}

// FetchNodeDirectory reconciles signed snapshots from multiple pinned seeds.
// The returned records are the union of all successfully verified views; one
// seed cannot add an unapproved node, although any directory can still omit a
// node from its own response.
func FetchNodeDirectory(ctx context.Context, config DirectoryBootstrap, httpClient *http.Client, now time.Time) (VerifiedDirectory, error) {
	policy, err := nodedir.NewPolicy(config.Seeds, config.AuthorityQuorum, config.AllowPrivateIPs, config.MaxNodes)
	if err != nil {
		return VerifiedDirectory{}, err
	}
	if config.MinSeedResponses <= 0 || config.MinSeedResponses > len(config.Seeds) {
		return VerifiedDirectory{}, errors.New("invalid minimum seed response count")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 8 * time.Second}
	}
	safeClient := *httpClient
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	registry, err := nodedir.NewRegistry(policy)
	if err != nil {
		return VerifiedDirectory{}, err
	}
	type result struct {
		seed     nodedir.PinnedNode
		snapshot nodedir.Snapshot
		err      error
	}
	results := make(chan result, len(config.Seeds))
	var wait sync.WaitGroup
	for _, seed := range config.Seeds {
		wait.Add(1)
		go func(seed nodedir.PinnedNode) {
			defer wait.Done()
			snapshot, fetchErr := nodedir.FetchSnapshot(ctx, &safeClient, seed.Endpoint, seed.Identity, now, policy.MaxNodes)
			results <- result{seed: seed, snapshot: snapshot, err: fetchErr}
		}(seed)
	}
	wait.Wait()
	close(results)
	successes := 0
	var failures []error
	for result := range results {
		if result.err != nil {
			failures = append(failures, fmt.Errorf("seed %s: %w", result.seed.Identity.NodeID, result.err))
			continue
		}
		if err := registry.MergeSnapshot(result.snapshot, result.seed.Identity.NodeID, now); err != nil {
			failures = append(failures, fmt.Errorf("seed %s: %w", result.seed.Identity.NodeID, err))
			continue
		}
		successes++
	}
	if successes < config.MinSeedResponses {
		return VerifiedDirectory{}, fmt.Errorf("verified only %d of %d required seed views: %w", successes, config.MinSeedResponses, errors.Join(failures...))
	}
	return VerifiedDirectory{records: cloneDirectoryRecords(registry.Active(now)), policy: policy, verifiedAt: now.UTC()}, nil
}

// ConnectDirectoryRecords verifies that each contacted endpoint presents the
// exact hybrid identity admitted by the directory. Limit prevents a directory
// response from making the client dial an unbounded number of nodes. This
// production path only permits identity-pinned HTTPS, even when the directory
// policy admits private IP addresses.
func ConnectDirectoryRecords(ctx context.Context, directory VerifiedDirectory, limit int, httpClient *http.Client) ([]*HTTPNode, error) {
	return connectDirectoryRecords(ctx, directory, limit, httpClient, false)
}

// ConnectDirectoryRecordsForDevelopment explicitly opts into plain HTTP for
// verified records whose endpoint is a literal loopback or private IP. It must
// not be used by production clients.
func ConnectDirectoryRecordsForDevelopment(ctx context.Context, directory VerifiedDirectory, limit int, httpClient *http.Client) ([]*HTTPNode, error) {
	return connectDirectoryRecords(ctx, directory, limit, httpClient, true)
}

func connectDirectoryRecords(ctx context.Context, directory VerifiedDirectory, limit int, httpClient *http.Client, allowPrivateDevelopment bool) ([]*HTTPNode, error) {
	if limit <= 0 || limit > MaxClientNodes || directory.verifiedAt.IsZero() ||
		len(directory.records) == 0 || len(directory.records) > nodedir.MaxDirectoryNodes {
		return nil, errors.New("invalid directory connection limit")
	}
	policy, err := nodedir.NewPolicy(directory.policy.Seeds, directory.policy.AuthorityQuorum, directory.policy.AllowPrivateIPs, directory.policy.MaxNodes)
	if err != nil {
		return nil, errors.New("invalid verified directory")
	}
	records := cloneDirectoryRecords(directory.records)
	now := time.Now().UTC()
	for _, record := range records {
		if err := nodedir.VerifyRecord(policy, record, now); err != nil {
			return nil, errors.New("verified directory record is no longer valid")
		}
	}
	nodes := make([]*HTTPNode, 0, min(limit, len(records)))
	attempted := 0
	for _, record := range records {
		if attempted >= limit {
			break
		}
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var node *HTTPNode
		var connectErr error
		switch record.Announcement.Endpoint.Scheme {
		case "https":
			attempted++
			node, connectErr = ConnectPinnedHTTPNode(ctx, record.Announcement.Endpoint.BaseURL(), record.Announcement.Identity, httpClient)
		case "http":
			if !allowPrivateDevelopment {
				continue
			}
			attempted++
			node, connectErr = DiscoverHTTPNodeForDevelopment(ctx, record.Announcement.Endpoint.BaseURL(), httpClient)
		default:
			continue
		}
		if connectErr != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if !sameNodeIdentity(node.identity, record.Announcement.Identity) {
			continue
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, errors.New("no admitted directory node was reachable")
	}
	return nodes, nil
}

func cloneDirectoryRecords(records []nodedir.Record) []nodedir.Record {
	result := make([]nodedir.Record, len(records))
	for index, record := range records {
		record.Announcement.Identity = cloneNodeIdentity(record.Announcement.Identity)
		record.Announcement.Signature.Ed25519 = append([]byte(nil), record.Announcement.Signature.Ed25519...)
		record.Announcement.Signature.MLDSA65 = append([]byte(nil), record.Announcement.Signature.MLDSA65...)
		record.Attestations = append([]nodedir.Attestation(nil), record.Attestations...)
		for attestationIndex := range record.Attestations {
			attestation := &record.Attestations[attestationIndex]
			attestation.AnnouncementHash = append([]byte(nil), attestation.AnnouncementHash...)
			attestation.Signature.Ed25519 = append([]byte(nil), attestation.Signature.Ed25519...)
			attestation.Signature.MLDSA65 = append([]byte(nil), attestation.Signature.MLDSA65...)
		}
		result[index] = record
	}
	return result
}
