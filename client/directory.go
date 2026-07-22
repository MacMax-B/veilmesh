package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"propagare/nodedir"
)

type DirectoryBootstrap struct {
	Seeds            []nodedir.PinnedNode
	AuthorityQuorum  int
	MinSeedResponses int
	AllowPrivateIPs  bool
	MaxNodes         int
}

// FetchNodeDirectory reconciles signed snapshots from multiple pinned seeds.
// The returned records are the union of all successfully verified views; one
// seed cannot add an unapproved node, although any directory can still omit a
// node from its own response.
func FetchNodeDirectory(ctx context.Context, config DirectoryBootstrap, httpClient *http.Client, now time.Time) ([]nodedir.Record, error) {
	policy, err := nodedir.NewPolicy(config.Seeds, config.AuthorityQuorum, config.AllowPrivateIPs, config.MaxNodes)
	if err != nil {
		return nil, err
	}
	if config.MinSeedResponses <= 0 || config.MinSeedResponses > len(config.Seeds) {
		return nil, errors.New("invalid minimum seed response count")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 8 * time.Second}
	}
	safeClient := *httpClient
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	registry, err := nodedir.NewRegistry(policy)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("verified only %d of %d required seed views: %w", successes, config.MinSeedResponses, errors.Join(failures...))
	}
	return registry.Active(now), nil
}

// ConnectDirectoryRecords verifies that each contacted endpoint presents the
// exact hybrid identity admitted by the directory. Limit prevents a directory
// response from making the client dial an unbounded number of nodes.
func ConnectDirectoryRecords(ctx context.Context, records []nodedir.Record, limit int, httpClient *http.Client) ([]*HTTPNode, error) {
	if limit <= 0 || limit > MaxClientNodes || len(records) > nodedir.MaxDirectoryNodes {
		return nil, errors.New("invalid directory connection limit")
	}
	if len(records) > limit {
		records = records[:limit]
	}
	nodes := make([]*HTTPNode, 0, len(records))
	for _, record := range records {
		var node *HTTPNode
		var err error
		if record.Announcement.Endpoint.Scheme == "http" {
			node, err = DiscoverHTTPNodeForDevelopment(ctx, record.Announcement.Endpoint.BaseURL(), httpClient)
		} else {
			node, err = ConnectPinnedHTTPNode(ctx, record.Announcement.Endpoint.BaseURL(), record.Announcement.Identity, httpClient)
		}
		if err != nil {
			continue
		}
		if node.Identity.NodeID != record.Announcement.Identity.NodeID {
			continue
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, errors.New("no admitted directory node was reachable")
	}
	return nodes, nil
}
