package client

import (
	"sort"
	"sync"
	"time"
)

type NodeScore struct {
	NodeID           string    `json:"node_id"`
	SuccessfulStores uint64    `json:"successful_stores"`
	SuccessfulProofs uint64    `json:"successful_proofs"`
	Failures         uint64    `json:"failures"`
	ConsecutiveFails uint32    `json:"consecutive_failures"`
	ExcludedUntil    time.Time `json:"excluded_until"`
	LastFailure      string    `json:"last_failure,omitempty"`
}

type Reputation struct {
	mu     sync.RWMutex
	scores map[string]NodeScore
}

func NewReputation() *Reputation {
	return &Reputation{scores: make(map[string]NodeScore)}
}

func (r *Reputation) Success(nodeID string, proof bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	score := r.scores[nodeID]
	score.NodeID = nodeID
	score.ConsecutiveFails = 0
	if proof {
		score.SuccessfulProofs++
	} else {
		score.SuccessfulStores++
	}
	r.scores[nodeID] = score
}

func (r *Reputation) Failure(nodeID string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	score := r.scores[nodeID]
	score.NodeID = nodeID
	score.Failures++
	score.ConsecutiveFails++
	if err != nil {
		score.LastFailure = err.Error()
	}
	if score.ConsecutiveFails >= 3 {
		score.ExcludedUntil = time.Now().Add(24 * time.Hour)
	}
	r.scores[nodeID] = score
}

func (r *Reputation) Exclude(nodeID string, duration time.Duration, reason error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	score := r.scores[nodeID]
	score.NodeID = nodeID
	score.Failures++
	score.ConsecutiveFails++
	score.ExcludedUntil = time.Now().Add(duration)
	if reason != nil {
		score.LastFailure = reason.Error()
	}
	r.scores[nodeID] = score
}

func (r *Reputation) Allowed(nodeID string, now time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.scores[nodeID].ExcludedUntil.After(now)
}

func (r *Reputation) Snapshot() []NodeScore {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]NodeScore, 0, len(r.scores))
	for _, score := range r.scores {
		result = append(result, score)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NodeID < result[j].NodeID })
	return result
}
