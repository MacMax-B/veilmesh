package nodedir

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
)

func TestAgentRunPropagatesInitialSynchronizationFailure(t *testing.T) {
	syncFailure := errors.New("directory unavailable")
	agent := newRunTestAgent(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, syncFailure
	}))

	err := agent.Run(context.Background(), time.Minute)
	if !errors.Is(err, syncFailure) {
		t.Fatalf("Run returned %v, want the initial synchronization failure", err)
	}
}

func TestAgentRunPropagatesPeriodicSynchronizationFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	signer := testSigner(t)
	snapshot, err := SignSnapshot(signer, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("periodic directory failure")
	firstRequest := make(chan struct{})
	var requests atomic.Uint32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(firstRequest)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       ioNopCloser{bytes.NewReader(encoded)},
			}, nil
		}
		return nil, syncFailure
	})}
	agent := newRunTestAgentWithSigner(t, signer, client)
	ticks := make(chan time.Time, 1)
	result := make(chan error, 1)
	go func() { result <- agent.run(context.Background(), now, ticks) }()

	select {
	case <-firstRequest:
	case <-time.After(time.Second):
		t.Fatal("initial synchronization did not run")
	}
	ticks <- now.Add(time.Minute)
	select {
	case err := <-result:
		if !errors.Is(err, syncFailure) {
			t.Fatalf("run returned %v, want the periodic synchronization failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic synchronization failure was ignored")
	}
}

func TestAgentRunReturnsCanceledContextWithoutNetworkWork(t *testing.T) {
	var requests atomic.Uint32
	agent := newRunTestAgent(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, request.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := agent.Run(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if requests.Load() != 0 {
		t.Fatal("Run performed directory I/O after cancellation")
	}
}

func TestAgentRunRejectsIntervalLongerThanHalfConfiguredLease(t *testing.T) {
	var requests atomic.Uint32
	agent := newRunTestAgent(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	}))

	if err := agent.Run(context.Background(), MinLease/2+time.Nanosecond); err == nil {
		t.Fatal("Run accepted an interval longer than half its configured lease")
	}
	if requests.Load() != 0 {
		t.Fatal("Run performed directory I/O before rejecting its interval")
	}
}

func newRunTestAgent(t *testing.T, transport http.RoundTripper) *Agent {
	t.Helper()
	return newRunTestAgentWithSigner(t, testSigner(t), &http.Client{Transport: transport})
}

func newRunTestAgentWithSigner(t *testing.T, signer *pqcrypto.HybridSigner, client *http.Client) *Agent {
	t.Helper()
	seed := testSeed(signer, "127.0.0.1", 8787)
	policy, err := NewPolicy([]PinnedNode{seed}, 1, true, MaxDirectoryNodes)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(policy, seed.Endpoint, signer, MinLease, client, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return agent
}
