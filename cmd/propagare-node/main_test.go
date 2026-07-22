package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/node"
	"github.com/MacMax-B/propagare/nodedir"
)

func TestNodeHTTPServerDiscardsTransportErrorMetadata(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	server := newNodeHTTPServer("127.0.0.1:0", http.NotFoundHandler(), tlsConfig)
	if server.ErrorLog == nil || server.ErrorLog.Writer() != io.Discard {
		t.Fatal("HTTP server error log could retain TLS peer metadata")
	}
	if server.TLSConfig == tlsConfig {
		t.Fatal("HTTP server retained a mutable caller-owned TLS config")
	}
}

func TestExpirySweepStopsWhenContextIsCanceled(t *testing.T) {
	store, err := node.NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		_ = runExpirySweep(ctx, time.Hour, store, nil)
	}()
	cancel()
	if err := waitForWorkers(&worker, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestExpirySweepFailureIsReturnedToLifecycle(t *testing.T) {
	store, err := node.NewDiskStore(t.TempDir(), 1024*1024, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runExpirySweep(ctx, time.Millisecond, store, nil); !errors.Is(err, node.ErrStoreClosed) {
		t.Fatalf("closed-store sweep returned %v, want ErrStoreClosed", err)
	}
}

func TestServeUntilContextRejectsMissingTLSBeforeStarting(t *testing.T) {
	server := &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler()}
	if err := serveUntilContext(context.Background(), server, 1, time.Second); err == nil {
		t.Fatal("server without TLS configuration was started")
	}
}

func TestDirectoryScheduleIsBoundToConfiguredLease(t *testing.T) {
	validLease := nodedir.MinLease
	if err := validateDirectorySchedule("203.0.113.1", 8787, validLease, validLease/2); err != nil {
		t.Fatalf("valid directory schedule was rejected: %v", err)
	}
	tests := []struct {
		name     string
		port     uint
		lease    time.Duration
		interval time.Duration
	}{
		{name: "zero port", port: 0, lease: validLease, interval: time.Minute},
		{name: "short lease", port: 8787, lease: nodedir.MinLease - time.Nanosecond, interval: time.Minute},
		{name: "long lease", port: 8787, lease: nodedir.MaxLease + time.Nanosecond, interval: time.Minute},
		{name: "short sync", port: 8787, lease: validLease, interval: time.Minute - time.Nanosecond},
		{name: "sync exceeds lease half", port: 8787, lease: validLease, interval: validLease/2 + time.Nanosecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateDirectorySchedule("203.0.113.1", test.port, test.lease, test.interval); err == nil {
				t.Fatal("invalid directory schedule was accepted")
			}
		})
	}
}

func TestConnectionLimitListenerBoundsAcceptedConnections(t *testing.T) {
	base := newQueuedListener()
	limited, err := newConnectionLimitListener(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()

	firstResult := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := limited.Accept()
		firstResult <- acceptResult{connection: connection, err: acceptErr}
	}()
	waitForAcceptCall(t, base.calls)
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	base.connections <- firstServer
	first := waitForAcceptResult(t, firstResult)
	if first.err != nil {
		t.Fatal(first.err)
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan acceptResult, 1)
	go func() {
		close(secondStarted)
		connection, acceptErr := limited.Accept()
		secondResult <- acceptResult{connection: connection, err: acceptErr}
	}()
	<-secondStarted
	select {
	case <-base.calls:
		t.Fatal("listener accepted another connection while its live limit was full")
	case <-time.After(50 * time.Millisecond):
	}

	if err := first.connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitForAcceptCall(t, base.calls)
	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	base.connections <- secondServer
	second := waitForAcceptResult(t, secondResult)
	if second.err != nil {
		t.Fatal(second.err)
	}
	if err := second.connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionLimitListenerRejectsUnsafeLimits(t *testing.T) {
	base := newQueuedListener()
	defer base.Close()
	for _, limit := range []int{0, -1, maxLiveConnectionLimit + 1} {
		if _, err := newConnectionLimitListener(base, limit); err == nil {
			t.Fatalf("connection limit %d was accepted", limit)
		}
	}
}

func TestConnectionLimitListenerCloseUnblocksPermitWaiter(t *testing.T) {
	base := newQueuedListener()
	limited, err := newConnectionLimitListener(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := limited.Accept()
		firstResult <- acceptResult{connection: connection, err: acceptErr}
	}()
	waitForAcceptCall(t, base.calls)
	firstServer, firstClient := net.Pipe()
	defer firstClient.Close()
	base.connections <- firstServer
	first := waitForAcceptResult(t, firstResult)
	if first.err != nil {
		t.Fatal(first.err)
	}
	defer first.connection.Close()

	blockedResult := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := limited.Accept()
		blockedResult <- acceptResult{connection: connection, err: acceptErr}
	}()
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}
	blocked := waitForAcceptResult(t, blockedResult)
	if !errors.Is(blocked.err, net.ErrClosed) {
		t.Fatalf("blocked Accept returned %v, want net.ErrClosed", blocked.err)
	}
}

type acceptResult struct {
	connection net.Conn
	err        error
}

type queuedListener struct {
	connections chan net.Conn
	calls       chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
}

func newQueuedListener() *queuedListener {
	return &queuedListener{
		connections: make(chan net.Conn),
		calls:       make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}
}

func (listener *queuedListener) Accept() (net.Conn, error) {
	select {
	case listener.calls <- struct{}{}:
	case <-listener.closed:
		return nil, net.ErrClosed
	}
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *queuedListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return nil
}

func (listener *queuedListener) Addr() net.Addr { return testAddress("queued-listener") }

type testAddress string

func (address testAddress) Network() string { return string(address) }
func (address testAddress) String() string  { return string(address) }

func waitForAcceptCall(t *testing.T, calls <-chan struct{}) {
	t.Helper()
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("listener did not call its underlying Accept")
	}
}

func waitForAcceptResult(t *testing.T, results <-chan acceptResult) acceptResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(time.Second):
		t.Fatal("listener Accept did not return")
		return acceptResult{}
	}
}
