package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/MacMax-B/propagare/internal/releaseinfo"
	"github.com/MacMax-B/propagare/node"
	"github.com/MacMax-B/propagare/nodedir"
	"github.com/MacMax-B/propagare/protocol"
	"github.com/MacMax-B/propagare/transportauth"
)

const (
	gracefulShutdownTimeout = 15 * time.Second
	maxLiveConnectionLimit  = 4096
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (returnErr error) {
	config := node.DefaultConfig()
	flag.StringVar(&config.ListenAddress, "listen", config.ListenAddress, "listen address")
	flag.StringVar(&config.DataDir, "data", config.DataDir, "encrypted item data directory")
	flag.StringVar(&config.KeyFile, "key", config.KeyFile, "node signing key path")
	difficulty := flag.Uint("difficulty", uint(config.BaseDifficulty), "minimum postage proof difficulty")
	flag.Int64Var(&config.StorageCapacity, "capacity", config.StorageCapacity, "storage capacity in bytes")
	advertiseIP := flag.String("advertise-ip", "", "literal public IP advertised in the signed node directory")
	advertisePort := flag.Uint("advertise-port", 8787, "TCP port advertised in the signed node directory")
	seedFile := flag.String("node-seeds", "./propagare-seeds.json", "pinned standard node list shared by clients and nodes")
	directoryQuorum := flag.Int("node-quorum", 3, "number of pinned seed attestations required for admission")
	directoryLease := flag.Duration("node-lease", time.Hour, "signed node lease lifetime")
	directorySync := flag.Duration("node-sync", 10*time.Minute, "node-directory reconciliation interval")
	allowPrivateNodeIPs := flag.Bool("allow-private-node-ips", false, "allow private IPs in the signed directory for local development only")
	initializeEmptyStore := flag.Bool("initialize-empty-store", false, "explicitly bind an existing node key to a new empty data directory")
	showVersion := flag.Bool("version", false, "print release version and exit")
	flag.Parse()
	if *showVersion {
		_, err := fmt.Printf("propagare-node %s\n", releaseinfo.String())
		return err
	}
	if *difficulty > uint(protocol.MaxWorkDifficulty-2) {
		return errors.New("difficulty exceeds protocol maximum")
	}
	config.BaseDifficulty = uint8(*difficulty) // #nosec G115 -- checked against the uint8 protocol maximum above.
	if err := validateDirectorySchedule(*advertiseIP, *advertisePort, *directoryLease, *directorySync); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	store, err := node.NewDiskStore(config.DataDir, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, store.Close()) }()
	_, storeIsBound := store.BoundIdentity()
	if !storeIsBound && !store.IdentityInitializationAllowed() {
		return node.ErrUnboundStore
	}
	signerLease, err := node.AcquireNodeSigner(config.KeyFile, !storeIsBound)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, signerLease.Close()) }()
	if !storeIsBound && !signerLease.Created && !*initializeEmptyStore {
		return errors.New("existing node key requires --initialize-empty-store before binding a new empty data directory")
	}
	signer := signerLease.Signer
	transportTLS, err := transportauth.ServerTLSConfigForSigner(signer)
	if err != nil {
		return err
	}
	server, err := node.NewServer(config, store, signer)
	if err != nil {
		return err
	}
	var directoryAgent *nodedir.Agent
	if *advertiseIP != "" {
		seeds, loadErr := nodedir.LoadPinnedNodes(*seedFile)
		if loadErr != nil {
			return loadErr
		}
		policy, policyErr := nodedir.NewPolicy(seeds, *directoryQuorum, *allowPrivateNodeIPs, nodedir.MaxDirectoryNodes)
		if policyErr != nil {
			return policyErr
		}
		directoryAgent, err = nodedir.NewAgent(policy, nodedir.Endpoint{
			Scheme: "https", IP: *advertiseIP, Port: uint16(*advertisePort), // #nosec G115 -- range checked above.
		}, signer, *directoryLease, nil, nil, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := server.EnableDirectory(directoryAgent); err != nil {
			return err
		}
	}

	httpServer := newNodeHTTPServer(config.ListenAddress, server.Handler(), transportTLS)
	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runContext, cancelRun := context.WithCancelCause(signalContext)
	defer cancelRun(context.Canceled)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		if runErr := runExpirySweep(runContext, config.SweepInterval, store, directoryAgent); runErr != nil && !errors.Is(runErr, context.Canceled) {
			cancelRun(errors.New("expiry sweep stopped unexpectedly"))
		}
	}()
	if directoryAgent != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if runErr := directoryAgent.Run(runContext, *directorySync); runErr != nil && !errors.Is(runErr, context.Canceled) {
				cancelRun(errors.New("node directory synchronization stopped unexpectedly"))
			}
		}()
	}

	log.Printf("propagare node %s listening with CA-PKI-free pinned TLS on %s", signer.PublicIdentity().NodeID, config.ListenAddress)
	serveErr := serveUntilContext(runContext, httpServer, config.MaxConcurrentRequests, gracefulShutdownTimeout)
	lifecycleErr := context.Cause(runContext)
	cancelRun(context.Canceled)
	if err := waitForWorkers(&workers, gracefulShutdownTimeout); err != nil {
		_ = httpServer.Close()
		return errors.Join(serveErr, lifecycleFailure(lifecycleErr), err)
	}
	return errors.Join(serveErr, lifecycleFailure(lifecycleErr))
}

func validateDirectorySchedule(advertiseIP string, advertisePort uint, lease, interval time.Duration) error {
	if advertiseIP == "" {
		return nil
	}
	if advertisePort == 0 || advertisePort > 65535 {
		return errors.New("advertise-port is out of range")
	}
	if lease < nodedir.MinLease || lease > nodedir.MaxLease {
		return errors.New("node-lease is out of range")
	}
	if interval < time.Minute || interval > lease/2 {
		return errors.New("node-sync must be between one minute and half the node lease")
	}
	return nil
}

func newNodeHTTPServer(address string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         tlsConfig.Clone(),
		// net/http includes the peer IP in TLS handshake failures. Discarding
		// its internal error stream prevents those transport metadata records.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func runExpirySweep(ctx context.Context, interval time.Duration, store *node.DiskStore, directoryAgent *nodedir.Agent) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if err := store.SweepContext(ctx, now); err != nil {
				return err
			}
			if directoryAgent != nil {
				directoryAgent.Registry().Sweep(now)
			}
		}
	}
}

func lifecycleFailure(cause error) error {
	if cause == nil || errors.Is(cause, context.Canceled) {
		return nil
	}
	return cause
}

func serveUntilContext(ctx context.Context, server *http.Server, maxConnections int, timeout time.Duration) error {
	if server == nil || server.TLSConfig == nil {
		return errors.New("TLS HTTP server is unavailable")
	}
	if maxConnections <= 0 || maxConnections > maxLiveConnectionLimit {
		return errors.New("invalid live TLS connection limit")
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	limitedListener, err := newConnectionLimitListener(listener, maxConnections)
	if err != nil {
		_ = listener.Close()
		return err
	}
	tlsListener := tls.NewListener(limitedListener, server.TLSConfig)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(tlsListener) }()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), timeout)
	defer cancelShutdown()
	shutdownErr := server.Shutdown(shutdownContext)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	var serveErr error
	select {
	case serveErr = <-serveErrors:
	case <-shutdownContext.Done():
		_ = server.Close()
		return errors.Join(shutdownErr, shutdownContext.Err())
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(shutdownErr, serveErr)
}

type connectionLimitListener struct {
	listener  net.Listener
	permits   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newConnectionLimitListener(listener net.Listener, limit int) (*connectionLimitListener, error) {
	if listener == nil || limit <= 0 || limit > maxLiveConnectionLimit {
		return nil, errors.New("invalid live connection listener configuration")
	}
	return &connectionLimitListener{
		listener: listener,
		permits:  make(chan struct{}, limit),
		closed:   make(chan struct{}),
	}, nil
}

func (listener *connectionLimitListener) Accept() (net.Conn, error) {
	select {
	case listener.permits <- struct{}{}:
	case <-listener.closed:
		return nil, net.ErrClosed
	}
	connection, err := listener.listener.Accept()
	if err != nil {
		<-listener.permits
		return nil, err
	}
	return &connectionLimitConn{Conn: connection, release: func() { <-listener.permits }}, nil
}

func (listener *connectionLimitListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.closed)
		listener.closeErr = listener.listener.Close()
	})
	return listener.closeErr
}

func (listener *connectionLimitListener) Addr() net.Addr { return listener.listener.Addr() }

type connectionLimitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (connection *connectionLimitConn) Close() error {
	err := connection.Conn.Close()
	connection.releaseOnce.Do(connection.release)
	return err
}

func waitForWorkers(workers *sync.WaitGroup, timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("background workers did not stop before the shutdown deadline")
	}
}
