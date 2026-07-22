package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"veilmesh/node"
	"veilmesh/nodedir"
	"veilmesh/protocol"
	"veilmesh/transportauth"
)

func main() {
	config := node.DefaultConfig()
	flag.StringVar(&config.ListenAddress, "listen", config.ListenAddress, "listen address")
	flag.StringVar(&config.DataDir, "data", config.DataDir, "encrypted item data directory")
	flag.StringVar(&config.KeyFile, "key", config.KeyFile, "node signing key path")
	difficulty := flag.Uint("difficulty", uint(config.BaseDifficulty), "minimum postage proof difficulty")
	flag.Int64Var(&config.StorageCapacity, "capacity", config.StorageCapacity, "storage capacity in bytes")
	advertiseIP := flag.String("advertise-ip", "", "literal public IP advertised in the signed node directory")
	advertisePort := flag.Uint("advertise-port", 8787, "TCP port advertised in the signed node directory")
	seedFile := flag.String("node-seeds", "./veilmesh-seeds.json", "pinned standard node list shared by clients and nodes")
	directoryQuorum := flag.Int("node-quorum", 3, "number of pinned seed attestations required for admission")
	directoryLease := flag.Duration("node-lease", time.Hour, "signed node lease lifetime")
	directorySync := flag.Duration("node-sync", 10*time.Minute, "node-directory reconciliation interval")
	allowPrivateNodeIPs := flag.Bool("allow-private-node-ips", false, "allow private IPs in the signed directory for local development only")
	flag.Parse()
	if *difficulty > uint(protocol.MaxWorkDifficulty-2) {
		log.Fatal("difficulty exceeds protocol maximum")
	}
	config.BaseDifficulty = uint8(*difficulty) // #nosec G115 -- checked against the uint8 protocol maximum above.
	if err := config.Validate(); err != nil {
		log.Fatal(err)
	}
	signer, err := node.LoadOrCreateSigner(config.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	transportTLS, err := transportauth.ServerTLSConfigForSigner(signer)
	if err != nil {
		log.Fatal(err)
	}
	store, err := node.NewDiskStore(config.DataDir, config.StorageCapacity, config.MailboxQuota)
	if err != nil {
		log.Fatal(err)
	}
	server, err := node.NewServer(config, store, signer)
	if err != nil {
		log.Fatal(err)
	}
	var directoryAgent *nodedir.Agent
	if *advertiseIP != "" {
		if *advertisePort == 0 || *advertisePort > 65535 {
			log.Fatal("advertise-port is out of range")
		}
		seeds, loadErr := nodedir.LoadPinnedNodes(*seedFile)
		if loadErr != nil {
			log.Fatal(loadErr)
		}
		policy, policyErr := nodedir.NewPolicy(seeds, *directoryQuorum, *allowPrivateNodeIPs, nodedir.MaxDirectoryNodes)
		if policyErr != nil {
			log.Fatal(policyErr)
		}
		directoryAgent, err = nodedir.NewAgent(policy, nodedir.Endpoint{
			Scheme: "https", IP: *advertiseIP, Port: uint16(*advertisePort), // #nosec G115 -- range checked above.
		}, signer, *directoryLease, nil, nil, time.Now().UTC())
		if err != nil {
			log.Fatal(err)
		}
		if err := server.EnableDirectory(directoryAgent); err != nil {
			log.Fatal(err)
		}
		go func() {
			if runErr := directoryAgent.Run(context.Background(), *directorySync); runErr != nil {
				log.Printf("node directory stopped: %v", runErr)
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(config.SweepInterval)
		defer ticker.Stop()
		for now := range ticker.C {
			if err := store.Sweep(now); err != nil {
				log.Printf("expiry sweep: %v", err)
			}
			if directoryAgent != nil {
				directoryAgent.Registry().Sweep(now)
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         transportTLS,
	}
	log.Printf("veilmesh node %s listening with CA-PKI-free pinned TLS on %s", signer.PublicIdentity().NodeID, config.ListenAddress)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
