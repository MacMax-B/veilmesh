package client

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"veilmesh/node"
	"veilmesh/pqcrypto"
	"veilmesh/transportauth"
)

func TestDirectMessageReplicatesFallsBackAuditsAndDeletes(t *testing.T) {
	ctx := context.Background()
	servers := make([]*httptest.Server, 0, 4)
	stores := make([]*node.DiskStore, 0, 4)
	nodes := make([]*HTTPNode, 0, 4)
	for range 4 {
		config := node.DefaultConfig()
		config.DataDir = t.TempDir()
		config.BaseDifficulty = 8
		config.StorageCapacity = 32 * 1024 * 1024
		signer, err := pqcrypto.GenerateHybridSigner()
		if err != nil {
			t.Fatal(err)
		}
		store, err := node.NewDiskStore(config.DataDir, config.StorageCapacity, config.MailboxQuota)
		if err != nil {
			t.Fatal(err)
		}
		stores = append(stores, store)
		nodeServer, err := node.NewServer(config, store, signer)
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig, err := transportauth.ServerTLSConfigForSigner(signer)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(nodeServer.Handler())
		server.TLS = tlsConfig
		server.StartTLS()
		servers = append(servers, server)
		descriptor, err := ConnectPinnedHTTPNode(ctx, server.URL, signer.PublicIdentity(), server.Client())
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, descriptor)
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
		for _, store := range stores {
			_ = store.Close()
		}
	}()
	// Break a primary node after discovery. The fourth candidate must replace it.
	servers[0].Close()

	core, err := New(Config{Nodes: nodes, Replicas: 3, WriteQuorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := pqcrypto.GenerateHybridKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	routeTag, _ := RandomCapability()
	plaintext := []byte("private hello")
	delivery, err := core.SendDirect(ctx, recipient.PublicKey, routeTag, plaintext, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Receipts) != 3 {
		t.Fatalf("expected repaired replica set of 3, got %d", len(delivery.Receipts))
	}
	items, err := core.Fetch(ctx, []string{routeTag})
	if err != nil || len(items) != 1 {
		t.Fatalf("fetch: items=%d err=%v", len(items), err)
	}
	opened, err := OpenDirectItem(recipient.PrivateKey, items[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("opened message differs")
	}
	for nodeID, err := range core.Audit(ctx, delivery) {
		if err != nil {
			t.Fatalf("audit %s: %v", nodeID, err)
		}
	}
	for nodeID, err := range core.Delete(ctx, delivery) {
		if err != nil {
			t.Fatalf("delete %s: %v", nodeID, err)
		}
	}
	items, err = core.Fetch(ctx, []string{routeTag})
	if err != nil || len(items) != 0 {
		t.Fatalf("deleted item still fetched: items=%d err=%v", len(items), err)
	}
}
