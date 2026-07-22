package mixtransport

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/nodedir"
	"github.com/MacMax-B/propagare/pqcrypto"
)

func TestFullRouteUsesDistinctVerifiedFullNodes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	policy, records := fullRouteFixture(t, now, []string{
		"10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1", "10.0.4.1", "10.0.5.1", "10.0.6.1",
	})
	route, err := SelectFullRoute(policy, records, now, bytes.NewReader(make([]byte, 128)))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, fullRouteNodeCount)
	for _, record := range append(append(route.Mixes[:], route.Courier), route.Replicas[:]...) {
		nodeID := record.Announcement.Identity.NodeID
		if _, duplicate := seen[nodeID]; duplicate {
			t.Fatal("full node was assigned more than one duty in the same route")
		}
		seen[nodeID] = struct{}{}
	}
	if len(seen) != fullRouteNodeCount {
		t.Fatalf("route contains %d nodes, want %d", len(seen), fullRouteNodeCount)
	}

	// Returned routes must not alias caller-owned directory records.
	selectedID := route.Mixes[0].Announcement.Identity.NodeID
	selectedIndex := -1
	for index := range records {
		if records[index].Announcement.Identity.NodeID == selectedID {
			selectedIndex = index
			break
		}
	}
	if selectedIndex < 0 {
		t.Fatal("selected mix was not present in the candidate set")
	}
	before := records[selectedIndex].Announcement.Identity.Ed25519Public[0]
	route.Mixes[0].Announcement.Identity.Ed25519Public[0] ^= 1
	if records[selectedIndex].Announcement.Identity.Ed25519Public[0] != before {
		t.Fatal("selected route aliases caller-owned directory identity bytes")
	}
}

func TestFullRouteRejectsInvalidDuplicateAndTopologicallyCollapsedCandidates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	policy, records := fullRouteFixture(t, now, []string{
		"10.1.0.1", "10.1.1.1", "10.1.2.1", "10.1.3.1", "10.1.4.1", "10.1.5.1", "10.1.6.1",
	})

	tampered := append([]nodedir.Record(nil), records...)
	tampered[0] = nodedir.CloneRecord(tampered[0])
	tampered[0].Announcement.Endpoint.Port++
	if _, err := SelectFullRoute(policy, tampered, now, bytes.NewReader(make([]byte, 128))); err == nil {
		t.Fatal("route selection accepted a tampered directory record")
	}

	duplicate := append([]nodedir.Record(nil), records...)
	duplicate[len(duplicate)-1] = nodedir.CloneRecord(duplicate[0])
	if _, err := SelectFullRoute(policy, duplicate, now, bytes.NewReader(make([]byte, 128))); err == nil {
		t.Fatal("route selection accepted a duplicate node identity")
	}

	collapsedPolicy, collapsed := fullRouteFixture(t, now, []string{
		"10.2.0.1", "10.2.0.2", "10.2.0.3", "10.2.0.4", "10.2.0.5", "10.2.0.6", "10.2.0.7",
	})
	if _, err := SelectFullRoute(collapsedPolicy, collapsed, now, bytes.NewReader(make([]byte, 128))); !errors.Is(err, ErrInsufficientRouteDiversity) {
		t.Fatalf("collapsed route returned %v, want ErrInsufficientRouteDiversity", err)
	}
}

func TestFullRouteRejectsMissingOrFailingEntropy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	policy, records := fullRouteFixture(t, now, []string{
		"10.3.0.1", "10.3.1.1", "10.3.2.1", "10.3.3.1", "10.3.4.1", "10.3.5.1", "10.3.6.1",
	})
	if _, err := SelectFullRoute(policy, records, now, nil); !errors.Is(err, ErrInsufficientRouteDiversity) {
		t.Fatalf("nil entropy returned %v", err)
	}
	if _, err := SelectFullRoute(policy, records, now, failingReader{}); err == nil {
		t.Fatal("route selection ignored an entropy failure")
	}
}

func fullRouteFixture(t *testing.T, now time.Time, addresses []string) (nodedir.Policy, []nodedir.Record) {
	t.Helper()
	if len(addresses) != fullRouteNodeCount {
		t.Fatalf("fixture has %d addresses, want %d", len(addresses), fullRouteNodeCount)
	}
	seeds := make([]nodedir.PinnedNode, len(addresses))
	signers := make([]*pqcrypto.HybridSigner, len(addresses))
	for index, address := range addresses {
		signer, err := pqcrypto.GenerateHybridSigner()
		if err != nil {
			t.Fatal(err)
		}
		signers[index] = signer
		seeds[index] = nodedir.PinnedNode{
			Identity: signer.PublicIdentity(),
			Endpoint: nodedir.Endpoint{Scheme: "http", IP: address, Port: uint16(8700 + index)},
		}
	}
	policy, err := nodedir.NewPolicy(seeds, 1, true, nodedir.MaxDirectoryNodes)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]nodedir.Record, len(seeds))
	for index, seed := range seeds {
		announcement, signErr := nodedir.SignAnnouncement(signers[index], seed.Endpoint, 1, now, nodedir.MinLease, true)
		if signErr != nil {
			t.Fatal(signErr)
		}
		records[index] = nodedir.Record{Announcement: announcement}
	}
	return policy, records
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
