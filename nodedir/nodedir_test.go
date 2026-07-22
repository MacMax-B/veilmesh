package nodedir

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/pqcrypto"
)

func testSigner(t *testing.T) *pqcrypto.HybridSigner {
	t.Helper()
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testSeed(signer *pqcrypto.HybridSigner, ip string, port uint16) PinnedNode {
	return PinnedNode{Identity: signer.PublicIdentity(), Endpoint: Endpoint{Scheme: "http", IP: ip, Port: port}}
}

func TestPolicyRejectsUnboundedDuplicateAndNonIPSeeds(t *testing.T) {
	signer := testSigner(t)
	seed := testSeed(signer, "127.0.0.1", 8787)
	if _, err := NewPolicy([]PinnedNode{seed}, 1, true, MaxDirectoryNodes); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPolicy([]PinnedNode{seed, seed}, 1, true, MaxDirectoryNodes); err == nil {
		t.Fatal("duplicate seed identity was accepted")
	}
	if _, err := NewPolicy([]PinnedNode{seed}, 2, true, MaxDirectoryNodes); err == nil {
		t.Fatal("impossible seed quorum was accepted")
	}
	seed.Endpoint.IP = "seed.example"
	if _, err := NewPolicy([]PinnedNode{seed}, 1, true, MaxDirectoryNodes); err == nil {
		t.Fatal("DNS name was accepted as a node IP")
	}
	seed.Endpoint = Endpoint{Scheme: "https", IP: "127.0.0.1", Port: 8787}
	if _, err := NewPolicy([]PinnedNode{seed}, 1, false, MaxDirectoryNodes); err == nil {
		t.Fatal("private production seed was accepted")
	}
	seed.Endpoint.IP = "192.0.2.1"
	if _, err := NewPolicy([]PinnedNode{seed}, 1, false, MaxDirectoryNodes); err == nil {
		t.Fatal("non-routable documentation prefix was accepted")
	}
}

func TestHybridSignedQuorumLeaseRollbackAndExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	firstAuthority := testSigner(t)
	secondAuthority := testSigner(t)
	member := testSigner(t)
	policy, err := NewPolicy([]PinnedNode{
		testSeed(firstAuthority, "10.0.0.1", 8787),
		testSeed(secondAuthority, "10.0.0.2", 8787),
	}, 2, true, 8)
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := SignAnnouncement(member, Endpoint{Scheme: "http", IP: "10.0.0.3", Port: 8787}, 10, now, MinLease, true)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Announcement: announcement}
	if err := VerifyRecord(policy, record, now); err == nil {
		t.Fatal("unattested member was accepted")
	}
	first, _ := SignAttestation(firstAuthority, announcement, now)
	record = appendAttestation(record, first)
	if err := VerifyRecord(policy, record, now); err == nil {
		t.Fatal("one-of-two authority quorum was accepted")
	}
	second, _ := SignAttestation(secondAuthority, announcement, now)
	record = appendAttestation(record, second)
	if err := VerifyRecord(policy, record, now); err != nil {
		t.Fatal(err)
	}

	registry, _ := NewRegistry(policy)
	if err := registry.Merge(record, now); err != nil {
		t.Fatal(err)
	}
	older, _ := SignAnnouncement(member, announcement.Endpoint, 9, now, MinLease, true)
	olderRecord := Record{Announcement: older}
	olderFirst, _ := SignAttestation(firstAuthority, older, now)
	olderSecond, _ := SignAttestation(secondAuthority, older, now)
	olderRecord = appendAttestation(appendAttestation(olderRecord, olderFirst), olderSecond)
	if err := registry.Merge(olderRecord, now); err == nil {
		t.Fatal("announcement sequence rollback was accepted")
	}
	newcomer := testSigner(t)
	newAnnouncement, _ := SignAnnouncement(newcomer, Endpoint{Scheme: "http", IP: "10.0.0.4", Port: 8787}, 1, now, MinLease, true)
	newFirst, _ := SignAttestation(firstAuthority, newAnnouncement, now)
	newSecond, _ := SignAttestation(secondAuthority, newAnnouncement, now)
	newRecord := appendAttestation(appendAttestation(Record{Announcement: newAnnouncement}, newFirst), newSecond)
	conflictingSnapshot, _ := SignSnapshot(firstAuthority, []Record{newRecord, olderRecord}, now)
	if err := registry.MergeSnapshot(conflictingSnapshot, firstAuthority.PublicIdentity().NodeID, now); err == nil {
		t.Fatal("snapshot containing a sequence rollback was accepted")
	}
	if active := registry.Active(now); len(active) != 1 || active[0].Announcement.Identity.NodeID != member.PublicIdentity().NodeID {
		t.Fatal("failed snapshot partially mutated the registry")
	}
	tampered := cloneRecord(record)
	tampered.Attestations[0].AnnouncementHash[0] ^= 1
	if err := VerifyRecord(policy, tampered, now); err == nil {
		t.Fatal("tampered authority attestation was accepted")
	}
	if removed := registry.Sweep(announcement.ExpiresAt); removed != 1 || len(registry.Active(announcement.ExpiresAt)) != 0 {
		t.Fatal("expired node lease remained active")
	}
}

func TestSnapshotAuthenticatesCompleteSortedDirectory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	authority := testSigner(t)
	policy, err := NewPolicy([]PinnedNode{testSeed(authority, "10.1.0.1", 8787)}, 1, true, 8)
	if err != nil {
		t.Fatal(err)
	}
	announcement, _ := SignAnnouncement(authority, policy.Seeds[0].Endpoint, 1, now, MinLease, true)
	record := Record{Announcement: announcement}
	snapshot, err := SignSnapshot(authority, []Record{record}, now)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(policy)
	if err := registry.MergeSnapshot(snapshot, authority.PublicIdentity().NodeID, now); err != nil {
		t.Fatal(err)
	}
	tampered := snapshot
	tampered.Records = []Record{cloneRecord(record)}
	tampered.Records[0].Announcement.Endpoint.Port++
	if err := registry.MergeSnapshot(tampered, authority.PublicIdentity().NodeID, now); err == nil {
		t.Fatal("snapshot record tampering was accepted")
	}
	if err := VerifySnapshotHeader(snapshot, "different-publisher", now, 8); err == nil {
		t.Fatal("snapshot from an unexpected publisher was accepted")
	}
}

func TestHTTPProberRejectsRedirectAndForgedChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	signer := testSigner(t)
	announcement, _ := SignAnnouncement(signer, Endpoint{Scheme: "http", IP: "127.0.0.1", Port: 8787}, 1, now, MinLease, true)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var challenge ChallengeRequest
		if err := json.NewDecoder(request.Body).Decode(&challenge); err != nil {
			return nil, err
		}
		response, err := SignChallenge(signer, challenge.Nonce, now)
		if err != nil {
			return nil, err
		}
		response.Nonce[0] ^= 1
		encoded, _ := json.Marshal(response)
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: ioNopCloser{bytes.NewReader(encoded)}, Header: make(http.Header)}, nil
	})}
	if err := (&HTTPProber{Client: client}).Verify(context.Background(), announcement); err == nil {
		t.Fatal("forged reachability response was accepted")
	}
	redirecting := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Status: "302 Found", Body: ioNopCloser{bytes.NewReader(nil)}, Header: http.Header{"Location": []string{"http://127.0.0.1:9999"}}}, nil
	}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := (&HTTPProber{Client: redirecting}).Verify(context.Background(), announcement); err == nil {
		t.Fatal("redirecting reachability endpoint was accepted")
	}
}

func TestPinnedSeedParserRejectsUnknownTrailingAndOversize(t *testing.T) {
	if _, err := DecodePinnedNodes([]byte(`[{"identity":{},"endpoint":{},"unknown":true}]`)); err == nil {
		t.Fatal("unknown seed field was accepted")
	}
	if _, err := DecodePinnedNodes([]byte(`[] {}`)); err == nil {
		t.Fatal("trailing seed data was accepted")
	}
	if _, err := DecodePinnedNodes(make([]byte, MaxSeedFileBytes+1)); err == nil {
		t.Fatal("oversized seed file was accepted")
	}
}

func FuzzDecodePinnedNodes(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodePinnedNodes(data)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type ioNopCloser struct{ *bytes.Reader }

func (ioNopCloser) Close() error { return nil }
