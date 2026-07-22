package nodedir

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"

	"veilmesh/pqcrypto"
)

type Registry struct {
	policy  Policy
	mu      sync.RWMutex
	records map[string]Record
}

func NewRegistry(policy Policy) (*Registry, error) {
	validated, err := NewPolicy(policy.Seeds, policy.AuthorityQuorum, policy.AllowPrivateIPs, policy.MaxNodes)
	if err != nil {
		return nil, err
	}
	return &Registry{policy: validated, records: make(map[string]Record)}, nil
}

func (registry *Registry) Policy() Policy {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	seeds := make([]PinnedNode, len(registry.policy.Seeds))
	for index := range registry.policy.Seeds {
		seeds[index] = clonePinnedNode(registry.policy.Seeds[index])
	}
	return Policy{
		Seeds: seeds, AuthorityQuorum: registry.policy.AuthorityQuorum,
		AllowPrivateIPs: registry.policy.AllowPrivateIPs, MaxNodes: registry.policy.MaxNodes,
	}
}

// Merge validates every signature before changing state. The monotonically
// increasing sequence prevents rollback to an older lease for the same node.
func (registry *Registry) Merge(record Record, now time.Time) error {
	if registry == nil {
		return errors.New("node registry is unavailable")
	}
	if err := VerifyRecord(registry.policy, record, now); err != nil {
		return err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return mergeVerifiedRecord(registry.records, registry.policy.MaxNodes, record)
}

func mergeVerifiedRecord(records map[string]Record, maxNodes int, record Record) error {
	nodeID := record.Announcement.Identity.NodeID
	existing, exists := records[nodeID]
	if !exists && len(records) >= maxNodes {
		return errors.New("node registry is full")
	}
	if exists {
		switch {
		case record.Announcement.Sequence < existing.Announcement.Sequence:
			return errors.New("node announcement sequence rollback")
		case record.Announcement.Sequence == existing.Announcement.Sequence:
			if !bytes.Equal(AnnouncementHash(record.Announcement), AnnouncementHash(existing.Announcement)) {
				return errors.New("conflicting node announcement sequence")
			}
			for _, attestation := range existing.Attestations {
				record = appendAttestation(record, attestation)
			}
		}
	}
	records[nodeID] = cloneRecord(record)
	return nil
}

func (registry *Registry) Active(now time.Time) []Record {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	records := make([]Record, 0, len(registry.records))
	for _, record := range registry.records {
		if record.Announcement.ExpiresAt.After(now) {
			records = append(records, cloneRecord(record))
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Announcement.Identity.NodeID < records[j].Announcement.Identity.NodeID
	})
	return records
}

func (registry *Registry) Sweep(now time.Time) int {
	if registry == nil {
		return 0
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	removed := 0
	for nodeID, record := range registry.records {
		if !record.Announcement.ExpiresAt.After(now) {
			delete(registry.records, nodeID)
			removed++
		}
	}
	return removed
}

func SignSnapshot(signer Signer, records []Record, now time.Time) (Snapshot, error) {
	if signer == nil || now.IsZero() || len(records) > MaxDirectoryNodes {
		return Snapshot{}, errors.New("invalid node directory snapshot input")
	}
	copyRecords := make([]Record, len(records))
	for index := range records {
		copyRecords[index] = cloneRecord(records[index])
	}
	sort.Slice(copyRecords, func(i, j int) bool {
		return copyRecords[i].Announcement.Identity.NodeID < copyRecords[j].Announcement.Identity.NodeID
	})
	for index := 1; index < len(copyRecords); index++ {
		if copyRecords[index-1].Announcement.Identity.NodeID == copyRecords[index].Announcement.Identity.NodeID {
			return Snapshot{}, errors.New("duplicate node in directory snapshot")
		}
	}
	snapshot := Snapshot{
		Version: ProtocolVersion, Publisher: signer.PublicIdentity(), GeneratedAt: now.UTC().Truncate(time.Millisecond), Records: copyRecords,
	}
	var err error
	snapshot.Signature, err = signer.Sign(snapshotDomain, snapshotSigningBytes(snapshot))
	return snapshot, err
}

func VerifySnapshotHeader(snapshot Snapshot, expectedPublisherID string, now time.Time, maxNodes int) error {
	if maxNodes <= 0 || maxNodes > MaxDirectoryNodes {
		maxNodes = MaxDirectoryNodes
	}
	if snapshot.Version != ProtocolVersion || len(snapshot.Records) > maxNodes ||
		!pqcrypto.ValidPublicIdentity(snapshot.Publisher) || snapshot.Publisher.NodeID != expectedPublisherID ||
		snapshot.GeneratedAt.Before(now.Add(-MaxClockSkew)) || snapshot.GeneratedAt.After(now.Add(MaxClockSkew)) {
		return errors.New("invalid node directory snapshot")
	}
	for index := 1; index < len(snapshot.Records); index++ {
		if snapshot.Records[index-1].Announcement.Identity.NodeID >= snapshot.Records[index].Announcement.Identity.NodeID {
			return errors.New("node directory snapshot is not uniquely sorted")
		}
	}
	if !pqcrypto.Verify(snapshot.Publisher, snapshotDomain, snapshotSigningBytes(snapshot), snapshot.Signature) {
		return errors.New("invalid node directory snapshot signature")
	}
	return nil
}

func (registry *Registry) MergeSnapshot(snapshot Snapshot, expectedPublisherID string, now time.Time) error {
	if registry == nil {
		return errors.New("node registry is unavailable")
	}
	if err := VerifySnapshotHeader(snapshot, expectedPublisherID, now, registry.policy.MaxNodes); err != nil {
		return err
	}
	// Validate the complete response first, so a malformed tail cannot cause a
	// partially accepted view.
	for _, record := range snapshot.Records {
		if err := VerifyRecord(registry.policy, record, now); err != nil {
			return err
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	updated := make(map[string]Record, len(registry.records)+len(snapshot.Records))
	for nodeID, record := range registry.records {
		updated[nodeID] = cloneRecord(record)
	}
	for _, record := range snapshot.Records {
		if err := mergeVerifiedRecord(updated, registry.policy.MaxNodes, record); err != nil {
			return err
		}
	}
	registry.records = updated
	return nil
}

func snapshotSigningBytes(snapshot Snapshot) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(snapshot.Version)
	writeIdentity(&buffer, snapshot.Publisher)
	writeTime(&buffer, snapshot.GeneratedAt)
	_ = binary.Write(&buffer, binary.BigEndian, uint32(len(snapshot.Records))) // #nosec G115 -- MaxDirectoryNodes bound.
	for _, record := range snapshot.Records {
		writeBytes(&buffer, announcementSigningBytes(record.Announcement))
		writeBytes(&buffer, signatureBytes(record.Announcement.Signature))
		_ = binary.Write(&buffer, binary.BigEndian, uint16(len(record.Attestations))) // #nosec G115 -- MaxAttestations bound.
		for _, attestation := range record.Attestations {
			writeBytes(&buffer, attestationSigningBytes(attestation))
			writeBytes(&buffer, signatureBytes(attestation.Signature))
		}
	}
	return buffer.Bytes()
}
