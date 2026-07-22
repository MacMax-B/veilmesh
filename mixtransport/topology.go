package mixtransport

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net/netip"
	"sort"
	"time"

	"github.com/MacMax-B/propagare/nodedir"
)

const (
	// FullRouteMixHops is fixed for ENIG-Mix v2. Changing it would create a
	// distinguishable traffic class and therefore requires a protocol version.
	FullRouteMixHops = 3
	// FullRouteReplicas matches the full-node reference replication profile.
	FullRouteReplicas  = 3
	fullRouteNodeCount = FullRouteMixHops + 1 + FullRouteReplicas
)

var ErrInsufficientRouteDiversity = errors.New("insufficient independently addressable full nodes for an ENIG-Mix route")

// FullRoute assigns temporary duties to otherwise identical full nodes. Every
// directory record is eligible for every duty; no permanent network role is
// encoded in the directory. A node may appear at most once in the assignment.
type FullRoute struct {
	Mixes    [FullRouteMixHops]nodedir.Record
	Courier  nodedir.Record
	Replicas [FullRouteReplicas]nodedir.Record
}

// SelectFullRoute verifies the complete candidate set before randomness or
// selection. It then assigns three mix hops, one courier and three replicas
// from distinct node identities and distinct coarse IP prefixes. Prefix
// diversity is only a topological safeguard; it is not proof of independent
// ownership and must later be combined with operator-diversity attestations.
func SelectFullRoute(policy nodedir.Policy, records []nodedir.Record, now time.Time, entropy io.Reader) (FullRoute, error) {
	if entropy == nil || now.IsZero() || len(records) < fullRouteNodeCount || len(records) > nodedir.MaxDirectoryNodes {
		return FullRoute{}, ErrInsufficientRouteDiversity
	}
	candidates := make([]nodedir.Record, len(records))
	seenNodes := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := nodedir.VerifyRecord(policy, record, now); err != nil {
			return FullRoute{}, err
		}
		nodeID := record.Announcement.Identity.NodeID
		if _, duplicate := seenNodes[nodeID]; duplicate {
			return FullRoute{}, errors.New("duplicate full node in route candidate set")
		}
		seenNodes[nodeID] = struct{}{}
		candidates[index] = nodedir.CloneRecord(record)
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].Announcement.Identity.NodeID < candidates[right].Announcement.Identity.NodeID
	})
	if err := shuffleRecords(entropy, candidates); err != nil {
		return FullRoute{}, err
	}

	selected := make([]nodedir.Record, 0, fullRouteNodeCount)
	seenDomains := make(map[netip.Prefix]struct{}, fullRouteNodeCount)
	for _, candidate := range candidates {
		domain, err := routeNetworkDomain(candidate.Announcement.Endpoint.IP)
		if err != nil {
			return FullRoute{}, err
		}
		if _, duplicate := seenDomains[domain]; duplicate {
			continue
		}
		seenDomains[domain] = struct{}{}
		selected = append(selected, candidate)
		if len(selected) == fullRouteNodeCount {
			break
		}
	}
	if len(selected) != fullRouteNodeCount {
		return FullRoute{}, ErrInsufficientRouteDiversity
	}

	var route FullRoute
	copy(route.Mixes[:], selected[:FullRouteMixHops])
	route.Courier = selected[FullRouteMixHops]
	copy(route.Replicas[:], selected[FullRouteMixHops+1:])
	return route, nil
}

func shuffleRecords(entropy io.Reader, records []nodedir.Record) error {
	for upper := len(records); upper > 1; upper-- {
		selected, err := rand.Int(entropy, big.NewInt(int64(upper)))
		if err != nil {
			return err
		}
		index := int(selected.Int64())
		records[index], records[upper-1] = records[upper-1], records[index]
	}
	return nil
}

func routeNetworkDomain(rawIP string) (netip.Prefix, error) {
	address, err := netip.ParseAddr(rawIP)
	if err != nil || address.Zone() != "" {
		return netip.Prefix{}, errors.New("route candidate has an invalid IP address")
	}
	address = address.Unmap()
	bits := 48
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked(), nil
}
