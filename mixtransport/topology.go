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

var ErrFullMixRequired = errors.New("a validated full ENIG-Mix route is required")

type RouteRequirement uint8

const (
	// AllowDirectBootstrap is an explicit early-network opt-in. The resulting
	// direct route encrypts content but provides no metadata anonymity.
	AllowDirectBootstrap RouteRequirement = iota + 1
	// RequireFullMix is the fail-closed setting for users who demand metadata
	// protection and for clients that have persisted a previous security upgrade.
	RequireFullMix
)

type OperationalRouteMode uint8

const (
	OperationalRouteDirectBootstrap OperationalRouteMode = iota + 1
	OperationalRouteFullMix
)

// MixReadiness can only be obtained from a Scheduler. Selection revalidates the
// referenced provider and sink so retaining this token cannot bypass a later
// assurance failure. It remains an integration guard, not cryptographic
// evidence that the named audit is sound.
type MixReadiness struct{ scheduler *Scheduler }

// OperationalRoute keeps the direct bootstrap path structurally separate from
// the full assignment so callers cannot accidentally describe a one-node path
// as a mix. Exactly one of Bootstrap or Full is meaningful according to Mode.
type OperationalRoute struct {
	Mode      OperationalRouteMode
	Bootstrap nodedir.Record
	Full      FullRoute
}

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
	candidates, err := verifiedRouteCandidates(policy, records, now)
	if err != nil {
		return FullRoute{}, err
	}
	return selectFullRouteCandidates(candidates, entropy)
}

// SelectOperationalRoute automatically prefers a full assignment when both a
// validated Scheduler and seven diverse Full Nodes are available. Otherwise it
// returns one randomly selected, fully verified direct bootstrap Node only when
// the caller explicitly permits that non-anonymous mode. A caller that persists
// RequireFullMix can therefore never be silently downgraded by a smaller or
// topologically collapsed directory view.
func SelectOperationalRoute(
	policy nodedir.Policy,
	records []nodedir.Record,
	now time.Time,
	entropy io.Reader,
	readiness MixReadiness,
	requirement RouteRequirement,
) (OperationalRoute, error) {
	if entropy == nil || now.IsZero() || len(records) == 0 || len(records) > nodedir.MaxDirectoryNodes ||
		(requirement != AllowDirectBootstrap && requirement != RequireFullMix) {
		return OperationalRoute{}, errors.New("invalid operational route input")
	}
	candidates, err := verifiedRouteCandidates(policy, records, now)
	if err != nil {
		return OperationalRoute{}, err
	}
	if readiness.valid() && len(candidates) >= fullRouteNodeCount {
		full, fullErr := selectFullRouteCandidates(candidates, entropy)
		if fullErr == nil {
			return OperationalRoute{Mode: OperationalRouteFullMix, Full: full}, nil
		}
		if !errors.Is(fullErr, ErrInsufficientRouteDiversity) {
			return OperationalRoute{}, fullErr
		}
	}
	if requirement == RequireFullMix {
		return OperationalRoute{}, ErrFullMixRequired
	}
	bootstrap := append([]nodedir.Record(nil), candidates...)
	if err := shuffleRecords(entropy, bootstrap); err != nil {
		return OperationalRoute{}, err
	}
	return OperationalRoute{
		Mode:      OperationalRouteDirectBootstrap,
		Bootstrap: nodedir.CloneRecord(bootstrap[0]),
	}, nil
}

func verifiedRouteCandidates(policy nodedir.Policy, records []nodedir.Record, now time.Time) ([]nodedir.Record, error) {
	if now.IsZero() || len(records) == 0 || len(records) > nodedir.MaxDirectoryNodes {
		return nil, errors.New("invalid route candidate set")
	}
	candidates := make([]nodedir.Record, len(records))
	seenNodes := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := nodedir.VerifyRecord(policy, record, now); err != nil {
			return nil, err
		}
		nodeID := record.Announcement.Identity.NodeID
		if _, duplicate := seenNodes[nodeID]; duplicate {
			return nil, errors.New("duplicate full node in route candidate set")
		}
		seenNodes[nodeID] = struct{}{}
		candidates[index] = nodedir.CloneRecord(record)
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].Announcement.Identity.NodeID < candidates[right].Announcement.Identity.NodeID
	})
	return candidates, nil
}

func selectFullRouteCandidates(candidates []nodedir.Record, entropy io.Reader) (FullRoute, error) {
	if entropy == nil || len(candidates) < fullRouteNodeCount {
		return FullRoute{}, ErrInsufficientRouteDiversity
	}
	candidates = append([]nodedir.Record(nil), candidates...)
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
