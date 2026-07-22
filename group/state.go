package group

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"veilmesh/identity"
	"veilmesh/pqcrypto"
	"veilmesh/protocol"
)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleBanned Role = "banned"
)

type ActionKind string

const (
	ActionAdd           ActionKind = "add"
	ActionRemove        ActionKind = "remove"
	ActionBan           ActionKind = "ban"
	ActionGrantAdmin    ActionKind = "grant_admin"
	ActionRevokeAdmin   ActionKind = "revoke_admin"
	ActionTransferOwner ActionKind = "transfer_owner"
)

type Policy struct {
	AdminsMayDelegate bool `json:"admins_may_delegate"`
}

type Member struct {
	Identity protocol.NodePublicIdentity `json:"identity"`
	Role     Role                        `json:"role"`
}

type Action struct {
	GroupID   string                      `json:"group_id"`
	Epoch     uint64                      `json:"epoch"`
	Previous  []byte                      `json:"previous"`
	Kind      ActionKind                  `json:"kind"`
	ActorID   string                      `json:"actor_id"`
	Subject   protocol.NodePublicIdentity `json:"subject"`
	CreatedAt time.Time                   `json:"created_at"`
	Signature protocol.HybridSignature    `json:"signature"`
}

type State struct {
	GroupID      string                      `json:"group_id"`
	Creator      protocol.NodePublicIdentity `json:"creator"`
	GenesisNonce []byte                      `json:"genesis_nonce"`
	Epoch        uint64                      `json:"epoch"`
	Policy       Policy                      `json:"policy"`
	Members      map[string]Member           `json:"members"`
	Hash         []byte                      `json:"hash"`
}

const MaxGroupMembers = 1000

func New(owner protocol.NodePublicIdentity, policy Policy) (*State, error) {
	if !pqcrypto.ValidPublicIdentity(owner) {
		return nil, errors.New("invalid owner identity")
	}
	random := make([]byte, identity.GenesisNonceBytes)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	state := &State{
		GroupID:      identity.GroupID(owner, random, policyCommitment(policy)),
		Creator:      owner,
		GenesisNonce: random,
		Epoch:        0,
		Policy:       policy,
		Members:      map[string]Member{owner.NodeID: {Identity: owner, Role: RoleOwner}},
	}
	state.Hash = stateHash(state)
	return state, nil
}

func actionBytes(action Action) ([]byte, error) {
	unsigned := action
	unsigned.Signature = protocol.HybridSignature{}
	return json.Marshal(unsigned)
}

func SignAction(signer *pqcrypto.HybridSigner, action Action) (Action, error) {
	if signer == nil {
		return Action{}, errors.New("group action signer is required")
	}
	action.ActorID = signer.PublicIdentity().NodeID
	message, err := actionBytes(action)
	if err != nil {
		return Action{}, err
	}
	action.Signature, err = signer.Sign("group-admin-action", message)
	return action, err
}

func (s *State) Apply(action Action) error {
	if !validState(s) {
		return errors.New("invalid current group state")
	}
	if action.GroupID != s.GroupID || action.Epoch == 0 || action.Epoch != s.Epoch+1 ||
		len(action.Previous) != sha256.Size || !bytesEqual(action.Previous, s.Hash) ||
		action.CreatedAt.IsZero() || action.CreatedAt.After(time.Now().Add(5*time.Minute)) {
		return errors.New("group action is not the next valid state transition")
	}
	next := *s
	next.Members = make(map[string]Member, len(s.Members)+1)
	for memberID, member := range s.Members {
		next.Members[memberID] = member
	}
	actor, ok := next.Members[action.ActorID]
	if !ok || (actor.Role != RoleOwner && actor.Role != RoleAdmin) {
		return errors.New("actor is not authorized")
	}
	message, err := actionBytes(action)
	if err != nil || !pqcrypto.Verify(actor.Identity, "group-admin-action", message, action.Signature) {
		return errors.New("invalid group action signature")
	}
	if !pqcrypto.ValidPublicIdentity(action.Subject) {
		return errors.New("invalid action subject")
	}
	subjectID := action.Subject.NodeID
	switch action.Kind {
	case ActionAdd:
		if len(next.Members) >= MaxGroupMembers {
			return errors.New("group member limit reached")
		}
		if existing, exists := next.Members[subjectID]; exists && existing.Role != RoleBanned {
			return errors.New("subject is already a member")
		}
		next.Members[subjectID] = Member{Identity: action.Subject, Role: RoleMember}
	case ActionRemove:
		subject, exists := next.Members[subjectID]
		if !exists {
			return errors.New("remove subject is not a member")
		}
		if subject.Role == RoleOwner {
			return errors.New("owner must transfer ownership before removal")
		}
		if actor.Role == RoleAdmin && subject.Role == RoleAdmin {
			return errors.New("admin cannot remove another admin")
		}
		delete(next.Members, subjectID)
	case ActionBan:
		subject, exists := next.Members[subjectID]
		if !exists && len(next.Members) >= MaxGroupMembers {
			return errors.New("group member limit reached")
		}
		if exists && subject.Role == RoleOwner {
			return errors.New("owner cannot be banned")
		}
		if exists && actor.Role == RoleAdmin && subject.Role == RoleAdmin {
			return errors.New("admin cannot ban another admin")
		}
		next.Members[subjectID] = Member{Identity: action.Subject, Role: RoleBanned}
	case ActionGrantAdmin:
		if actor.Role != RoleOwner && !next.Policy.AdminsMayDelegate {
			return errors.New("only owner may grant admin under this policy")
		}
		member, exists := next.Members[subjectID]
		if !exists || member.Role != RoleMember {
			return errors.New("admin subject must be a member")
		}
		member.Role = RoleAdmin
		next.Members[subjectID] = member
	case ActionRevokeAdmin:
		if actor.Role != RoleOwner {
			return errors.New("only owner may revoke admin")
		}
		member, exists := next.Members[subjectID]
		if !exists || member.Role != RoleAdmin {
			return errors.New("subject is not an admin")
		}
		member.Role = RoleMember
		next.Members[subjectID] = member
	case ActionTransferOwner:
		if actor.Role != RoleOwner {
			return errors.New("only owner may transfer ownership")
		}
		member, exists := next.Members[subjectID]
		if !exists || member.Role == RoleBanned {
			return errors.New("new owner must be an active member")
		}
		actor.Role = RoleAdmin
		next.Members[action.ActorID] = actor
		member.Role = RoleOwner
		next.Members[subjectID] = member
	default:
		return errors.New("unknown group action")
	}
	next.Epoch = action.Epoch
	next.Hash = stateHash(&next)
	*s = next
	return nil
}

func validState(state *State) bool {
	if state == nil || len(state.Members) == 0 || len(state.Members) > MaxGroupMembers ||
		len(state.Hash) != sha256.Size || !bytesEqual(state.Hash, stateHash(state)) {
		return false
	}
	if !identity.ValidGroupID(state.GroupID) || !pqcrypto.ValidPublicIdentity(state.Creator) ||
		len(state.GenesisNonce) != identity.GenesisNonceBytes ||
		state.GroupID != identity.GroupID(state.Creator, state.GenesisNonce, policyCommitment(state.Policy)) {
		return false
	}
	if state.Epoch == 0 {
		creator, ok := state.Members[state.Creator.NodeID]
		if !ok || len(state.Members) != 1 || creator.Role != RoleOwner ||
			!bytesEqual(creator.Identity.Ed25519Public, state.Creator.Ed25519Public) ||
			!bytesEqual(creator.Identity.MLDSA65Public, state.Creator.MLDSA65Public) {
			return false
		}
	}
	owners := 0
	for memberID, member := range state.Members {
		if memberID != member.Identity.NodeID || !pqcrypto.ValidPublicIdentity(member.Identity) {
			return false
		}
		switch member.Role {
		case RoleOwner:
			owners++
		case RoleAdmin, RoleMember, RoleBanned:
		default:
			return false
		}
	}
	return owners == 1
}

func policyCommitment(policy Policy) []byte {
	if policy.AdminsMayDelegate {
		return []byte{1}
	}
	return []byte{0}
}

func stateHash(state *State) []byte {
	copyState := *state
	copyState.Hash = nil
	encoded, _ := json.Marshal(copyState)
	sum := sha256.Sum256(encoded)
	return sum[:]
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
