package group

import (
	"testing"
	"time"

	"veilmesh/identity"
	"veilmesh/pqcrypto"
)

func TestOwnerDelegatesAdminWithoutSharingPrivateKey(t *testing.T) {
	owner, _ := pqcrypto.GenerateHybridSigner()
	admin, _ := pqcrypto.GenerateHybridSigner()
	member, _ := pqcrypto.GenerateHybridSigner()
	state, err := New(owner.PublicIdentity(), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(signer *pqcrypto.HybridSigner, kind ActionKind, subject *pqcrypto.HybridSigner) {
		t.Helper()
		action, err := SignAction(signer, Action{
			GroupID:   state.GroupID,
			Epoch:     state.Epoch + 1,
			Previous:  append([]byte(nil), state.Hash...),
			Kind:      kind,
			Subject:   subject.PublicIdentity(),
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Apply(action); err != nil {
			t.Fatal(err)
		}
	}
	apply(owner, ActionAdd, admin)
	apply(owner, ActionGrantAdmin, admin)
	apply(admin, ActionAdd, member)
	apply(admin, ActionBan, member)
	if state.Members[member.PublicIdentity().NodeID].Role != RoleBanned {
		t.Fatal("admin ban was not applied")
	}
}

func TestGroupENIGIdentityRejectsGenesisSubstitution(t *testing.T) {
	owner, _ := pqcrypto.GenerateHybridSigner()
	state, err := New(owner.PublicIdentity(), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if !identity.ValidGroupID(state.GroupID) || state.GroupID != identity.GroupID(state.Creator, state.GenesisNonce, policyCommitment(state.Policy)) {
		t.Fatal("group did not produce a self-certifying ENIG identity")
	}
	tampered := *state
	tampered.GenesisNonce = append([]byte(nil), state.GenesisNonce...)
	tampered.GenesisNonce[0] ^= 1
	tampered.Hash = stateHash(&tampered)
	if validState(&tampered) {
		t.Fatal("group with substituted genesis was accepted")
	}
	tampered = *state
	tampered.Policy.AdminsMayDelegate = !state.Policy.AdminsMayDelegate
	tampered.Hash = stateHash(&tampered)
	if validState(&tampered) {
		t.Fatal("group with substituted genesis policy was accepted")
	}
}

func TestAdminCannotBanAnotherAdminAndFailureIsAtomic(t *testing.T) {
	owner, _ := pqcrypto.GenerateHybridSigner()
	firstAdmin, _ := pqcrypto.GenerateHybridSigner()
	secondAdmin, _ := pqcrypto.GenerateHybridSigner()
	state, err := New(owner.PublicIdentity(), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(signer *pqcrypto.HybridSigner, kind ActionKind, subject *pqcrypto.HybridSigner) error {
		action, err := SignAction(signer, Action{
			GroupID: state.GroupID, Epoch: state.Epoch + 1, Previous: append([]byte(nil), state.Hash...),
			Kind: kind, Subject: subject.PublicIdentity(), CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		return state.Apply(action)
	}
	for _, admin := range []*pqcrypto.HybridSigner{firstAdmin, secondAdmin} {
		if err := apply(owner, ActionAdd, admin); err != nil {
			t.Fatal(err)
		}
		if err := apply(owner, ActionGrantAdmin, admin); err != nil {
			t.Fatal(err)
		}
	}
	epoch, hash := state.Epoch, append([]byte(nil), state.Hash...)
	if err := apply(firstAdmin, ActionBan, secondAdmin); err == nil {
		t.Fatal("admin was allowed to ban another admin")
	}
	if state.Epoch != epoch || !bytesEqual(state.Hash, hash) {
		t.Fatal("failed authorization mutated group state")
	}
}
