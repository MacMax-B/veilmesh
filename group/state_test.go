package group

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/MacMax-B/propagare/identity"
	"github.com/MacMax-B/propagare/pqcrypto"
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

func TestConcurrentActionsCommitAtMostOneTransition(t *testing.T) {
	owner, _ := pqcrypto.GenerateHybridSigner()
	first, _ := pqcrypto.GenerateHybridSigner()
	second, _ := pqcrypto.GenerateHybridSigner()
	state, err := New(owner.PublicIdentity(), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	makeAction := func(subject *pqcrypto.HybridSigner) Action {
		t.Helper()
		action, signErr := SignAction(owner, Action{
			GroupID: state.GroupID, Epoch: state.Epoch + 1, Previous: append([]byte(nil), state.Hash...),
			Kind: ActionAdd, Subject: subject.PublicIdentity(), CreatedAt: time.Now().UTC(),
		})
		if signErr != nil {
			t.Fatal(signErr)
		}
		return action
	}
	actions := []Action{makeAction(first), makeAction(second)}
	results := make(chan error, len(actions))
	var wait sync.WaitGroup
	for _, action := range actions {
		wait.Add(1)
		go func(action Action) {
			defer wait.Done()
			results <- state.Apply(action)
		}(action)
	}
	wait.Wait()
	close(results)
	successes := 0
	for applyErr := range results {
		if applyErr == nil {
			successes++
		}
	}
	if successes != 1 || state.Epoch != 1 || len(state.Members) != 2 {
		t.Fatalf("concurrent transition result is inconsistent: successes=%d epoch=%d members=%d", successes, state.Epoch, len(state.Members))
	}
}

func TestGroupStateJSONRestoreInitializesGuardAndValidates(t *testing.T) {
	owner, _ := pqcrypto.GenerateHybridSigner()
	member, _ := pqcrypto.GenerateHybridSigner()
	state, err := New(owner.PublicIdentity(), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var restored State
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("valid group state did not restore: %v", err)
	}
	action, err := SignAction(owner, Action{
		GroupID: restored.GroupID, Epoch: restored.Epoch + 1, Previous: append([]byte(nil), restored.Hash...),
		Kind: ActionAdd, Subject: member.PublicIdentity(), CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Apply(action); err != nil {
		t.Fatalf("restored group state has no usable concurrency guard: %v", err)
	}

	unknown := bytes.Replace(encoded, []byte(`{"group_id":`), []byte(`{"unknown":true,"group_id":`), 1)
	if err := json.Unmarshal(unknown, &State{}); err == nil {
		t.Fatal("group state with unknown JSON field was accepted")
	}
	trailing := append(append([]byte(nil), encoded...), []byte(` {}`)...)
	if err := json.Unmarshal(trailing, &State{}); err == nil {
		t.Fatal("group state with trailing JSON was accepted")
	}
	if err := json.Unmarshal(make([]byte, MaxGroupStateBytes+1), &State{}); err == nil {
		t.Fatal("oversized group state was accepted")
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
