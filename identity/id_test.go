package identity

import (
	"strings"
	"testing"

	"propagare/pqcrypto"
)

func TestENIGIdentifiersAreTypedAndSelfCertifying(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	public := signer.PublicIdentity()
	accountID := AccountID(public)
	deviceID := DeviceID(public)
	nonce := make([]byte, GenesisNonceBytes)
	nonce[0] = 1
	groupID := GroupID(public, nonce, []byte{0})
	if !strings.HasPrefix(accountID, "ENIG") || !ValidAccountID(accountID) ||
		!ValidDeviceID(deviceID) || !ValidGroupID(groupID) || accountID == deviceID || deviceID == groupID {
		t.Fatal("valid typed ENIG identifiers were not produced")
	}

	tampered := accountID[:len(accountID)-1] + "A"
	if tampered == accountID {
		tampered = accountID[:len(accountID)-1] + "B"
	}
	if AccountID(public) == tampered || !ValidAccountID(tampered) {
		// Format validation alone cannot detect a different valid digest. The
		// recomputed self-certifying binding must detect it.
		if AccountID(public) == tampered {
			t.Fatal("tampered account ID matched the public key")
		}
	}
	if ValidAccountID(strings.ToLower(accountID)) || ValidAccountID(accountID+"A") || ValidGroupID(accountID) {
		t.Fatal("malformed or cross-type ENIG identifier was accepted")
	}
}

func TestGroupIDBindsCreatorAndNonce(t *testing.T) {
	first, _ := pqcrypto.GenerateHybridSigner()
	second, _ := pqcrypto.GenerateHybridSigner()
	nonce := make([]byte, GenesisNonceBytes)
	firstID := GroupID(first.PublicIdentity(), nonce, []byte{0})
	nonce[0] = 1
	if firstID == GroupID(first.PublicIdentity(), nonce, []byte{0}) || firstID == GroupID(second.PublicIdentity(), make([]byte, GenesisNonceBytes), []byte{0}) {
		t.Fatal("group identifier did not bind creator and nonce")
	}
	if GroupID(first.PublicIdentity(), nonce[:len(nonce)-1], []byte{0}) != "" || GroupID(first.PublicIdentity(), nonce, nil) != "" {
		t.Fatal("short group genesis nonce was accepted")
	}
}
