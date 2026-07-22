package identity

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MacMax-B/propagare/pqcrypto"
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

func TestENIGIdentifiersRejectNonCanonicalBase32RestBits(t *testing.T) {
	signer, err := pqcrypto.GenerateHybridSigner()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, GenesisNonceBytes)
	ids := []struct {
		name   string
		prefix string
		id     string
		valid  func(string) bool
	}{
		{name: "account", prefix: AccountPrefix, id: AccountID(signer.PublicIdentity()), valid: ValidAccountID},
		{name: "device", prefix: DevicePrefix, id: DeviceID(signer.PublicIdentity()), valid: ValidDeviceID},
		{name: "group", prefix: GroupPrefix, id: GroupID(signer.PublicIdentity(), nonce, []byte{0}), valid: ValidGroupID},
	}
	for _, test := range ids {
		t.Run(test.name, func(t *testing.T) {
			canonicalSuffix := test.id[len(test.prefix):]
			last := canonicalSuffix[len(canonicalSuffix)-1]
			replacement := byte('B')
			if last == 'Q' {
				replacement = 'R'
			} else if last != 'A' {
				t.Fatalf("unexpected canonical final base32 symbol %q", last)
			}
			alias := test.id[:len(test.id)-1] + string(replacement)
			canonicalDigest, canonicalErr := encoding.DecodeString(canonicalSuffix)
			aliasDigest, aliasErr := encoding.DecodeString(alias[len(test.prefix):])
			if canonicalErr != nil || aliasErr != nil || !bytes.Equal(canonicalDigest, aliasDigest) {
				t.Fatal("test alias did not preserve the decoded digest")
			}
			if test.valid(alias) {
				t.Fatal("non-canonical base32 rest bits were accepted")
			}
		})
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
