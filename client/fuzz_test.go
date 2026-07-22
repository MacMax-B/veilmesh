package client

import (
	"testing"

	"veilmesh/protocol"
)

func FuzzStrictDirectCiphertextJSON(f *testing.F) {
	f.Add([]byte(`{"suite":"invalid","encapsulation":"","ciphertext":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var destination protocol.DirectCiphertext
		_ = decodeStrictJSON(data, &destination)
	})
}
