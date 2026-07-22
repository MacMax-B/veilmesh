package pqcrypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

var messageBuckets = []int{1024, 4096, 16384, 65536, 262144}

func PadMessage(plaintext []byte) ([]byte, error) {
	required := len(plaintext) + 4
	bucket := 0
	for _, candidate := range messageBuckets {
		if required <= candidate {
			bucket = candidate
			break
		}
	}
	if bucket == 0 {
		return nil, errors.New("message too large; use encrypted file chunks")
	}
	result := make([]byte, bucket)
	binary.BigEndian.PutUint32(result[:4], uint32(len(plaintext))) // #nosec G115 -- bucket selection bounds plaintext below 262 KiB.
	copy(result[4:], plaintext)
	if _, err := rand.Read(result[required:]); err != nil {
		return nil, err
	}
	return result, nil
}

func UnpadMessage(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, errors.New("invalid padded message")
	}
	length := int(binary.BigEndian.Uint32(padded[:4]))
	if length < 0 || length > len(padded)-4 {
		return nil, errors.New("invalid padded message length")
	}
	return append([]byte(nil), padded[4:4+length]...), nil
}
