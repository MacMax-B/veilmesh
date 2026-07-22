package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const workDomain = "veilmesh/postage/v1"

var ErrInvalidWork = errors.New("invalid proof of work")

func WorkDigest(item StoredItem, proof WorkProof) [sha256.Size]byte {
	var buf bytes.Buffer
	writeString(&buf, workDomain)
	_ = binary.Write(&buf, binary.BigEndian, proof.Epoch)
	writeString(&buf, item.ItemID)
	_ = binary.Write(&buf, binary.BigEndian, proof.Nonce)
	return sha256.Sum256(buf.Bytes())
}

func HasLeadingZeroBits(sum []byte, difficulty uint8) bool {
	remaining := difficulty
	for _, b := range sum {
		if remaining >= 8 {
			if b != 0 {
				return false
			}
			remaining -= 8
			continue
		}
		if remaining == 0 {
			return true
		}
		return b>>(8-remaining) == 0
	}
	return remaining == 0
}

func VerifyWork(item StoredItem, now time.Time, epochSeconds int64, minimumDifficulty uint8) error {
	if epochSeconds < MinWorkEpochSeconds || epochSeconds > MaxWorkEpochSeconds ||
		minimumDifficulty > MaxWorkDifficulty || item.Work.Difficulty > MaxWorkDifficulty ||
		item.Work.Difficulty < minimumDifficulty {
		return ErrInvalidWork
	}
	current := now.Unix() / epochSeconds
	if item.Work.Epoch < current-1 || item.Work.Epoch > current+1 {
		return ErrInvalidWork
	}
	sum := WorkDigest(item, item.Work)
	if !HasLeadingZeroBits(sum[:], item.Work.Difficulty) {
		return ErrInvalidWork
	}
	return nil
}

func SolveWork(ctx context.Context, item StoredItem, epochSeconds int64, difficulty uint8) (WorkProof, error) {
	if epochSeconds < MinWorkEpochSeconds || epochSeconds > MaxWorkEpochSeconds || difficulty > MaxWorkDifficulty {
		return WorkProof{}, ErrInvalidWork
	}
	proof := WorkProof{Epoch: time.Now().Unix() / epochSeconds, Difficulty: difficulty}
	for {
		if proof.Nonce&0x3fff == 0 {
			select {
			case <-ctx.Done():
				return WorkProof{}, ctx.Err()
			default:
			}
		}
		sum := WorkDigest(item, proof)
		if HasLeadingZeroBits(sum[:], difficulty) {
			return proof, nil
		}
		proof.Nonce++
	}
}
