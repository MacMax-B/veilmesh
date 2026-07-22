package nodedir

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const MaxSeedFileBytes = 1024 * 1024

func LoadPinnedNodes(path string) ([]PinnedNode, error) {
	if path == "" {
		return nil, errors.New("empty pinned seed path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxSeedFileBytes {
		return nil, errors.New("pinned seed file is not a bounded regular file")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- explicit operator-selected public seed file.
	if err != nil {
		return nil, err
	}
	return DecodePinnedNodes(data)
}

func DecodePinnedNodes(data []byte) ([]PinnedNode, error) {
	if len(data) == 0 || len(data) > MaxSeedFileBytes {
		return nil, errors.New("pinned seed data size is out of range")
	}
	var seeds []PinnedNode
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seeds); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("pinned seed file must contain one JSON value")
	}
	if len(seeds) == 0 || len(seeds) > MaxAttestations {
		return nil, errors.New("pinned seed count is out of range")
	}
	return seeds, nil
}
