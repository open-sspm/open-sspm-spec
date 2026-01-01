package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func CanonicalizeJSON(b []byte) ([]byte, error) {
	c, err := jsoncanonicalizer.Transform(b)
	if err != nil {
		return nil, fmt.Errorf("hash: canonicalize: %w", err)
	}
	return c, nil
}

func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func HashObjectJCS(v any) (hashHex string, canonical []byte, err error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", nil, fmt.Errorf("hash: marshal: %w", err)
	}
	canonical, err = CanonicalizeJSON(raw)
	if err != nil {
		return "", nil, err
	}
	return SHA256Hex(canonical), canonical, nil
}
