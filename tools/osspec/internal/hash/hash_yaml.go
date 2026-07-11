package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/cyaml"
)

func HashObjectCanonicalYAML(v any) (hashHex string, yamlBytes []byte, err error) {
	yamlBytes, err = cyaml.MarshalCanonical(v)
	if err != nil {
		return "", nil, fmt.Errorf("hash: canonical yaml: %w", err)
	}
	sum := sha256.Sum256(yamlBytes)
	return hex.EncodeToString(sum[:]), yamlBytes, nil
}
