package hash

import (
	"fmt"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/cyaml"
)

func HashObjectCanonicalYAML(v any) (hashHex string, yamlBytes []byte, err error) {
	yamlBytes, err = cyaml.MarshalCanonical(v)
	if err != nil {
		return "", nil, fmt.Errorf("hash: canonical yaml: %w", err)
	}
	return SHA256Hex(yamlBytes), yamlBytes, nil
}
