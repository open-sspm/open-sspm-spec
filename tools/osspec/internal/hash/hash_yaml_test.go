package hash

import (
	"strings"
	"testing"
)

func TestHashObjectCanonicalYAML_DeterministicAcrossOrdering(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1}
	b := map[string]any{"a": 1, "b": 2}

	h1, y1, err := HashObjectCanonicalYAML(a)
	if err != nil {
		t.Fatalf("HashObjectCanonicalYAML(a) error: %v", err)
	}
	h2, y2, err := HashObjectCanonicalYAML(b)
	if err != nil {
		t.Fatalf("HashObjectCanonicalYAML(b) error: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected equal hashes, got %s vs %s", h1, h2)
	}
	if string(y1) != string(y2) {
		t.Fatalf("expected equal yaml bytes, got\n%s\nvs\n%s", y1, y2)
	}
	if !strings.HasSuffix(string(y1), "\n") {
		t.Fatalf("expected trailing newline in canonical yaml")
	}
}
