package cyaml

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarshalCanonical_Golden(t *testing.T) {
	input := map[string]any{
		"d": "text",
		"b": map[string]any{
			"z":      []any{},
			"nested": []any{"x", nil, true},
		},
		"c": map[string]any{},
		"a": 1,
	}

	got, err := MarshalCanonical(input)
	if err != nil {
		t.Fatalf("MarshalCanonical() error: %v", err)
	}

	goldenPath := filepath.Join("testdata", "sample.golden.yaml")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("unexpected yaml output\nwant:\n%s\n\ngot:\n%s", string(want), string(got))
	}
}

func TestMarshalCanonical_DeterministicAcrossMapOrder(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1}
	b := map[string]any{"a": 1, "b": 2}

	y1, err := MarshalCanonical(a)
	if err != nil {
		t.Fatalf("MarshalCanonical(a): %v", err)
	}
	y2, err := MarshalCanonical(b)
	if err != nil {
		t.Fatalf("MarshalCanonical(b): %v", err)
	}

	if string(y1) != string(y2) {
		t.Fatalf("expected deterministic output, got\n%s\nvs\n%s", y1, y2)
	}
}
