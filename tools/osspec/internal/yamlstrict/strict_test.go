package yamlstrict

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeSingleStrictYAML_AcceptsValidDocument(t *testing.T) {
	input := []byte(`schema_version: 1
kind: opensspm.profile
profile:
  key: "p.v1"
  name: "Profile"
  rulesets:
    - key: "r.v1"
      version: "v1.0.0"
`)

	var out map[string]any
	if err := DecodeSingleStrictYAML(input, &out, true); err != nil {
		t.Fatalf("DecodeSingleStrictYAML() error: %v", err)
	}
	if out["schema_version"].(float64) != 1 {
		t.Fatalf("expected schema_version=1, got %#v", out["schema_version"])
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsDuplicateKeys(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("a: 1\na: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsAliases(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("a: &x 1\nb: *x\n"))
	if err == nil || (!strings.Contains(err.Error(), "aliases") && !strings.Contains(err.Error(), "anchors")) {
		t.Fatalf("expected aliases error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsMergeKeys(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("base: {a: 1}\nout:\n  <<: {b: 2}\n"))
	if err == nil || !strings.Contains(err.Error(), "merge keys") {
		t.Fatalf("expected merge keys error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsCustomTags(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("a: !custom value\n"))
	if err == nil || !strings.Contains(err.Error(), "unsupported tag") {
		t.Fatalf("expected unsupported tag error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsTimestamp(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("date: 2025-08-21\n"))
	if err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("expected timestamp error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsNonStringKeys(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("1: one\n"))
	if err == nil || !strings.Contains(err.Error(), "mapping keys must be strings") {
		t.Fatalf("expected mapping key error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsMultipleDocuments(t *testing.T) {
	_, err := DecodeSingleStrictYAMLToJSON([]byte("a: 1\n---\nb: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multi-doc error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_RejectsNaNAndInf(t *testing.T) {
	cases := []string{"x: .nan\n", "x: .inf\n", "x: -.inf\n"}
	for _, tc := range cases {
		_, err := DecodeSingleStrictYAMLToJSON([]byte(tc))
		if err == nil || !strings.Contains(err.Error(), "non-finite") {
			t.Fatalf("expected non-finite float error for %q, got %v", tc, err)
		}
	}
}

func TestDecodeSingleStrictYAML_KnownFields(t *testing.T) {
	type doc struct {
		A string `json:"a"`
	}
	var out doc

	err := DecodeSingleStrictYAML([]byte("a: ok\nextra: no\n"), &out, true)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestDecodeSingleStrictYAMLToJSON_ProducesJSONCompatibleNumbers(t *testing.T) {
	b, err := DecodeSingleStrictYAMLToJSON([]byte("a: 1\nb: 2.5\n"))
	if err != nil {
		t.Fatalf("DecodeSingleStrictYAMLToJSON() error: %v", err)
	}
	var out map[string]json.Number
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if out["a"].String() != "1" || out["b"].String() != "2.5" {
		t.Fatalf("unexpected numbers: %#v", out)
	}
}
