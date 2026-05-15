package regoengine

import (
	"context"
	"strings"
	"testing"
)

func TestValidateModuleOnlyRejectsInvalidRego(t *testing.T) {
	err := ValidateModuleOnly(context.Background(), "bad.rego", `package opensspm.bad

result := if {
`)
	if err == nil {
		t.Fatalf("ValidateModuleOnly() expected invalid Rego error")
	}
}

func TestEvaluateRejectsMultipleResults(t *testing.T) {
	const module = `package opensspm.test

results["pass"] := {"status": "pass"} if { true }
results["fail"] := {"status": "fail"} if { true }
`
	_, err := Evaluate(context.Background(), "test.rego", module, "data.opensspm.test.results[_]", map[string]any{})
	if err == nil {
		t.Fatalf("Evaluate() expected multiple results error")
	}
	if !strings.Contains(err.Error(), "exactly one object result") {
		t.Fatalf("Evaluate() error = %v, want exactly-one error", err)
	}
}

func TestEvaluateRejectsEmptyModule(t *testing.T) {
	_, err := Evaluate(context.Background(), "empty.rego", "  ", "data.opensspm.test.result", map[string]any{})
	if err == nil {
		t.Fatalf("Evaluate() expected empty module error")
	}
	if err.Error() != "rego module is required" {
		t.Fatalf("Evaluate() error = %v, want rego module is required", err)
	}
}

func TestEvaluateReturnsBuiltinErrors(t *testing.T) {
	const module = `package opensspm.test

expired if {
  time.parse_rfc3339_ns(input.entity.expires_at) < time.parse_rfc3339_ns(input.entity.evaluated_at)
}

result := {"risk_level": "critical"} if {
  expired
}

result := {"risk_level": "low"} if {
  not expired
}
`

	_, err := Evaluate(context.Background(), "test.rego", module, "data.opensspm.test.result", map[string]any{
		"entity": map[string]any{
			"expires_at":   "not-a-timestamp",
			"evaluated_at": "2026-05-15T12:00:00Z",
		},
	})
	if err == nil {
		t.Fatalf("Evaluate() expected malformed timestamp builtin error")
	}
}
