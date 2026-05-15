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
