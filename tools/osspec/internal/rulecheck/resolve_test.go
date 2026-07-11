package rulecheck

import (
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestResolveInheritanceAndOverride(t *testing.T) {
	policy := &types.RegoPolicy{Package: "shared", Rego: "shared module"}
	check := &types.Check{Query: "data.shared.result"}

	inherited := Resolve(policy, check)
	if inherited.Package != policy.Package || inherited.Rego != policy.Rego {
		t.Fatalf("Resolve() did not inherit policy: %+v", inherited)
	}
	if check.Package != "" || check.Rego != "" {
		t.Fatalf("Resolve() mutated source check: %+v", check)
	}

	override := Resolve(policy, &types.Check{Package: "rule", Rego: "rule module"})
	if override.Package != "rule" || override.Rego != "rule module" {
		t.Fatalf("Resolve() replaced rule override: %+v", override)
	}
}
