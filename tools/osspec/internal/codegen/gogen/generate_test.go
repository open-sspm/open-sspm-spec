package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestGenerateSpecTypes_RegoSurfaceAndHelpers(t *testing.T) {
	code, err := generateSpecTypes(types.EnumValues())
	if err != nil {
		t.Fatalf("generateSpecTypes() error: %v", err)
	}

	required := []string{
		"type Check struct",
		"Engine  CheckEngine",
		"Package string",
		"Query   string",
		"Rego    string",
		"type RegoPolicy struct",
		"type RulesetRequirement struct",
		"RegoSHA256",
		"type EvaluateStatus string",
		"type DatasetInputError struct",
		"type DatasetInput struct",
		"type EvaluateInput struct",
		"type EvaluateResult struct",
		"func (rs *Ruleset) AddRule(rule Rule) (bool, error)",
		"func (rs *Ruleset) RuleByKey(ruleKey string) (*Rule, bool)",
		"func EvaluateRule(rule *Rule, input EvaluateInput) (EvaluateResult, error)",
		"func (r *Rule) Evaluate(input EvaluateInput) (EvaluateResult, error)",
		"func EvaluateEntityPolicyPack(pack *EntityPolicyPack, entityInput map[string]any) (EntityPolicyEvaluateResult, error)",
		"func evaluateRego(moduleName, module, query string, input any) (map[string]any, error)",
		"rego.StrictBuiltinErrors(true)",
	}
	for _, want := range required {
		if !strings.Contains(code, want) {
			t.Fatalf("generated code missing %q", want)
		}
	}

	forbidden := []string{
		"Check" + "Plan",
		"Expression " + "string",
		"evaluate" + string([]byte{'C', 'E', 'L'}),
		"github.com/google/" + "c" + "el-go",
	}
	for _, bad := range forbidden {
		if strings.Contains(code, bad) {
			t.Fatalf("generated code unexpectedly contains legacy pattern: %q", bad)
		}
	}

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "types.gen.go", code, parser.AllErrors); err != nil {
		t.Fatalf("generated code does not parse: %v", err)
	}
}

func TestGenerateRuntimeTypes_EvaluateWrapper(t *testing.T) {
	code, err := generateRuntimeTypes(types.EnumValues())
	if err != nil {
		t.Fatalf("generateRuntimeTypes() error: %v", err)
	}

	required := []string{
		`specv2 "github.com/open-sspm/open-sspm-spec/gen/go/opensspm/spec/v2"`,
		"type EvaluateInput = specv2.EvaluateInput",
		"type EvaluateResult = specv2.EvaluateResult",
		"type EvaluateStatus = specv2.EvaluateStatus",
		"func EvaluateRule(rule *specv2.Rule, input EvaluateInput) (EvaluateResult, error)",
		"return specv2.EvaluateRule(rule, input)",
	}
	for _, want := range required {
		if !strings.Contains(code, want) {
			t.Fatalf("generated runtime code missing %q", want)
		}
	}

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "runtime.gen.go", code, parser.AllErrors); err != nil {
		t.Fatalf("generated runtime code does not parse: %v", err)
	}
}
