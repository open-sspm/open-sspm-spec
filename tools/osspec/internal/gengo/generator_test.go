package gengo

import (
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestGenerate_ReturnsExpectedFiles(t *testing.T) {
	files, err := Generate(types.Descriptor{})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
		if file.Content == "" {
			t.Errorf("Generate() returned empty content for %q", file.Path)
		}
	}

	want := []string{
		"opensspm/spec/v2/types.gen.go",
		"opensspm/spec/v2/descriptor_snapshot.gen.go",
		"opensspm/runtime/v2/runtime.gen.go",
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("Generate() paths = %v, want %v", paths, want)
	}
}

func TestGenerateDescriptorSnapshot_EmbedsJSON(t *testing.T) {
	desc := types.Descriptor{
		SchemaVersion: 2,
		Kind:          "opensspm.engine_descriptor",
		Rulesets: []types.Compiled[types.RulesetDoc]{
			{
				SourcePath: "specs/example.yaml",
				Object: types.RulesetDoc{
					SchemaVersion: 2,
					Kind:          "opensspm.ruleset",
					Ruleset: types.Ruleset{
						Key:    "example",
						Policy: &types.RegoPolicy{Rego: "package example\n\nmessage := `quoted`"},
						Rules: []types.Rule{
							{Key: "R1", Parameters: map[string]any{"enabled": true, "threshold": float64(3)}},
						},
					},
				},
			},
		},
	}

	code, err := generateDescriptorSnapshot(desc)
	if err != nil {
		t.Fatalf("generateDescriptorSnapshot() error: %v", err)
	}

	required := []string{
		`"encoding/json"`,
		`"strings"`,
		"var GeneratedDescriptor = mustDecodeGeneratedDescriptor(",
		"func mustDecodeGeneratedDescriptor(data string) Descriptor",
		"decoder.DisallowUnknownFields()",
		"decoder.Decode(&descriptor)",
	}
	for _, want := range required {
		if !strings.Contains(code, want) {
			t.Fatalf("generated snapshot missing %q", want)
		}
	}

	forbidden := []string{"generatedPtr", "var GeneratedDescriptor = Descriptor{"}
	for _, bad := range forbidden {
		if strings.Contains(code, bad) {
			t.Fatalf("generated snapshot unexpectedly contains %q", bad)
		}
	}

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "descriptor_snapshot.gen.go", code, parser.AllErrors); err != nil {
		t.Fatalf("generated snapshot does not parse: %v", err)
	}
}

func TestGenerateSpecTypes_RegoSurfaceAndHelpers(t *testing.T) {
	code, err := generateSpecTypes(types.EnumValues())
	if err != nil {
		t.Fatalf("generateSpecTypes() error: %v", err)
	}

	required := []string{
		"type Check struct",
		"Engine   CheckEngine",
		"Package  string",
		"Query    string",
		"Rego     string",
		"RegoPath string",
		"type RegoPolicy struct",
		"type EvaluateStatus string",
		"type DatasetInputError struct",
		"type DatasetInput struct",
		"type EvaluateInput struct",
		"type EvaluateResult struct",
		"Parameters   map[string]any",
		"func EvaluateRule(ruleset *Ruleset, rule *Rule, input EvaluateInput) (EvaluateResult, error)",
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
		"func (rs *Ruleset) AddRule",
		"func (rs *Ruleset) RuleByKey",
		"func EvaluateEntityPolicyPack",
		"type FrameworkMapping struct",
		"type RulesetRequirements struct",
		"type ParameterSchema struct",
		"type Evidence struct",
		"type Remediation struct",
		"type Lifecycle struct",
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

func TestGenerateRuntimeTypes_DatasetProviderContract(t *testing.T) {
	code, err := generateRuntimeTypes(types.EnumValues())
	if err != nil {
		t.Fatalf("generateRuntimeTypes() error: %v", err)
	}

	required := []string{
		"type DatasetRef struct",
		"type DatasetResult struct",
		"type DatasetProvider interface",
		"GetDataset(ctx context.Context, ref DatasetRef) DatasetResult",
	}
	for _, want := range required {
		if !strings.Contains(code, want) {
			t.Fatalf("generated runtime code missing %q", want)
		}
	}

	forbidden := []string{
		"type EvalContext struct",
		"Capabilities(ctx context.Context)",
		"type EvaluateInput =",
		"func EvaluateRule(",
		"ScopeKind",
		"specv2",
	}
	for _, bad := range forbidden {
		if strings.Contains(code, bad) {
			t.Fatalf("generated runtime code unexpectedly contains %q", bad)
		}
	}

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "runtime.gen.go", code, parser.AllErrors); err != nil {
		t.Fatalf("generated runtime code does not parse: %v", err)
	}
}
