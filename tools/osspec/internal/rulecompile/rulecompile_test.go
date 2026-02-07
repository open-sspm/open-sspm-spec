package rulecompile

import (
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestCompileRuleset_StructuredFieldCompareToCEL(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:policies/password"},
					Check: &SourceCheck{
						Type:    "dataset.field_compare",
						Dataset: "okta:policies/password",
						Where: []SourcePredicate{
							{Op: "eq", Path: "/status", Value: "ACTIVE"},
						},
						Assert: &SourcePredicate{Op: "gte", Path: "/settings/password/complexity/minLength", Value: 15},
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}

	if len(compiled.Ruleset.Rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(compiled.Ruleset.Rules))
	}
	check := compiled.Ruleset.Rules[0].Check
	if check == nil {
		t.Fatalf("expected compiled check")
	}
	if check.Engine != types.CheckEngineCEL {
		t.Fatalf("expected check.engine=cel, got %q", check.Engine)
	}

	want := `rows("okta:policies/password").filter(r, r["status"] == "ACTIVE").size() >= 1 && rows("okta:policies/password").filter(r, r["status"] == "ACTIVE").all(r, r["settings"]["password"]["complexity"]["minLength"] >= 15)`
	if check.Expression != want {
		t.Fatalf("unexpected compiled expression:\nwant: %s\ngot:  %s", want, check.Expression)
	}
}

func TestCompileRuleset_StructuredCountCompareWithSelector(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Selectors: map[string]SourceSelector{
				"active_streams": {
					Dataset: "okta:log-streams",
					Where: []SourcePredicate{
						{Op: "eq", Path: "/status", Value: "ACTIVE"},
					},
				},
			},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:log-streams"},
					Check: &SourceCheck{
						Type:     "dataset.count_compare",
						Selector: "active_streams",
						Where: []SourcePredicate{
							{Op: "eq", Path: "/region", Value: "US"},
						},
						Compare: &SourceCompare{Op: "gte", Value: 1},
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	check := compiled.Ruleset.Rules[0].Check
	if check == nil {
		t.Fatalf("expected compiled check")
	}

	want := `rows("okta:log-streams").filter(r, r["status"] == "ACTIVE" && r["region"] == "US").size() >= 1`
	if check.Expression != want {
		t.Fatalf("unexpected compiled expression:\nwant: %s\ngot:  %s", want, check.Expression)
	}
}

func TestCompileRuleset_StructuredPathEscapes(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:example"},
					Check: &SourceCheck{
						Type:    "dataset.field_compare",
						Dataset: "okta:example",
						Assert:  &SourcePredicate{Op: "eq", Path: "/a~1b/c~0d", Value: "x"},
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	expr := compiled.Ruleset.Rules[0].Check.Expression
	if !strings.Contains(expr, `r["a/b"]["c~d"]`) {
		t.Fatalf("expected decoded JSON pointer path in expression, got: %s", expr)
	}
}

func TestCompileRuleset_OnEmptyUnknownCompilesToCELPlan(t *testing.T) {
	minSelected := 0
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:example"},
					Check: &SourceCheck{
						Type:    "dataset.field_compare",
						Dataset: "okta:example",
						Assert:  &SourcePredicate{Op: "eq", Path: "/x", Value: 1},
						Expect: &SourceExpect{
							OnEmpty:     "unknown",
							MinSelected: &minSelected,
						},
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	check := compiled.Ruleset.Rules[0].Check
	if check == nil {
		t.Fatalf("expected compiled check")
	}
	if check.Engine != types.CheckEngineCELPlan {
		t.Fatalf("expected engine cel_plan for on_empty=unknown, got %q", check.Engine)
	}
	if check.Plan == nil {
		t.Fatalf("expected plan payload for cel_plan check")
	}
	if check.Plan.Expect == nil {
		t.Fatalf("expected plan expect settings")
	}
	if check.Plan.Expect.OnEmpty != "unknown" {
		t.Fatalf("expected on_empty=unknown in plan, got %q", check.Plan.Expect.OnEmpty)
	}
	if check.Plan.Expect.MinSelected != 0 {
		t.Fatalf("expected min_selected=0 in plan, got %d", check.Plan.Expect.MinSelected)
	}
}

func TestCompileRuleset_FieldComparePoliciesCompileToCELPlan(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:example"},
					Check: &SourceCheck{
						Type:             "dataset.field_compare",
						Dataset:          "okta:example",
						Assert:           &SourcePredicate{Op: "eq", Path: "/x", Value: 1},
						OnMissingDataset: "fail",
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	check := compiled.Ruleset.Rules[0].Check
	if check == nil {
		t.Fatalf("expected compiled check")
	}
	if check.Engine != types.CheckEngineCELPlan {
		t.Fatalf("expected engine cel_plan when policy actions are configured, got %q", check.Engine)
	}
	if check.Plan == nil {
		t.Fatalf("expected plan payload for cel_plan check")
	}
	if check.Plan.OnMissingDataset != "fail" {
		t.Fatalf("expected plan.on_missing_dataset=fail, got %q", check.Plan.OnMissingDataset)
	}
	if check.Plan.Expect == nil {
		t.Fatalf("expected plan expect settings")
	}
	if check.Plan.Expect.OnEmpty != "fail" {
		t.Fatalf("expected default on_empty=fail in plan, got %q", check.Plan.Expect.OnEmpty)
	}
}

func TestCompileRuleset_CountComparePoliciesCompileToCELPlan(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:example"},
					Check: &SourceCheck{
						Type:               "dataset.count_compare",
						Dataset:            "okta:example",
						Compare:            &SourceCompare{Op: "gte", Value: 1},
						OnPermissionDenied: "fail",
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	check := compiled.Ruleset.Rules[0].Check
	if check == nil {
		t.Fatalf("expected compiled check")
	}
	if check.Engine != types.CheckEngineCELPlan {
		t.Fatalf("expected engine cel_plan when policy actions are configured, got %q", check.Engine)
	}
	if check.Plan == nil {
		t.Fatalf("expected plan payload for cel_plan check")
	}
	if check.Plan.Compare == nil {
		t.Fatalf("expected plan compare settings")
	}
	if check.Plan.Compare.Op != "gte" {
		t.Fatalf("expected compare op gte, got %q", check.Plan.Compare.Op)
	}
	if check.Plan.OnPermissionDenied != "fail" {
		t.Fatalf("expected plan.on_permission_denied=fail, got %q", check.Plan.OnPermissionDenied)
	}
}

func TestCompileRuleset_ManualAttestationClearsCheck(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
					Check: &SourceCheck{
						Type: "manual.attestation",
					},
				},
			},
		},
	}

	compiled, err := CompileRuleset(doc)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	if compiled.Ruleset.Rules[0].Check != nil {
		t.Fatalf("manual.attestation should compile to nil check")
	}
}

func TestCompileRuleset_RejectsInvalidOnEmptyValue(t *testing.T) {
	doc := SourceRulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: SourceRuleset{
			Key:   "example.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Rules: []SourceRule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:example"},
					Check: &SourceCheck{
						Type:    "dataset.field_compare",
						Dataset: "okta:example",
						Assert:  &SourcePredicate{Op: "eq", Path: "/x", Value: 1},
						Expect: &SourceExpect{
							OnEmpty: "pass",
						},
					},
				},
			},
		},
	}

	_, err := CompileRuleset(doc)
	if err == nil {
		t.Fatalf("expected compile error for invalid on_empty value")
	}
	if !strings.Contains(err.Error(), "on_empty") {
		t.Fatalf("expected on_empty validation error detail, got: %v", err)
	}
}
