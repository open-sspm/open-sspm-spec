package rulecompile

import (
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestCompileRuleset_StructuredFieldCompareToCELPlan(t *testing.T) {
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
							{Op: "eq", Path: "status", Value: "ACTIVE"},
						},
						Assert: &SourcePredicate{Op: "gte", Path: "settings.password.complexity.minLength", Value: 15},
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
	if check.Engine != types.CheckEngineCELPlan {
		t.Fatalf("expected check.engine=cel_plan, got %q", check.Engine)
	}
	if check.Plan == nil {
		t.Fatalf("expected plan payload for cel_plan check")
	}
	if check.Plan.Type != "dataset.field_compare" {
		t.Fatalf("expected plan.type=dataset.field_compare, got %q", check.Plan.Type)
	}
	if check.Plan.Dataset != "okta:policies/password" {
		t.Fatalf("expected plan.dataset=okta:policies/password, got %q", check.Plan.Dataset)
	}
	if !strings.Contains(check.Plan.WhereExpression, `field(r, "status")`) {
		t.Fatalf("expected field() in where_expression, got %q", check.Plan.WhereExpression)
	}
	if !strings.Contains(check.Plan.AssertExpression, `field(r, "settings.password.complexity.minLength")`) {
		t.Fatalf("expected field() in assert_expression, got %q", check.Plan.AssertExpression)
	}
	if check.Plan.Expect == nil || check.Plan.Expect.Match != "all" || check.Plan.Expect.MinSelected != 1 || check.Plan.Expect.OnEmpty != "fail" {
		t.Fatalf("unexpected expect: %+v", check.Plan.Expect)
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
						{Op: "eq", Path: "status", Value: "ACTIVE"},
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
							{Op: "eq", Path: "region", Value: "US"},
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

	if check.Engine != types.CheckEngineCELPlan {
		t.Fatalf("expected check.engine=cel_plan, got %q", check.Engine)
	}
	if check.Plan == nil {
		t.Fatalf("expected plan payload for cel_plan check")
	}
	if check.Plan.Type != "dataset.count_compare" {
		t.Fatalf("expected plan.type=dataset.count_compare, got %q", check.Plan.Type)
	}
	if check.Plan.Dataset != "okta:log-streams" {
		t.Fatalf("expected plan.dataset=okta:log-streams, got %q", check.Plan.Dataset)
	}
	if !strings.Contains(check.Plan.WhereExpression, `field(r, "status")`) || !strings.Contains(check.Plan.WhereExpression, `field(r, "region")`) {
		t.Fatalf("expected field() in where_expression, got %q", check.Plan.WhereExpression)
	}
	if check.Plan.Compare == nil || check.Plan.Compare.Op != "gte" {
		t.Fatalf("expected compare op gte, got %+v", check.Plan.Compare)
	}
}

func TestCompileRuleset_StructuredDotPath(t *testing.T) {
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
						Assert:  &SourcePredicate{Op: "eq", Path: "a.b.c", Value: "x"},
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
	if check == nil || check.Plan == nil {
		t.Fatalf("expected compiled check with plan")
	}
	if !strings.Contains(check.Plan.AssertExpression, `field(r, "a.b.c")`) {
		t.Fatalf("expected field() with dot path in assert_expression, got: %s", check.Plan.AssertExpression)
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
						Assert:  &SourcePredicate{Op: "eq", Path: "x", Value: 1},
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
						Assert:           &SourcePredicate{Op: "eq", Path: "x", Value: 1},
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
						Assert:  &SourcePredicate{Op: "eq", Path: "x", Value: 1},
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

func TestCompileRuleset_RejectsCountCompareValueParam(t *testing.T) {
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
						Type:    "dataset.count_compare",
						Dataset: "okta:example",
						Compare: &SourceCompare{
							Op:         "gte",
							ValueParam: "min_count",
						},
					},
				},
			},
		},
	}

	_, err := CompileRuleset(doc)
	if err == nil {
		t.Fatalf("expected compile error for count compare value_param")
	}
	if !strings.Contains(err.Error(), "value_param is not supported") {
		t.Fatalf("expected value_param unsupported error, got: %v", err)
	}
}

func TestCompileRuleset_RejectsSlashPath(t *testing.T) {
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
						Assert: &SourcePredicate{
							Op:    "eq",
							Path:  "/status",
							Value: "ACTIVE",
						},
					},
				},
			},
		},
	}

	_, err := CompileRuleset(doc)
	if err == nil {
		t.Fatalf("expected compile error for slash path")
	}
	if !strings.Contains(err.Error(), "must not contain '/'") {
		t.Fatalf("expected slash path validation error, got: %v", err)
	}
}
