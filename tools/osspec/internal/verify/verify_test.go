package verify

import (
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestEvaluateRuleCELPlanFieldComparePass(t *testing.T) {
	rule := &types.Rule{
		Key:        "R1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
		Check: &types.Check{
			Engine: types.CheckEngineCELPlan,
			Plan: &types.CheckPlan{
				Type:             "dataset.field_compare",
				Dataset:          "d",
				WhereExpression:  `r["enabled"] == true`,
				AssertExpression: `r["score"] >= int(param("min"))`,
				Expect: &types.CheckPlanExpect{
					Match:       "all",
					MinSelected: 1,
					OnEmpty:     "fail",
				},
			},
		},
		Parameters: &types.Parameters{
			Defaults: map[string]any{"min": 10},
		},
	}

	status, err := evaluateRule(rule, map[string][]any{
		"d": {
			map[string]any{"enabled": true, "score": 12},
			map[string]any{"enabled": false, "score": 5},
		},
	}, nil)
	if err != nil {
		t.Fatalf("evaluateRule() returned error: %v", err)
	}
	if status != "pass" {
		t.Fatalf("expected pass, got %q", status)
	}
}

func TestEvaluateRuleCELPlanCountComparePass(t *testing.T) {
	rule := &types.Rule{
		Key:        "R1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
		Check: &types.Check{
			Engine: types.CheckEngineCELPlan,
			Plan: &types.CheckPlan{
				Type:            "dataset.count_compare",
				Dataset:         "d",
				WhereExpression: `r["enabled"] == true`,
				Compare: &types.CheckPlanCompare{
					Op:    "gte",
					Value: 2,
				},
			},
		},
	}

	status, err := evaluateRule(rule, map[string][]any{
		"d": {
			map[string]any{"enabled": true},
			map[string]any{"enabled": true},
			map[string]any{"enabled": false},
		},
	}, nil)
	if err != nil {
		t.Fatalf("evaluateRule() returned error: %v", err)
	}
	if status != "pass" {
		t.Fatalf("expected pass, got %q", status)
	}
}

func TestEvaluateRuleCELPlanMissingDatasetPolicy(t *testing.T) {
	baseRule := func(action string) *types.Rule {
		return &types.Rule{
			Key:        "R1",
			Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
			Check: &types.Check{
				Engine: types.CheckEngineCELPlan,
				Plan: &types.CheckPlan{
					Type:             "dataset.field_compare",
					Dataset:          "d",
					AssertExpression: `r["enabled"] == true`,
					OnMissingDataset: action,
				},
			},
		}
	}

	status, err := evaluateRule(baseRule(""), nil, nil)
	if err != nil {
		t.Fatalf("expected no error for default unknown policy, got %v", err)
	}
	if status != "unknown" {
		t.Fatalf("expected unknown for default policy, got %q", status)
	}

	status, err = evaluateRule(baseRule("fail"), nil, nil)
	if err != nil {
		t.Fatalf("expected no error for fail policy, got %v", err)
	}
	if status != "fail" {
		t.Fatalf("expected fail for fail policy, got %q", status)
	}

	status, err = evaluateRule(baseRule("error"), nil, nil)
	if err == nil {
		t.Fatalf("expected error for error policy")
	}
	if status != "unknown" {
		t.Fatalf("expected unknown status for error policy, got %q", status)
	}
}

func TestEvaluateRuleManualAlwaysUnknown(t *testing.T) {
	rule := &types.Rule{
		Key:        "M1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusManual},
		Check: &types.Check{
			Engine:     types.CheckEngineCEL,
			Expression: `true`,
		},
	}

	status, err := evaluateRule(rule, map[string][]any{
		"d": {map[string]any{"x": 1}},
	}, nil)
	if err != nil {
		t.Fatalf("expected no error for manual rule, got %v", err)
	}
	if status != "unknown" {
		t.Fatalf("expected unknown for manual rule, got %q", status)
	}
}
