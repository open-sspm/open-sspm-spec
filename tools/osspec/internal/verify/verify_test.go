package verify

import (
	"strconv"
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

func TestEvaluateEntityPolicyParsesTimestampInputs(t *testing.T) {
	pack := &types.EntityPolicyPack{
		Metadata: types.EntityPolicyMetadata{
			ID:      "builtin.test.credential",
			Version: "1.0.0",
			Domain:  types.EntityPolicyDomainCredential,
		},
		Spec: types.EntityPolicySpec{
			Inputs: types.EntityPolicyInputs{Schema: "credential_risk_input.v1"},
			Constants: map[string][]string{
				"active_like_statuses": {"active"},
			},
			Rules: []types.EntityPolicyRule{
				{
					ID:       "expired_active",
					Severity: "critical",
					When:     `expires_at != null && expires_at < evaluated_at && status in active_like_statuses`,
					Title:    "Credential has expired while still marked active",
				},
			},
			Aggregation: types.EntityPolicyAggregation{
				RiskLevel: types.EntityPolicyAggregationStrategy{
					Default: "low",
				},
			},
		},
	}

	got, err := evaluateEntityPolicyPack(pack, map[string]any{
		"status":       "ACTIVE",
		"expires_at":   "2026-05-01T12:00:00Z",
		"evaluated_at": "2026-05-09T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("evaluateEntityPolicyPack() error = %v", err)
	}
	if got.RiskLevel != "critical" || len(got.Signals) != 1 || got.Signals[0].ID != "expired_active" {
		t.Fatalf("evaluateEntityPolicyPack() = %+v, want expired_active critical signal", got)
	}

	_, err = evaluateEntityPolicyPack(pack, map[string]any{
		"status":       "active",
		"expires_at":   "not-a-timestamp",
		"evaluated_at": "2026-05-09T12:00:00Z",
	})
	if err == nil {
		t.Fatal("evaluateEntityPolicyPack() error = nil, want invalid timestamp error")
	}
}

func TestNormalizeEntityPolicyIntRejectsUintOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("uint cannot exceed int64 on this platform")
	}

	_, err := normalizeEntityPolicyInt("actors_30d", uint(^uint(0)))
	if err == nil {
		t.Fatal("normalizeEntityPolicyInt() error = nil, want uint overflow error")
	}
}
