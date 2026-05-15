package verify

import (
	"context"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

const testRuleRego = `package opensspm.test

selected := [r |
  r := input.datasets.d.rows[_]
  r.enabled == true
]

passed := [r |
  r := selected[_]
  r.score >= input.params.min
]

result := {"status": "pass", "selected_count": count(selected), "passed_count": count(passed)} if {
  count(selected) >= 1
  count(passed) == count(selected)
}

result := {"status": "fail", "selected_count": count(selected), "passed_count": count(passed)} if {
  count(selected) < 1
}

result := {"status": "fail", "selected_count": count(selected), "passed_count": count(passed)} if {
  count(selected) >= 1
  count(passed) != count(selected)
}
`

func TestEvaluateRuleRegoPassWithFakeData(t *testing.T) {
	rule := &types.Rule{
		Key:        "R1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
		Check: &types.Check{
			Engine:  types.CheckEngineRego,
			Package: "opensspm.test",
			Query:   "data.opensspm.test.result",
			Rego:    testRuleRego,
		},
		Parameters: &types.Parameters{
			Defaults: map[string]any{"min": 10},
		},
	}

	status, err := evaluateRule(context.Background(), rule, map[string][]any{
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

func TestEvaluateRuleManualAlwaysUnknown(t *testing.T) {
	rule := &types.Rule{
		Key:        "M1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusManual},
	}

	status, err := evaluateRule(context.Background(), rule, map[string][]any{
		"d": {map[string]any{"x": 1}},
	}, nil)
	if err != nil {
		t.Fatalf("expected no error for manual rule, got %v", err)
	}
	if status != "unknown" {
		t.Fatalf("expected unknown for manual rule, got %q", status)
	}
}

func TestEvaluateRuleRejectsInvalidRegoStatus(t *testing.T) {
	rule := &types.Rule{
		Key:        "R1",
		Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
		Check: &types.Check{
			Engine:  types.CheckEngineRego,
			Package: "opensspm.test",
			Query:   "data.opensspm.test.result",
			Rego: `package opensspm.test

result := {"status": "skipped"} if { true }
`,
		},
	}

	status, err := evaluateRule(context.Background(), rule, nil, nil)
	if err == nil {
		t.Fatalf("evaluateRule() expected invalid status error")
	}
	if status != "unknown" {
		t.Fatalf("expected unknown status on invalid Rego status, got %q", status)
	}
}

func TestIntFromStringRejectsOutOfRange(t *testing.T) {
	if got, ok := intFromString("9223372036854775808"); ok {
		t.Fatalf("intFromString() accepted value above int64 range: %d", got)
	}
	if got, ok := intFromString("-9223372036854775809"); ok {
		t.Fatalf("intFromString() accepted value below int64 range: %d", got)
	}
	if got, ok := intFromString("2/1"); ok {
		t.Fatalf("intFromString() accepted non-JSON fraction syntax: %d", got)
	}
}

func TestEvaluateEntityPolicyPackRego(t *testing.T) {
	pack := &types.EntityPolicyPack{
		Metadata: types.EntityPolicyMetadata{
			ID:      "builtin.test",
			Version: "1.0.0",
			Domain:  types.EntityPolicyDomainCredential,
		},
		Inputs: types.EntityPolicyInputs{Schema: "credential_risk_input.v1"},
		Policy: types.RegoPolicy{
			Engine:  types.CheckEngineRego,
			Package: "opensspm.entity.test",
			Query:   "data.opensspm.entity.test.result",
			Rego: `package opensspm.entity.test

result := {
  "risk_level": "critical",
  "risk_score": 90,
  "signals": [{"id": "expired_active", "severity": "critical", "title": "Credential has expired"}],
} if {
  input.entity.status == "active"
}
`,
		},
	}

	got, err := evaluateEntityPolicyPack(context.Background(), pack, map[string]any{"status": "active"})
	if err != nil {
		t.Fatalf("evaluateEntityPolicyPack() error = %v", err)
	}
	if got.RiskLevel != "critical" || got.RiskScore != 90 || len(got.Signals) != 1 || got.Signals[0].ID != "expired_active" {
		t.Fatalf("evaluateEntityPolicyPack() = %+v, want critical expired_active result", got)
	}
}

func TestEvaluateEntityPolicyPackReturnsBuiltinErrors(t *testing.T) {
	pack := &types.EntityPolicyPack{
		Metadata: types.EntityPolicyMetadata{
			ID:      "builtin.test",
			Version: "1.0.0",
			Domain:  types.EntityPolicyDomainCredential,
		},
		Policy: types.RegoPolicy{
			Engine:  types.CheckEngineRego,
			Package: "opensspm.entity.test",
			Query:   "data.opensspm.entity.test.result",
			Rego: `package opensspm.entity.test

expired if {
  time.parse_rfc3339_ns(input.entity.expires_at) < time.parse_rfc3339_ns(input.entity.evaluated_at)
}

result := {"risk_level": "critical"} if {
  expired
}

result := {"risk_level": "low"} if {
  not expired
}
`,
		},
	}

	_, err := evaluateEntityPolicyPack(context.Background(), pack, map[string]any{
		"expires_at":   "not-a-timestamp",
		"evaluated_at": "2026-05-15T12:00:00Z",
	})
	if err == nil {
		t.Fatalf("evaluateEntityPolicyPack() expected malformed timestamp builtin error")
	}
}
