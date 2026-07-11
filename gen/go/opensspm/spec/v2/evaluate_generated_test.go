package v2

import (
	"strings"
	"testing"
)

const testRuleRego = `package opensspm.tests

rows := object.get(object.get(input.datasets, "d", {}), "rows", [])

result := {
	"status": "pass",
	"selected_count": count(rows),
	"passed_count": count(rows),
	"count_value": count(rows),
	"target_value": input.params.min,
} if {
	count(rows) == input.params.min
}

result := {
	"status": "fail",
	"selected_count": count(rows),
	"passed_count": 0,
	"count_value": count(rows),
	"target_value": input.params.min,
} if {
	count(rows) != input.params.min
}`

func TestEvaluateRuleRegoPassFail(t *testing.T) {
	ruleset := Ruleset{Policy: &RegoPolicy{Rego: testRuleRego}}
	rule := Rule{
		Key:        "R1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check: &Check{
			Engine: CheckEngine_REGO,
			Query:  "data.opensspm.tests.result",
		},
		Parameters: &Parameters{Defaults: map[string]any{"min": 2}},
	}

	passRes, err := EvaluateRule(&ruleset, &rule, EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Rows: []any{map[string]any{"x": 1}, map[string]any{"x": 2}}},
		},
	})
	if err != nil {
		t.Fatalf("expected pass evaluation without error, got %v", err)
	}
	if passRes.Status != EvaluateStatus_PASS || passRes.TargetValue == nil || *passRes.TargetValue != 2 {
		t.Fatalf("expected pass status and target, got %+v", passRes)
	}
	if passRes.SelectedCount != 2 || passRes.PassedCount != 2 || passRes.CountValue != 2 {
		t.Fatalf("unexpected aggregate counters for pass: %+v", passRes)
	}

	failRes, err := EvaluateRule(&ruleset, &rule, EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Rows: []any{map[string]any{"x": 1}}},
		},
	})
	if err != nil {
		t.Fatalf("expected fail evaluation without error, got %v", err)
	}
	if failRes.Status != EvaluateStatus_FAIL {
		t.Fatalf("expected fail status, got %+v", failRes)
	}
}

func TestEvaluateRulePrefersRuleModule(t *testing.T) {
	ruleset := Ruleset{Policy: &RegoPolicy{Rego: `package opensspm.tests

result := {"status": "fail"} if { true }`}}
	rule := Rule{
		Key:        "R1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check: &Check{
			Engine: CheckEngine_REGO,
			Query:  "data.opensspm.tests.result",
			Rego: `package opensspm.tests

result := {"status": "pass"} if { true }`,
		},
	}

	result, err := EvaluateRule(&ruleset, &rule, EvaluateInput{})
	if err != nil {
		t.Fatalf("EvaluateRule() returned error: %v", err)
	}
	if result.Status != EvaluateStatus_PASS {
		t.Fatalf("EvaluateRule() ignored rule module override: %+v", result)
	}
}

func TestEvaluateRuleRejectsUnresolvedRuleRegoPath(t *testing.T) {
	ruleset := Ruleset{Policy: &RegoPolicy{Rego: `package opensspm.tests

result := {"status": "pass"} if { true }`}}
	rule := Rule{
		Key:        "R1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check: &Check{
			Engine:   CheckEngine_REGO,
			Query:    "data.opensspm.tests.result",
			RegoPath: "rule.rego",
		},
	}

	result, err := EvaluateRule(&ruleset, &rule, EvaluateInput{})
	if err == nil || !strings.Contains(err.Error(), "must be resolved") {
		t.Fatalf("EvaluateRule() error = %v, want unresolved rego_path error", err)
	}
	if result.Status != EvaluateStatus_UNKNOWN || result.ReasonCode != "rego_error" {
		t.Fatalf("EvaluateRule() result = %+v, want Rego error", result)
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

func TestEvaluateRuleManualAndErrors(t *testing.T) {
	manual := Rule{
		Key:        "M1",
		Monitoring: Monitoring{Status: MonitoringStatus_MANUAL},
	}
	manualRes, err := EvaluateRule(nil, &manual, EvaluateInput{})
	if err != nil {
		t.Fatalf("manual rule should not error: %v", err)
	}
	if manualRes.Status != EvaluateStatus_UNKNOWN || manualRes.ReasonCode != "manual_rule" {
		t.Fatalf("unexpected manual result: %+v", manualRes)
	}

	missingCheck := Rule{
		Key:        "A1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
	}
	res, err := EvaluateRule(nil, &missingCheck, EvaluateInput{})
	if err == nil {
		t.Fatalf("missing check should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "missing_check" {
		t.Fatalf("unexpected missing-check result: %+v", res)
	}

	badEngine := Rule{
		Key:        "E1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine("legacy"), Query: "data.bad.result", Rego: `package bad`},
	}
	res, err = EvaluateRule(nil, &badEngine, EvaluateInput{})
	if err == nil {
		t.Fatalf("unsupported engine should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "unsupported_engine" {
		t.Fatalf("unexpected unsupported engine result: %+v", res)
	}
}

func TestEvaluateRuleDatasetErrorVisibleToRego(t *testing.T) {
	const module = `package opensspm.tests

result := {"status": "unknown", "reason_code": sprintf("dataset_%s", [kind])} if {
	err := object.get(object.get(input.datasets, "d", {}), "error", null)
	err != null
	kind := object.get(err, "kind", "engine_error")
}`
	rule := Rule{
		Key:        "D1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_REGO, Query: "data.opensspm.tests.result", Rego: module},
	}

	res, err := EvaluateRule(nil, &rule, EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Error: &DatasetInputError{Kind: DatasetErrorKind_PERMISSION_DENIED}},
		},
	})
	if err != nil {
		t.Fatalf("dataset error policy should evaluate in Rego: %v", err)
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "dataset_permission_denied" {
		t.Fatalf("unexpected dataset error result: %+v", res)
	}
}

func TestEvaluateRuleRejectsInvalidStatus(t *testing.T) {
	const module = `package opensspm.tests

result := {"status": "skipped"} if { true }`
	rule := Rule{
		Key:        "S1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_REGO, Query: "data.opensspm.tests.result", Rego: module},
	}

	res, err := EvaluateRule(nil, &rule, EvaluateInput{})
	if err == nil {
		t.Fatalf("invalid Rego status should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "invalid_status" {
		t.Fatalf("unexpected invalid-status result: %+v", res)
	}
}

func TestEvaluateRuleRejectsMissingStatus(t *testing.T) {
	const module = `package opensspm.tests

result := {"reason_code": "missing_status"} if { true }`
	rule := Rule{
		Key:        "S2",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_REGO, Query: "data.opensspm.tests.result", Rego: module},
	}

	res, err := EvaluateRule(nil, &rule, EvaluateInput{})
	if err == nil {
		t.Fatalf("missing Rego status should return error")
	}
	if err.Error() != "rego result.status is required" {
		t.Fatalf("unexpected missing-status error: %v", err)
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "invalid_status" {
		t.Fatalf("unexpected missing-status result: %+v", res)
	}
}

func TestEvaluateRuleRejectsMultipleQueryResults(t *testing.T) {
	const module = `package opensspm.tests

results["pass"] := {"status": "pass"} if { true }
results["fail"] := {"status": "fail"} if { true }`
	rule := Rule{
		Key:        "M1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_REGO, Query: "data.opensspm.tests.results[_]", Rego: module},
	}

	res, err := EvaluateRule(nil, &rule, EvaluateInput{})
	if err == nil {
		t.Fatalf("multiple Rego query results should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "rego_error" {
		t.Fatalf("unexpected multiple-result response: %+v", res)
	}
}
