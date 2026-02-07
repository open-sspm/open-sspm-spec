package v2

import (
	"encoding/json"
	"testing"
)

func TestRulesetAddRuleAppendReplaceAndErrors(t *testing.T) {
	rs := &Ruleset{Rules: []Rule{{Key: "R1", Title: "old"}}}

	replaced, err := rs.AddRule(Rule{Key: "R2", Title: "new"})
	if err != nil {
		t.Fatalf("AddRule append returned error: %v", err)
	}
	if replaced {
		t.Fatalf("AddRule append should not report replaced")
	}
	if len(rs.Rules) != 2 || rs.Rules[1].Key != "R2" {
		t.Fatalf("AddRule append produced unexpected rules: %+v", rs.Rules)
	}

	replaced, err = rs.AddRule(Rule{Key: "R1", Title: "updated"})
	if err != nil {
		t.Fatalf("AddRule replace returned error: %v", err)
	}
	if !replaced {
		t.Fatalf("AddRule replace should report replaced")
	}
	if len(rs.Rules) != 2 || rs.Rules[0].Title != "updated" || rs.Rules[0].Key != "R1" {
		t.Fatalf("AddRule replace should preserve index and update value: %+v", rs.Rules)
	}

	if _, err := rs.AddRule(Rule{Key: "  "}); err == nil {
		t.Fatalf("AddRule should reject empty rule key")
	}

	var nilRuleset *Ruleset
	if _, err := nilRuleset.AddRule(Rule{Key: "R3"}); err == nil {
		t.Fatalf("AddRule should fail on nil receiver")
	}
}

func TestEvaluateRuleCELPassFail(t *testing.T) {
	rule := Rule{
		Key: "R1",
		Monitoring: Monitoring{
			Status: MonitoringStatus_AUTOMATED,
		},
		Check: &Check{
			Engine:     CheckEngine_CEL,
			Expression: `rows("d").size() == int(param("min"))`,
		},
		Parameters: &Parameters{
			Defaults: map[string]any{"min": 2},
		},
	}

	passRes, err := rule.Evaluate(EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Rows: []any{map[string]any{"x": 1}, map[string]any{"x": 2}}},
		},
	})
	if err != nil {
		t.Fatalf("expected pass evaluation without error, got %v", err)
	}
	if passRes.Status != EvaluateStatus_PASS {
		t.Fatalf("expected pass status, got %+v", passRes)
	}
	if passRes.SelectedCount != 1 || passRes.PassedCount != 1 || passRes.CountValue != 1 {
		t.Fatalf("unexpected aggregate counters for pass: %+v", passRes)
	}

	failRes, err := rule.Evaluate(EvaluateInput{
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
	if failRes.SelectedCount != 1 || failRes.PassedCount != 0 || failRes.CountValue != 0 {
		t.Fatalf("unexpected aggregate counters for fail: %+v", failRes)
	}
}

func TestEvaluateRuleManualAndDatasetOutcomes(t *testing.T) {
	manual := Rule{
		Key:        "M1",
		Monitoring: Monitoring{Status: MonitoringStatus_MANUAL},
	}
	manualRes, err := manual.Evaluate(EvaluateInput{})
	if err != nil {
		t.Fatalf("manual rule should not error: %v", err)
	}
	if manualRes.Status != EvaluateStatus_UNKNOWN || manualRes.ReasonCode != "manual_rule" {
		t.Fatalf("unexpected manual result: %+v", manualRes)
	}

	automated := Rule{
		Key:        "A1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_CEL, Expression: `rows("d").size() > 0`},
	}

	missingDatasetRes, err := automated.Evaluate(EvaluateInput{Datasets: map[string]DatasetInput{}})
	if err != nil {
		t.Fatalf("missing dataset should not hard-fail: %v", err)
	}
	if missingDatasetRes.Status != EvaluateStatus_UNKNOWN || missingDatasetRes.ReasonCode != "dataset_missing_dataset" {
		t.Fatalf("unexpected missing dataset result: %+v", missingDatasetRes)
	}

	datasetErrRes, err := automated.Evaluate(EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Error: &DatasetInputError{Kind: DatasetErrorKind_PERMISSION_DENIED}},
		},
	})
	if err != nil {
		t.Fatalf("dataset error should not hard-fail: %v", err)
	}
	if datasetErrRes.Status != EvaluateStatus_UNKNOWN || datasetErrRes.ReasonCode != "dataset_permission_denied" {
		t.Fatalf("unexpected dataset error result: %+v", datasetErrRes)
	}
}

func TestEvaluateRuleMissingParamAndBadEngine(t *testing.T) {
	missingParam := Rule{
		Key:        "P1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_CEL, Expression: `rows("d").size() == int(param("min"))`},
	}
	res, err := missingParam.Evaluate(EvaluateInput{
		Datasets: map[string]DatasetInput{"d": {Rows: []any{map[string]any{"x": 1}}}},
	})
	if err == nil {
		t.Fatalf("missing param should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "missing_param" {
		t.Fatalf("unexpected missing param result: %+v", res)
	}

	badEngine := Rule{
		Key:        "E1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine("rego"), Expression: `true`},
	}
	res, err = badEngine.Evaluate(EvaluateInput{})
	if err == nil {
		t.Fatalf("unsupported engine should return error")
	}
	if res.Status != EvaluateStatus_UNKNOWN || res.ReasonCode != "unsupported_engine" {
		t.Fatalf("unexpected unsupported engine result: %+v", res)
	}
}

func TestEvaluateRuleHasDatasetGuardDoesNotRequireDataset(t *testing.T) {
	rule := Rule{
		Key:        "H1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_CEL, Expression: `!has_dataset("missing")`},
	}

	res, err := rule.Evaluate(EvaluateInput{Datasets: map[string]DatasetInput{}})
	if err != nil {
		t.Fatalf("has_dataset guard should evaluate without error, got %v", err)
	}
	if res.Status != EvaluateStatus_PASS {
		t.Fatalf("expected pass from !has_dataset guard, got %+v", res)
	}
}

func TestEvaluateRuleDirectDatasetAccessUsesProvidedDatasets(t *testing.T) {
	rule := Rule{
		Key:        "D1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_CEL, Expression: `datasets["d"].size() == 1`},
	}

	res, err := rule.Evaluate(EvaluateInput{
		Datasets: map[string]DatasetInput{
			"d": {Rows: []any{map[string]any{"x": 1}}},
		},
	})
	if err != nil {
		t.Fatalf("direct datasets access should evaluate without error, got %v", err)
	}
	if res.Status != EvaluateStatus_PASS {
		t.Fatalf("expected pass from direct datasets access, got %+v", res)
	}
}

func TestEvaluateResultIsAggregateOnly(t *testing.T) {
	rule := Rule{
		Key:        "R1",
		Monitoring: Monitoring{Status: MonitoringStatus_AUTOMATED},
		Check:      &Check{Engine: CheckEngine_CEL, Expression: `rows("d").size() > 0`},
	}
	res, err := rule.Evaluate(EvaluateInput{Datasets: map[string]DatasetInput{"d": {Rows: []any{map[string]any{"marker": "DO_NOT_LEAK"}}}}})
	if err != nil {
		t.Fatalf("evaluate returned error: %v", err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal evaluate result: %v", err)
	}
	if containsString(string(b), "DO_NOT_LEAK") {
		t.Fatalf("result leaked row payload: %s", string(b))
	}
	if containsString(string(b), "evidence") {
		t.Fatalf("aggregate-only output should not include evidence fields: %s", string(b))
	}
}

func containsString(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
