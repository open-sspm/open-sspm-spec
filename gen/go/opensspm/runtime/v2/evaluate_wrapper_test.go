package v2

import (
	"reflect"
	"testing"

	specv2 "github.com/open-sspm/open-sspm-spec/gen/go/opensspm/spec/v2"
)

func TestEvaluateAliasesCompile(t *testing.T) {
	var _ EvaluateInput = specv2.EvaluateInput{}
	var _ EvaluateResult = specv2.EvaluateResult{}
	var _ EvaluateStatus = specv2.EvaluateStatus("")
}

func TestEvaluateRuleWrapperParity(t *testing.T) {
	rule := &specv2.Rule{
		Key: "R1",
		Monitoring: specv2.Monitoring{
			Status: specv2.MonitoringStatus_AUTOMATED,
		},
		Check: &specv2.Check{
			Engine: specv2.CheckEngine_REGO,
			Query:  "data.opensspm.tests.result",
			Rego: `package opensspm.tests

result := {"status": "pass"} if {
	count(object.get(object.get(input.datasets, "d", {}), "rows", [])) == 1
}`,
		},
	}
	ruleset := &specv2.Ruleset{}
	input := EvaluateInput{
		Datasets: map[string]specv2.DatasetInput{
			"d": {Rows: []any{map[string]any{"x": 1}}},
		},
	}

	wrapped, wrappedErr := EvaluateRule(ruleset, rule, input)
	direct, directErr := specv2.EvaluateRule(ruleset, rule, specv2.EvaluateInput(input))

	if (wrappedErr == nil) != (directErr == nil) {
		t.Fatalf("wrapper/direct error mismatch: wrapped=%v direct=%v", wrappedErr, directErr)
	}
	if wrappedErr != nil {
		return
	}
	if !reflect.DeepEqual(wrapped, direct) {
		t.Fatalf("wrapper/direct result mismatch:\nwrapped=%+v\ndirect=%+v", wrapped, direct)
	}
}
