package evaluate

import (
	"fmt"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

func Evaluate(rule *types.Rule, datasets map[string][]any, params map[string]any) (Status, error) {
	if rule.Check == nil {
		return StatusUnknown, nil
	}

	effectiveParams := make(map[string]any)
	if rule.Parameters != nil {
		for k, v := range rule.Parameters.Defaults {
			effectiveParams[k] = v
		}
	}
	for k, v := range params {
		effectiveParams[k] = v
	}

	switch rule.Check.Type {
	case types.CheckTypeDatasetFieldCompare:
		return evaluateFieldCompare(rule.Check, datasets, effectiveParams)
	case types.CheckTypeDatasetCountCompare:
		return evaluateCountCompare(rule.Check, datasets, effectiveParams)
	case types.CheckTypeManualAttestation:
		return StatusUnknown, nil
	default:
		return StatusUnknown, fmt.Errorf("unsupported check type %q", rule.Check.Type)
	}
}

func evaluateFieldCompare(check *types.Check, datasets map[string][]any, params map[string]any) (Status, error) {
	rows, ok := datasets[check.Dataset]
	if !ok {
		return StatusUnknown, fmt.Errorf("dataset %q not found", check.Dataset)
	}

	var selectedRows []any
	for _, row := range rows {
		match := true
		for _, p := range check.Where {
			ok, err := evaluatePredicate(p, row, params)
			if err != nil {
				return StatusUnknown, err
			}
			if !ok {
				match = false
				break
			}
		}
		if match {
			selectedRows = append(selectedRows, row)
		}
	}

	if len(selectedRows) == 0 {
		switch check.Expect.OnEmpty {
		case types.FieldCompareOnEmptyPass:
			return StatusPass, nil
		case types.FieldCompareOnEmptyFail:
			return StatusFail, nil
		case types.FieldCompareOnEmptyUnknown:
			return StatusUnknown, nil
		default:
			return StatusUnknown, nil
		}
	}

	passCount := 0
	for _, row := range selectedRows {
		pass, err := evaluatePredicate(*check.Assert, row, params)
		if err != nil {
			return StatusUnknown, err
		}
		if pass {
			passCount++
		}
	}

	match := check.Expect.Match
	if match == "" {
		match = types.FieldCompareMatchAll
	}

	switch match {
	case types.FieldCompareMatchAll:
		if passCount == len(selectedRows) {
			return StatusPass, nil
		}
		return StatusFail, nil
	case types.FieldCompareMatchAny:
		if passCount > 0 {
			return StatusPass, nil
		}
		return StatusFail, nil
	case types.FieldCompareMatchNone:
		if passCount == 0 {
			return StatusPass, nil
		}
		return StatusFail, nil
	default:
		return StatusUnknown, fmt.Errorf("unsupported match strategy %q", match)
	}
}

func evaluateCountCompare(check *types.Check, datasets map[string][]any, params map[string]any) (Status, error) {
	rows, ok := datasets[check.Dataset]
	if !ok {
		return StatusUnknown, fmt.Errorf("dataset %q not found", check.Dataset)
	}

	count := 0
	for _, row := range rows {
		match := true
		for _, p := range check.Where {
			ok, err := evaluatePredicate(p, row, params)
			if err != nil {
				return StatusUnknown, err
			}
			if !ok {
				match = false
				break
			}
		}
		if match {
			count++
		}
	}

	target := 0
	if check.Compare.Value != nil {
		target = *check.Compare.Value
	} else if check.Compare.ValueParam != "" {
		v, ok := params[check.Compare.ValueParam]
		if !ok {
			return StatusUnknown, fmt.Errorf("param %q not found", check.Compare.ValueParam)
		}
		switch t := v.(type) {
		case int:
			target = t
		case float64:
			target = int(t)
		default:
			return StatusUnknown, fmt.Errorf("param %q must be an integer", check.Compare.ValueParam)
		}
	}

	var pass bool
	switch check.Compare.Op {
	case types.CompareOpEq:
		pass = count == target
	case types.CompareOpNeq:
		pass = count != target
	case types.CompareOpLt:
		pass = count < target
	case types.CompareOpLte:
		pass = count <= target
	case types.CompareOpGt:
		pass = count > target
	case types.CompareOpGte:
		pass = count >= target
	default:
		return StatusUnknown, fmt.Errorf("unsupported compare op %q", check.Compare.Op)
	}

	if pass {
		return StatusPass, nil
	}
	return StatusFail, nil
}
