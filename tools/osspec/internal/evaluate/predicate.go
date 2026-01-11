package evaluate

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func evaluatePredicate(p types.Predicate, row any, params map[string]any) (bool, error) {
	val, exists, err := getValueAtPath(row, p.Path)
	if err != nil {
		return false, err
	}

	if p.Op == types.OperatorExists {
		return exists, nil
	}
	if p.Op == types.OperatorAbsent {
		return !exists, nil
	}

	if !exists {
		return false, nil
	}

	target := p.Value
	if p.ValueParam != "" {
		v, ok := params[p.ValueParam]
		if !ok {
			return false, fmt.Errorf("param %q not found", p.ValueParam)
		}
		target = v
	}

	return compareValues(val, p.Op, target)
}

func getValueAtPath(data any, path string) (any, bool, error) {
	if path == "" || path == "/" {
		return data, true, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	curr := data
	for _, part := range parts {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")

		switch v := curr.(type) {
		case map[string]any:
			next, ok := v[part]
			if !ok {
				return nil, false, nil
			}
			curr = next
		case []any:
			var idx int
			if _, err := fmt.Sscanf(part, "%d", &idx); err != nil {
				return nil, false, fmt.Errorf("invalid array index %q", part)
			}
			if idx < 0 || idx >= len(v) {
				return nil, false, nil
			}
			curr = v[idx]
		default:
			return nil, false, nil
		}
	}
	return curr, true, nil
}

func compareValues(actual any, op types.Operator, expected any) (bool, error) {
	switch op {
	case types.OperatorEq:
		return reflect.DeepEqual(actual, expected), nil
	case types.OperatorNeq:
		return !reflect.DeepEqual(actual, expected), nil
	case types.OperatorIn:
		expList, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("op 'in' requires array target")
		}
		for _, e := range expList {
			if reflect.DeepEqual(actual, e) {
				return true, nil
			}
		}
		return false, nil
	}

	// For numeric comparisons
	aNum, aOk := toFloat64(actual)
	eNum, eOk := toFloat64(expected)
	if aOk && eOk {
		switch op {
		case types.OperatorLt:
			return aNum < eNum, nil
		case types.OperatorLte:
			return aNum <= eNum, nil
		case types.OperatorGt:
			return aNum > eNum, nil
		case types.OperatorGte:
			return aNum >= eNum, nil
		}
	}

	return false, fmt.Errorf("unsupported operator %q or type mismatch", op)
}

func toFloat64(v any) (float64, bool) {
	switch i := v.(type) {
	case float64:
		return i, true
	case float32:
		return float64(i), true
	case int:
		return float64(i), true
	case int64:
		return float64(i), true
	}
	return 0, false
}
