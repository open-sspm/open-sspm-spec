package regoengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	DefaultRuleQuery         = "data.opensspm.rule.result"
	DefaultEntityPolicyQuery = "data.opensspm.entity.result"
)

type EvaluationResult map[string]any

func ValidateModule(ctx context.Context, moduleName, module, query string) error {
	module = strings.TrimSpace(module)
	if module == "" {
		return fmt.Errorf("rego module is required")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return fmt.Errorf("rego query is required")
	}

	_, err := rego.New(
		rego.Query(query),
		rego.Module(moduleName, module),
		rego.Strict(true),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}
	return nil
}

func ValidateModuleOnly(ctx context.Context, moduleName, module string) error {
	module = strings.TrimSpace(module)
	if module == "" {
		return fmt.Errorf("rego module is required")
	}

	_, err := rego.New(
		rego.Query("true"),
		rego.Module(moduleName, module),
		rego.Strict(true),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}
	return nil
}

func Evaluate(ctx context.Context, moduleName, module, query string, input any) (EvaluationResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("rego query is required")
	}

	rs, err := rego.New(
		rego.Query(query),
		rego.Module(moduleName, module),
		rego.Input(input),
		rego.Strict(true),
	).Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("rego query %q is undefined", query)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return nil, fmt.Errorf("rego query %q must return exactly one object result, got %d results", query, len(rs))
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rego query %q must return object, got %T", query, rs[0].Expressions[0].Value)
	}
	return EvaluationResult(result), nil
}

func ResultString(result EvaluationResult, key string) string {
	value, ok := result[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
