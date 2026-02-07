package verify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/celengine"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/compiler"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/yamlstrict"
)

func Run(ctx context.Context, repoRoot string) error {
	res, err := compiler.Compile(ctx, compiler.Options{RepoRoot: repoRoot})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	testFiles, err := findTestFiles(repoRoot)
	if err != nil {
		return err
	}

	if len(testFiles) == 0 {
		fmt.Println("No test cases found.")
		return nil
	}

	rulesByKey := make(map[string]*types.Rule)
	for _, rs := range res.Descriptor.Rulesets {
		for i := range rs.Object.Ruleset.Rules {
			r := &rs.Object.Ruleset.Rules[i]
			rulesByKey[r.Key] = r
		}
	}

	passed := 0
	failed := 0

	for _, tf := range testFiles {
		tc, err := loadTestCase(tf)
		if err != nil {
			fmt.Printf("FAIL: %s: %v\n", tf, err)
			failed++
			continue
		}

		rule, ok := rulesByKey[tc.RuleKey]
		if !ok {
			fmt.Printf("FAIL: %s: rule %q not found\n", tf, tc.RuleKey)
			failed++
			continue
		}

		status, err := evaluateRule(rule, tc.Inputs, tc.Parameters)
		if err != nil {
			fmt.Printf("FAIL: %s: %v\n", tf, err)
			failed++
			continue
		}

		if status != tc.Expect {
			fmt.Printf("FAIL: %s: expected %s, got %s\n", tf, tc.Expect, status)
			failed++
		} else {
			fmt.Printf("PASS: %s (%s)\n", tf, tc.Description)
			passed++
		}
	}

	fmt.Printf("\nSummary: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d tests failed", failed)
	}
	return nil
}

func evaluateRule(rule *types.Rule, datasets map[string][]any, params map[string]any) (string, error) {
	if rule == nil {
		return "unknown", fmt.Errorf("rule is nil")
	}
	if datasets == nil {
		datasets = map[string][]any{}
	}
	if params == nil {
		params = map[string]any{}
	}

	if rule.Monitoring.Status == types.MonitoringStatusManual || rule.Monitoring.Status == types.MonitoringStatusUnsupported {
		return "unknown", nil
	}

	if rule.Check == nil {
		return "unknown", nil
	}
	engine := strings.TrimSpace(string(rule.Check.Engine))
	if engine != string(types.CheckEngineCEL) && engine != string(types.CheckEngineCELPlan) {
		return "unknown", fmt.Errorf("unsupported check.engine %q", rule.Check.Engine)
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

	switch engine {
	case string(types.CheckEngineCEL):
		expression := strings.TrimSpace(rule.Check.Expression)
		if expression == "" {
			return "unknown", fmt.Errorf("check.expression is required")
		}

		ok, err := celengine.Evaluate(expression, datasets, effectiveParams)
		if err != nil {
			var missingDatasetErr celengine.MissingDatasetError
			if isMissingDatasetError(err, &missingDatasetErr) {
				return "unknown", nil
			}
			return "unknown", err
		}
		if ok {
			return "pass", nil
		}
		return "fail", nil
	case string(types.CheckEngineCELPlan):
		return evaluateCELPlan(rule.Check.Plan, datasets, effectiveParams)
	default:
		return "unknown", fmt.Errorf("unsupported check.engine %q", rule.Check.Engine)
	}
}

func isMissingDatasetError(err error, target *celengine.MissingDatasetError) bool {
	return errors.As(err, target)
}

func evaluateCELPlan(plan *types.CheckPlan, datasets map[string][]any, params map[string]any) (string, error) {
	if plan == nil {
		return "unknown", fmt.Errorf("check.plan is required for check.engine=cel_plan")
	}
	dataset := strings.TrimSpace(plan.Dataset)
	if dataset == "" {
		return "unknown", fmt.Errorf("check.plan.dataset is required")
	}

	rows, ok := datasets[dataset]
	if !ok {
		return statusForPolicyAction(plan.OnMissingDataset)
	}

	selected := rows
	whereExpr := strings.TrimSpace(plan.WhereExpression)
	if whereExpr != "" && whereExpr != "true" {
		filtered := make([]any, 0, len(rows))
		for _, row := range rows {
			match, err := celengine.EvaluatePredicate(whereExpr, row, params)
			if err != nil {
				return "unknown", err
			}
			if match {
				filtered = append(filtered, row)
			}
		}
		selected = filtered
	}

	switch strings.TrimSpace(plan.Type) {
	case "dataset.field_compare":
		return evaluateFieldComparePlan(plan, selected, params)
	case "dataset.count_compare":
		return evaluateCountComparePlan(plan, selected)
	default:
		return "unknown", fmt.Errorf("unsupported check.plan.type %q", plan.Type)
	}
}

func evaluateFieldComparePlan(plan *types.CheckPlan, selected []any, params map[string]any) (string, error) {
	assertExpr := strings.TrimSpace(plan.AssertExpression)
	if assertExpr == "" {
		return "unknown", fmt.Errorf("check.plan.assert_expression is required")
	}

	match := "all"
	minSelected := 1
	onEmpty := "fail"
	if plan.Expect != nil {
		if v := strings.ToLower(strings.TrimSpace(plan.Expect.Match)); v != "" {
			match = v
		}
		minSelected = plan.Expect.MinSelected
		if v := strings.ToLower(strings.TrimSpace(plan.Expect.OnEmpty)); v != "" {
			onEmpty = v
		}
	}

	if minSelected < 0 {
		return "unknown", fmt.Errorf("check.plan.expect.min_selected must be >= 0")
	}
	if onEmpty != "fail" && onEmpty != "unknown" {
		return "unknown", fmt.Errorf("check.plan.expect.on_empty must be fail|unknown")
	}
	if match != "all" && match != "any" {
		return "unknown", fmt.Errorf("check.plan.expect.match must be all|any")
	}

	selectedCount := len(selected)
	if selectedCount == 0 {
		if onEmpty == "unknown" {
			return "unknown", nil
		}
		return "fail", nil
	}
	if selectedCount < minSelected {
		return "fail", nil
	}

	passed := 0
	for _, row := range selected {
		ok, err := celengine.EvaluatePredicate(assertExpr, row, params)
		if err != nil {
			return "unknown", err
		}
		if ok {
			passed++
		}
	}

	if match == "all" {
		if passed == selectedCount {
			return "pass", nil
		}
		return "fail", nil
	}
	if passed > 0 {
		return "pass", nil
	}
	return "fail", nil
}

func evaluateCountComparePlan(plan *types.CheckPlan, selected []any) (string, error) {
	if plan.Compare == nil {
		return "unknown", fmt.Errorf("check.plan.compare is required")
	}
	target, ok := intValue(plan.Compare.Value)
	if !ok {
		return "unknown", fmt.Errorf("check.plan.compare.value must be an integer")
	}

	count := len(selected)
	op := strings.ToLower(strings.TrimSpace(plan.Compare.Op))
	pass, err := compareInts(op, count, target)
	if err != nil {
		return "unknown", err
	}
	if pass {
		return "pass", nil
	}
	return "fail", nil
}

func compareInts(op string, left, right int) (bool, error) {
	switch op {
	case "eq":
		return left == right, nil
	case "neq":
		return left != right, nil
	case "gt":
		return left > right, nil
	case "gte":
		return left >= right, nil
	case "lt":
		return left < right, nil
	case "lte":
		return left <= right, nil
	default:
		return false, fmt.Errorf("unsupported compare op %q", op)
	}
}

func intValue(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int8:
		return int(t), true
	case int16:
		return int(t), true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case uint:
		return int(t), true
	case uint8:
		return int(t), true
	case uint16:
		return int(t), true
	case uint32:
		return int(t), true
	case uint64:
		return int(t), true
	case float32:
		i := int(t)
		return i, float32(i) == t
	case float64:
		i := int(t)
		return i, float64(i) == t
	default:
		return 0, false
	}
}

func statusForPolicyAction(action string) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "", "unknown":
		return "unknown", nil
	case "fail":
		return "fail", nil
	case "error":
		return "unknown", fmt.Errorf("dataset missing and policy action is error")
	default:
		return "unknown", fmt.Errorf("unsupported policy action %q", action)
	}
}

func findTestFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".test.yaml") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func loadTestCase(path string) (*types.TestCaseDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tc types.TestCaseDoc
	if err := yamlstrict.DecodeSingleStrictYAML(b, &tc, true); err != nil {
		return nil, err
	}
	return &tc, nil
}
