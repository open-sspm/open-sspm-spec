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
		if rule.Check == nil || strings.TrimSpace(rule.Check.Expression) == "" {
			return "unknown", nil
		}
	}

	if rule.Check == nil {
		return "unknown", nil
	}
	if strings.TrimSpace(string(rule.Check.Engine)) != string(types.CheckEngineCEL) {
		return "unknown", fmt.Errorf("unsupported check.engine %q", rule.Check.Engine)
	}
	expression := strings.TrimSpace(rule.Check.Expression)
	if expression == "" {
		return "unknown", fmt.Errorf("check.expression is required")
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
}

func isMissingDatasetError(err error, target *celengine.MissingDatasetError) bool {
	return errors.As(err, target)
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
