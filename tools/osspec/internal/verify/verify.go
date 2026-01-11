package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/compiler"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/evaluate"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
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

		status, err := evaluate.Evaluate(rule, tc.Inputs, tc.Parameters)
		if err != nil {
			fmt.Printf("FAIL: %s: %v\n", tf, err)
			failed++
			continue
		}

		if string(status) != tc.Expect {
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

func findTestFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".test.json") {
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
	if err := json.Unmarshal(b, &tc); err != nil {
		return nil, err
	}
	return &tc, nil
}
