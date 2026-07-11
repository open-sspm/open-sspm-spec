package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/compiler"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/regoengine"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/rulecheck"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/yamlstrict"
)

func Run(ctx context.Context, repoRoot string) error {
	desc, err := compiler.Compile(ctx, repoRoot)
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

	type rulesetRule struct {
		ruleset *types.Ruleset
		rule    *types.Rule
	}
	rulesByKey := make(map[string]rulesetRule)
	for i := range desc.Rulesets {
		ruleset := &desc.Rulesets[i].Object.Ruleset
		for j := range ruleset.Rules {
			rule := &ruleset.Rules[j]
			rulesByKey[rule.Key] = rulesetRule{ruleset: ruleset, rule: rule}
		}
	}

	entityPolicyPacksByKey := make(map[string]*types.EntityPolicyPack)
	for i := range desc.EntityPolicyPacks {
		compiled := &desc.EntityPolicyPacks[i]
		pack := &compiled.Object.EntityPolicyPack
		entityPolicyPacksByKey[pack.Metadata.ID] = pack
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

		if strings.TrimSpace(tc.ArtifactKind) == "opensspm.entity_policy_pack" {
			pack, ok := entityPolicyPacksByKey[tc.ArtifactKey]
			if !ok {
				fmt.Printf("FAIL: %s: entity policy pack %q not found\n", tf, tc.ArtifactKey)
				failed++
				continue
			}
			got, err := evaluateEntityPolicyPack(ctx, pack, tc.EntityInput)
			if err != nil {
				fmt.Printf("FAIL: %s: %v\n", tf, err)
				failed++
				continue
			}
			if err := compareEntityPolicyResult(tc.ExpectEntity, got); err != nil {
				fmt.Printf("FAIL: %s: %v\n", tf, err)
				failed++
			} else {
				fmt.Printf("PASS: %s (%s)\n", tf, tc.Description)
				passed++
			}
			continue
		}

		target, ok := rulesByKey[tc.RuleKey]
		if !ok {
			fmt.Printf("FAIL: %s: rule %q not found\n", tf, tc.RuleKey)
			failed++
			continue
		}
		status, err := evaluateRule(ctx, target.ruleset, target.rule, tc.Inputs, tc.Parameters)
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

type entityPolicyResult struct {
	RiskLevel string
	RiskScore int
	Signals   []types.EntityPolicyTestSignal
}

func evaluateRule(ctx context.Context, ruleset *types.Ruleset, rule *types.Rule, datasets map[string][]any, params map[string]any) (string, error) {
	if rule == nil {
		return "unknown", fmt.Errorf("rule is nil")
	}
	if rule.Monitoring.Status == types.MonitoringStatusManual || rule.Monitoring.Status == types.MonitoringStatusUnsupported {
		return "unknown", nil
	}
	if rule.Check == nil {
		return "unknown", nil
	}
	var policy *types.RegoPolicy
	if ruleset != nil {
		policy = ruleset.Policy
	}
	check := rulecheck.Resolve(policy, rule.Check)

	effectiveParams := make(map[string]any)
	for k, v := range rule.Parameters {
		effectiveParams[k] = v
	}
	for k, v := range params {
		effectiveParams[k] = v
	}

	input := map[string]any{
		"datasets": wrapDatasets(datasets),
		"params":   effectiveParams,
		"rule": map[string]any{
			"key":           rule.Key,
			"required_data": rule.RequiredData,
		},
	}

	result, err := regoengine.Evaluate(ctx, rule.Key+".rego", check.Rego, check.Query, input)
	if err != nil {
		return "unknown", err
	}
	return ruleStatusFromResult(result)
}

func evaluateEntityPolicyPack(ctx context.Context, pack *types.EntityPolicyPack, entityInput map[string]any) (entityPolicyResult, error) {
	if pack == nil {
		return entityPolicyResult{}, fmt.Errorf("entity policy pack is nil")
	}
	input := map[string]any{
		"entity": entityInput,
		"policy": map[string]any{
			"id":     pack.Metadata.ID,
			"domain": pack.Metadata.Domain,
		},
	}

	result, err := regoengine.Evaluate(ctx, pack.Metadata.ID+".rego", pack.Policy.Rego, pack.Policy.Query, input)
	if err != nil {
		return entityPolicyResult{}, err
	}
	return entityPolicyResultFromMap(result)
}

func wrapDatasets(inputs map[string][]any) map[string]any {
	out := make(map[string]any, len(inputs))
	for dataset, rows := range inputs {
		out[dataset] = map[string]any{"rows": rows}
	}
	return out
}

func ruleStatusFromResult(result regoengine.EvaluationResult) (string, error) {
	status := regoengine.ResultString(result, "status")
	switch status {
	case "pass", "fail", "unknown":
		return status, nil
	case "":
		return "unknown", fmt.Errorf("rego result.status is required")
	default:
		return "unknown", fmt.Errorf("rego result.status %q is invalid", status)
	}
}

func entityPolicyResultFromMap(result regoengine.EvaluationResult) (entityPolicyResult, error) {
	out := entityPolicyResult{
		RiskLevel: regoengine.ResultString(result, "risk_level"),
	}
	if v, ok := intFromAny(result["risk_score"]); ok {
		out.RiskScore = v
	}
	signals, ok := result["signals"].([]any)
	if !ok {
		return out, nil
	}
	for _, raw := range signals {
		signal, ok := raw.(map[string]any)
		if !ok {
			return entityPolicyResult{}, fmt.Errorf("entity policy signal must be object, got %T", raw)
		}
		out.Signals = append(out.Signals, types.EntityPolicyTestSignal{
			ID:       strings.TrimSpace(fmt.Sprint(signal["id"])),
			Severity: strings.TrimSpace(fmt.Sprint(signal["severity"])),
			Title:    strings.TrimSpace(fmt.Sprint(signal["title"])),
		})
	}
	return out, nil
}

func intFromAny(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return intFromInt64(v)
	case float64:
		return intFromFloat64(v)
	case json.Number:
		return intFromString(v.String())
	case string:
		return intFromString(v)
	default:
		return 0, false
	}
}

func intFromString(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if i, err := strconv.ParseInt(value, 10, strconv.IntSize); err == nil {
		return intFromInt64(i)
	}
	if strings.Contains(value, "/") {
		return 0, false
	}
	rat, ok := new(big.Rat).SetString(value)
	if !ok || !rat.IsInt() {
		return 0, false
	}
	if rat.Cmp(big.NewRat(int64(math.MinInt), 1)) < 0 || rat.Cmp(big.NewRat(int64(math.MaxInt), 1)) > 0 {
		return 0, false
	}
	return intFromInt64(rat.Num().Int64())
}

func intFromInt64(value int64) (int, bool) {
	if value < int64(math.MinInt) || value > int64(math.MaxInt) {
		return 0, false
	}
	return int(value), true
}

func intFromFloat64(value float64) (int, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
		return 0, false
	}
	if value < float64(math.MinInt) || value > float64(math.MaxInt) {
		return 0, false
	}
	if strconv.IntSize == 64 && value == float64(math.MaxInt) {
		return 0, false
	}
	return int(value), true
}

func compareEntityPolicyResult(expect *types.EntityPolicyTestExpect, got entityPolicyResult) error {
	if expect == nil {
		return fmt.Errorf("expect_entity is required")
	}
	if expect.RiskLevel != "" && expect.RiskLevel != got.RiskLevel {
		return fmt.Errorf("expected risk_level %s, got %s", expect.RiskLevel, got.RiskLevel)
	}
	if expect.RiskScore != nil && *expect.RiskScore != got.RiskScore {
		return fmt.Errorf("expected risk_score %d, got %d", *expect.RiskScore, got.RiskScore)
	}
	if len(expect.Signals) != len(got.Signals) {
		return fmt.Errorf("expected %d signals, got %d", len(expect.Signals), len(got.Signals))
	}
	for i := range expect.Signals {
		if expect.Signals[i].ID != got.Signals[i].ID {
			return fmt.Errorf("signal[%d].id: expected %s, got %s", i, expect.Signals[i].ID, got.Signals[i].ID)
		}
		if expect.Signals[i].Severity != "" && expect.Signals[i].Severity != got.Signals[i].Severity {
			return fmt.Errorf("signal[%d].severity: expected %s, got %s", i, expect.Signals[i].Severity, got.Signals[i].Severity)
		}
		if expect.Signals[i].Title != "" && expect.Signals[i].Title != got.Signals[i].Title {
			return fmt.Errorf("signal[%d].title: expected %s, got %s", i, expect.Signals[i].Title, got.Signals[i].Title)
		}
	}
	return nil
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
