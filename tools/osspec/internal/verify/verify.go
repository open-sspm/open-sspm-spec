package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"

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
	entityPolicyPacksByKey := make(map[string]*types.EntityPolicyPack)
	for i := range res.Descriptor.EntityPolicyPacks {
		compiled := &res.Descriptor.EntityPolicyPacks[i]
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
			got, err := evaluateEntityPolicyPack(pack, tc.EntityInput)
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

type entityPolicyResult struct {
	RiskLevel string
	RiskScore int
	Signals   []types.EntityPolicyTestSignal
}

func evaluateEntityPolicyPack(pack *types.EntityPolicyPack, input map[string]any) (entityPolicyResult, error) {
	if pack == nil {
		return entityPolicyResult{}, fmt.Errorf("entity policy pack is nil")
	}
	env, err := cel.NewEnv(entityPolicyEnvOptions(pack)...)
	if err != nil {
		return entityPolicyResult{}, fmt.Errorf("%s: create entity policy CEL env: %w", pack.Metadata.ID, err)
	}

	normalizedInput, err := normalizeEntityPolicyInput(input, pack.Metadata.Domain)
	if err != nil {
		return entityPolicyResult{}, err
	}
	activation := entityPolicyActivation(normalizedInput, pack.Spec.Constants, pack.Spec.Scoring.Base, "", "")
	switch pack.Metadata.Domain {
	case types.EntityPolicyDomainSaaS:
		return evaluateSaaSEntityPolicyPack(env, pack, activation)
	case types.EntityPolicyDomainCredential, types.EntityPolicyDomainIdentity:
		result := entityPolicyResult{RiskLevel: pack.Spec.Aggregation.RiskLevel.Default}
		if err := appendEntityPolicySignals(env, pack.Metadata.ID, "", pack.Spec.Rules, activation, &result); err != nil {
			return entityPolicyResult{}, err
		}
		if result.RiskLevel == "" {
			result.RiskLevel = "low"
		}
		return result, nil
	default:
		return entityPolicyResult{}, fmt.Errorf("%s: unsupported entity policy domain %q", pack.Metadata.ID, pack.Metadata.Domain)
	}
}

func evaluateSaaSEntityPolicyPack(env *cel.Env, pack *types.EntityPolicyPack, activation map[string]any) (entityPolicyResult, error) {
	result := entityPolicyResult{}

	businessCriticality, err := evaluateEntityPolicySuggestionRules(env, pack.Metadata.ID, pack.Spec.Suggestions.BusinessCriticality, activation)
	if err != nil {
		return entityPolicyResult{}, err
	}
	dataClassification, err := evaluateEntityPolicySuggestionRules(env, pack.Metadata.ID, pack.Spec.Suggestions.DataClassification, activation)
	if err != nil {
		return entityPolicyResult{}, err
	}

	for _, scopedRule := range pack.Spec.ScopedRules {
		if !entityPolicyAppScopeMatches(scopedRule.Scope.App, activation) {
			continue
		}
		businessCriticality = maxBusinessCriticality(businessCriticality, scopedRule.Suggestions.BusinessCriticality)
		dataClassification = maxDataClassification(dataClassification, scopedRule.Suggestions.DataClassification)
	}

	effectiveBusinessCriticality := effectiveBusinessCriticality(entityPolicyString(activation, "configured_business_criticality"), businessCriticality)
	effectiveDataClassification := effectiveDataClassification(entityPolicyString(activation, "configured_data_classification"), dataClassification)

	score := pack.Spec.Scoring.Base
	for _, rule := range pack.Spec.Scoring.Rules {
		ruleActivation := entityPolicyActivation(activation, pack.Spec.Constants, score, effectiveBusinessCriticality, effectiveDataClassification)
		matched, err := evaluateEntityPolicyBool(env, pack.Metadata.ID, rule.ID, rule.When, ruleActivation)
		if err != nil {
			return entityPolicyResult{}, err
		}
		if !matched {
			continue
		}

		score += rule.Points
		if rule.Signal.Severity != "" {
			result.Signals = append(result.Signals, types.EntityPolicyTestSignal{
				ID:       rule.ID,
				Severity: rule.Signal.Severity,
				Title:    rule.Signal.Title,
			})
		}
	}

	appliedScopedSignals := map[string]struct{}{}
	for _, scopedRule := range pack.Spec.ScopedRules {
		if !entityPolicyAppScopeMatches(scopedRule.Scope.App, activation) {
			continue
		}
		for _, rule := range scopedRule.Rules {
			ruleActivation := entityPolicyActivation(activation, pack.Spec.Constants, score, effectiveBusinessCriticality, effectiveDataClassification)
			ruleID := scopedRule.ID + "/" + rule.ID
			matched, err := evaluateEntityPolicyBool(env, pack.Metadata.ID, ruleID, rule.When, ruleActivation)
			if err != nil {
				return entityPolicyResult{}, err
			}
			if !matched {
				continue
			}
			dedupeKey := rule.ID + "\x00" + rule.Severity + "\x00" + rule.Title
			if _, ok := appliedScopedSignals[dedupeKey]; ok {
				continue
			}
			appliedScopedSignals[dedupeKey] = struct{}{}

			score += rule.ScoreDelta
			result.Signals = append(result.Signals, types.EntityPolicyTestSignal{
				ID:       rule.ID,
				Severity: rule.Severity,
				Title:    rule.Title,
			})
		}
	}

	result.RiskScore = clampScore(score, pack.Spec.Scoring.Max)
	levelActivation := entityPolicyActivation(activation, pack.Spec.Constants, result.RiskScore, effectiveBusinessCriticality, effectiveDataClassification)
	level, err := evaluateEntityPolicyLevelRules(env, pack.Metadata.ID, pack.Spec.Levels, levelActivation)
	if err != nil {
		return entityPolicyResult{}, err
	}
	if level != "" {
		result.RiskLevel = level
	}
	if result.RiskLevel == "" {
		result.RiskLevel = "low"
	}
	return result, nil
}

func appendEntityPolicySignals(env *cel.Env, packID, rulePrefix string, rules []types.EntityPolicyRule, activation map[string]any, result *entityPolicyResult) error {
	for _, rule := range rules {
		ruleID := rule.ID
		if rulePrefix != "" {
			ruleID = rulePrefix + "/" + rule.ID
		}
		matched, err := evaluateEntityPolicyBool(env, packID, ruleID, rule.When, activation)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		result.Signals = append(result.Signals, types.EntityPolicyTestSignal{
			ID:       rule.ID,
			Severity: rule.Severity,
			Title:    rule.Title,
		})
		result.RiskLevel = maxSeverity(result.RiskLevel, rule.Severity)
		result.RiskScore += rule.ScoreDelta
	}
	return nil
}

func evaluateEntityPolicySuggestionRules(env *cel.Env, packID string, rules []types.EntityPolicySuggestionRule, activation map[string]any) (string, error) {
	for _, rule := range rules {
		matched, err := evaluateEntityPolicyBool(env, packID, rule.ID, rule.When, activation)
		if err != nil {
			return "", err
		}
		if matched {
			return rule.Level, nil
		}
	}
	return "", nil
}

func evaluateEntityPolicyLevelRules(env *cel.Env, packID string, rules []types.EntityPolicyLevelRule, activation map[string]any) (string, error) {
	for _, rule := range rules {
		matched, err := evaluateEntityPolicyBool(env, packID, "level:"+rule.Level, rule.When, activation)
		if err != nil {
			return "", err
		}
		if matched {
			return rule.Level, nil
		}
	}
	return "", nil
}

func entityPolicyActivation(input map[string]any, constants map[string][]string, score int, effectiveBusinessCriticality, effectiveDataClassification string) map[string]any {
	activation := make(map[string]any)
	for k, v := range input {
		activation[k] = v
	}
	for k, v := range constants {
		activation[k] = v
	}
	activation["score"] = int64(score)
	if effectiveBusinessCriticality != "" {
		activation["effective_business_criticality"] = effectiveBusinessCriticality
	}
	if effectiveDataClassification != "" {
		activation["effective_data_classification"] = effectiveDataClassification
	}
	return activation
}

func evaluateEntityPolicyBool(env *cel.Env, packID, ruleID, expression string, activation map[string]any) (bool, error) {
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("%s: %s: compile %q: %w", packID, ruleID, expression, issues.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return false, fmt.Errorf("%s: %s: compile %q: expression must return bool, got %s", packID, ruleID, expression, ast.OutputType())
	}
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return false, fmt.Errorf("%s: %s: create CEL program for %q: %w", packID, ruleID, expression, err)
	}
	value, _, err := program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("%s: %s: evaluate %q: %w", packID, ruleID, expression, err)
	}
	matched, ok := value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("%s: %s: evaluate %q: expected bool result, got %T", packID, ruleID, expression, value.Value())
	}
	return matched, nil
}

func entityPolicyEnvOptions(pack *types.EntityPolicyPack) []cel.EnvOption {
	out := entityPolicyDomainEnvOptions(pack.Metadata.Domain)
	for name := range pack.Spec.Constants {
		out = append(out, cel.Variable(name, cel.ListType(cel.StringType)))
	}
	return out
}

func entityPolicyDomainEnvOptions(domain types.EntityPolicyDomain) []cel.EnvOption {
	switch domain {
	case types.EntityPolicyDomainCredential:
		return []cel.EnvOption{
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("credential_kind", cel.StringType),
			cel.Variable("status", cel.StringType),
			cel.Variable("expires_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("last_used_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("created_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("created_by_external_id", cel.StringType),
			cel.Variable("created_by_display_name", cel.StringType),
			cel.Variable("approved_by_external_id", cel.StringType),
			cel.Variable("approved_by_display_name", cel.StringType),
			cel.Variable("asset_ref_kind", cel.StringType),
			cel.Variable("asset_ref_external_id", cel.StringType),
			cel.Variable("scope_json", cel.DynType),
			cel.Variable("evaluated_at", cel.TimestampType),
		}
	case types.EntityPolicyDomainSaaS:
		return []cel.EnvOption{
			cel.Variable("canonical_key", cel.StringType),
			cel.Variable("display_name", cel.StringType),
			cel.Variable("primary_domain", cel.StringType),
			cel.Variable("vendor_name", cel.StringType),
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("category", cel.StringType),
			cel.Variable("actors_30d", cel.IntType),
			cel.Variable("has_privileged_scope", cel.BoolType),
			cel.Variable("has_confidential_scope", cel.BoolType),
			cel.Variable("managed_state", cel.StringType),
			cel.Variable("managed_reason", cel.StringType),
			cel.Variable("owner_identity_id", cel.IntType),
			cel.Variable("governance_state", cel.StringType),
			cel.Variable("review_disposition", cel.StringType),
			cel.Variable("follow_up_due_date", cel.NullableType(cel.TimestampType)),
			cel.Variable("configured_business_criticality", cel.StringType),
			cel.Variable("configured_data_classification", cel.StringType),
			cel.Variable("effective_business_criticality", cel.StringType),
			cel.Variable("effective_data_classification", cel.StringType),
			cel.Variable("connector_binding_configured", cel.BoolType),
			cel.Variable("connector_binding_enabled", cel.BoolType),
			cel.Variable("connector_binding_stale", cel.BoolType),
			cel.Variable("connector_binding_healthy", cel.BoolType),
			cel.Variable("score", cel.IntType),
		}
	case types.EntityPolicyDomainIdentity:
		return []cel.EnvOption{
			cel.Variable("identity_id", cel.IntType),
			cel.Variable("principal_ref", cel.StringType),
			cel.Variable("principal_type", cel.StringType),
			cel.Variable("source_kind", cel.StringType),
			cel.Variable("source_name", cel.StringType),
			cel.Variable("display_name", cel.StringType),
			cel.Variable("primary_email", cel.StringType),
			cel.Variable("last_seen_at", cel.NullableType(cel.TimestampType)),
			cel.Variable("owner_presence", cel.StringType),
			cel.Variable("governance_state", cel.StringType),
			cel.Variable("linked_assets_count", cel.IntType),
			cel.Variable("linked_credentials_count", cel.IntType),
			cel.Variable("credential_signals", cel.ListType(cel.StringType)),
			cel.Variable("has_critical_credential", cel.BoolType),
			cel.Variable("has_high_risk_credential", cel.BoolType),
			cel.Variable("has_expired_credential", cel.BoolType),
			cel.Variable("has_expiring_credential", cel.BoolType),
			cel.Variable("has_unused_credential", cel.BoolType),
			cel.Variable("has_stale_evidence", cel.BoolType),
		}
	default:
		return nil
	}
}

func normalizeEntityPolicyInput(input map[string]any, domain types.EntityPolicyDomain) (map[string]any, error) {
	out := make(map[string]any, len(input))
	for key, value := range input {
		switch key {
		case "source_kind":
			out[key] = normalizeEntityPolicySourceKind(fmt.Sprint(value), domain)
		case "credential_kind",
			"status",
			"asset_ref_kind",
			"canonical_key",
			"primary_domain",
			"vendor_name",
			"category",
			"managed_state",
			"managed_reason",
			"governance_state",
			"review_disposition",
			"configured_business_criticality",
			"configured_data_classification",
			"principal_type",
			"primary_email",
			"owner_presence":
			out[key] = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
		case "source_name",
			"display_name",
			"created_by_external_id",
			"created_by_display_name",
			"approved_by_external_id",
			"approved_by_display_name",
			"asset_ref_external_id",
			"principal_ref":
			out[key] = strings.TrimSpace(fmt.Sprint(value))
		case "credential_signals":
			out[key] = normalizeStringList(value)
		case "actors_30d",
			"owner_identity_id",
			"identity_id",
			"linked_assets_count",
			"linked_credentials_count":
			normalized, err := normalizeEntityPolicyInt(key, value)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		case "expires_at",
			"last_used_at",
			"created_at",
			"evaluated_at",
			"follow_up_due_date",
			"last_seen_at":
			normalized, err := normalizeEntityPolicyTimestamp(key, value)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		default:
			out[key] = value
		}
	}
	return out, nil
}

func normalizeStringList(value any) []string {
	switch values := value.(type) {
	case []string:
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, strings.ToLower(strings.TrimSpace(value)))
		}
		return out
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, strings.ToLower(strings.TrimSpace(fmt.Sprint(value))))
		}
		return out
	default:
		return nil
	}
}

func normalizeEntityPolicySourceKind(value string, domain types.EntityPolicyDomain) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if domain == types.EntityPolicyDomainSaaS && normalized == "aws_identity_center" {
		return "aws"
	}
	return normalized
}

func normalizeEntityPolicyInt(key string, value any) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case uint:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint64:
		if v > uint64(^uint64(0)>>1) {
			return 0, fmt.Errorf("entity_input.%s must fit in int64, got %d", key, v)
		}
		return int64(v), nil
	case float32:
		i := int64(v)
		if float32(i) != v {
			return 0, fmt.Errorf("entity_input.%s must be an integer, got %v", key, v)
		}
		return i, nil
	case float64:
		i := int64(v)
		if float64(i) != v {
			return 0, fmt.Errorf("entity_input.%s must be an integer, got %v", key, v)
		}
		return i, nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("entity_input.%s must be an integer: %w", key, err)
		}
		return i, nil
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("entity_input.%s must be an integer: %w", key, err)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("entity_input.%s must be an integer, got %T", key, value)
	}
}

func normalizeEntityPolicyTimestamp(key string, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch v := value.(type) {
	case time.Time:
		return v.UTC(), nil
	case string:
		value := strings.TrimSpace(v)
		if value == "" {
			return nil, nil
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, fmt.Errorf("entity_input.%s must be an RFC3339 timestamp: %w", key, err)
		}
		return parsed.UTC(), nil
	default:
		return nil, fmt.Errorf("entity_input.%s must be an RFC3339 timestamp string or null, got %T", key, value)
	}
}

func entityPolicyString(activation map[string]any, key string) string {
	value, ok := activation[key]
	if !ok || value == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
}

func entityPolicyAppScopeMatches(scope types.EntityPolicyAppScope, activation map[string]any) bool {
	if scope.CanonicalKey != "" && scope.CanonicalKey != entityPolicyString(activation, "canonical_key") {
		return false
	}
	if scope.PrimaryDomain != "" && scope.PrimaryDomain != entityPolicyString(activation, "primary_domain") {
		return false
	}
	if len(scope.DomainMatches) > 0 && !matchesDomainPatterns(entityPolicyString(activation, "primary_domain"), scope.DomainMatches) {
		return false
	}
	if scope.VendorName != "" && scope.VendorName != entityPolicyString(activation, "vendor_name") {
		return false
	}
	if scope.SourceKind != "" && scope.SourceKind != entityPolicyString(activation, "source_kind") {
		return false
	}
	if scope.SourceName != "" && scope.SourceName != strings.TrimSpace(fmt.Sprint(activation["source_name"])) {
		return false
	}
	if scope.Category != "" && scope.Category != entityPolicyString(activation, "category") {
		return false
	}
	return true
}

func matchesDomainPatterns(domain string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if domain == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(domain, suffix) {
				return true
			}
		}
		if strings.HasPrefix(pattern, ".") && strings.HasSuffix(domain, pattern) {
			return true
		}
	}
	return false
}

func effectiveBusinessCriticality(value, suggested string) string {
	if value != "" && value != "unknown" && businessCriticalityRank(value) > 0 {
		return value
	}
	return suggested
}

func effectiveDataClassification(value, suggested string) string {
	if value != "" && value != "unknown" && dataClassificationRank(value) > 0 {
		return value
	}
	return suggested
}

func maxBusinessCriticality(values ...string) string {
	return maxRankedValue(businessCriticalityRank, values...)
}

func maxDataClassification(values ...string) string {
	return maxRankedValue(dataClassificationRank, values...)
}

func maxRankedValue(rank func(string) int, values ...string) string {
	maxRank := -1
	maxValue := ""
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if currentRank := rank(value); currentRank > maxRank {
			maxRank = currentRank
			maxValue = value
		}
	}
	return maxValue
}

func businessCriticalityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func dataClassificationRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "public":
		return 1
	case "internal":
		return 2
	case "confidential":
		return 3
	case "restricted":
		return 4
	default:
		return 0
	}
}

func clampScore(score, maxScore int) int {
	if score < 0 {
		return 0
	}
	if maxScore > 0 && score > maxScore {
		return maxScore
	}
	return score
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

func maxSeverity(values ...string) string {
	maxRank := 0
	maxSeverity := ""
	for _, value := range values {
		rank := severityRank(value)
		if rank > maxRank {
			maxRank = rank
			maxSeverity = strings.ToLower(strings.TrimSpace(value))
		}
	}
	return maxSeverity
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
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
