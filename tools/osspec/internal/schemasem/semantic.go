package schemasem

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/celengine"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/entitypolicycel"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

type Bundle struct {
	Version  types.Version
	Rulesets []struct {
		Path string
		Doc  types.RulesetDoc
	}
	Profiles []struct {
		Path string
		Doc  types.ProfileDoc
	}
	EntityPolicyPacks []struct {
		Path string
		Doc  types.EntityPolicyPackDoc
	}
}

func ValidateSemantic(b *Bundle) []error {
	if b == nil {
		return []error{fmt.Errorf("semantic: nil bundle")}
	}

	var errs []error

	seenRulesetKeys := map[string]string{}
	rulesetsByKey := map[string]struct{}{}
	for _, rs := range b.Rulesets {
		key := rs.Doc.Ruleset.Key
		if prev, ok := seenRulesetKeys[key]; ok {
			errs = append(errs, fmt.Errorf("semantic: duplicate ruleset.key %q in %s and %s", key, prev, rs.Path))
		} else {
			seenRulesetKeys[key] = rs.Path
		}
		rulesetsByKey[key] = struct{}{}

		errs = append(errs, validateScope(rs.Path, rs.Doc.Ruleset.Scope)...)
		errs = append(errs, validateRulesetRules(rs.Path, &rs.Doc)...)
	}

	seenEntityPolicyPackIDs := map[string]string{}
	for _, pack := range b.EntityPolicyPacks {
		id := pack.Doc.EntityPolicyPack.Metadata.ID
		if prev, ok := seenEntityPolicyPackIDs[id]; ok {
			errs = append(errs, fmt.Errorf("semantic: duplicate entity_policy_pack.metadata.id %q in %s and %s", id, prev, pack.Path))
		} else {
			seenEntityPolicyPackIDs[id] = pack.Path
		}
		errs = append(errs, validateEntityPolicyPack(pack.Path, &pack.Doc)...)
	}

	seenProfileKeys := map[string]string{}
	for _, p := range b.Profiles {
		key := p.Doc.Profile.Key
		if prev, ok := seenProfileKeys[key]; ok {
			errs = append(errs, fmt.Errorf("semantic: duplicate profile.key %q in %s and %s", key, prev, p.Path))
		} else {
			seenProfileKeys[key] = p.Path
		}

		seenRulesetRefs := map[string]struct{}{}
		for i := range p.Doc.Profile.Rulesets {
			r := p.Doc.Profile.Rulesets[i]
			if _, ok := rulesetsByKey[r.Key]; !ok {
				errs = append(errs, fmt.Errorf("semantic: %s: profile %q references missing ruleset.key %q", p.Path, key, r.Key))
			}
			if _, dup := seenRulesetRefs[r.Key]; dup {
				errs = append(errs, fmt.Errorf("semantic: %s: profile %q has duplicate ruleset ref %q", p.Path, key, r.Key))
			} else {
				seenRulesetRefs[r.Key] = struct{}{}
			}
		}
	}

	return errs
}

func validateEntityPolicyPack(path string, doc *types.EntityPolicyPackDoc) []error {
	var errs []error
	if doc == nil {
		return []error{fmt.Errorf("semantic: %s: nil entity policy pack", path)}
	}
	pack := doc.EntityPolicyPack
	if strings.TrimSpace(pack.Metadata.ID) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: entity_policy_pack.metadata.id is required", path))
	}
	if strings.TrimSpace(pack.Metadata.Version) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: entity_policy_pack.metadata.version is required", path))
	}
	switch pack.Metadata.Domain {
	case types.EntityPolicyDomainCredential, types.EntityPolicyDomainSaaS, types.EntityPolicyDomainIdentity:
	default:
		errs = append(errs, fmt.Errorf("semantic: %s: entity_policy_pack.metadata.domain %q is not supported", path, pack.Metadata.Domain))
	}
	if strings.TrimSpace(pack.Spec.Inputs.Schema) == "" && len(pack.Spec.ScopedRules) == 0 {
		errs = append(errs, fmt.Errorf("semantic: %s: entity_policy_pack.spec.inputs.schema is required", path))
	}

	ruleIDs := map[string]string{}
	validateEntityPolicySuggestions(&errs, path, "spec.suggestions.business_criticality", pack.Spec.Suggestions.BusinessCriticality, ruleIDs, validBusinessCriticality)
	validateEntityPolicySuggestions(&errs, path, "spec.suggestions.data_classification", pack.Spec.Suggestions.DataClassification, ruleIDs, validDataClassification)
	validateEntityPolicyScoring(&errs, path, pack.Spec.Scoring, ruleIDs)
	validateEntityPolicyLevelRules(&errs, path, "spec.levels", pack.Spec.Levels)
	validateEntityPolicyRules(&errs, path, "spec.rules", pack.Spec.Rules, ruleIDs)
	validateEntityPolicyAggregation(&errs, path, pack.Spec.Aggregation)
	validateEntityPolicyScopedRules(&errs, path, pack.Spec.ScopedRules, ruleIDs)
	validateEntityPolicyExpressionRefs(&errs, path, pack)

	if len(errs) == 0 {
		if err := validateEntityPolicyCEL(path, pack); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func validateEntityPolicySuggestions(errs *[]error, path, fieldPath string, rules []types.EntityPolicySuggestionRule, ruleIDs map[string]string, validLevel func(string) bool) {
	for i, rule := range rules {
		currentPath := fmt.Sprintf("%s.%s[%d]", path, fieldPath, i)
		validateEntityPolicyID(errs, currentPath+".id", rule.ID, ruleIDs)
		if rule.Level == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.level is required", currentPath))
		} else if !validLevel(rule.Level) {
			*errs = append(*errs, fmt.Errorf("semantic: %s.level %q is invalid", currentPath, rule.Level))
		}
		if rule.When == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.when is required", currentPath))
		}
	}
	if len(rules) > 0 && strings.TrimSpace(rules[len(rules)-1].When) != "true" {
		*errs = append(*errs, fmt.Errorf("semantic: %s.%s must end with a deterministic fallback where when is true", path, fieldPath))
	}
}

func validateEntityPolicyScoring(errs *[]error, path string, scoring types.EntityPolicyScoring, ruleIDs map[string]string) {
	if scoring.Max == 0 && len(scoring.Rules) == 0 {
		return
	}
	if scoring.Max <= 0 {
		*errs = append(*errs, fmt.Errorf("semantic: %s: spec.scoring.max must be greater than zero", path))
	}
	if scoring.Base < 0 {
		*errs = append(*errs, fmt.Errorf("semantic: %s: spec.scoring.base must be non-negative", path))
	}
	if scoring.Max > 0 && scoring.Base > scoring.Max {
		*errs = append(*errs, fmt.Errorf("semantic: %s: spec.scoring.base must not exceed spec.scoring.max", path))
	}
	for i, rule := range scoring.Rules {
		currentPath := fmt.Sprintf("%s.spec.scoring.rules[%d]", path, i)
		validateEntityPolicyID(errs, currentPath+".id", rule.ID, ruleIDs)
		if rule.Points == 0 {
			*errs = append(*errs, fmt.Errorf("semantic: %s.points must be non-zero", currentPath))
		}
		if rule.When == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.when is required", currentPath))
		}
		if rule.Signal.Severity != "" && !validSeverity(rule.Signal.Severity) {
			*errs = append(*errs, fmt.Errorf("semantic: %s.signal.severity %q is invalid", currentPath, rule.Signal.Severity))
		}
		if rule.Signal.Severity != "" && rule.Signal.Title == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.signal.title is required when signal.severity is set", currentPath))
		}
	}
}

func validateEntityPolicyLevelRules(errs *[]error, path, fieldPath string, rules []types.EntityPolicyLevelRule) {
	for i, rule := range rules {
		currentPath := fmt.Sprintf("%s.%s[%d]", path, fieldPath, i)
		if !validSeverity(rule.Level) {
			*errs = append(*errs, fmt.Errorf("semantic: %s.level %q is invalid", currentPath, rule.Level))
		}
		if rule.When == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.when is required", currentPath))
		}
	}
	if len(rules) > 0 && strings.TrimSpace(rules[len(rules)-1].When) != "true" {
		*errs = append(*errs, fmt.Errorf("semantic: %s.%s must end with a deterministic fallback where when is true", path, fieldPath))
	}
}

func validateEntityPolicyRules(errs *[]error, path, fieldPath string, rules []types.EntityPolicyRule, ruleIDs map[string]string) {
	for i, rule := range rules {
		currentPath := fmt.Sprintf("%s.%s[%d]", path, fieldPath, i)
		validateEntityPolicyID(errs, currentPath+".id", rule.ID, ruleIDs)
		if !validSeverity(rule.Severity) {
			*errs = append(*errs, fmt.Errorf("semantic: %s.severity %q is invalid", currentPath, rule.Severity))
		}
		if rule.When == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.when is required", currentPath))
		}
		if rule.Title == "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s.title is required", currentPath))
		}
	}
}

func validateEntityPolicyAggregation(errs *[]error, path string, aggregation types.EntityPolicyAggregation) {
	if aggregation.RiskLevel.Strategy != "" {
		if aggregation.RiskLevel.Strategy != "max_severity" {
			*errs = append(*errs, fmt.Errorf("semantic: %s: spec.aggregation.risk_level.strategy %q is not supported", path, aggregation.RiskLevel.Strategy))
		}
		if aggregation.RiskLevel.Default != "" && !validSeverity(aggregation.RiskLevel.Default) {
			*errs = append(*errs, fmt.Errorf("semantic: %s: spec.aggregation.risk_level.default %q is invalid", path, aggregation.RiskLevel.Default))
		}
	}
	if aggregation.RiskReasonCount.Strategy != "" && aggregation.RiskReasonCount.Strategy != "count_matching_rules" {
		*errs = append(*errs, fmt.Errorf("semantic: %s: spec.aggregation.risk_reason_count.strategy %q is not supported", path, aggregation.RiskReasonCount.Strategy))
	}
}

func validateEntityPolicyScopedRules(errs *[]error, path string, scopedRules []types.EntityPolicyScopedRule, ruleIDs map[string]string) {
	for i, scopedRule := range scopedRules {
		currentPath := fmt.Sprintf("%s.spec.scoped_rules[%d]", path, i)
		validateEntityPolicyID(errs, currentPath+".id", scopedRule.ID, ruleIDs)
		if !entityPolicyAppScopeHasSelector(scopedRule.Scope.App) {
			*errs = append(*errs, fmt.Errorf("semantic: %s.scope.app must include at least one selector", currentPath))
		}
		validateEntityPolicyScopedSuggestions(errs, currentPath+".suggestions", scopedRule.Suggestions)
		scopedRuleIDs := make(map[string]string, len(scopedRule.Rules))
		validateEntityPolicyRules(errs, path, fmt.Sprintf("spec.scoped_rules[%d].rules", i), scopedRule.Rules, scopedRuleIDs)
	}
}

func validateEntityPolicyScopedSuggestions(errs *[]error, path string, suggestions types.EntityPolicyScopedSuggestions) {
	if suggestions.BusinessCriticality != "" && !validBusinessCriticality(suggestions.BusinessCriticality) {
		*errs = append(*errs, fmt.Errorf("semantic: %s.business_criticality %q is invalid", path, suggestions.BusinessCriticality))
	}
	if suggestions.DataClassification != "" && !validDataClassification(suggestions.DataClassification) {
		*errs = append(*errs, fmt.Errorf("semantic: %s.data_classification %q is invalid", path, suggestions.DataClassification))
	}
}

func validSeverity(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validBusinessCriticality(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validDataClassification(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "public", "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func entityPolicyAppScopeHasSelector(scope types.EntityPolicyAppScope) bool {
	return scope.CanonicalKey != "" ||
		scope.PrimaryDomain != "" ||
		len(scope.DomainMatches) > 0 ||
		scope.VendorName != "" ||
		scope.SourceKind != "" ||
		scope.SourceName != "" ||
		scope.Category != ""
}

func validateEntityPolicyID(errs *[]error, path, id string, seen map[string]string) {
	if id == "" {
		*errs = append(*errs, fmt.Errorf("semantic: %s is required", path))
		return
	}
	if strings.ContainsAny(id, ":/") {
		*errs = append(*errs, fmt.Errorf("semantic: %s %q must not contain reserved expression separators ':' or '/'", path, id))
		return
	}
	if previousPath := seen[id]; previousPath != "" {
		*errs = append(*errs, fmt.Errorf("semantic: %s duplicates id %q from %s", path, id, previousPath))
		return
	}
	seen[id] = path
}

func validateEntityPolicyExpressionRefs(errs *[]error, path string, pack types.EntityPolicyPack) {
	seen := map[string]string{}
	add := func(ref, refPath string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if previousPath := seen[ref]; previousPath != "" {
			*errs = append(*errs, fmt.Errorf("semantic: %s duplicates generated expression ref %q from %s", refPath, ref, previousPath))
			return
		}
		seen[ref] = refPath
	}

	for i, rule := range pack.Spec.Suggestions.BusinessCriticality {
		add(rule.ID, fmt.Sprintf("%s.spec.suggestions.business_criticality[%d].id", path, i))
	}
	for i, rule := range pack.Spec.Suggestions.DataClassification {
		add(rule.ID, fmt.Sprintf("%s.spec.suggestions.data_classification[%d].id", path, i))
	}
	for i, rule := range pack.Spec.Scoring.Rules {
		add(rule.ID, fmt.Sprintf("%s.spec.scoring.rules[%d].id", path, i))
	}
	for i, rule := range pack.Spec.Levels {
		add("level:"+rule.Level, fmt.Sprintf("%s.spec.levels[%d].level", path, i))
	}
	for i, rule := range pack.Spec.Rules {
		add(rule.ID, fmt.Sprintf("%s.spec.rules[%d].id", path, i))
	}
	for i, scopedRule := range pack.Spec.ScopedRules {
		for j, rule := range scopedRule.Rules {
			add(scopedRule.ID+"/"+rule.ID, fmt.Sprintf("%s.spec.scoped_rules[%d].rules[%d].id", path, i, j))
		}
	}
}

func validateEntityPolicyCEL(path string, pack types.EntityPolicyPack) error {
	env, err := newEntityPolicyEnv(pack)
	if err != nil {
		return fmt.Errorf("semantic: %s: create entity policy CEL env: %w", path, err)
	}
	var errs []error
	compile := func(ruleID, expression string) {
		ast, issues := env.Compile(expression)
		if issues != nil && issues.Err() != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: %s: compile %q: %w", path, ruleID, expression, issues.Err()))
			return
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			errs = append(errs, fmt.Errorf("semantic: %s: %s: compile %q: expression must return bool, got %s", path, ruleID, expression, ast.OutputType()))
		}
	}
	for _, rule := range pack.Spec.Suggestions.BusinessCriticality {
		compile(rule.ID, rule.When)
	}
	for _, rule := range pack.Spec.Suggestions.DataClassification {
		compile(rule.ID, rule.When)
	}
	for _, rule := range pack.Spec.Scoring.Rules {
		compile(rule.ID, rule.When)
	}
	for _, rule := range pack.Spec.Levels {
		compile("level:"+rule.Level, rule.When)
	}
	for _, rule := range pack.Spec.Rules {
		compile(rule.ID, rule.When)
	}
	for _, scopedRule := range pack.Spec.ScopedRules {
		for _, rule := range scopedRule.Rules {
			compile(scopedRule.ID+"/"+rule.ID, rule.When)
		}
	}
	return errors.Join(errs...)
}

func newEntityPolicyEnv(pack types.EntityPolicyPack) (*cel.Env, error) {
	return cel.NewEnv(entitypolicycel.EnvOptions(pack.Metadata.Domain, pack.Spec.Constants)...)
}

func validateScope(path string, s types.Scope) []error {
	var errs []error
	switch s.Kind {
	case types.ScopeKindConnectorInstance:
		if strings.TrimSpace(s.ConnectorKind) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: scope.kind=connector_instance requires scope.connector_kind", path))
		}
	case types.ScopeKindGlobal:
		if strings.TrimSpace(s.ConnectorKind) != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: scope.kind=global forbids scope.connector_kind", path))
		}
	default:
		errs = append(errs, fmt.Errorf("semantic: %s: unknown scope.kind %q", path, s.Kind))
	}
	return errs
}

type datasetContractIndex struct {
	versionsByDataset map[string][]int
}

func indexDatasetContracts(contracts []types.DatasetContractRef) datasetContractIndex {
	idx := datasetContractIndex{versionsByDataset: map[string][]int{}}
	for _, dc := range contracts {
		idx.versionsByDataset[dc.Dataset] = append(idx.versionsByDataset[dc.Dataset], dc.Version)
	}
	for k := range idx.versionsByDataset {
		versions := idx.versionsByDataset[k]
		slices.Sort(versions)
		versions = slices.Compact(versions)
		idx.versionsByDataset[k] = versions
	}
	return idx
}

func validateRulesetRules(path string, doc *types.RulesetDoc) []error {
	var errs []error

	contractsIdx := indexDatasetContracts(doc.Ruleset.DataContracts)

	seenRuleKeys := map[string]struct{}{}
	for i := range doc.Ruleset.Rules {
		r := &doc.Ruleset.Rules[i]

		if _, ok := seenRuleKeys[r.Key]; ok {
			errs = append(errs, fmt.Errorf("semantic: %s: duplicate rule.key %q", path, r.Key))
		} else {
			seenRuleKeys[r.Key] = struct{}{}
		}

		errs = append(errs, validateRule(path, &doc.Ruleset, r, contractsIdx)...)
	}

	return errs
}

func validateRule(path string, rs *types.Ruleset, r *types.Rule, contractsIdx datasetContractIndex) []error {
	var errs []error

	if r.Parameters != nil && r.Parameters.Schema != nil {
		for k := range r.Parameters.Schema {
			if r.Parameters.Defaults == nil {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: parameters.schema=%q but parameters.defaults is missing", path, r.Key, k))
				continue
			}
			if _, ok := r.Parameters.Defaults[k]; !ok {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: parameters.schema=%q not found in parameters.defaults", path, r.Key, k))
			}
		}
	}

	requiresCheck := false
	switch r.Monitoring.Status {
	case types.MonitoringStatusAutomated, types.MonitoringStatusPartial:
		requiresCheck = true
	case types.MonitoringStatusManual, types.MonitoringStatusUnsupported:
		requiresCheck = false
	default:
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: unknown monitoring.status %q", path, r.Key, r.Monitoring.Status))
	}

	if requiresCheck && r.Check == nil {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q requires rule.check", path, r.Key, r.Monitoring.Status))
		return errs
	}

	if !requiresCheck {
		if r.Check != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q requires rule.check to be omitted", path, r.Key, r.Monitoring.Status))
		}
		return errs
	}

	if r.Check == nil {
		return errs
	}

	errs = append(errs, validateCheck(path, rs, r, r.Check, contractsIdx)...)
	return errs
}

func validateCheck(path string, rs *types.Ruleset, r *types.Rule, c *types.Check, contractsIdx datasetContractIndex) []error {
	var errs []error

	engine := types.CheckEngine(strings.TrimSpace(string(c.Engine)))
	if engine == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.engine is required", path, r.Key))
	} else if engine != types.CheckEngineCEL && engine != types.CheckEngineCELPlan {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: unsupported check.engine %q", path, r.Key, c.Engine))
	}

	if engine == types.CheckEngineCELPlan {
		if strings.TrimSpace(c.Expression) != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.expression must be empty for check.engine=cel_plan", path, r.Key))
		}
		errs = append(errs, validatePlanCheck(path, rs, r, c, contractsIdx)...)
		return errs
	}
	if c.Plan != nil {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan is only allowed with check.engine=cel_plan", path, r.Key))
	}

	expression := strings.TrimSpace(c.Expression)
	if expression == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.expression is required", path, r.Key))
		return errs
	}

	if err := celengine.ValidateExpression(expression); err != nil {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid CEL expression: %v", path, r.Key, err))
		return errs
	}

	refs := celengine.ExtractReferences(expression)
	errs = append(errs, validateExpressionReferences(path, rs, r, refs, contractsIdx)...)
	return errs
}

func validateExpressionReferences(path string, rs *types.Ruleset, r *types.Rule, refs celengine.References, contractsIdx datasetContractIndex) []error {
	var errs []error

	requiredDataSet := map[string]struct{}{}
	for _, d := range r.RequiredData {
		requiredDataSet[d] = struct{}{}
	}
	for _, d := range refs.Datasets {
		if _, ok := requiredDataSet[d]; !ok {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: required_data missing dataset %q referenced by check.expression", path, r.Key, d))
		}
		versions := contractsIdx.versionsByDataset[d]
		if len(versions) == 0 {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: ruleset.data_contracts missing dataset %q referenced by check.expression", path, r.Key, d))
			continue
		}
		if len(versions) > 1 {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset %q has multiple data_contracts versions; CEL checks require exactly one version per dataset", path, r.Key, d))
		}
	}

	if len(refs.Params) > 0 {
		if r.Parameters == nil || r.Parameters.Defaults == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.expression references params but parameters.defaults is missing", path, r.Key))
		} else {
			for _, p := range refs.Params {
				if _, ok := r.Parameters.Defaults[p]; !ok {
					errs = append(errs, fmt.Errorf("semantic: %s: rule %q: param %q referenced by check.expression not found in parameters.defaults", path, r.Key, p))
				}
			}
		}
	}

	_ = rs
	return errs
}

func validatePlanCheck(path string, rs *types.Ruleset, r *types.Rule, c *types.Check, contractsIdx datasetContractIndex) []error {
	var errs []error

	if c.Plan == nil {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan is required for check.engine=cel_plan", path, r.Key))
		return errs
	}
	plan := c.Plan

	planType := strings.TrimSpace(plan.Type)
	if planType == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.type is required", path, r.Key))
	}

	dataset := strings.TrimSpace(plan.Dataset)
	if dataset == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.dataset is required", path, r.Key))
	} else {
		refs := celengine.References{Datasets: []string{dataset}, RequiredDatasets: []string{dataset}}
		refs.Params = append(refs.Params, celengine.ExtractParamReferences(plan.WhereExpression)...)
		refs.Params = append(refs.Params, celengine.ExtractParamReferences(plan.AssertExpression)...)
		refs.Params = normalizeStringSet(refs.Params)
		errs = append(errs, validateExpressionReferences(path, rs, r, refs, contractsIdx)...)
	}

	switch planType {
	case "dataset.field_compare":
		if strings.TrimSpace(plan.AssertExpression) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.assert_expression is required for type dataset.field_compare", path, r.Key))
		} else if err := celengine.ValidatePredicateExpression(plan.AssertExpression); err != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid check.plan.assert_expression: %v", path, r.Key, err))
		}
		if strings.TrimSpace(plan.WhereExpression) != "" {
			if err := celengine.ValidatePredicateExpression(plan.WhereExpression); err != nil {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid check.plan.where_expression: %v", path, r.Key, err))
			}
		}

		if plan.Expect == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.expect is required for type dataset.field_compare", path, r.Key))
		} else {
			match := strings.ToLower(strings.TrimSpace(plan.Expect.Match))
			if match != "all" && match != "any" {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.expect.match must be all|any", path, r.Key))
			}
			if plan.Expect.MinSelected < 0 {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.expect.min_selected must be >= 0", path, r.Key))
			}
			onEmpty := strings.ToLower(strings.TrimSpace(plan.Expect.OnEmpty))
			if onEmpty != "fail" && onEmpty != "unknown" {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.expect.on_empty must be fail|unknown", path, r.Key))
			}
		}
		if plan.Compare != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.compare not allowed for type dataset.field_compare", path, r.Key))
		}
	case "dataset.count_compare":
		if plan.Compare == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.compare is required for type dataset.count_compare", path, r.Key))
		}
		if strings.TrimSpace(plan.WhereExpression) != "" {
			if err := celengine.ValidatePredicateExpression(plan.WhereExpression); err != nil {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid check.plan.where_expression: %v", path, r.Key, err))
			}
		}
		if strings.TrimSpace(plan.AssertExpression) != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.assert_expression not allowed for type dataset.count_compare", path, r.Key))
		}
		if plan.Expect != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.plan.expect not allowed for type dataset.count_compare", path, r.Key))
		}
	default:
		if planType != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: unsupported check.plan.type %q", path, r.Key, planType))
		}
	}

	if err := validatePlanPolicy(path, r.Key, "on_missing_dataset", plan.OnMissingDataset); err != nil {
		errs = append(errs, err)
	}
	if err := validatePlanPolicy(path, r.Key, "on_permission_denied", plan.OnPermissionDenied); err != nil {
		errs = append(errs, err)
	}
	if err := validatePlanPolicy(path, r.Key, "on_sync_error", plan.OnSyncError); err != nil {
		errs = append(errs, err)
	}

	return errs
}

func validatePlanPolicy(path, ruleKey, name, value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "unknown", "error", "fail":
		return nil
	default:
		return fmt.Errorf("semantic: %s: rule %q: check.plan.%s must be unknown|error|fail", path, ruleKey, name)
	}
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
