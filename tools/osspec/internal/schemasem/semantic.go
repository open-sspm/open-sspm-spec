package schemasem

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/celengine"
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
