package rulecompile

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

const (
	checkTypeDatasetFieldCompare = "dataset.field_compare"
	checkTypeDatasetCountCompare = "dataset.count_compare"
	checkTypeManualAttestation   = "manual.attestation"
)

type SourceRulesetDoc struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          string        `json:"kind"`
	Ruleset       SourceRuleset `json:"ruleset"`
}

type SourceRuleset struct {
	Key               string                     `json:"key"`
	Name              string                     `json:"name"`
	Scope             types.Scope                `json:"scope"`
	Source            *types.Source              `json:"source,omitempty"`
	Status            string                     `json:"status,omitempty"`
	Description       string                     `json:"description,omitempty"`
	Tags              []string                   `json:"tags,omitempty"`
	References        []types.Reference          `json:"references,omitempty"`
	FrameworkMappings []types.FrameworkMapping   `json:"framework_mappings,omitempty"`
	Requirements      *types.RulesetRequirements `json:"requirements,omitempty"`
	DataContracts     []types.DatasetContractRef `json:"data_contracts,omitempty"`
	Defaults          *SourceDefaults            `json:"defaults,omitempty"`
	Selectors         map[string]SourceSelector  `json:"selectors,omitempty"`
	Rules             []SourceRule               `json:"rules"`
}

type SourceDefaults struct {
	Check SourceCheckDefaults `json:"check,omitempty"`
}

type SourceCheckDefaults struct {
	OnMissingDataset   string `json:"on_missing_dataset,omitempty"`
	OnPermissionDenied string `json:"on_permission_denied,omitempty"`
	OnSyncError        string `json:"on_sync_error,omitempty"`
}

type SourceSelector struct {
	Dataset string            `json:"dataset"`
	Where   []SourcePredicate `json:"where,omitempty"`
}

type SourceRule struct {
	Key               string                   `json:"key"`
	Title             string                   `json:"title"`
	Severity          types.Severity           `json:"severity"`
	Monitoring        types.Monitoring         `json:"monitoring"`
	RequiredData      []string                 `json:"required_data"`
	Summary           string                   `json:"summary,omitempty"`
	Description       string                   `json:"description,omitempty"`
	Category          string                   `json:"category,omitempty"`
	Parameters        *types.Parameters        `json:"parameters,omitempty"`
	Check             *SourceCheck             `json:"check,omitempty"`
	Evidence          *types.Evidence          `json:"evidence,omitempty"`
	Remediation       *types.Remediation       `json:"remediation,omitempty"`
	References        []types.Reference        `json:"references,omitempty"`
	FrameworkMappings []types.FrameworkMapping `json:"framework_mappings,omitempty"`
	Tags              []string                 `json:"tags,omitempty"`
	Lifecycle         *types.Lifecycle         `json:"lifecycle,omitempty"`
}

type SourceCheck struct {
	Engine     types.CheckEngine `json:"engine,omitempty"`
	Expression string            `json:"expression,omitempty"`

	Type     string            `json:"type,omitempty"`
	Dataset  string            `json:"dataset,omitempty"`
	Selector string            `json:"selector,omitempty"`
	Where    []SourcePredicate `json:"where,omitempty"`
	Assert   *SourcePredicate  `json:"assert,omitempty"`
	Compare  *SourceCompare    `json:"compare,omitempty"`
	Expect   *SourceExpect     `json:"expect,omitempty"`

	OnMissingDataset   string `json:"on_missing_dataset,omitempty"`
	OnPermissionDenied string `json:"on_permission_denied,omitempty"`
	OnSyncError        string `json:"on_sync_error,omitempty"`
}

type SourcePredicate struct {
	Op         string `json:"op"`
	Path       string `json:"path"`
	Value      any    `json:"value,omitempty"`
	ValueParam string `json:"value_param,omitempty"`
}

type SourceCompare struct {
	Op         string `json:"op"`
	Value      any    `json:"value,omitempty"`
	ValueParam string `json:"value_param,omitempty"`
}

type SourceExpect struct {
	Match       string `json:"match,omitempty"`
	MinSelected *int   `json:"min_selected,omitempty"`
	OnEmpty     string `json:"on_empty,omitempty"`
}

func CompileRuleset(src SourceRulesetDoc) (types.RulesetDoc, error) {
	dst := types.RulesetDoc{
		SchemaVersion: src.SchemaVersion,
		Kind:          src.Kind,
		Ruleset: types.Ruleset{
			Key:               src.Ruleset.Key,
			Name:              src.Ruleset.Name,
			Scope:             src.Ruleset.Scope,
			Source:            src.Ruleset.Source,
			Status:            src.Ruleset.Status,
			Description:       src.Ruleset.Description,
			Tags:              append([]string{}, src.Ruleset.Tags...),
			References:        append([]types.Reference{}, src.Ruleset.References...),
			FrameworkMappings: append([]types.FrameworkMapping{}, src.Ruleset.FrameworkMappings...),
			Requirements:      src.Ruleset.Requirements,
			DataContracts:     append([]types.DatasetContractRef{}, src.Ruleset.DataContracts...),
		},
	}

	defaults := SourceCheckDefaults{}
	if src.Ruleset.Defaults != nil {
		defaults = src.Ruleset.Defaults.Check
	}

	dst.Ruleset.Rules = make([]types.Rule, 0, len(src.Ruleset.Rules))
	for _, sourceRule := range src.Ruleset.Rules {
		compiledCheck, err := compileRuleCheck(sourceRule.Key, sourceRule.Monitoring.Status, sourceRule.Check, src.Ruleset.Selectors, defaults)
		if err != nil {
			return types.RulesetDoc{}, err
		}

		dst.Ruleset.Rules = append(dst.Ruleset.Rules, types.Rule{
			Key:               sourceRule.Key,
			Title:             sourceRule.Title,
			Severity:          sourceRule.Severity,
			Monitoring:        sourceRule.Monitoring,
			RequiredData:      append([]string{}, sourceRule.RequiredData...),
			Summary:           sourceRule.Summary,
			Description:       sourceRule.Description,
			Category:          sourceRule.Category,
			Parameters:        sourceRule.Parameters,
			Check:             compiledCheck,
			Evidence:          sourceRule.Evidence,
			Remediation:       sourceRule.Remediation,
			References:        append([]types.Reference{}, sourceRule.References...),
			FrameworkMappings: append([]types.FrameworkMapping{}, sourceRule.FrameworkMappings...),
			Tags:              append([]string{}, sourceRule.Tags...),
			Lifecycle:         sourceRule.Lifecycle,
		})
	}

	return dst, nil
}

func compileRuleCheck(ruleKey string, monitoringStatus types.MonitoringStatus, sourceCheck *SourceCheck, selectors map[string]SourceSelector, defaults SourceCheckDefaults) (*types.Check, error) {
	if sourceCheck == nil {
		return nil, nil
	}

	policies, err := resolvePolicies(sourceCheck, defaults)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", ruleKey, err)
	}

	rawCheckConfigured := strings.TrimSpace(string(sourceCheck.Engine)) != "" || strings.TrimSpace(sourceCheck.Expression) != ""
	structuredType := strings.TrimSpace(sourceCheck.Type)
	structuredFieldsConfigured := hasStructuredFields(sourceCheck)

	if rawCheckConfigured && (structuredType != "" || structuredFieldsConfigured) {
		return nil, fmt.Errorf("rule %q: check cannot combine raw CEL fields with structured DSL fields", ruleKey)
	}

	if structuredType == "" {
		if structuredFieldsConfigured {
			return nil, fmt.Errorf("rule %q: check.type is required when using structured DSL fields", ruleKey)
		}
		return &types.Check{
			Engine:     sourceCheck.Engine,
			Expression: sourceCheck.Expression,
		}, nil
	}

	switch structuredType {
	case checkTypeDatasetFieldCompare:
		check, err := compileDatasetFieldCompare(ruleKey, sourceCheck, selectors, policies)
		if err != nil {
			return nil, err
		}
		return check, nil
	case checkTypeDatasetCountCompare:
		check, err := compileDatasetCountCompare(ruleKey, sourceCheck, selectors, policies)
		if err != nil {
			return nil, err
		}
		return check, nil
	case checkTypeManualAttestation:
		if monitoringStatus != types.MonitoringStatusManual && monitoringStatus != types.MonitoringStatusUnsupported {
			return nil, fmt.Errorf("rule %q: check.type %q requires monitoring.status manual or unsupported", ruleKey, checkTypeManualAttestation)
		}
		if sourceCheck.Assert != nil || sourceCheck.Compare != nil || sourceCheck.Expect != nil || strings.TrimSpace(sourceCheck.Dataset) != "" || strings.TrimSpace(sourceCheck.Selector) != "" || len(sourceCheck.Where) > 0 {
			return nil, fmt.Errorf("rule %q: check.type %q does not allow dataset/selector/where/assert/compare/expect fields", ruleKey, checkTypeManualAttestation)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("rule %q: unsupported check.type %q", ruleKey, structuredType)
	}
}

func hasStructuredFields(check *SourceCheck) bool {
	if check == nil {
		return false
	}
	return strings.TrimSpace(check.Dataset) != "" ||
		strings.TrimSpace(check.Selector) != "" ||
		len(check.Where) > 0 ||
		check.Assert != nil ||
		check.Compare != nil ||
		check.Expect != nil ||
		strings.TrimSpace(check.OnMissingDataset) != "" ||
		strings.TrimSpace(check.OnPermissionDenied) != "" ||
		strings.TrimSpace(check.OnSyncError) != ""
}

type resolvedPolicies struct {
	OnMissingDataset   string
	OnPermissionDenied string
	OnSyncError        string
}

func resolvePolicies(check *SourceCheck, defaults SourceCheckDefaults) (resolvedPolicies, error) {
	if check == nil {
		return resolvedPolicies{}, nil
	}
	policies := resolvedPolicies{
		OnMissingDataset:   strings.ToLower(strings.TrimSpace(defaults.OnMissingDataset)),
		OnPermissionDenied: strings.ToLower(strings.TrimSpace(defaults.OnPermissionDenied)),
		OnSyncError:        strings.ToLower(strings.TrimSpace(defaults.OnSyncError)),
	}

	if override := strings.TrimSpace(check.OnMissingDataset); override != "" {
		policies.OnMissingDataset = strings.ToLower(override)
	}
	if override := strings.TrimSpace(check.OnPermissionDenied); override != "" {
		policies.OnPermissionDenied = strings.ToLower(override)
	}
	if override := strings.TrimSpace(check.OnSyncError); override != "" {
		policies.OnSyncError = strings.ToLower(override)
	}

	if err := validatePolicyAction("on_missing_dataset", policies.OnMissingDataset); err != nil {
		return resolvedPolicies{}, err
	}
	if err := validatePolicyAction("on_permission_denied", policies.OnPermissionDenied); err != nil {
		return resolvedPolicies{}, err
	}
	if err := validatePolicyAction("on_sync_error", policies.OnSyncError); err != nil {
		return resolvedPolicies{}, err
	}
	return policies, nil
}

func validatePolicyAction(name, value string) error {
	switch value {
	case "", "unknown", "error", "fail":
		return nil
	default:
		return fmt.Errorf("check.%s must be one of unknown|error|fail (got %q)", name, value)
	}
}

func compileDatasetFieldCompare(ruleKey string, sourceCheck *SourceCheck, selectors map[string]SourceSelector, policies resolvedPolicies) (*types.Check, error) {
	if sourceCheck == nil {
		return nil, fmt.Errorf("rule %q: check is required", ruleKey)
	}
	if sourceCheck.Assert == nil {
		return nil, fmt.Errorf("rule %q: check.assert is required for %q", ruleKey, checkTypeDatasetFieldCompare)
	}
	if sourceCheck.Compare != nil {
		return nil, fmt.Errorf("rule %q: check.compare is not allowed for %q", ruleKey, checkTypeDatasetFieldCompare)
	}

	dataset, where, err := resolveDatasetAndWhere(ruleKey, sourceCheck, selectors)
	if err != nil {
		return nil, err
	}

	expect := SourceExpect{
		Match:   "all",
		OnEmpty: "fail",
	}
	minSelected := 1
	expect.MinSelected = &minSelected
	if sourceCheck.Expect != nil {
		if v := strings.TrimSpace(sourceCheck.Expect.Match); v != "" {
			expect.Match = v
		}
		if sourceCheck.Expect.MinSelected != nil {
			ms := *sourceCheck.Expect.MinSelected
			expect.MinSelected = &ms
		}
		if v := strings.TrimSpace(sourceCheck.Expect.OnEmpty); v != "" {
			expect.OnEmpty = v
		}
	}

	matchMode := strings.ToLower(strings.TrimSpace(expect.Match))
	switch matchMode {
	case "all", "any":
	default:
		return nil, fmt.Errorf("rule %q: check.expect.match must be one of all|any (got %q)", ruleKey, expect.Match)
	}

	if expect.MinSelected == nil || *expect.MinSelected < 0 {
		return nil, fmt.Errorf("rule %q: check.expect.min_selected must be >= 0", ruleKey)
	}
	minExpected := *expect.MinSelected

	onEmpty := strings.ToLower(strings.TrimSpace(expect.OnEmpty))
	if onEmpty == "" {
		onEmpty = "fail"
	}
	if onEmpty != "fail" && onEmpty != "unknown" {
		return nil, fmt.Errorf("rule %q: check.expect.on_empty must be one of fail|unknown (got %q)", ruleKey, expect.OnEmpty)
	}

	whereExpr, err := compileWhereClause(ruleKey, where, "r")
	if err != nil {
		return nil, err
	}
	assertExpr, err := compilePredicate(ruleKey, *sourceCheck.Assert, "r")
	if err != nil {
		return nil, err
	}

	return &types.Check{
		Engine: types.CheckEngineCELPlan,
		Plan: &types.CheckPlan{
			Type:             checkTypeDatasetFieldCompare,
			Dataset:          dataset,
			WhereExpression:  whereExpr,
			AssertExpression: assertExpr,
			Expect: &types.CheckPlanExpect{
				Match:       matchMode,
				MinSelected: minExpected,
				OnEmpty:     onEmpty,
			},
			OnMissingDataset:   policies.OnMissingDataset,
			OnPermissionDenied: policies.OnPermissionDenied,
			OnSyncError:        policies.OnSyncError,
		},
	}, nil
}

func compileDatasetCountCompare(ruleKey string, sourceCheck *SourceCheck, selectors map[string]SourceSelector, policies resolvedPolicies) (*types.Check, error) {
	if sourceCheck == nil {
		return nil, fmt.Errorf("rule %q: check is required", ruleKey)
	}
	if sourceCheck.Compare == nil {
		return nil, fmt.Errorf("rule %q: check.compare is required for %q", ruleKey, checkTypeDatasetCountCompare)
	}
	if sourceCheck.Assert != nil {
		return nil, fmt.Errorf("rule %q: check.assert is not allowed for %q", ruleKey, checkTypeDatasetCountCompare)
	}
	if sourceCheck.Expect != nil {
		return nil, fmt.Errorf("rule %q: check.expect is not allowed for %q", ruleKey, checkTypeDatasetCountCompare)
	}

	dataset, where, err := resolveDatasetAndWhere(ruleKey, sourceCheck, selectors)
	if err != nil {
		return nil, err
	}

	whereExpr, err := compileWhereClause(ruleKey, where, "r")
	if err != nil {
		return nil, err
	}

	hasValueParam := strings.TrimSpace(sourceCheck.Compare.ValueParam) != ""
	if hasValueParam && sourceCheck.Compare.Value != nil {
		return nil, fmt.Errorf("rule %q: check.compare cannot have both value and value_param", ruleKey)
	}
	if hasValueParam {
		return nil, fmt.Errorf("rule %q: check.compare.value_param is not supported for %q", ruleKey, checkTypeDatasetCountCompare)
	}

	return &types.Check{
		Engine: types.CheckEngineCELPlan,
		Plan: &types.CheckPlan{
			Type:            checkTypeDatasetCountCompare,
			Dataset:         dataset,
			WhereExpression: whereExpr,
			Compare: &types.CheckPlanCompare{
				Op:    strings.ToLower(strings.TrimSpace(sourceCheck.Compare.Op)),
				Value: sourceCheck.Compare.Value,
			},
			OnMissingDataset:   policies.OnMissingDataset,
			OnPermissionDenied: policies.OnPermissionDenied,
			OnSyncError:        policies.OnSyncError,
		},
	}, nil
}

func resolveDatasetAndWhere(ruleKey string, sourceCheck *SourceCheck, selectors map[string]SourceSelector) (string, []SourcePredicate, error) {
	if sourceCheck == nil {
		return "", nil, fmt.Errorf("rule %q: check is required", ruleKey)
	}

	dataset := strings.TrimSpace(sourceCheck.Dataset)
	combinedWhere := append([]SourcePredicate{}, sourceCheck.Where...)

	selectorName := strings.TrimSpace(sourceCheck.Selector)
	if selectorName != "" {
		selector, ok := selectors[selectorName]
		if !ok {
			return "", nil, fmt.Errorf("rule %q: check.selector %q not found", ruleKey, selectorName)
		}
		if dataset != "" {
			return "", nil, fmt.Errorf("rule %q: check.dataset cannot be set when check.selector is used", ruleKey)
		}
		dataset = strings.TrimSpace(selector.Dataset)
		combinedWhere = append(append([]SourcePredicate{}, selector.Where...), combinedWhere...)
	}

	if dataset == "" {
		return "", nil, fmt.Errorf("rule %q: check.dataset is required for structured dataset checks", ruleKey)
	}

	return dataset, combinedWhere, nil
}

func compileWhereClause(ruleKey string, where []SourcePredicate, varName string) (string, error) {
	if len(where) == 0 {
		return "true", nil
	}

	parts := make([]string, 0, len(where))
	for _, predicate := range where {
		compiled, err := compilePredicate(ruleKey, predicate, varName)
		if err != nil {
			return "", err
		}
		parts = append(parts, compiled)
	}
	return strings.Join(parts, " && "), nil
}

func compilePredicate(ruleKey string, predicate SourcePredicate, varName string) (string, error) {
	if strings.TrimSpace(predicate.Path) == "" {
		return "", fmt.Errorf("rule %q: predicate.path is required", ruleKey)
	}
	pathExpr, err := pathToCEL(varName, predicate.Path)
	if err != nil {
		return "", fmt.Errorf("rule %q: invalid predicate.path %q: %w", ruleKey, predicate.Path, err)
	}
	if strings.TrimSpace(predicate.ValueParam) != "" {
		if predicate.Value != nil {
			return "", fmt.Errorf("rule %q: predicate cannot have both value and value_param", ruleKey)
		}
		return compileComparisonParam(ruleKey, pathExpr, predicate.Op, predicate.ValueParam)
	}
	return compileComparison(ruleKey, pathExpr, predicate.Op, predicate.Value)
}

func compileComparisonParam(ruleKey, leftExpr, op string, paramName string) (string, error) {
	operator := strings.ToLower(strings.TrimSpace(op))
	if operator == "" {
		return "", fmt.Errorf("rule %q: predicate op is required", ruleKey)
	}
	paramName = strings.TrimSpace(paramName)
	if paramName == "" {
		return "", fmt.Errorf("rule %q: value_param name is required", ruleKey)
	}
	paramRef := fmt.Sprintf(`param(%s)`, strconv.Quote(paramName))

	switch operator {
	case "eq":
		return fmt.Sprintf(`%s == %s`, leftExpr, paramRef), nil
	case "neq":
		return fmt.Sprintf(`%s != %s`, leftExpr, paramRef), nil
	case "gt":
		return fmt.Sprintf(`%s > %s`, leftExpr, paramRef), nil
	case "gte":
		return fmt.Sprintf(`%s >= %s`, leftExpr, paramRef), nil
	case "lt":
		return fmt.Sprintf(`%s < %s`, leftExpr, paramRef), nil
	case "lte":
		return fmt.Sprintf(`%s <= %s`, leftExpr, paramRef), nil
	case "in":
		return fmt.Sprintf(`%s in %s`, leftExpr, paramRef), nil
	case "nin":
		return fmt.Sprintf(`!(%s in %s)`, leftExpr, paramRef), nil
	default:
		return "", fmt.Errorf("rule %q: unsupported comparison op %q", ruleKey, op)
	}
}

func compileComparison(ruleKey, leftExpr, op string, value any) (string, error) {
	operator := strings.ToLower(strings.TrimSpace(op))
	if operator == "" {
		return "", fmt.Errorf("rule %q: predicate op is required", ruleKey)
	}
	literal, err := celLiteral(value)
	if err != nil {
		return "", fmt.Errorf("rule %q: invalid comparison value: %w", ruleKey, err)
	}

	switch operator {
	case "eq":
		return fmt.Sprintf(`%s == %s`, leftExpr, literal), nil
	case "neq":
		return fmt.Sprintf(`%s != %s`, leftExpr, literal), nil
	case "gt":
		return fmt.Sprintf(`%s > %s`, leftExpr, literal), nil
	case "gte":
		return fmt.Sprintf(`%s >= %s`, leftExpr, literal), nil
	case "lt":
		return fmt.Sprintf(`%s < %s`, leftExpr, literal), nil
	case "lte":
		return fmt.Sprintf(`%s <= %s`, leftExpr, literal), nil
	case "in":
		return fmt.Sprintf(`%s in %s`, leftExpr, literal), nil
	case "nin":
		return fmt.Sprintf(`!(%s in %s)`, leftExpr, literal), nil
	default:
		return "", fmt.Errorf("rule %q: unsupported comparison op %q", ruleKey, op)
	}
}

func pathToCEL(varName, path string) (string, error) {
	if err := validateDotPath(path); err != nil {
		return "", err
	}
	return fmt.Sprintf(`field(%s, %s)`, varName, strconv.Quote(path)), nil
}

func validateDotPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required")
	}
	if strings.Contains(path, "/") {
		return fmt.Errorf("path must use dot notation and must not contain '/'")
	}
	for _, segment := range strings.Split(path, ".") {
		if segment == "" {
			return fmt.Errorf("path contains empty segment: %q", path)
		}
	}
	return nil
}

func celLiteral(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
