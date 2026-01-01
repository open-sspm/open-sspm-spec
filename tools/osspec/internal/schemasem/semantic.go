package schemasem

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

type Bundle struct {
	Version    types.Version
	Dictionary struct {
		Path string
		Doc  types.DictionaryDoc
	}
	Rulesets []struct {
		Path string
		Doc  types.RulesetDoc
	}
	DatasetContracts []struct {
		Path string
		Doc  types.DatasetContractDoc
	}
	Connectors []struct {
		Path string
		Doc  types.ConnectorManifestDoc
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
	for _, rs := range b.Rulesets {
		key := rs.Doc.Ruleset.Key
		if prev, ok := seenRulesetKeys[key]; ok {
			errs = append(errs, fmt.Errorf("semantic: duplicate ruleset.key %q in %s and %s", key, prev, rs.Path))
		} else {
			seenRulesetKeys[key] = rs.Path
		}

		errs = append(errs, validateScope(rs.Path, rs.Doc.Ruleset.Scope)...)
		errs = append(errs, validateRulesetRules(rs.Path, &rs.Doc)...)
	}

	seenDataset := map[string]string{}
	for _, dc := range b.DatasetContracts {
		k := fmt.Sprintf("%s@%d", dc.Doc.Dataset.Key, dc.Doc.Dataset.Version)
		if prev, ok := seenDataset[k]; ok {
			errs = append(errs, fmt.Errorf("semantic: duplicate dataset (key,version) %q in %s and %s", k, prev, dc.Path))
		} else {
			seenDataset[k] = dc.Path
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
	// versionsByDataset is used for ambiguity checks.
	versionsByDataset map[string][]int
	// pairSet is used for existence checks when check.dataset_version is set.
	pairSet map[string]struct{}
}

func indexDatasetContracts(contracts []types.DatasetContractRef) datasetContractIndex {
	idx := datasetContractIndex{
		versionsByDataset: map[string][]int{},
		pairSet:           map[string]struct{}{},
	}
	for _, dc := range contracts {
		idx.versionsByDataset[dc.Dataset] = append(idx.versionsByDataset[dc.Dataset], dc.Version)
		idx.pairSet[fmt.Sprintf("%s@%d", dc.Dataset, dc.Version)] = struct{}{}
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

	// 3.3 Parameters schema keys must exist in defaults.
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

	// 6.3 Monitoring/check constraints
	switch r.Monitoring.Status {
	case types.MonitoringStatusAutomated, types.MonitoringStatusPartial:
		if r.Check == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q requires rule.check", path, r.Key, r.Monitoring.Status))
			// If check is missing, further check validation is not meaningful.
			return errs
		}
	case types.MonitoringStatusManual, types.MonitoringStatusUnsupported:
		if r.Check != nil && r.Check.Type != types.CheckTypeManualAttestation {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q only allows check.type=manual.attestation or check omission", path, r.Key, r.Monitoring.Status))
		}
	default:
		// Schema should catch unknowns, but keep semantic validation explicit.
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: unknown monitoring.status %q", path, r.Key, r.Monitoring.Status))
	}

	if r.Check == nil {
		return errs
	}

	errs = append(errs, validateCheck(path, rs, r, r.Check, contractsIdx)...)
	return errs
}

func validateCheck(path string, rs *types.Ruleset, r *types.Rule, c *types.Check, contractsIdx datasetContractIndex) []error {
	var errs []error

	// 6.4 Supported check types only (whitelist)
	switch c.Type {
	case types.CheckTypeDatasetFieldCompare, types.CheckTypeDatasetCountCompare, types.CheckTypeDatasetJoinCountCompare, types.CheckTypeManualAttestation:
		// ok
	default:
		return []error{fmt.Errorf("semantic: %s: rule %q: unknown check.type %q", path, r.Key, c.Type)}
	}

	// Type-specific required fields.
	switch c.Type {
	case types.CheckTypeManualAttestation:
		// No additional required fields.
	case types.CheckTypeDatasetFieldCompare:
		if strings.TrimSpace(c.Dataset) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.field_compare requires check.dataset", path, r.Key))
		}
		if c.Assert == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.field_compare requires check.assert", path, r.Key))
		}
		if c.Compare != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.field_compare forbids check.compare", path, r.Key))
		}
		if c.Left != nil || c.Right != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.field_compare forbids check.left/check.right", path, r.Key))
		}
	case types.CheckTypeDatasetCountCompare:
		if strings.TrimSpace(c.Dataset) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.count_compare requires check.dataset", path, r.Key))
		}
		if c.Compare == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.count_compare requires check.compare", path, r.Key))
		}
		if c.Assert != nil || c.Expect != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.count_compare forbids check.assert/check.expect", path, r.Key))
		}
		if c.Left != nil || c.Right != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.count_compare forbids check.left/check.right", path, r.Key))
		}
	case types.CheckTypeDatasetJoinCountCompare:
		if c.Left == nil || strings.TrimSpace(c.Left.Dataset) == "" || strings.TrimSpace(c.Left.KeyPath) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.join_count_compare requires check.left.dataset and check.left.key_path", path, r.Key))
		}
		if c.Right == nil || strings.TrimSpace(c.Right.Dataset) == "" || strings.TrimSpace(c.Right.KeyPath) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.join_count_compare requires check.right.dataset and check.right.key_path", path, r.Key))
		}
		if c.Compare == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.join_count_compare requires check.compare", path, r.Key))
		}
		if strings.TrimSpace(c.Dataset) != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.join_count_compare forbids check.dataset", path, r.Key))
		}
		if c.Assert != nil || c.Expect != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset.join_count_compare forbids check.assert/check.expect", path, r.Key))
		}
	}

	// 6.8 Predicate structural constraints
	if c.Type == types.CheckTypeDatasetJoinCountCompare {
		for i := range c.Where {
			errs = append(errs, validateJoinPredicate(path, r.Key, "check.where", i, c.Where[i])...)
		}
	} else {
		for i := range c.Where {
			errs = append(errs, validatePredicate(path, r.Key, "check.where", i, c.Where[i])...)
		}
		if c.Assert != nil {
			errs = append(errs, validatePredicate(path, r.Key, "check.assert", -1, *c.Assert)...)
		}
	}

	// 6.5 Required data coverage
	requiredDataSet := map[string]struct{}{}
	for _, d := range r.RequiredData {
		requiredDataSet[d] = struct{}{}
	}
	for _, d := range datasetsReferencedByCheck(c) {
		if _, ok := requiredDataSet[d]; !ok {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: required_data missing dataset %q referenced by check", path, r.Key, d))
		}
	}

	// 6.6 Dataset version declarations and ambiguity checks
	referencedDatasets := datasetsReferencedByCheck(c)
	for _, d := range referencedDatasets {
		versions := contractsIdx.versionsByDataset[d]
		if c.DatasetVersion == 0 && len(versions) > 1 {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset %q has multiple data_contracts versions; check.dataset_version is required", path, r.Key, d))
		}
		if c.DatasetVersion != 0 {
			if _, ok := contractsIdx.pairSet[fmt.Sprintf("%s@%d", d, c.DatasetVersion)]; !ok {
				errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.dataset_version=%d requires ruleset.data_contracts entry for %q@%d", path, r.Key, c.DatasetVersion, d, c.DatasetVersion))
			}
		}
	}

	// 6.7 Parameter references (value_param)
	valueParams := valueParamsReferencedByCheck(c)
	if len(valueParams) > 0 {
		if r.Parameters == nil || r.Parameters.Defaults == nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: value_param used but parameters.defaults is missing", path, r.Key))
		} else {
			for _, vp := range valueParams {
				if _, ok := r.Parameters.Defaults[vp]; !ok {
					errs = append(errs, fmt.Errorf("semantic: %s: rule %q: value_param %q not found in parameters.defaults", path, r.Key, vp))
				}
			}
		}
	}

	// Compare clause structural constraints (also includes parameter references).
	if c.Compare != nil {
		errs = append(errs, validateCompare(path, r.Key, c.Compare)...)
	}

	_ = rs
	return errs
}

func datasetsReferencedByCheck(c *types.Check) []string {
	if c == nil {
		return nil
	}
	switch c.Type {
	case types.CheckTypeDatasetFieldCompare, types.CheckTypeDatasetCountCompare:
		if strings.TrimSpace(c.Dataset) == "" {
			return nil
		}
		return []string{c.Dataset}
	case types.CheckTypeDatasetJoinCountCompare:
		var out []string
		if c.Left != nil && strings.TrimSpace(c.Left.Dataset) != "" {
			out = append(out, c.Left.Dataset)
		}
		if c.Right != nil && strings.TrimSpace(c.Right.Dataset) != "" {
			out = append(out, c.Right.Dataset)
		}
		return out
	default:
		return nil
	}
}

func valueParamsReferencedByCheck(c *types.Check) []string {
	if c == nil {
		return nil
	}
	set := map[string]struct{}{}

	for i := range c.Where {
		if vp := strings.TrimSpace(c.Where[i].ValueParam); vp != "" {
			set[vp] = struct{}{}
		}
	}
	if c.Assert != nil {
		if vp := strings.TrimSpace(c.Assert.ValueParam); vp != "" {
			set[vp] = struct{}{}
		}
	}
	if c.Compare != nil {
		if vp := strings.TrimSpace(c.Compare.ValueParam); vp != "" {
			set[vp] = struct{}{}
		}
	}

	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func validatePredicate(path, ruleKey, field string, index int, p types.Predicate) []error {
	var errs []error

	if strings.TrimSpace(p.Path) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: missing path", path, ruleKey, field, index))
	}
	if strings.TrimSpace(p.LeftPath) != "" || strings.TrimSpace(p.RightPath) != "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: left_path/right_path not allowed in non-join predicate", path, ruleKey, field, index))
	}
	if p.Op == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: missing op", path, ruleKey, field, index))
		return errs
	}

	errs = append(errs, validatePredicateValue(path, ruleKey, field, index, p.Op, p.Value, p.ValueParam)...)
	return errs
}

func validateJoinPredicate(path, ruleKey, field string, index int, p types.Predicate) []error {
	var errs []error

	if strings.TrimSpace(p.Path) != "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: path not allowed in join predicate", path, ruleKey, field, index))
	}
	leftSet := strings.TrimSpace(p.LeftPath) != ""
	rightSet := strings.TrimSpace(p.RightPath) != ""
	if leftSet == rightSet {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: must set exactly one of left_path or right_path", path, ruleKey, field, index))
	}
	if p.Op == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: missing op", path, ruleKey, field, index))
		return errs
	}

	errs = append(errs, validatePredicateValue(path, ruleKey, field, index, p.Op, p.Value, p.ValueParam)...)
	return errs
}

func validatePredicateValue(path, ruleKey, field string, index int, op types.Operator, value any, valueParam string) []error {
	var errs []error
	if op == types.OperatorExists || op == types.OperatorAbsent {
		if value != nil || strings.TrimSpace(valueParam) != "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: op=%q forbids value and value_param", path, ruleKey, field, index, op))
		}
		return errs
	}
	if value != nil && strings.TrimSpace(valueParam) != "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: %s[%d]: value and value_param are mutually exclusive", path, ruleKey, field, index))
	}
	return errs
}

func validateCompare(path, ruleKey string, c *types.Compare) []error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.Op == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.compare missing op", path, ruleKey))
	}
	hasValue := c.Value != nil
	hasValueParam := strings.TrimSpace(c.ValueParam) != ""
	if hasValue == hasValueParam {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.compare must set exactly one of value or value_param", path, ruleKey))
	}
	return errs
}
