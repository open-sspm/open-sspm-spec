package compiler

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func buildRequirements(b *schemasem.Bundle) types.RequirementsIndex {
	out := types.RequirementsIndex{
		SchemaVersion: 1,
		Kind:          "opensspm.requirements_index",
	}

	for _, rs := range b.Rulesets {
		req := types.RulesetRequirement{
			RulesetKey: rs.Doc.Ruleset.Key,
			Status:     rs.Doc.Ruleset.Status,
			Scope:      rs.Doc.Ruleset.Scope,
		}

		checkTypes := map[types.CheckType]struct{}{}
		valueParams := map[string]struct{}{}
		datasets := map[string]types.DatasetRefSpec{}

		for i := range rs.Doc.Ruleset.Rules {
			r := &rs.Doc.Ruleset.Rules[i]

			var checkTypePtr *types.CheckType
			if r.Check != nil {
				ct := r.Check.Type
				checkTypePtr = &ct
				checkTypes[ct] = struct{}{}
			}

			rDatasets := datasetsForRuleCheck(rs.Doc.Ruleset, r.Check)
			rDatasets = normalize.DatasetRefs(rDatasets)
			for _, d := range rDatasets {
				datasets[fmt.Sprintf("%s@%d", d.Dataset, d.Version)] = d
			}

			rValueParams := valueParamsForRuleCheck(r.Check)
			for _, vp := range rValueParams {
				valueParams[vp] = struct{}{}
			}

			req.Rules = append(req.Rules, types.RuleRequirement{
				RuleKey:    r.Key,
				IsManual:   isManualRule(r),
				Datasets:   rDatasets,
				CheckType:  checkTypePtr,
				ValueParams: rValueParams,
				Monitoring: struct {
					Status types.MonitoringStatus `json:"status"`
				}{Status: r.Monitoring.Status},
			})
		}

		req.Datasets = setToSortedDatasetRefs(datasets)
		req.CheckTypes = setToSortedCheckTypes(checkTypes)
		req.ValueParams = setToSortedStringSlice(valueParams)

		out.Rulesets = append(out.Rulesets, req)
	}

	slices.SortFunc(out.Rulesets, func(a, b types.RulesetRequirement) int {
		return strings.Compare(a.RulesetKey, b.RulesetKey)
	})
	return out
}

func isManualRule(r *types.Rule) bool {
	if r == nil {
		return true
	}
	if r.Monitoring.Status == types.MonitoringStatusManual {
		return true
	}
	if r.Check == nil {
		return true
	}
	return r.Check.Type == types.CheckTypeManualAttestation
}

func datasetsForRuleCheck(rs types.Ruleset, c *types.Check) []types.DatasetRefSpec {
	if c == nil {
		return []types.DatasetRefSpec{}
	}
	switch c.Type {
	case types.CheckTypeDatasetFieldCompare, types.CheckTypeDatasetCountCompare:
		if strings.TrimSpace(c.Dataset) == "" {
			return []types.DatasetRefSpec{}
		}
		v := types.EffectiveDatasetVersion(c.Dataset, rs.DataContracts, c.DatasetVersion)
		return []types.DatasetRefSpec{{Dataset: c.Dataset, Version: v}}
	case types.CheckTypeDatasetJoinCountCompare:
		var out []types.DatasetRefSpec
		if c.Left != nil && strings.TrimSpace(c.Left.Dataset) != "" {
			v := types.EffectiveDatasetVersion(c.Left.Dataset, rs.DataContracts, c.DatasetVersion)
			out = append(out, types.DatasetRefSpec{Dataset: c.Left.Dataset, Version: v})
		}
		if c.Right != nil && strings.TrimSpace(c.Right.Dataset) != "" {
			v := types.EffectiveDatasetVersion(c.Right.Dataset, rs.DataContracts, c.DatasetVersion)
			out = append(out, types.DatasetRefSpec{Dataset: c.Right.Dataset, Version: v})
		}
		return out
	default:
		return []types.DatasetRefSpec{}
	}
}

func valueParamsForRuleCheck(c *types.Check) []string {
	if c == nil {
		return []string{}
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
		return []string{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func setToSortedDatasetRefs(m map[string]types.DatasetRefSpec) []types.DatasetRefSpec {
	if len(m) == 0 {
		return []types.DatasetRefSpec{}
	}
	out := make([]types.DatasetRefSpec, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return normalize.DatasetRefs(out)
}

func setToSortedCheckTypes(m map[types.CheckType]struct{}) []types.CheckType {
	if len(m) == 0 {
		return []types.CheckType{}
	}
	out := make([]types.CheckType, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b types.CheckType) int { return strings.Compare(string(a), string(b)) })
	return out
}

func setToSortedStringSlice(m map[string]struct{}) []string {
	if len(m) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

