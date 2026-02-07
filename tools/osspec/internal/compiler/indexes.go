package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/celengine"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

const (
	inputSourceDefaults        = "defaults"
	inputSourceSchema          = "schema"
	inputSourceExpressionParam = "expression_param"
)

type rulesetInputAccumulator struct {
	types   map[string]struct{}
	sources map[string]struct{}
	ruleSet map[string]struct{}
}

func buildRequirements(b *schemasem.Bundle) types.RequirementsIndex {
	out := types.RequirementsIndex{
		SchemaVersion: 2,
		Kind:          "opensspm.requirements_index",
	}

	for _, rs := range b.Rulesets {
		req := types.RulesetRequirement{
			RulesetKey: rs.Doc.Ruleset.Key,
			Status:     rs.Doc.Ruleset.Status,
			Scope:      rs.Doc.Ruleset.Scope,
		}

		engines := map[types.CheckEngine]struct{}{}
		paramsReferenced := map[string]struct{}{}
		datasetsReferenced := map[string]struct{}{}
		datasets := map[string]types.DatasetRefSpec{}
		rulesetInputs := map[string]*rulesetInputAccumulator{}

		for i := range rs.Doc.Ruleset.Rules {
			r := &rs.Doc.Ruleset.Rules[i]

			refs := celengine.References{Datasets: []string{}, RequiredDatasets: []string{}, Params: []string{}}
			var enginePtr *types.CheckEngine
			expression := ""
			expressionSHA256 := ""
			if r.Check != nil {
				engine := types.CheckEngine(strings.TrimSpace(string(r.Check.Engine)))
				if engine != "" {
					engineCopy := engine
					enginePtr = &engineCopy
					engines[engine] = struct{}{}
				}
				expression = strings.TrimSpace(r.Check.Expression)
				if expression != "" {
					refs = celengine.ExtractReferences(expression)
					sum := sha256.Sum256([]byte(expression))
					expressionSHA256 = hex.EncodeToString(sum[:])
				}
				if r.Check.Plan != nil {
					dataset := strings.TrimSpace(r.Check.Plan.Dataset)
					if dataset != "" {
						refs.Datasets = append(refs.Datasets, dataset)
						refs.RequiredDatasets = append(refs.RequiredDatasets, dataset)
					}
					refs.Params = append(refs.Params, celengine.ExtractParamReferences(r.Check.Plan.WhereExpression)...)
					refs.Params = append(refs.Params, celengine.ExtractParamReferences(r.Check.Plan.AssertExpression)...)
				}
			}
			refs.Datasets = normalize.Strings(refs.Datasets)
			refs.RequiredDatasets = normalize.Strings(refs.RequiredDatasets)
			refs.Params = normalize.Strings(refs.Params)

			rDatasets := datasetsForRuleReferences(rs.Doc.Ruleset, refs.Datasets)
			rDatasets = normalize.DatasetRefs(rDatasets)
			for _, d := range rDatasets {
				datasets[fmt.Sprintf("%s@%d", d.Dataset, d.Version)] = d
				datasetsReferenced[d.Dataset] = struct{}{}
			}
			for _, d := range refs.Datasets {
				datasetsReferenced[d] = struct{}{}
			}
			for _, p := range refs.Params {
				paramsReferenced[p] = struct{}{}
			}

			rInputs := inputsForRule(r, refs.Params)
			accumulateRulesetInputs(rulesetInputs, r.Key, rInputs)

			req.Rules = append(req.Rules, types.RuleRequirement{
				RuleKey:            r.Key,
				IsManual:           isManualRule(r),
				Datasets:           rDatasets,
				Engine:             enginePtr,
				Expression:         expression,
				ExpressionSHA256:   expressionSHA256,
				DatasetsReferenced: refs.Datasets,
				ParamsReferenced:   refs.Params,
				Inputs:             rInputs,
				Monitoring: types.RuleRequirementMonitoring{
					Status: r.Monitoring.Status,
				},
			})
		}

		req.Datasets = setToSortedDatasetRefs(datasets)
		req.Engines = setToSortedEngines(engines)
		req.DatasetsReferenced = setToSortedStringSlice(datasetsReferenced)
		req.ParamsReferenced = setToSortedStringSlice(paramsReferenced)
		req.Inputs = setToSortedRulesetInputs(rulesetInputs)

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
	switch r.Monitoring.Status {
	case types.MonitoringStatusManual, types.MonitoringStatusUnsupported:
		return true
	}
	if r.Check == nil {
		return true
	}
	return false
}

func datasetsForRuleReferences(rs types.Ruleset, datasetNames []string) []types.DatasetRefSpec {
	if len(datasetNames) == 0 {
		return []types.DatasetRefSpec{}
	}
	set := map[string]struct{}{}
	for _, dataset := range datasetNames {
		dataset = strings.TrimSpace(dataset)
		if dataset == "" {
			continue
		}
		set[dataset] = struct{}{}
	}
	if len(set) == 0 {
		return []types.DatasetRefSpec{}
	}
	out := make([]types.DatasetRefSpec, 0, len(set))
	for dataset := range set {
		out = append(out, types.DatasetRefSpec{
			Dataset: dataset,
			Version: resolveDatasetVersion(dataset, rs.DataContracts),
		})
	}
	return out
}

func resolveDatasetVersion(dataset string, contracts []types.DatasetContractRef) int {
	versions := make([]int, 0, 1)
	for _, dc := range contracts {
		if dc.Dataset != dataset {
			continue
		}
		versions = append(versions, dc.Version)
	}
	if len(versions) == 0 {
		return 1
	}
	slices.Sort(versions)
	versions = slices.Compact(versions)
	return versions[0]
}

func inputsForRule(r *types.Rule, referencedParams []string) []types.RuleInputRequirement {
	if r == nil {
		return []types.RuleInputRequirement{}
	}

	type ruleInputAccumulator struct {
		typ        string
		hasDefault bool
		defaultVal any
		sources    map[string]struct{}
	}
	inputs := map[string]*ruleInputAccumulator{}
	ensure := func(name string) *ruleInputAccumulator {
		acc, ok := inputs[name]
		if ok {
			return acc
		}
		acc = &ruleInputAccumulator{sources: map[string]struct{}{}}
		inputs[name] = acc
		return acc
	}

	if r.Parameters != nil {
		for name, defaultVal := range r.Parameters.Defaults {
			if strings.TrimSpace(name) == "" {
				continue
			}
			acc := ensure(name)
			acc.hasDefault = true
			acc.defaultVal = defaultVal
			acc.sources[inputSourceDefaults] = struct{}{}
		}
		for name, schema := range r.Parameters.Schema {
			if strings.TrimSpace(name) == "" {
				continue
			}
			acc := ensure(name)
			typ := strings.TrimSpace(schema.Type)
			if typ != "" {
				acc.typ = typ
			}
			acc.sources[inputSourceSchema] = struct{}{}
		}
	}

	for _, refParam := range referencedParams {
		if strings.TrimSpace(refParam) == "" {
			continue
		}
		acc := ensure(refParam)
		acc.sources[inputSourceExpressionParam] = struct{}{}
	}

	if len(inputs) == 0 {
		return []types.RuleInputRequirement{}
	}

	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	slices.Sort(names)

	out := make([]types.RuleInputRequirement, 0, len(names))
	for _, name := range names {
		acc := inputs[name]
		item := types.RuleInputRequirement{
			Name:       name,
			Type:       acc.typ,
			HasDefault: acc.hasDefault,
			Sources:    setToSortedInputSources(acc.sources),
		}
		if acc.hasDefault {
			item.Default = acc.defaultVal
		}
		out = append(out, item)
	}
	return out
}

func accumulateRulesetInputs(agg map[string]*rulesetInputAccumulator, ruleKey string, inputs []types.RuleInputRequirement) {
	for _, input := range inputs {
		acc, ok := agg[input.Name]
		if !ok {
			acc = &rulesetInputAccumulator{
				types:   map[string]struct{}{},
				sources: map[string]struct{}{},
				ruleSet: map[string]struct{}{},
			}
			agg[input.Name] = acc
		}

		if strings.TrimSpace(input.Type) != "" {
			acc.types[input.Type] = struct{}{}
		}
		for _, source := range input.Sources {
			acc.sources[source] = struct{}{}
		}
		if strings.TrimSpace(ruleKey) != "" {
			acc.ruleSet[ruleKey] = struct{}{}
		}
	}
}

func setToSortedRulesetInputs(m map[string]*rulesetInputAccumulator) []types.RulesetInputRequirement {
	if len(m) == 0 {
		return []types.RulesetInputRequirement{}
	}

	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)

	out := make([]types.RulesetInputRequirement, 0, len(names))
	for _, name := range names {
		acc := m[name]
		out = append(out, types.RulesetInputRequirement{
			Name:     name,
			Type:     collapseTypes(acc.types),
			Sources:  setToSortedInputSources(acc.sources),
			RuleKeys: setToSortedStringSlice(acc.ruleSet),
		})
	}
	return out
}

func collapseTypes(set map[string]struct{}) string {
	if len(set) != 1 {
		return ""
	}
	for t := range set {
		return t
	}
	return ""
}

func setToSortedInputSources(m map[string]struct{}) []string {
	if len(m) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(m))
	for source := range m {
		out = append(out, source)
	}
	slices.SortFunc(out, func(a, b string) int {
		oa := inputSourceOrder(a)
		ob := inputSourceOrder(b)
		if oa != ob {
			return oa - ob
		}
		return strings.Compare(a, b)
	})
	return out
}

func inputSourceOrder(source string) int {
	switch source {
	case inputSourceDefaults:
		return 0
	case inputSourceSchema:
		return 1
	case inputSourceExpressionParam:
		return 2
	default:
		return 3
	}
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

func setToSortedEngines(m map[types.CheckEngine]struct{}) []types.CheckEngine {
	if len(m) == 0 {
		return []types.CheckEngine{}
	}
	out := make([]types.CheckEngine, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b types.CheckEngine) int { return strings.Compare(string(a), string(b)) })
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
