package schemasem

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/regoengine"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/rulecheck"
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
		errs = append(errs, validateRulesetPolicy(rs.Path, rs.Doc.Ruleset.Policy)...)
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

// ValidateSemantic validates relationships and executable Rego after documents
// have passed JSON Schema validation, normalization, and Rego path resolution.
func validateEntityPolicyPack(path string, doc *types.EntityPolicyPackDoc) []error {
	return validateRegoPolicy(path, "entity_policy_pack.policy", &doc.EntityPolicyPack.Policy)
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

func validateRulesetPolicy(path string, policy *types.RegoPolicy) []error {
	if policy == nil {
		return nil
	}
	return validateRegoPolicy(path, "ruleset.policy", policy)
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

		errs = append(errs, validateRule(path, r, doc.Ruleset.Policy, contractsIdx)...)
	}

	return errs
}

func validateRule(path string, r *types.Rule, policy *types.RegoPolicy, contractsIdx datasetContractIndex) []error {
	var errs []error

	if r.Monitoring.Status == types.MonitoringStatusManual || r.Monitoring.Status == types.MonitoringStatusUnsupported {
		if r.Check != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q requires rule.check to be omitted", path, r.Key, r.Monitoring.Status))
		}
		return errs
	}
	if r.Check == nil {
		return append(errs, fmt.Errorf("semantic: %s: rule %q: monitoring.status=%q requires rule.check", path, r.Key, r.Monitoring.Status))
	}

	errs = append(errs, validateCheck(path, r, policy)...)
	errs = append(errs, validateRequiredData(path, r, contractsIdx)...)
	return errs
}

func validateCheck(path string, r *types.Rule, policy *types.RegoPolicy) []error {
	if r.Check == nil {
		return nil
	}
	c := rulecheck.Resolve(policy, r.Check)
	var errs []error
	if strings.TrimSpace(c.Package) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.package is required", path, r.Key))
	}
	rego := strings.TrimSpace(c.Rego)
	if rego == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.rego is required, either inline, via check.rego_path, or via ruleset.policy", path, r.Key))
		return errs
	}
	if len(errs) == 0 {
		if err := regoengine.ValidateModule(context.Background(), path+":"+r.Key+".rego", rego, c.Query); err != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid Rego: %v", path, r.Key, err))
		}
	}
	return errs
}

func validateRegoPolicy(path, field string, policy *types.RegoPolicy) []error {
	rego := strings.TrimSpace(policy.Rego)
	if strings.TrimSpace(policy.Query) == "" {
		if err := regoengine.ValidateModuleOnly(context.Background(), path+":"+field+".rego", rego); err != nil {
			return []error{fmt.Errorf("semantic: %s: %s invalid Rego: %v", path, field, err)}
		}
		return nil
	}
	if err := regoengine.ValidateModule(context.Background(), path+":"+field+".rego", rego, policy.Query); err != nil {
		return []error{fmt.Errorf("semantic: %s: %s invalid Rego: %v", path, field, err)}
	}
	return nil
}

func validateRequiredData(path string, r *types.Rule, contractsIdx datasetContractIndex) []error {
	var errs []error
	for _, dataset := range r.RequiredData {
		dataset = strings.TrimSpace(dataset)
		if dataset == "" {
			continue
		}

		versions := contractsIdx.versionsByDataset[dataset]
		if len(versions) == 0 {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: ruleset.data_contracts missing dataset %q from required_data", path, r.Key, dataset))
			continue
		}
		if len(versions) > 1 {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: dataset %q has multiple data_contracts versions; Rego rules require exactly one version per required dataset", path, r.Key, dataset))
		}
	}
	return errs
}
