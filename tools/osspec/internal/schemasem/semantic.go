package schemasem

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/regoengine"
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
	if strings.TrimSpace(pack.Inputs.Schema) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: entity_policy_pack.inputs.schema is required", path))
	}
	errs = append(errs, validateRegoPolicy(path, "entity_policy_pack.policy", &pack.Policy, true)...)
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

func validateRulesetPolicy(path string, policy *types.RegoPolicy) []error {
	if policy == nil {
		return nil
	}
	return validateRegoPolicy(path, "ruleset.policy", policy, false)
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

		errs = append(errs, validateRule(path, r, contractsIdx)...)
	}

	return errs
}

func validateRule(path string, r *types.Rule, contractsIdx datasetContractIndex) []error {
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

	errs = append(errs, validateCheck(path, r, r.Check)...)
	errs = append(errs, validateRequiredData(path, r, contractsIdx)...)
	return errs
}

func validateCheck(path string, r *types.Rule, c *types.Check) []error {
	if c == nil {
		return nil
	}
	var errs []error
	if strings.TrimSpace(string(c.Engine)) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.engine is required", path, r.Key))
	} else if c.Engine != types.CheckEngineRego {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: unsupported check.engine %q", path, r.Key, c.Engine))
	}
	if strings.TrimSpace(c.Package) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.package is required", path, r.Key))
	}
	if strings.TrimSpace(c.Query) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.query is required", path, r.Key))
	}
	rego := strings.TrimSpace(c.Rego)
	if rego == "" {
		if strings.TrimSpace(c.RegoPath) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: check.rego is required, either inline, via check.rego_path, or via ruleset.policy", path, r.Key))
		}
		return errs
	}
	if len(errs) == 0 {
		if err := regoengine.ValidateModule(context.Background(), path+":"+r.Key+".rego", rego, c.Query); err != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: invalid Rego: %v", path, r.Key, err))
		}
	}
	return errs
}

func validateRegoPolicy(path, field string, policy *types.RegoPolicy, requireQuery bool) []error {
	var errs []error
	if policy == nil {
		return []error{fmt.Errorf("semantic: %s: %s is required", path, field)}
	}
	if policy.Engine != types.CheckEngineRego {
		errs = append(errs, fmt.Errorf("semantic: %s: %s.engine must be rego", path, field))
	}
	if strings.TrimSpace(policy.Package) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: %s.package is required", path, field))
	}
	if requireQuery && strings.TrimSpace(policy.Query) == "" {
		errs = append(errs, fmt.Errorf("semantic: %s: %s.query is required", path, field))
	}
	rego := strings.TrimSpace(policy.Rego)
	if rego == "" {
		if strings.TrimSpace(policy.RegoPath) == "" {
			errs = append(errs, fmt.Errorf("semantic: %s: %s.rego is required, either inline or via rego_path", path, field))
		}
		return errs
	}
	if len(errs) == 0 {
		if strings.TrimSpace(policy.Query) == "" {
			if err := regoengine.ValidateModuleOnly(context.Background(), path+":"+field+".rego", rego); err != nil {
				errs = append(errs, fmt.Errorf("semantic: %s: %s invalid Rego: %v", path, field, err))
			}
			return errs
		}
		if err := regoengine.ValidateModule(context.Background(), path+":"+field+".rego", rego, policy.Query); err != nil {
			errs = append(errs, fmt.Errorf("semantic: %s: %s invalid Rego: %v", path, field, err))
		}
	}
	return errs
}

func validateRequiredData(path string, r *types.Rule, contractsIdx datasetContractIndex) []error {
	var errs []error
	seen := map[string]struct{}{}
	for _, dataset := range r.RequiredData {
		dataset = strings.TrimSpace(dataset)
		if dataset == "" {
			continue
		}
		if _, ok := seen[dataset]; ok {
			errs = append(errs, fmt.Errorf("semantic: %s: rule %q: duplicate required_data dataset %q", path, r.Key, dataset))
			continue
		}
		seen[dataset] = struct{}{}

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
