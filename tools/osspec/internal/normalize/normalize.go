package normalize

import (
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func Strings(v []string) []string {
	out := append([]string{}, v...)
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}

func References(v []types.Reference) []types.Reference {
	out := append([]types.Reference{}, v...)
	slices.SortFunc(out, func(a, b types.Reference) int {
		if c := strings.Compare(a.URL, b.URL); c != 0 {
			return c
		}
		if c := strings.Compare(a.Title, b.Title); c != 0 {
			return c
		}
		return strings.Compare(string(a.Type), string(b.Type))
	})
	return out
}

func RulesetDoc(doc *types.RulesetDoc) {
	if doc == nil {
		return
	}
	if doc.Ruleset.Status == "" {
		doc.Ruleset.Status = "active"
	}
	normalizeReferences(doc.Ruleset.References)
	normalizeRegoPolicy(doc.Ruleset.Policy)

	doc.Ruleset.Tags = Strings(doc.Ruleset.Tags)
	doc.Ruleset.References = References(doc.Ruleset.References)
	doc.Ruleset.DataContracts = DataContracts(doc.Ruleset.DataContracts)

	if len(doc.Ruleset.Rules) > 0 {
		slices.SortFunc(doc.Ruleset.Rules, func(a, b types.Rule) int {
			return strings.Compare(a.Key, b.Key)
		})
		for i := range doc.Ruleset.Rules {
			doc.Ruleset.Rules[i].Tags = Strings(doc.Ruleset.Rules[i].Tags)
			doc.Ruleset.Rules[i].RequiredData = Strings(doc.Ruleset.Rules[i].RequiredData)
			normalizeReferences(doc.Ruleset.Rules[i].References)
			doc.Ruleset.Rules[i].References = References(doc.Ruleset.Rules[i].References)
			normalizeRuleCheck(doc.Ruleset.Rules[i].Check)
		}
	}
}

func ProfileDoc(doc *types.ProfileDoc) {
	if doc == nil {
		return
	}
	if len(doc.Profile.Rulesets) == 0 {
		return
	}
	out := append([]types.ProfileRulesetRef(nil), doc.Profile.Rulesets...)
	slices.SortFunc(out, func(a, b types.ProfileRulesetRef) int {
		if c := strings.Compare(a.Key, b.Key); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	doc.Profile.Rulesets = out
}

func EntityPolicyPackDoc(doc *types.EntityPolicyPackDoc) {
	if doc == nil {
		return
	}
	pack := &doc.EntityPolicyPack
	pack.Metadata.ID = strings.TrimSpace(pack.Metadata.ID)
	pack.Metadata.Version = strings.TrimSpace(pack.Metadata.Version)
	pack.Metadata.Domain = types.EntityPolicyDomain(strings.ToLower(strings.TrimSpace(string(pack.Metadata.Domain))))
	pack.Inputs.Schema = strings.TrimSpace(pack.Inputs.Schema)
	normalizeRegoPolicy(&pack.Policy)
}

func DataContracts(v []types.DatasetContractRef) []types.DatasetContractRef {
	out := append([]types.DatasetContractRef{}, v...)
	slices.SortFunc(out, func(a, b types.DatasetContractRef) int {
		if c := strings.Compare(a.Dataset, b.Dataset); c != 0 {
			return c
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return strings.Compare(a.Description, b.Description)
	})
	return out
}

func normalizeReferences(v []types.Reference) {
	for i := range v {
		if v[i].Type == "" {
			v[i].Type = types.ReferenceTypeOther
		}
	}
}

func normalizeRuleCheck(c *types.Check) {
	if c == nil {
		return
	}
	c.Engine = types.CheckEngine(strings.ToLower(strings.TrimSpace(string(c.Engine))))
	c.Package = strings.TrimSpace(c.Package)
	c.Query = strings.TrimSpace(c.Query)
	c.Rego = strings.TrimSpace(c.Rego)
}

func normalizeRegoPolicy(p *types.RegoPolicy) {
	if p == nil {
		return
	}
	p.Engine = types.CheckEngine(strings.ToLower(strings.TrimSpace(string(p.Engine))))
	p.Package = strings.TrimSpace(p.Package)
	p.Query = strings.TrimSpace(p.Query)
	p.Rego = strings.TrimSpace(p.Rego)
}
