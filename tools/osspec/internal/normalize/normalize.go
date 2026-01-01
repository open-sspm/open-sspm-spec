package normalize

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
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

func DatasetRefs(v []types.DatasetRefSpec) []types.DatasetRefSpec {
	out := append([]types.DatasetRefSpec{}, v...)
	slices.SortFunc(out, func(a, b types.DatasetRefSpec) int {
		if c := strings.Compare(a.Dataset, b.Dataset); c != 0 {
			return c
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
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
	normalizeFrameworkMappings(doc.Ruleset.FrameworkMappings)
	normalizeDataContracts(doc.Ruleset.DataContracts)
	normalizeRulesetRequirements(doc.Ruleset.Requirements)

	doc.Ruleset.Tags = Strings(doc.Ruleset.Tags)
	doc.Ruleset.References = References(doc.Ruleset.References)
	doc.Ruleset.FrameworkMappings = FrameworkMappings(doc.Ruleset.FrameworkMappings)
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
			normalizeFrameworkMappings(doc.Ruleset.Rules[i].FrameworkMappings)
			doc.Ruleset.Rules[i].FrameworkMappings = FrameworkMappings(doc.Ruleset.Rules[i].FrameworkMappings)
			normalizeRuleLifecycle(doc.Ruleset.Rules[i].Lifecycle)
			normalizeCheckDefaults(doc.Ruleset.Rules[i].Check)
		}
	}
}

func ConnectorManifestDoc(doc *types.ConnectorManifestDoc) {
	if doc == nil {
		return
	}
	doc.Connector.Provides = DatasetRefs(doc.Connector.Provides)
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

func DictionaryDoc(doc *types.DictionaryDoc) {
	if doc == nil {
		return
	}
	if doc.Dictionary.Enums == nil {
		return
	}
	for k := range doc.Dictionary.Enums {
		doc.Dictionary.Enums[k] = Strings(doc.Dictionary.Enums[k])
	}
}

func FrameworkMappings(v []types.FrameworkMapping) []types.FrameworkMapping {
	out := append([]types.FrameworkMapping{}, v...)
	slices.SortFunc(out, func(a, b types.FrameworkMapping) int {
		if c := strings.Compare(a.Framework, b.Framework); c != 0 {
			return c
		}
		if c := strings.Compare(a.Control, b.Control); c != 0 {
			return c
		}
		if c := strings.Compare(a.Enhancement, b.Enhancement); c != 0 {
			return c
		}
		if c := strings.Compare(string(a.Coverage), string(b.Coverage)); c != 0 {
			return c
		}
		return strings.Compare(a.Notes, b.Notes)
	})
	return out
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

func normalizeFrameworkMappings(v []types.FrameworkMapping) {
	for i := range v {
		if v[i].Coverage == "" {
			v[i].Coverage = types.FrameworkCoverageSupporting
		}
	}
}

func normalizeDataContracts(_ []types.DatasetContractRef) {
	// currently no defaulting required
}

func normalizeRulesetRequirements(req *types.RulesetRequirements) {
	if req == nil {
		return
	}
	req.APIScopes = Strings(req.APIScopes)
	req.Permissions = Strings(req.Permissions)
}

func normalizeRuleLifecycle(lc *types.Lifecycle) {
	if lc == nil {
		return
	}
	if lc.IsActive == nil {
		v := true
		lc.IsActive = &v
	}
}

func normalizeCheckDefaults(c *types.Check) {
	if c == nil {
		return
	}

	if c.OnMissingDataset == "" {
		c.OnMissingDataset = types.ErrorPolicyUnknown
	}
	if c.OnPermissionDenied == "" {
		c.OnPermissionDenied = types.ErrorPolicyUnknown
	}
	if c.OnSyncError == "" {
		c.OnSyncError = types.ErrorPolicyError
	}

	if len(c.Where) > 0 {
		sortPredicates(c.Type, c.Where)
	}

	switch c.Type {
	case types.CheckTypeDatasetFieldCompare:
		if c.Expect == nil {
			c.Expect = &types.FieldCompareExpect{}
		}
		if c.Expect.Match == "" {
			c.Expect.Match = types.FieldCompareMatchAll
		}
		if c.Expect.OnEmpty == "" {
			c.Expect.OnEmpty = types.FieldCompareOnEmptyUnknown
		}
	case types.CheckTypeDatasetJoinCountCompare:
		if c.OnUnmatchedLeft == "" {
			c.OnUnmatchedLeft = types.OnUnmatchedLeftIgnore
		}
	}
}

func sortPredicates(checkType types.CheckType, preds []types.Predicate) {
	// Sorting is stable/deterministic per newspec.md section 7.1.
	slices.SortFunc(preds, func(a, b types.Predicate) int {
		if checkType == types.CheckTypeDatasetJoinCountCompare {
			if c := strings.Compare(a.LeftPath, b.LeftPath); c != 0 {
				return c
			}
			if c := strings.Compare(a.RightPath, b.RightPath); c != 0 {
				return c
			}
		} else {
			if c := strings.Compare(a.Path, b.Path); c != 0 {
				return c
			}
		}

		if c := strings.Compare(string(a.Op), string(b.Op)); c != 0 {
			return c
		}
		if c := strings.Compare(a.ValueParam, b.ValueParam); c != 0 {
			return c
		}
		return strings.Compare(canonicalValue(a.Value), canonicalValue(b.Value))
	})
}

func canonicalValue(v any) string {
	if v == nil {
		return "null"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		// Unmarshal sources are already JSON, so marshal failures are unexpected.
		return ""
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return string(raw)
	}
	return string(canonical)
}
