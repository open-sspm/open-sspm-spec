package schemasem

import (
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

const testRegoModule = `package opensspm.test

results["R1"] := {"status": "pass"} if { true }
`

func TestValidateSemantic_ValidRegoRule(t *testing.T) {
	doc := types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.rego.v2",
			Name:  "Example Rego",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "okta:log-streams", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:log-streams"},
					Check: &types.Check{
						Engine:  types.CheckEngineRego,
						Package: "opensspm.test",
						Query:   `data.opensspm.test.results["R1"]`,
						Rego:    testRegoModule,
					},
				},
			},
		},
	}
	errs := ValidateSemantic(&Bundle{Rulesets: []struct {
		Path string
		Doc  types.RulesetDoc
	}{{Path: "specs/example.yaml", Doc: doc}}})
	if len(errs) != 0 {
		t.Fatalf("expected no semantic errors, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_RuleInheritsRulesetPolicy(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Policy = &types.RegoPolicy{
		Engine:  types.CheckEngineRego,
		Package: "opensspm.test",
		Rego:    testRegoModule,
	}
	doc.Ruleset.Rules[0].Check.Package = ""
	doc.Ruleset.Rules[0].Check.Rego = ""

	errs := ValidateSemantic(bundleWithRuleset(doc))
	if len(errs) != 0 {
		t.Fatalf("expected inherited ruleset policy to be valid, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_EffectiveCheckRequiresPackageAndRego(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Rules[0].Check.Package = ""
	doc.Ruleset.Rules[0].Check.Rego = ""

	errs := ValidateSemantic(bundleWithRuleset(doc))
	for _, want := range []string{"check.package is required", "check.rego is required (inline or inherited from ruleset.policy)"} {
		if !containsErr(errs, want) {
			t.Fatalf("expected %q error, got:\n%s", want, joinErrs(errs))
		}
	}
}

func TestValidateSemantic_ScopeRelationships(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Scope = types.Scope{Kind: types.ScopeKindConnectorInstance}
	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "requires scope.connector_kind") {
		t.Fatalf("expected missing connector kind error, got:\n%s", joinErrs(errs))
	}

	doc = validRulesetDoc()
	doc.Ruleset.Scope.ConnectorKind = "okta"
	errs = ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "scope.kind=global forbids scope.connector_kind") {
		t.Fatalf("expected forbidden connector kind error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_MonitoringCheckRelationships(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Rules[0].Check = nil
	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "requires rule.check") {
		t.Fatalf("expected required check error, got:\n%s", joinErrs(errs))
	}

	doc = validRulesetDoc()
	doc.Ruleset.Rules[0].Monitoring.Status = types.MonitoringStatusManual
	errs = ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "requires rule.check to be omitted") {
		t.Fatalf("expected omitted check error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_RequiredDataContracts(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Rules[0].RequiredData = []string{"okta:missing"}
	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, `ruleset.data_contracts missing dataset "okta:missing"`) {
		t.Fatalf("expected missing data contract error, got:\n%s", joinErrs(errs))
	}

	doc = validRulesetDoc()
	doc.Ruleset.DataContracts = append(doc.Ruleset.DataContracts, types.DatasetContractRef{
		Dataset: "okta:log-streams",
		Version: 2,
	})
	errs = ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "has multiple data_contracts versions") {
		t.Fatalf("expected multiple versions error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_UniquenessAndProfileReferences(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Rules = append(doc.Ruleset.Rules, doc.Ruleset.Rules[0])
	bundle := bundleWithRuleset(doc)
	bundle.Rulesets = append(bundle.Rulesets, bundle.Rulesets[0])
	bundle.Profiles = []struct {
		Path string
		Doc  types.ProfileDoc
	}{
		{
			Path: "specs/profile.yaml",
			Doc: types.ProfileDoc{SchemaVersion: 2, Kind: "opensspm.profile", Profile: types.Profile{
				Key:  "profile.v2",
				Name: "Profile",
				Rulesets: []types.ProfileRulesetRef{
					{Key: doc.Ruleset.Key},
					{Key: doc.Ruleset.Key},
					{Key: "missing.v2"},
				},
			}},
		},
	}

	errs := ValidateSemantic(bundle)
	for _, want := range []string{
		"duplicate ruleset.key",
		"duplicate rule.key",
		"duplicate ruleset ref",
		"references missing ruleset.key",
	} {
		if !containsErr(errs, want) {
			t.Fatalf("expected %q error, got:\n%s", want, joinErrs(errs))
		}
	}
}

func TestValidateSemantic_InvalidRego(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Rules[0].Check.Rego = `package opensspm.test

results["R1"] := if {
`
	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "invalid Rego") {
		t.Fatalf("expected invalid Rego error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_InvalidQuerylessRulesetPolicyRego(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Policy = &types.RegoPolicy{
		Engine:  types.CheckEngineRego,
		Package: "opensspm.policy",
		Rego: `package opensspm.policy

helper := if {
`,
	}
	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "ruleset.policy invalid Rego") {
		t.Fatalf("expected invalid ruleset policy Rego error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_RulesetPolicyRequiresRego(t *testing.T) {
	doc := validRulesetDoc()
	doc.Ruleset.Policy = &types.RegoPolicy{
		Engine:  types.CheckEngineRego,
		Package: "opensspm.policy",
	}

	errs := ValidateSemantic(bundleWithRuleset(doc))
	if !containsErr(errs, "ruleset.policy.rego is required (inline or via rego_path)") {
		t.Fatalf("expected missing ruleset policy Rego error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_EntityPolicyPack(t *testing.T) {
	pack := types.EntityPolicyPackDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.entity_policy_pack",
		EntityPolicyPack: types.EntityPolicyPack{
			Metadata: types.EntityPolicyMetadata{
				ID:      "builtin.test",
				Version: "1.0.0",
				Domain:  types.EntityPolicyDomainSaaS,
			},
			Inputs: types.EntityPolicyInputs{Schema: "test_input.v1"},
			Policy: types.RegoPolicy{
				Engine:  types.CheckEngineRego,
				Package: "opensspm.entity.test",
				Query:   "data.opensspm.entity.test.result",
				Rego: `package opensspm.entity.test

result := {"risk_level": "low", "signals": []} if { true }
`,
			},
		},
	}

	errs := ValidateSemantic(&Bundle{EntityPolicyPacks: []struct {
		Path string
		Doc  types.EntityPolicyPackDoc
	}{{Path: "specs/policies/test.yaml", Doc: pack}}})
	if len(errs) != 0 {
		t.Fatalf("expected no semantic errors, got:\n%s", joinErrs(errs))
	}
}

func validRulesetDoc() types.RulesetDoc {
	return types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.rego.v2",
			Name:  "Example Rego",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "okta:log-streams", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:log-streams"},
					Check: &types.Check{
						Engine:  types.CheckEngineRego,
						Package: "opensspm.test",
						Query:   `data.opensspm.test.results["R1"]`,
						Rego:    testRegoModule,
					},
				},
			},
		},
	}
}

func bundleWithRuleset(doc types.RulesetDoc) *Bundle {
	return &Bundle{Rulesets: []struct {
		Path string
		Doc  types.RulesetDoc
	}{{Path: "specs/example.yaml", Doc: doc}}}
}

func containsErr(errs []error, substr string) bool {
	for _, err := range errs {
		if strings.Contains(err.Error(), substr) {
			return true
		}
	}
	return false
}

func joinErrs(errs []error) string {
	var b strings.Builder
	for _, err := range errs {
		b.WriteString(err.Error())
		b.WriteByte('\n')
	}
	return b.String()
}
