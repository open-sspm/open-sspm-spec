package hash

import (
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestHashObjectJCS_NormalizedRulesetStableAcrossOrdering(t *testing.T) {
	expr := `rows("okta:log-streams").exists(r, r["enabled"] == true)`

	doc1 := types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.ruleset.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			Tags:  []string{"b", "a"},
			References: []types.Reference{
				{URL: "https://b.example", Title: "B"},
				{URL: "https://a.example", Title: "A", Type: types.ReferenceTypeOther},
			},
			FrameworkMappings: []types.FrameworkMapping{
				{Framework: "B", Control: "2", Coverage: types.FrameworkCoveragePartial},
				{Framework: "A", Control: "1"},
			},
			Requirements: &types.RulesetRequirements{
				APIScopes:   []string{"b", "a"},
				Permissions: []string{"p2", "p1"},
			},
			DataContracts: []types.DatasetContractRef{{Dataset: "okta:log-streams", Version: 1}},
			Rules: []types.Rule{
				{
					Key:          "B",
					Title:        "B",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
				},
				{
					Key:          "A",
					Title:        "A",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:log-streams"},
					Check:        &types.Check{Engine: types.CheckEngineCEL, Expression: expr},
				},
			},
		},
	}

	doc2 := types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:    "example.ruleset.v2",
			Name:   "Example",
			Scope:  types.Scope{Kind: types.ScopeKindGlobal},
			Status: "active",
			Tags:   []string{"a", "b"},
			References: []types.Reference{
				{URL: "https://a.example", Title: "A"},
				{URL: "https://b.example", Title: "B", Type: types.ReferenceTypeOther},
			},
			FrameworkMappings: []types.FrameworkMapping{
				{Framework: "A", Control: "1", Coverage: types.FrameworkCoverageSupporting},
				{Framework: "B", Control: "2", Coverage: types.FrameworkCoveragePartial},
			},
			Requirements: &types.RulesetRequirements{
				APIScopes:   []string{"a", "b"},
				Permissions: []string{"p1", "p2"},
			},
			DataContracts: []types.DatasetContractRef{{Dataset: "okta:log-streams", Version: 1}},
			Rules: []types.Rule{
				{
					Key:          "A",
					Title:        "A",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"okta:log-streams"},
					Check:        &types.Check{Engine: types.CheckEngineCEL, Expression: expr},
				},
				{
					Key:          "B",
					Title:        "B",
					Severity:     types.SeverityLow,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
				},
			},
		},
	}

	normalize.RulesetDoc(&doc1)
	normalize.RulesetDoc(&doc2)

	h1, _, err := HashObjectJCS(doc1)
	if err != nil {
		t.Fatalf("HashObjectJCS(doc1) error: %v", err)
	}
	h2, _, err := HashObjectJCS(doc2)
	if err != nil {
		t.Fatalf("HashObjectJCS(doc2) error: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected equal hashes, got %s vs %s", h1, h2)
	}
}

func TestHashObjectJCS_NormalizedRulesetStableAcrossRequiredDataOrdering(t *testing.T) {
	expr := `rows("core:a").size() > 0 && rows("core:b").size() > 0`

	doc1 := types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.join.ruleset.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "core:b", Version: 1},
				{Dataset: "core:a", Version: 1},
			},
			Rules: []types.Rule{{
				Key:          "R1",
				Title:        "R1",
				Severity:     types.SeverityLow,
				Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
				RequiredData: []string{"core:b", "core:a"},
				Check:        &types.Check{Engine: types.CheckEngineCEL, Expression: expr},
			}},
		},
	}
	doc2 := types.RulesetDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.join.ruleset.v2",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "core:a", Version: 1},
				{Dataset: "core:b", Version: 1},
			},
			Rules: []types.Rule{{
				Key:          "R1",
				Title:        "R1",
				Severity:     types.SeverityLow,
				Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
				RequiredData: []string{"core:a", "core:b"},
				Check:        &types.Check{Engine: types.CheckEngineCEL, Expression: expr},
			}},
		},
	}

	normalize.RulesetDoc(&doc1)
	normalize.RulesetDoc(&doc2)

	h1, _, err := HashObjectJCS(doc1)
	if err != nil {
		t.Fatalf("HashObjectJCS(doc1) error: %v", err)
	}
	h2, _, err := HashObjectJCS(doc2)
	if err != nil {
		t.Fatalf("HashObjectJCS(doc2) error: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected equal hashes, got %s vs %s", h1, h2)
	}
}
