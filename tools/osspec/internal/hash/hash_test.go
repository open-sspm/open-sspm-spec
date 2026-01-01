package hash

import (
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestHashObjectJCS_NormalizedRulesetStableAcrossOrdering(t *testing.T) {
	zero := 0

	doc1 := types.RulesetDoc{
		SchemaVersion: 1,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.ruleset.v1",
			Name:  "Example",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			// omit status to exercise defaulting
			Tags: []string{"b", "a"},
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
			DataContracts: []types.DatasetContractRef{
				{Dataset: "okta:log-streams", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:         "B",
					Title:       "B",
					Severity:    types.SeverityLow,
					Monitoring:  types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
					Check:       &types.Check{Type: types.CheckTypeManualAttestation},
				},
				{
					Key:      "A",
					Title:    "A",
					Severity: types.SeverityLow,
					Monitoring: types.Monitoring{
						Status: types.MonitoringStatusAutomated,
					},
					RequiredData: []string{"okta:log-streams"},
					Parameters:   &types.Parameters{Defaults: map[string]any{"min": 0}},
					Check: &types.Check{
						Type:           types.CheckTypeDatasetCountCompare,
						Dataset:        "okta:log-streams",
						DatasetVersion: 1,
						Where: []types.Predicate{
							{Path: "/enabled", Op: types.OperatorEq, Value: true},
							{Path: "/type", Op: types.OperatorEq, Value: "event_hook"},
						},
						Compare: &types.Compare{Op: types.CompareOpGte, Value: &zero},
					},
				},
			},
		},
	}

	doc2 := types.RulesetDoc{
		SchemaVersion: 1,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:    "example.ruleset.v1",
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
			DataContracts: []types.DatasetContractRef{
				{Dataset: "okta:log-streams", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:      "A",
					Title:    "A",
					Severity: types.SeverityLow,
					Monitoring: types.Monitoring{
						Status: types.MonitoringStatusAutomated,
					},
					RequiredData: []string{"okta:log-streams"},
					Parameters:   &types.Parameters{Defaults: map[string]any{"min": 0}},
					Check: &types.Check{
						Type:           types.CheckTypeDatasetCountCompare,
						Dataset:        "okta:log-streams",
						DatasetVersion: 1,
						Where: []types.Predicate{
							{Path: "/type", Op: types.OperatorEq, Value: "event_hook"},
							{Path: "/enabled", Op: types.OperatorEq, Value: true},
						},
						Compare: &types.Compare{Op: types.CompareOpGte, Value: &zero},
					},
				},
				{
					Key:         "B",
					Title:       "B",
					Severity:    types.SeverityLow,
					Monitoring:  types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
					Check:       &types.Check{Type: types.CheckTypeManualAttestation},
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

func TestHashObjectJCS_NormalizedRulesetStableAcrossJoinWhereOrdering(t *testing.T) {
	zero := 0

	doc1 := types.RulesetDoc{
		SchemaVersion: 1,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.join.ruleset.v1",
			Name:  "Example join",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "core:entitlement_assignments", Version: 1},
				{Dataset: "core:identities", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:         "R1",
					Title:       "R1",
					Severity:    types.SeverityLow,
					Monitoring:  types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"core:entitlement_assignments", "core:identities"},
					Parameters:   &types.Parameters{Defaults: map[string]any{"max": 0}},
					Check: &types.Check{
						Type:           types.CheckTypeDatasetJoinCountCompare,
						DatasetVersion: 1,
						Left:           &types.JoinSide{Dataset: "core:identities", KeyPath: "/email"},
						Right:          &types.JoinSide{Dataset: "core:entitlement_assignments", KeyPath: "/identity/email"},
						Where: []types.Predicate{
							{RightPath: "/entitlement/tags", Op: types.OperatorContains, Value: "admin"},
							{LeftPath: "/email", Op: types.OperatorExists},
						},
						Compare: &types.Compare{Op: types.CompareOpLte, Value: &zero},
					},
				},
			},
		},
	}

	doc2 := types.RulesetDoc{
		SchemaVersion: 1,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   "example.join.ruleset.v1",
			Name:  "Example join",
			Scope: types.Scope{Kind: types.ScopeKindGlobal},
			DataContracts: []types.DatasetContractRef{
				{Dataset: "core:identities", Version: 1},
				{Dataset: "core:entitlement_assignments", Version: 1},
			},
			Rules: []types.Rule{
				{
					Key:         "R1",
					Title:       "R1",
					Severity:    types.SeverityLow,
					Monitoring:  types.Monitoring{Status: types.MonitoringStatusAutomated},
					RequiredData: []string{"core:identities", "core:entitlement_assignments"},
					Parameters:   &types.Parameters{Defaults: map[string]any{"max": 0}},
					Check: &types.Check{
						Type:           types.CheckTypeDatasetJoinCountCompare,
						DatasetVersion: 1,
						Left:           &types.JoinSide{Dataset: "core:identities", KeyPath: "/email"},
						Right:          &types.JoinSide{Dataset: "core:entitlement_assignments", KeyPath: "/identity/email"},
						Where: []types.Predicate{
							{LeftPath: "/email", Op: types.OperatorExists},
							{RightPath: "/entitlement/tags", Op: types.OperatorContains, Value: "admin"},
						},
						Compare: &types.Compare{Op: types.CompareOpLte, Value: &zero},
					},
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
