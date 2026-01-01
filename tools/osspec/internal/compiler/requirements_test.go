package compiler

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestBuildRequirements_CapturesRulesetAndRuleDetails(t *testing.T) {
	checkTypeManual := types.CheckTypeManualAttestation
	checkTypeCount := types.CheckTypeDatasetCountCompare

	b := &schemasem.Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{
			{
				Path: "specs/rulesets/example.json",
				Doc: types.RulesetDoc{
					SchemaVersion: 1,
					Kind:          "opensspm.ruleset",
					Ruleset: types.Ruleset{
						Key:    "example.ruleset.v1",
						Name:   "Example",
						Scope:  types.Scope{Kind: types.ScopeKindGlobal},
						Status: "active",
						DataContracts: []types.DatasetContractRef{
							{Dataset: "okta:log-streams", Version: 2},
						},
						Rules: []types.Rule{
							{
								Key:          "R1",
								Title:        "R1",
								Severity:     types.SeverityLow,
								Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
								RequiredData: []string{"okta:log-streams"},
								Parameters:   &types.Parameters{Defaults: map[string]any{"min": 1, "enabled": true}},
								Check: &types.Check{
									Type:    types.CheckTypeDatasetCountCompare,
									Dataset: "okta:log-streams",
									// omit dataset_version; effective version should resolve from ruleset.data_contracts (2)
									Where: []types.Predicate{
										{Path: "/enabled", Op: types.OperatorEq, ValueParam: "enabled"},
									},
									Compare: &types.Compare{Op: types.CompareOpGte, ValueParam: "min"},
								},
							},
							{
								Key:          "R2",
								Title:        "R2",
								Severity:     types.SeverityInfo,
								Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
								RequiredData: []string{},
								Check:        &types.Check{Type: types.CheckTypeManualAttestation},
							},
						},
					},
				},
			},
		},
	}

	got := buildRequirements(b)
	want := types.RequirementsIndex{
		SchemaVersion: 1,
		Kind:          "opensspm.requirements_index",
		Rulesets: []types.RulesetRequirement{
			{
				RulesetKey: "example.ruleset.v1",
				Status:     "active",
				Scope:      types.Scope{Kind: types.ScopeKindGlobal},
				Datasets: []types.DatasetRefSpec{
					{Dataset: "okta:log-streams", Version: 2},
				},
				CheckTypes: []types.CheckType{
					types.CheckTypeDatasetCountCompare,
					types.CheckTypeManualAttestation,
				},
				ValueParams: []string{"enabled", "min"},
				Rules: []types.RuleRequirement{
					{
						RuleKey:    "R1",
						IsManual:   false,
						Datasets:   []types.DatasetRefSpec{{Dataset: "okta:log-streams", Version: 2}},
						CheckType:  &checkTypeCount,
						ValueParams: []string{"enabled", "min"},
						Monitoring: struct {
							Status types.MonitoringStatus `json:"status"`
						}{Status: types.MonitoringStatusAutomated},
					},
					{
						RuleKey:    "R2",
						IsManual:   true,
						Datasets:   []types.DatasetRefSpec{},
						CheckType:  &checkTypeManual,
						ValueParams: []string{},
						Monitoring: struct {
							Status types.MonitoringStatus `json:"status"`
						}{Status: types.MonitoringStatusManual},
					},
				},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("buildRequirements mismatch (-want +got):\n%s", diff)
	}
}

