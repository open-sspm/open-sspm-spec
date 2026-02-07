package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestBuildRequirements_CapturesRulesetAndRuleDetails(t *testing.T) {
	r1Expr := `rows("okta:log-streams").exists(r, r["enabled"] == param("enabled")) && rows("okta:log-streams").size() >= int(param("min"))`
	r3Expr := `rows("okta:log-streams").exists(r, r["enabled"] == param("enabled"))`
	engineCEL := types.CheckEngineCEL

	b := &schemasem.Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{
			{
				Path: "specs/rulesets/example.json",
				Doc: types.RulesetDoc{
					SchemaVersion: 2,
					Kind:          "opensspm.ruleset",
					Ruleset: types.Ruleset{
						Key:    "example.ruleset.v2",
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
									Engine:     types.CheckEngineCEL,
									Expression: r1Expr,
								},
							},
							{
								Key:          "R2",
								Title:        "R2",
								Severity:     types.SeverityInfo,
								Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
								RequiredData: []string{},
							},
							{
								Key:        "R3",
								Title:      "R3",
								Severity:   types.SeverityLow,
								Monitoring: types.Monitoring{Status: types.MonitoringStatusAutomated},
								Parameters: &types.Parameters{
									Defaults: map[string]any{"enabled": false, "threshold": 5},
									Schema: map[string]types.ParameterSchema{
										"enabled":   {Type: "boolean"},
										"threshold": {Type: "integer"},
									},
								},
								Check: &types.Check{
									Engine:     types.CheckEngineCEL,
									Expression: r3Expr,
								},
							},
						},
					},
				},
			},
		},
	}

	got := buildRequirements(b)
	want := types.RequirementsIndex{
		SchemaVersion: 2,
		Kind:          "opensspm.requirements_index",
		Rulesets: []types.RulesetRequirement{
			{
				RulesetKey:         "example.ruleset.v2",
				Status:             "active",
				Scope:              types.Scope{Kind: types.ScopeKindGlobal},
				Datasets:           []types.DatasetRefSpec{{Dataset: "okta:log-streams", Version: 2}},
				Engines:            []types.CheckEngine{types.CheckEngineCEL},
				DatasetsReferenced: []string{"okta:log-streams"},
				ParamsReferenced:   []string{"enabled", "min"},
				Inputs: []types.RulesetInputRequirement{
					{
						Name:     "enabled",
						Type:     "boolean",
						Sources:  []string{"defaults", "schema", "expression_param"},
						RuleKeys: []string{"R1", "R3"},
					},
					{
						Name:     "min",
						Sources:  []string{"defaults", "expression_param"},
						RuleKeys: []string{"R1"},
					},
					{
						Name:     "threshold",
						Type:     "integer",
						Sources:  []string{"defaults", "schema"},
						RuleKeys: []string{"R3"},
					},
				},
				Rules: []types.RuleRequirement{
					{
						RuleKey:            "R1",
						IsManual:           false,
						Datasets:           []types.DatasetRefSpec{{Dataset: "okta:log-streams", Version: 2}},
						Engine:             &engineCEL,
						Expression:         r1Expr,
						ExpressionSHA256:   hashExpr(r1Expr),
						DatasetsReferenced: []string{"okta:log-streams"},
						ParamsReferenced:   []string{"enabled", "min"},
						Inputs: []types.RuleInputRequirement{
							{
								Name:       "enabled",
								Default:    true,
								HasDefault: true,
								Sources:    []string{"defaults", "expression_param"},
							},
							{
								Name:       "min",
								Default:    1,
								HasDefault: true,
								Sources:    []string{"defaults", "expression_param"},
							},
						},
						Monitoring: types.RuleRequirementMonitoring{Status: types.MonitoringStatusAutomated},
					},
					{
						RuleKey:            "R2",
						IsManual:           true,
						Datasets:           []types.DatasetRefSpec{},
						Engine:             nil,
						Expression:         "",
						ExpressionSHA256:   "",
						DatasetsReferenced: []string{},
						ParamsReferenced:   []string{},
						Inputs:             []types.RuleInputRequirement{},
						Monitoring:         types.RuleRequirementMonitoring{Status: types.MonitoringStatusManual},
					},
					{
						RuleKey:            "R3",
						IsManual:           false,
						Datasets:           []types.DatasetRefSpec{{Dataset: "okta:log-streams", Version: 2}},
						Engine:             &engineCEL,
						Expression:         r3Expr,
						ExpressionSHA256:   hashExpr(r3Expr),
						DatasetsReferenced: []string{"okta:log-streams"},
						ParamsReferenced:   []string{"enabled"},
						Inputs: []types.RuleInputRequirement{
							{
								Name:       "enabled",
								Type:       "boolean",
								Default:    false,
								HasDefault: true,
								Sources:    []string{"defaults", "schema", "expression_param"},
							},
							{
								Name:       "threshold",
								Type:       "integer",
								Default:    5,
								HasDefault: true,
								Sources:    []string{"defaults", "schema"},
							},
						},
						Monitoring: types.RuleRequirementMonitoring{Status: types.MonitoringStatusAutomated},
					},
				},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("buildRequirements mismatch (-want +got):\n%s", diff)
	}
}

func hashExpr(expr string) string {
	sum := sha256.Sum256([]byte(expr))
	return hex.EncodeToString(sum[:])
}
