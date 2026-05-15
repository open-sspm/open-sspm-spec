package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/schemasem"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestBuildRequirements_CapturesRegoRulesetAndRuleDetails(t *testing.T) {
	regoModule := `package opensspm.example

results["R1"] := {"status": "pass"} if { true }
results["R3"] := {"status": "pass"} if { true }
`
	engineRego := types.CheckEngineRego

	b := &schemasem.Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{
			{
				Path: "specs/rulesets/example.yaml",
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
									Engine:  types.CheckEngineRego,
									Package: "opensspm.example",
									Query:   `data.opensspm.example.results["R1"]`,
									Rego:    regoModule,
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
									Engine:  types.CheckEngineRego,
									Package: "opensspm.example",
									Query:   `data.opensspm.example.results["R3"]`,
									Rego:    regoModule,
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
				Engines:            []types.CheckEngine{types.CheckEngineRego},
				DatasetsReferenced: []string{"okta:log-streams"},
				ParamsReferenced:   []string{},
				Inputs: []types.RulesetInputRequirement{
					{
						Name:     "enabled",
						Type:     "boolean",
						Sources:  []string{"defaults", "schema"},
						RuleKeys: []string{"R1", "R3"},
					},
					{
						Name:     "min",
						Sources:  []string{"defaults"},
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
						Engine:             &engineRego,
						RegoPackage:        "opensspm.example",
						RegoQuery:          `data.opensspm.example.results["R1"]`,
						RegoSHA256:         hashRego(regoModule),
						DatasetsReferenced: []string{"okta:log-streams"},
						ParamsReferenced:   []string{},
						Inputs: []types.RuleInputRequirement{
							{Name: "enabled", Default: true, HasDefault: true, Sources: []string{"defaults"}},
							{Name: "min", Default: 1, HasDefault: true, Sources: []string{"defaults"}},
						},
						Monitoring: types.RuleRequirementMonitoring{Status: types.MonitoringStatusAutomated},
					},
					{
						RuleKey:            "R2",
						IsManual:           true,
						Datasets:           []types.DatasetRefSpec{},
						Engine:             nil,
						DatasetsReferenced: []string{},
						ParamsReferenced:   []string{},
						Inputs:             []types.RuleInputRequirement{},
						Monitoring:         types.RuleRequirementMonitoring{Status: types.MonitoringStatusManual},
					},
					{
						RuleKey:            "R3",
						IsManual:           false,
						Datasets:           []types.DatasetRefSpec{},
						Engine:             &engineRego,
						RegoPackage:        "opensspm.example",
						RegoQuery:          `data.opensspm.example.results["R3"]`,
						RegoSHA256:         hashRego(regoModule),
						DatasetsReferenced: []string{},
						ParamsReferenced:   []string{},
						Inputs: []types.RuleInputRequirement{
							{Name: "enabled", Type: "boolean", Default: false, HasDefault: true, Sources: []string{"defaults", "schema"}},
							{Name: "threshold", Type: "integer", Default: 5, HasDefault: true, Sources: []string{"defaults", "schema"}},
						},
						Monitoring: types.RuleRequirementMonitoring{Status: types.MonitoringStatusAutomated},
					},
				},
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("buildRequirements() mismatch (-want +got):\n%s", diff)
	}
}

func hashRego(module string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(module)))
	return hex.EncodeToString(sum[:])
}
