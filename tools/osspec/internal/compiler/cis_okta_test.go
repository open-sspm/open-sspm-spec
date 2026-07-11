package compiler

import (
	"context"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/testutil"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestCompile_CISOktaRuleset(t *testing.T) {
	root := testutil.RepoRoot(t)
	desc, err := Compile(context.Background(), root)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	var ruleset *types.Ruleset
	for i := range desc.Rulesets {
		candidate := &desc.Rulesets[i].Object.Ruleset
		if candidate.Key == "cis.okta.idaas_stig.v2" {
			ruleset = candidate
			break
		}
	}
	if ruleset == nil {
		t.Fatalf("missing ruleset cis.okta.idaas_stig.v2 in descriptor")
	}

	if ruleset.Status != "active" {
		t.Fatalf("expected status=active, got %q", ruleset.Status)
	}
	if ruleset.Scope.Kind != types.ScopeKindConnectorInstance || ruleset.Scope.ConnectorKind != "okta" {
		t.Fatalf("unexpected scope: %+v", ruleset.Scope)
	}
	if len(ruleset.DataContracts) != 6 {
		t.Fatalf("expected 6 data contracts, got %+v", ruleset.DataContracts)
	}
	if ruleset.Policy == nil || ruleset.Policy.Rego == "" {
		t.Fatalf("expected shared ruleset Rego policy")
	}

	if len(ruleset.Rules) != 24 {
		t.Fatalf("expected 24 rules, got %d", len(ruleset.Rules))
	}
	expected := map[string]struct {
		status   types.MonitoringStatus
		datasets int
	}{
		"OKTA-APP-000020": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000025": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000090": {status: types.MonitoringStatusManual, datasets: 0},
		"OKTA-APP-000170": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000180": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000190": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000200": {status: types.MonitoringStatusManual, datasets: 0},
		"OKTA-APP-000560": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000570": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000650": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000670": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000680": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000690": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000700": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000740": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-000745": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001430": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001665": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001670": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001700": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001710": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-001920": {status: types.MonitoringStatusManual, datasets: 0},
		"OKTA-APP-002980": {status: types.MonitoringStatusAutomated, datasets: 1},
		"OKTA-APP-003010": {status: types.MonitoringStatusAutomated, datasets: 1},
	}

	for _, rule := range ruleset.Rules {
		exp, ok := expected[rule.Key]
		if !ok {
			t.Fatalf("unexpected rule %q in descriptor", rule.Key)
		}
		if exp.status == types.MonitoringStatusManual {
			if rule.Check != nil {
				t.Fatalf("expected manual rule %q to omit check", rule.Key)
			}
		} else if rule.Check == nil || rule.Check.Engine != types.CheckEngineRego {
			t.Fatalf("expected automated rule %q to use Rego, got %+v", rule.Key, rule.Check)
		} else if rule.Check.Rego != "" {
			t.Fatalf("expected automated rule %q to inherit shared Rego without copying it", rule.Key)
		}
		if rule.Monitoring.Status != exp.status {
			t.Fatalf("expected rule %q monitoring.status=%q, got %q", rule.Key, exp.status, rule.Monitoring.Status)
		}
		if len(rule.RequiredData) != exp.datasets {
			t.Fatalf("expected rule %q to have %d datasets, got %+v", rule.Key, exp.datasets, rule.RequiredData)
		}
	}
}
