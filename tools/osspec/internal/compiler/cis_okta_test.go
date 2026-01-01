package compiler

import (
	"context"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/testutil"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestCompile_CISOktaRulesetIndexed(t *testing.T) {
	root := testutil.RepoRoot(t)
	res, err := Compile(context.Background(), Options{RepoRoot: root})
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	var rr *types.RulesetRequirement
	for i := range res.Requirements.Rulesets {
		if res.Requirements.Rulesets[i].RulesetKey == "cis.okta.idaas_stig.v1" {
			rr = &res.Requirements.Rulesets[i]
			break
		}
	}
	if rr == nil {
		t.Fatalf("missing ruleset cis.okta.idaas_stig.v1 in requirements index")
	}

	if rr.Status != "active" {
		t.Fatalf("expected status=active, got %q", rr.Status)
	}
	if rr.Scope.Kind != types.ScopeKindConnectorInstance || rr.Scope.ConnectorKind != "okta" {
		t.Fatalf("unexpected scope: %+v", rr.Scope)
	}
	if len(rr.Datasets) != 4 {
		t.Fatalf("expected 4 datasets, got %+v", rr.Datasets)
	}
	if len(rr.ValueParams) != 0 {
		t.Fatalf("expected no value params, got %+v", rr.ValueParams)
	}

	foundManual := false
	for _, ct := range rr.CheckTypes {
		if ct == types.CheckTypeManualAttestation {
			foundManual = true
			break
		}
	}
	if !foundManual {
		t.Fatalf("expected manual.attestation in check_types, got %+v", rr.CheckTypes)
	}

	if len(rr.Rules) != 24 {
		t.Fatalf("expected 24 rules, got %d", len(rr.Rules))
	}
	expected := map[string]struct {
		manual   bool
		status   types.MonitoringStatus
		check    types.CheckType
		datasets int
	}{
		"OKTA-APP-000020": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000025": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000090": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000170": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000180": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000190": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000200": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000560": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000570": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-000650": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000670": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000680": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000690": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000700": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000740": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-000745": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-001430": {manual: false, status: types.MonitoringStatusPartial, check: types.CheckTypeDatasetCountCompare, datasets: 1},
		"OKTA-APP-001665": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-001670": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-001700": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-001710": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-001920": {manual: true, status: types.MonitoringStatusManual, check: types.CheckTypeManualAttestation, datasets: 0},
		"OKTA-APP-002980": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
		"OKTA-APP-003010": {manual: false, status: types.MonitoringStatusAutomated, check: types.CheckTypeDatasetFieldCompare, datasets: 1},
	}

	for _, r := range rr.Rules {
		exp, ok := expected[r.RuleKey]
		if !ok {
			t.Fatalf("unexpected rule %q in requirements index", r.RuleKey)
		}
		if r.IsManual != exp.manual {
			t.Fatalf("expected rule %q is_manual=%v, got %v", r.RuleKey, exp.manual, r.IsManual)
		}
		if r.CheckType == nil || *r.CheckType != exp.check {
			t.Fatalf("expected rule %q check_type=%q, got %#v", r.RuleKey, exp.check, r.CheckType)
		}
		if r.Monitoring.Status != exp.status {
			t.Fatalf("expected rule %q monitoring.status=%q, got %q", r.RuleKey, exp.status, r.Monitoring.Status)
		}
		if len(r.Datasets) != exp.datasets {
			t.Fatalf("expected rule %q to have %d datasets, got %+v", r.RuleKey, exp.datasets, r.Datasets)
		}
		if len(r.ValueParams) != 0 {
			t.Fatalf("expected rule %q to have no value params, got %+v", r.RuleKey, r.ValueParams)
		}
	}
}
