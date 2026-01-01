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
	if len(rr.Datasets) != 0 {
		t.Fatalf("expected no datasets, got %+v", rr.Datasets)
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
	for _, r := range rr.Rules {
		if !r.IsManual {
			t.Fatalf("expected rule %q to be manual", r.RuleKey)
		}
		if r.CheckType == nil || *r.CheckType != types.CheckTypeManualAttestation {
			t.Fatalf("expected rule %q check_type=manual.attestation, got %#v", r.RuleKey, r.CheckType)
		}
		if r.Monitoring.Status != types.MonitoringStatusManual {
			t.Fatalf("expected rule %q monitoring.status=manual, got %q", r.RuleKey, r.Monitoring.Status)
		}
		if len(r.Datasets) != 0 {
			t.Fatalf("expected rule %q to have no datasets, got %+v", r.RuleKey, r.Datasets)
		}
		if len(r.ValueParams) != 0 {
			t.Fatalf("expected rule %q to have no value params, got %+v", r.RuleKey, r.ValueParams)
		}
	}
}

