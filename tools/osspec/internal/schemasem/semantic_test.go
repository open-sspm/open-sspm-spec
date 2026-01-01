package schemasem

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/testutil"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/types"
)

func TestValidateSemantic_DuplicateRulesetKey(t *testing.T) {
	b := &Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{
			{Path: "specs/rulesets/a.json", Doc: minimalRulesetDoc("dup", types.Scope{Kind: types.ScopeKindGlobal})},
			{Path: "specs/rulesets/b.json", Doc: minimalRulesetDoc("dup", types.Scope{Kind: types.ScopeKindGlobal})},
		},
	}
	errs := ValidateSemantic(b)
	if len(errs) == 0 {
		t.Fatalf("expected errors")
	}
	if !containsErr(errs, "duplicate ruleset.key") {
		t.Fatalf("expected duplicate ruleset.key error, got: %v", errs)
	}
}

func TestValidateSemantic_ScopeRules(t *testing.T) {
	b := &Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{
			{Path: "specs/rulesets/global-with-connector.json", Doc: minimalRulesetDoc("r1", types.Scope{Kind: types.ScopeKindGlobal, ConnectorKind: "okta"})},
			{Path: "specs/rulesets/connector-missing-kind.json", Doc: minimalRulesetDoc("r2", types.Scope{Kind: types.ScopeKindConnectorInstance})},
		},
	}
	errs := ValidateSemantic(b)
	if len(errs) == 0 {
		t.Fatalf("expected errors")
	}
	joined := joinErrs(errs)
	if !strings.Contains(joined, "forbids") || !strings.Contains(joined, "requires") {
		t.Fatalf("expected scope errors, got:\n%s", joined)
	}
}

func TestValidateSemantic_ValidExamples_PerCheckType(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "manual.attestation",
			doc: `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.manual.v1",
    "name": "Example manual",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "status": "active",
    "data_contracts": [],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "manual" },
        "required_data": [],
        "check": { "type": "manual.attestation" }
      }
    ]
  }
}`,
		},
		{
			name: "dataset.field_compare",
			doc: `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.field_compare.v1",
    "name": "Example field compare",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "data_contracts": [
      { "dataset": "okta:policies/sign-on", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "Idle timeout",
        "severity": "high",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:policies/sign-on"],
        "parameters": { "defaults": { "max_idle_minutes": 15 } },
        "check": {
          "type": "dataset.field_compare",
          "dataset": "okta:policies/sign-on",
          "dataset_version": 1,
          "where": [
            { "path": "/is_default", "op": "eq", "value": true }
          ],
          "assert": { "path": "/session/max_idle_minutes", "op": "lte", "value_param": "max_idle_minutes" }
        }
      }
    ]
  }
}`,
		},
		{
			name: "dataset.count_compare",
			doc: `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.count_compare.v1",
    "name": "Example count compare",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "At least N enabled",
        "severity": "medium",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "parameters": { "defaults": { "min_enabled": 1 } },
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "where": [
            { "path": "/enabled", "op": "eq", "value": true }
          ],
          "compare": { "op": "gte", "value_param": "min_enabled" }
        }
      }
    ]
  }
}`,
		},
		{
			name: "dataset.join_count_compare",
			doc: `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.join_count_compare.v1",
    "name": "Example join count compare",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "core:identities", "version": 1 },
      { "dataset": "core:entitlement_assignments", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "No admin entitlements",
        "severity": "high",
        "monitoring": { "status": "automated" },
        "required_data": ["core:identities", "core:entitlement_assignments"],
        "parameters": { "defaults": { "max_admin_entitlements": 0 } },
        "check": {
          "type": "dataset.join_count_compare",
          "dataset_version": 1,
          "left": { "dataset": "core:identities", "key_path": "/email" },
          "right": { "dataset": "core:entitlement_assignments", "key_path": "/identity/email" },
          "where": [
            { "right_path": "/entitlement/tags", "op": "contains", "value": "admin" }
          ],
          "compare": { "op": "lte", "value_param": "max_admin_entitlements" }
        }
      }
    ]
  }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateRulesetDocJSON(t, tc.doc)
			if len(errs) != 0 {
				t.Fatalf("expected no errors, got:\n%s", joinErrs(errs))
			}
		})
	}
}

func TestValidateSemantic_MonitoringAutomatedRequiresCheck(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.missing_check.v1",
    "name": "Example missing check",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": []
      }
    ]
  }
}`)
	if !containsErr(errs, "requires rule.check") {
		t.Fatalf("expected monitoring/check constraint error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_ManualAllowsMissingCheck(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.manual_missing_check.v1",
    "name": "Example manual missing check",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "manual" },
        "required_data": []
      }
    ]
  }
}`)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_ManualForbidsNonManualCheck(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.manual_bad_check.v1",
    "name": "Example manual bad check",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "manual" },
        "required_data": ["okta:log-streams"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "compare": { "op": "gt", "value": 0 }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "only allows check.type=manual.attestation") {
		t.Fatalf("expected manual constraint error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_RequiredDataCoverage(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.required_data.v1",
    "name": "Example required_data",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": [],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "compare": { "op": "gt", "value": 0 }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "required_data missing dataset") {
		t.Fatalf("expected required_data coverage error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_DatasetVersionRequiresContract(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.dataset_version_contract.v1",
    "name": "Example dataset_version contract",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 2,
          "compare": { "op": "gt", "value": 0 }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "requires ruleset.data_contracts entry") {
		t.Fatalf("expected data_contracts match error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_MultipleContractsRequireDatasetVersion(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.ambiguous_contracts.v1",
    "name": "Example ambiguous contracts",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 },
      { "dataset": "okta:log-streams", "version": 2 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "compare": { "op": "gt", "value": 0 }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "dataset_version is required") {
		t.Fatalf("expected ambiguity error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_ValueParamRequiresParametersDefaults(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.value_param_missing_defaults.v1",
    "name": "Example value_param missing defaults",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "compare": { "op": "gte", "value_param": "min_enabled" }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "parameters.defaults is missing") {
		t.Fatalf("expected missing parameters.defaults error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_JoinWhereExactlyOneSide(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.join_where_bad.v1",
    "name": "Example join where bad",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "core:identities", "version": 1 },
      { "dataset": "core:entitlement_assignments", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["core:identities", "core:entitlement_assignments"],
        "parameters": { "defaults": { "max": 0 } },
        "check": {
          "type": "dataset.join_count_compare",
          "dataset_version": 1,
          "left": { "dataset": "core:identities", "key_path": "/email" },
          "right": { "dataset": "core:entitlement_assignments", "key_path": "/identity/email" },
          "where": [
            { "left_path": "/email", "right_path": "/identity/email", "op": "eq", "value": "x" }
          ],
          "compare": { "op": "eq", "value_param": "max" }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "must set exactly one of left_path or right_path") {
		t.Fatalf("expected join predicate side error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_PredicateExistsForbidsValue(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.exists_has_value.v1",
    "name": "Example exists has value",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "where": [
            { "path": "/enabled", "op": "exists", "value": true }
          ],
          "compare": { "op": "gt", "value": 0 }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "forbids value and value_param") {
		t.Fatalf("expected exists/absent value error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_CompareValueAndValueParamExclusive(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.compare_both.v1",
    "name": "Example compare both",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "parameters": { "defaults": { "x": 1 } },
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "compare": { "op": "gt", "value": 0, "value_param": "x" }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "must set exactly one of value or value_param") {
		t.Fatalf("expected compare exclusivity error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_ParameterSchemaKeysMustExistInDefaults(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.param_schema_keys.v1",
    "name": "Example param schema keys",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "manual" },
        "required_data": [],
        "parameters": {
          "defaults": { "a": 1 },
          "schema": {
            "b": { "type": "integer", "minimum": 0 }
          }
        }
      }
    ]
  }
}`)
	if !containsErr(errs, "parameters.schema") || !containsErr(errs, "parameters.defaults") {
		t.Fatalf("expected parameters schema key error, got:\n%s", joinErrs(errs))
	}
}

func minimalRulesetDoc(key string, scope types.Scope) types.RulesetDoc {
	return types.RulesetDoc{
		SchemaVersion: 1,
		Kind:          "opensspm.ruleset",
		Ruleset: types.Ruleset{
			Key:   key,
			Name:  "n",
			Scope: scope,
			Rules: []types.Rule{
				{
					Key:          "R1",
					Title:        "R1",
					Severity:     types.SeverityInfo,
					Monitoring:   types.Monitoring{Status: types.MonitoringStatusManual},
					RequiredData: []string{},
					Check:        &types.Check{Type: types.CheckTypeManualAttestation},
				},
			},
		},
	}
}

func validateRulesetDocJSON(t *testing.T, doc string) []error {
	t.Helper()

	root := testutil.RepoRoot(t)
	reg, err := LoadRegistry(filepath.Join(root, "metaschema"))
	if err != nil {
		t.Fatalf("LoadRegistry error: %v", err)
	}

	b := []byte(doc)
	if err := reg.ValidateKindJSON("opensspm.ruleset", b); err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}

	var rs types.RulesetDoc
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatalf("unmarshal ruleset: %v", err)
	}
	normalize.RulesetDoc(&rs)

	bundle := &Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{{Path: "inline.json", Doc: rs}},
	}
	return ValidateSemantic(bundle)
}

func containsErr(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}

func joinErrs(errs []error) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return b.String()
}
