package schemasem

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/normalize"
	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/rulecompile"
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

func TestValidateSemantic_ValidCELRule(t *testing.T) {
	errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.cel.v2",
    "name": "Example CEL",
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
        "required_data": ["okta:log-streams"],
        "parameters": {
          "defaults": { "min_count": 1 },
          "schema": {
            "min_count": { "type": "integer" }
          }
        },
        "check": {
          "engine": "cel",
          "expression": "rows(\"okta:log-streams\").size() >= int(param(\"min_count\"))"
        }
      }
    ]
  }
}`)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_MonitoringConstraints(t *testing.T) {
	t.Run("automated requires check", func(t *testing.T) {
		errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.missing_check.v2",
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
			t.Fatalf("expected monitoring/check error, got:\n%s", joinErrs(errs))
		}
	})

	t.Run("manual allows omitted check", func(t *testing.T) {
		errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.manual.v2",
    "name": "Example manual",
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
	})

	t.Run("manual rejects check", func(t *testing.T) {
		errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.manual_with_check.v2",
    "name": "Example manual with check",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "manual" },
        "required_data": [],
        "check": { "engine": "cel", "expression": "true" }
      }
    ]
  }
}`)
		if !containsErr(errs, "requires rule.check to be omitted") {
			t.Fatalf("expected manual rule check omission error, got:\n%s", joinErrs(errs))
		}
	})
}

func TestValidateSemantic_CheckEngineAndExpressionValidation(t *testing.T) {
	errNonBool := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.non_bool.v2",
    "name": "Example",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": [],
        "check": { "engine": "cel", "expression": "1 + 1" }
      }
    ]
  }
}`)
	if !containsErr(errNonBool, "invalid CEL expression") {
		t.Fatalf("expected CEL bool output validation error, got:\n%s", joinErrs(errNonBool))
	}
}

func TestRulesetSchemaAcceptsStructuredCheckDSL(t *testing.T) {
	root := testutil.RepoRoot(t)
	reg, err := LoadRegistry(filepath.Join(root, "metaschema"))
	if err != nil {
		t.Fatalf("LoadRegistry error: %v", err)
	}

	structured := []byte(`{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.structured_check_shape.v2",
    "name": "Example",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:a", "version": 1 }
    ],
    "defaults": {
      "check": {
        "on_missing_dataset": "unknown",
        "on_permission_denied": "unknown",
        "on_sync_error": "error"
      }
    },
    "selectors": {
      "active_a": {
        "dataset": "okta:a",
        "where": [
          { "op": "eq", "path": "status", "value": "ACTIVE" }
        ]
      }
    },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:a"],
        "check": {
          "type": "dataset.field_compare",
          "selector": "active_a",
          "assert": { "op": "gte", "path": "count", "value": 1 },
          "expect": { "match": "all", "min_selected": 1, "on_empty": "fail" }
        }
      }
    ]
  }
}`)

	err = reg.ValidateKindJSON("opensspm.ruleset", structured)
	if err != nil {
		t.Fatalf("expected schema validation to accept structured check DSL fields, got: %v", err)
	}

	var source rulecompile.SourceRulesetDoc
	if err := json.Unmarshal(structured, &source); err != nil {
		t.Fatalf("unmarshal source ruleset: %v", err)
	}
	compiled, err := rulecompile.CompileRuleset(source)
	if err != nil {
		t.Fatalf("CompileRuleset() error: %v", err)
	}
	normalize.RulesetDoc(&compiled)

	bundle := &Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{{Path: "inline.json", Doc: compiled}},
	}
	if errs := ValidateSemantic(bundle); len(errs) != 0 {
		t.Fatalf("expected semantic validation to pass after structured compile, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_CELReferences(t *testing.T) {
	t.Run("required_data and data_contracts for dataset refs", func(t *testing.T) {
		errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.dataset_refs.v2",
    "name": "Example",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:a", "version": 1 },
      { "dataset": "okta:a", "version": 2 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": [],
        "check": {
          "engine": "cel",
          "expression": "rows(\"okta:a\").size() > 0"
        }
      }
    ]
  }
}`)
		if !containsErr(errs, "required_data missing dataset") {
			t.Fatalf("expected required_data error, got:\n%s", joinErrs(errs))
		}
		if !containsErr(errs, "exactly one version") {
			t.Fatalf("expected multi-version error, got:\n%s", joinErrs(errs))
		}
	})

	t.Run("param references must exist in defaults", func(t *testing.T) {
		errs := validateRulesetDocJSON(t, `{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.param_refs.v2",
    "name": "Example",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "okta:a", "version": 1 }
    ],
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:a"],
        "check": {
          "engine": "cel",
          "expression": "rows(\"okta:a\").size() > int(param(\"missing\"))"
        }
      }
    ]
  }
}`)
		if !containsErr(errs, "parameters.defaults is missing") && !containsErr(errs, "not found in parameters.defaults") {
			t.Fatalf("expected param defaults error, got:\n%s", joinErrs(errs))
		}
	})
}

func TestValidateSemantic_CELPlanCheck(t *testing.T) {
	doc := minimalRulesetDoc("example.plan.v2", types.Scope{Kind: types.ScopeKindGlobal})
	doc.Ruleset.DataContracts = []types.DatasetContractRef{{Dataset: "okta:a", Version: 1}}
	doc.Ruleset.Rules[0] = types.Rule{
		Key:          "R1",
		Title:        "R1",
		Severity:     types.SeverityLow,
		Monitoring:   types.Monitoring{Status: types.MonitoringStatusAutomated},
		RequiredData: []string{"okta:a"},
		Check: &types.Check{
			Engine: types.CheckEngineCELPlan,
			Plan: &types.CheckPlan{
				Type:             "dataset.field_compare",
				Dataset:          "okta:a",
				WhereExpression:  `r["status"] == "ACTIVE"`,
				AssertExpression: `r["count"] >= int(param("min"))`,
				Expect: &types.CheckPlanExpect{
					Match:       "all",
					MinSelected: 0,
					OnEmpty:     "unknown",
				},
				OnMissingDataset: "unknown",
			},
		},
		Parameters: &types.Parameters{
			Defaults: map[string]any{"min": 1},
		},
	}
	normalize.RulesetDoc(&doc)

	bundle := &Bundle{
		Rulesets: []struct {
			Path string
			Doc  types.RulesetDoc
		}{{Path: "inline", Doc: doc}},
	}
	errs := ValidateSemantic(bundle)
	if len(errs) != 0 {
		t.Fatalf("expected no semantic errors for cel_plan rule, got:\n%s", joinErrs(errs))
	}

	doc.Ruleset.Rules[0].Check.Expression = "true"
	errs = ValidateSemantic(bundle)
	if !containsErr(errs, "must be empty for check.engine=cel_plan") {
		t.Fatalf("expected cel_plan expression validation error, got:\n%s", joinErrs(errs))
	}
}

func TestValidateSemantic_EntityPolicyExpressionIDs(t *testing.T) {
	for _, id := range []string{"bad/rule", "level:high"} {
		t.Run("reserved separator "+id, func(t *testing.T) {
			doc := minimalEntityPolicyPackDoc()
			doc.EntityPolicyPack.Spec.Rules[0].ID = id

			errs := validateEntityPolicyPackDocInTest(doc)
			if !containsErr(errs, "reserved expression separators") {
				t.Fatalf("expected reserved separator error, got:\n%s", joinErrs(errs))
			}
		})
	}

	t.Run("duplicate generated level ref", func(t *testing.T) {
		doc := minimalEntityPolicyPackDoc()
		doc.EntityPolicyPack.Spec.Rules = nil
		doc.EntityPolicyPack.Spec.Levels = []types.EntityPolicyLevelRule{
			{Level: "high", When: "false"},
			{Level: "high", When: "true"},
		}

		errs := validateEntityPolicyPackDocInTest(doc)
		if !containsErr(errs, `duplicates generated expression ref "level:high"`) {
			t.Fatalf("expected duplicate generated expression ref error, got:\n%s", joinErrs(errs))
		}
	})
}

func minimalRulesetDoc(key string, scope types.Scope) types.RulesetDoc {
	return types.RulesetDoc{
		SchemaVersion: 2,
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
				},
			},
		},
	}
}

func minimalEntityPolicyPackDoc() types.EntityPolicyPackDoc {
	return types.EntityPolicyPackDoc{
		SchemaVersion: 2,
		Kind:          "opensspm.entity_policy_pack",
		EntityPolicyPack: types.EntityPolicyPack{
			Metadata: types.EntityPolicyMetadata{
				ID:      "builtin.test.risk",
				Version: "1.0.0",
				Domain:  types.EntityPolicyDomainCredential,
			},
			Spec: types.EntityPolicySpec{
				Inputs: types.EntityPolicyInputs{Schema: "credential_risk_input.v1"},
				Rules: []types.EntityPolicyRule{
					{
						ID:       "always",
						Severity: "low",
						When:     "true",
						Title:    "Always",
					},
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

func validateEntityPolicyPackDocInTest(doc types.EntityPolicyPackDoc) []error {
	normalize.EntityPolicyPackDoc(&doc)
	bundle := &Bundle{
		EntityPolicyPacks: []struct {
			Path string
			Doc  types.EntityPolicyPackDoc
		}{{Path: "inline.yaml", Doc: doc}},
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
