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

func TestRulesetSchemaRejectsLegacyCheckDSL(t *testing.T) {
	root := testutil.RepoRoot(t)
	reg, err := LoadRegistry(filepath.Join(root, "metaschema"))
	if err != nil {
		t.Fatalf("LoadRegistry error: %v", err)
	}

	legacy := []byte(`{
  "schema_version": 2,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.legacy_check_shape.v2",
    "name": "Example",
    "scope": { "kind": "global" },
    "rules": [
      {
        "key": "R1",
        "title": "R1",
        "severity": "low",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:a"],
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:a",
          "compare": { "op": "gte", "value": 1 }
        }
      }
    ]
  }
}`)

	err = reg.ValidateKindJSON("opensspm.ruleset", legacy)
	if err == nil {
		t.Fatalf("expected schema validation to reject legacy check DSL fields")
	}
	if !strings.Contains(err.Error(), "engine") || !strings.Contains(err.Error(), "expression") {
		t.Fatalf("expected CEL check field validation details, got: %v", err)
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
