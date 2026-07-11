package schemasem

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-sspm/open-sspm-spec/tools/osspec/internal/testutil"
)

func TestRegistryAcceptsStructurallyValidDocuments(t *testing.T) {
	registry := loadTestRegistry(t)
	for kind, document := range map[string]map[string]any{
		"opensspm.ruleset":            validRulesetJSON(),
		"opensspm.entity_policy_pack": validEntityPolicyPackJSON(),
	} {
		if err := validateTestDocument(registry, kind, document); err != nil {
			t.Fatalf("ValidateKindJSON(%q) error = %v", kind, err)
		}
	}
}

func TestRegistryOwnsStructuralValidation(t *testing.T) {
	registry := loadTestRegistry(t)
	tests := []struct {
		name     string
		kind     string
		document func() map[string]any
		mutate   func(map[string]any)
	}{
		{
			name:     "ruleset check requires engine",
			kind:     "opensspm.ruleset",
			document: validRulesetJSON,
			mutate: func(doc map[string]any) {
				delete(rulesetCheckJSON(doc), "engine")
			},
		},
		{
			name:     "ruleset check engine is rego",
			kind:     "opensspm.ruleset",
			document: validRulesetJSON,
			mutate: func(doc map[string]any) {
				rulesetCheckJSON(doc)["engine"] = "legacy"
			},
		},
		{
			name:     "ruleset check requires query",
			kind:     "opensspm.ruleset",
			document: validRulesetJSON,
			mutate: func(doc map[string]any) {
				delete(rulesetCheckJSON(doc), "query")
			},
		},
		{
			name:     "ruleset monitoring status is known",
			kind:     "opensspm.ruleset",
			document: validRulesetJSON,
			mutate: func(doc map[string]any) {
				rulesetRuleJSON(doc)["monitoring"].(map[string]any)["status"] = "legacy"
			},
		},
		{
			name:     "ruleset scope kind is known",
			kind:     "opensspm.ruleset",
			document: validRulesetJSON,
			mutate: func(doc map[string]any) {
				doc["ruleset"].(map[string]any)["scope"].(map[string]any)["kind"] = "tenant"
			},
		},
		{
			name:     "entity policy metadata requires id",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["metadata"].(map[string]any), "id")
			},
		},
		{
			name:     "entity policy domain is known",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				entityPolicyPackJSON(doc)["metadata"].(map[string]any)["domain"] = "device"
			},
		},
		{
			name:     "entity policy metadata requires version",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["metadata"].(map[string]any), "version")
			},
		},
		{
			name:     "entity policy inputs require schema",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["inputs"].(map[string]any), "schema")
			},
		},
		{
			name:     "entity policy engine is rego",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				entityPolicyPackJSON(doc)["policy"].(map[string]any)["engine"] = "legacy"
			},
		},
		{
			name:     "entity policy requires package",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["policy"].(map[string]any), "package")
			},
		},
		{
			name:     "entity policy requires query",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["policy"].(map[string]any), "query")
			},
		},
		{
			name:     "entity policy requires Rego source",
			kind:     "opensspm.entity_policy_pack",
			document: validEntityPolicyPackJSON,
			mutate: func(doc map[string]any) {
				delete(entityPolicyPackJSON(doc)["policy"].(map[string]any), "rego")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := tt.document()
			tt.mutate(document)
			err := validateTestDocument(registry, tt.kind, document)
			if err == nil || !strings.Contains(err.Error(), "schema validation failed") {
				t.Fatalf("ValidateKindJSON() error = %v, want schema validation error", err)
			}
		})
	}
}

func loadTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := LoadRegistry(filepath.Join(testutil.RepoRoot(t), "metaschema"))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	return registry
}

func validateTestDocument(registry *Registry, kind string, document map[string]any) error {
	b, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return registry.ValidateKindJSON(kind, b)
}

func validRulesetJSON() map[string]any {
	return map[string]any{
		"schema_version": 2,
		"kind":           "opensspm.ruleset",
		"ruleset": map[string]any{
			"key":   "example.v2",
			"name":  "Example",
			"scope": map[string]any{"kind": "global"},
			"rules": []any{
				map[string]any{
					"key":           "R1",
					"title":         "Rule 1",
					"severity":      "low",
					"monitoring":    map[string]any{"status": "automated"},
					"required_data": []any{},
					"check": map[string]any{
						"engine":  "rego",
						"package": "opensspm.test",
						"query":   "data.opensspm.test.result",
						"rego":    "package opensspm.test\nresult := {\"status\": \"pass\"}",
					},
				},
			},
		},
	}
}

func rulesetRuleJSON(document map[string]any) map[string]any {
	ruleset := document["ruleset"].(map[string]any)
	return ruleset["rules"].([]any)[0].(map[string]any)
}

func rulesetCheckJSON(document map[string]any) map[string]any {
	return rulesetRuleJSON(document)["check"].(map[string]any)
}

func validEntityPolicyPackJSON() map[string]any {
	return map[string]any{
		"schema_version": 2,
		"kind":           "opensspm.entity_policy_pack",
		"entity_policy_pack": map[string]any{
			"metadata": map[string]any{
				"id":      "builtin.test",
				"version": "1.0.0",
				"domain":  "saas",
			},
			"inputs": map[string]any{"schema": "test_input.v1"},
			"policy": map[string]any{
				"engine":  "rego",
				"package": "opensspm.entity.test",
				"query":   "data.opensspm.entity.test.result",
				"rego":    "package opensspm.entity.test\nresult := {\"risk_level\": \"low\"}",
			},
		},
	}
}

func entityPolicyPackJSON(document map[string]any) map[string]any {
	return document["entity_policy_pack"].(map[string]any)
}
