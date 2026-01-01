# Spec v1 refined upgrade - Validation

Validation is split into JSON Schema validation (structure) and semantic validation (cross-field rules).

## Schema validation

- Source: `metaschema/opensspm.ruleset.schema.json`
- Execution: `tools/osspec/internal/schemasem/schema.go` (`Registry.ValidateKindJSON`)
- Notes:
  - `rule.check` is structurally optional in schema; semantic validation enforces monitoring constraints.

## Semantic validation (enforced rules)

Source: `tools/osspec/internal/schemasem/semantic.go`

- Identity and uniqueness
  - `ruleset.key` unique across bundle
  - `rule.key` unique within ruleset
- Scope constraints
  - `scope.kind=global` forbids non-empty `scope.connector_kind`
  - `scope.kind=connector_instance` requires non-empty `scope.connector_kind`
- Monitoring/check constraints (newspec 6.3)
  - `automated|partial` requires `rule.check`
  - `manual|unsupported` allows `rule.check` omission or `check.type=manual.attestation` only
- Supported check types only (newspec 6.4)
  - whitelist enforced for `rule.check.type`
- Required data coverage (newspec 6.5)
  - datasets referenced by a check must be included in `rule.required_data`
- Dataset version declarations (newspec 6.6)
  - if `check.dataset_version` is set, `(dataset, version)` must exist in `ruleset.data_contracts` for every dataset referenced by the check
  - if multiple `ruleset.data_contracts` entries exist for a dataset, `check.dataset_version` is required when referencing it
- Parameter references (newspec 6.7)
  - every `value_param` used in predicates or compare clauses must exist in `rule.parameters.defaults`
  - if any `value_param` is used, `rule.parameters.defaults` must exist
  - parameter schema keys must exist in defaults (newspec 3.3)
- Predicate and compare structural constraints (newspec 6.8)
  - `exists|absent` forbids `value` and `value_param`
  - otherwise, `value` and `value_param` are mutually exclusive
  - join where clauses must set exactly one of `left_path` or `right_path`
  - compare clauses must set exactly one of `value` or `value_param`

## Test coverage

- `tools/osspec/internal/schemasem/semantic_test.go`
  - Valid examples for each check type: `manual.attestation`, `dataset.field_compare`, `dataset.count_compare`, `dataset.join_count_compare`
  - Invalid cases for each semantic rule listed above (monitoring constraints, required_data coverage, dataset version/contract rules, value_param validation, join where side rules, predicate and compare structural rules, parameter schema keys)
