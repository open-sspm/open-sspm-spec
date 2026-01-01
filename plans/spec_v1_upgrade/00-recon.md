# Spec v1 refined upgrade - Recon

Source of truth: `newspec.md`.

## Relevant packages and files

### Ruleset parsing, validation, compilation

- `metaschema/opensspm.ruleset.schema.json` - JSON Schema for `kind: opensspm.ruleset` (refined v1 model and canonical check DSL).
- `tools/osspec/internal/compiler/compiler.go` - main compile pipeline (load, schema validate, JSON unmarshal, normalize, semantic validation, hash, descriptor output).
- `tools/osspec/internal/compiler/indexes.go` - requirements index generation (`dist/index/requirements.json`).
- `tools/osspec/internal/normalize/normalize.go` - normalization (sorting + a few defaults) prior to hashing/output.
- `tools/osspec/internal/hash/hash.go` - JCS (RFC 8785) canonicalization + SHA-256 hex hashing.
- `tools/osspec/internal/schemasem/schema.go` - loads metaschema and runs JSON Schema validation.
- `tools/osspec/internal/schemasem/semantic.go` - semantic validation (duplicate keys, scope rules, monitoring/check constraints, canonical check validation).

### Generated consumer types (ABI surface)

- `tools/osspec/cmd/osspec-gen-go/main.go` - Go codegen plugin; embeds the spec model structs and enums.
- `gen/go/opensspm/spec/v1/types.gen.go` - generated Go types for the compiled descriptor model (mirrors `tools/osspec/internal/types/*`).
- `gen/go/opensspm/runtime/v1/runtime.gen.go` - generated Go types for the runtime dataset provider ABI (no check evaluation logic here).

### Example rulesets

- `specs/rulesets/cis/okta/cis.okta.idaas_stig.v1.json` - repository example ruleset (24 manual attestation rules).

## Current data model summary

### Ruleset shape

`opensspm.ruleset` uses:

- `ruleset.data_contracts[]` for dataset version declarations referenced by checks.
- `ruleset.source` is optional.
- Rule-level `required_data[]` is required (dataset keys, may be empty).

### Check shape (canonical)

`rule.check` is modeled as a type-discriminated canonical check DSL:

- `manual.attestation`
- `dataset.field_compare` with `where[]`, `assert`, and `expect`
- `dataset.count_compare` with `where[]` and `compare`
- `dataset.join_count_compare` with `left/right`, join `where[]`, `compare`, and `on_unmatched_left`

This model is encoded in:

- `tools/osspec/internal/types/spec.go` (`type Check struct { ... }`)
- `metaschema/opensspm.ruleset.schema.json` (`definitions.check`)
- `tools/osspec/internal/schemasem/semantic.go` (`validateCheck` and related helpers)
- `tools/osspec/internal/compiler/indexes.go` (requirements index computation)
- `tools/osspec/cmd/osspec-gen-go/main.go` and `gen/go/opensspm/spec/v1/types.gen.go`

## Gap list vs `newspec.md`

### Model and schema gaps

- Add `ruleset.data_contracts[]` and remove dependence on `ruleset.required_data[]`.
- Add new optional ruleset metadata: `description`, `references` (with `type`), `framework_mappings`, `requirements`, `tags`, `status` defaulting to `active`, and optional `source`.
- Update rule model to require `title`, `required_data[]` (string dataset keys), and `monitoring.reason`.
- Add `rule.parameters.defaults` as `{param_name: any}` and optional `rule.parameters.schema`.
- Add rule metadata: `evidence`, `remediation`, `lifecycle`.

### Canonical check DSL gaps

- Implement canonical check objects:
  - `manual.attestation`
  - `dataset.field_compare` with `where[]`, `assert`, `expect`
  - `dataset.count_compare` with `where[]`, `compare`
  - `dataset.join_count_compare` with `left/right`, `where[]` (left_path/right_path), `compare`, `on_unmatched_left`
- Add common check fields: `dataset_version`, `on_missing_dataset`, `on_permission_denied`, `on_sync_error`, `notes`.
- Add predicate/compare structures and validation rules (value vs value_param, join predicate side rules).

### Semantic validation gaps

Implement all semantic rules from `newspec.md` section 6, including:

- rule key uniqueness within a ruleset
- scope connector_kind constraints
- monitoring vs check presence constraints
- check.type whitelist
- check dataset coverage by `rule.required_data`
- dataset version declaration and ambiguity checks vs `ruleset.data_contracts`
- parameter reference validation for every `value_param` occurrence
- join where clause must set exactly one of `left_path`/`right_path`
- effective dataset version resolution (newspec section 4.1) for index computation

### Determinism gaps

- Extend normalization to sort all set-like arrays per `newspec.md` section 7, including:
  - ruleset and rule tags, references, framework_mappings, requirements arrays
  - ruleset.data_contracts
  - ruleset.rules by rule.key
  - rule.required_data
  - check.where sorting for non-join and join predicates (including canonical(value) for tie-breaking)
- Ensure hashing is computed over normalized objects only (then JCS, then SHA-256).

### Requirements index gaps

- Update `dist/index/requirements.json` model and computation to match `newspec.md` section 8:
  - per ruleset: include `status`, scope fields, datasets with effective versions, check_types, value_params
  - per rule: include monitoring.status, is_manual, datasets with effective versions, check_type nullable, value_params

### Engine compatibility

- This repository currently contains the runtime dataset-provider ABI types, but no check evaluation engine implementation.
- Compatibility work here is limited to producing canonical check shapes and deterministic artifacts for engines to consume.
