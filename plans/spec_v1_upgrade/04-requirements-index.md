# Spec v1 refined upgrade - Requirements index

The compiler emits `dist/index/requirements.json` as an orchestration/preflight index, per `newspec.md` section 8.

## Implementation

Source: `tools/osspec/internal/compiler/indexes.go`

### Per ruleset fields

- `ruleset_key`
- `status`
- `scope` (includes `kind` and `connector_kind` when applicable)
- `datasets[]`: distinct set of `{dataset, version}` referenced by any rule check (not `required_data` alone)
- `check_types[]`: distinct set of `rule.check.type` for rules where `check` exists
- `value_params[]`: distinct set of all `value_param` identifiers referenced in any rule check
- `rules[]`: per-rule breakdown

### Per rule fields

- `rule_key`
- `monitoring.status`
- `is_manual`: true iff monitoring.status is `manual` OR check.type is `manual.attestation` OR check is absent
- `datasets[]`: `{dataset, version}` referenced by the check, using effective dataset version resolution
- `check_type`: string or null
- `value_params[]`: value params referenced by that rule’s check

### Effective dataset version resolution

For each dataset reference in a check:

1. If `check.dataset_version` is set, use it.
2. Else if `ruleset.data_contracts` has exactly one matching entry for that dataset, use its `version`.
3. Else default to `1`.

Source: `tools/osspec/internal/types/dataset_version.go`

## Examples

### Manual-only ruleset (CIS Okta sample)

- ruleset datasets: `[]`
- ruleset check_types: `["manual.attestation"]`
- every rule:
  - `is_manual = true`
  - `check_type = "manual.attestation"`
  - `datasets = []`

## Tests

- `tools/osspec/internal/compiler/requirements_test.go` asserts ruleset and rule index fields, including effective dataset version resolution and value_param collection.
- `tools/osspec/internal/compiler/cis_okta_test.go` asserts the CIS Okta sample compiles and is indexed with 24 manual rules.

