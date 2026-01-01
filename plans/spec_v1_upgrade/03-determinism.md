# Spec v1 refined upgrade - Determinism (normalization + hashing)

This repo ensures deterministic compilation and hashing via:

1. Normalize in-memory objects
2. JCS canonicalize JSON (RFC 8785)
3. SHA-256 and lowercase hex

## Normalization rules (implemented)

Source: `tools/osspec/internal/normalize/normalize.go`

### Arrays treated as sets

Sorted deterministically (ascending lexicographic unless noted):

- `ruleset.tags`
- `ruleset.references` by `(url, title, type)`
- `ruleset.framework_mappings` by `(framework, control, enhancement, coverage, notes)`
- `ruleset.requirements.api_scopes`
- `ruleset.requirements.permissions`
- `ruleset.data_contracts` by `(dataset, version, description)`
- `ruleset.rules` by `rule.key`
- Per rule:
  - `rule.tags`
  - `rule.references` by `(url, title, type)`
  - `rule.framework_mappings` by `(framework, control, enhancement, coverage, notes)`
  - `rule.required_data`

### Predicate sorting

`check.where[]` is sorted deterministically:

- non-join checks: `(path, op, value_param, canonical(value))`
- join checks: `(left_path, right_path, op, value_param, canonical(value))`

`canonical(value)` uses JCS canonicalization of the JSON encoding of the value.

### Defaulting for canonical output

Defaults defined by `newspec.md` are applied during normalization to ensure stable hashing when authors omit defaults:

- `ruleset.status` defaults to `active`
- `reference.type` defaults to `other`
- `framework_mappings.coverage` defaults to `supporting`
- check error policy fields default to `unknown|unknown|error`
- `dataset.field_compare.expect` defaults to `match=all`, `min_selected=0`, `on_empty=unknown`
- `dataset.join_count_compare.on_unmatched_left` defaults to `ignore`

## Hashing rules

Source: `tools/osspec/internal/hash/hash.go`

- Hash input is the normalized Go object marshaled to JSON.
- Canonicalization uses the JCS reference implementation.
- Hash output is SHA-256 in lowercase hex.

## Tests

- `tools/osspec/internal/hash/hash_test.go` proves:
  - ruleset hashes are stable across ordering differences
  - join `check.where[]` ordering differences do not affect hashes

