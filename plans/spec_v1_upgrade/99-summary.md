# Spec v1 refined upgrade - Summary

## Changelog

- Updated `opensspm.ruleset` schema and Go models to the refined v1 ruleset spec in `newspec.md`.
- Implemented the canonical check DSL (`where`/`assert`/`expect`/`compare`/`left`/`right`) and shared check fields (dataset_version, error policies, notes).
- Enforced semantic validation rules from `newspec.md` (monitoring constraints, required_data coverage, dataset version declarations, value_param validation, predicate/compare structure).
- Implemented deterministic normalization and hashing: normalize then JCS (RFC 8785) then SHA-256 hex.
- Updated requirements index generation to include status, effective dataset versions, check types, and value params.
- Updated the CIS Okta sample ruleset to the refined rule shape and verified it compiles and is indexed.
- Updated Go codegen and regenerated `gen/go` outputs.

## Tests

Run all tests:

`GOCACHE=$PWD/.cache/go-build go test ./...`
