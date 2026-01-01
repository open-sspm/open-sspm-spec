# Spec v1 refined upgrade - Engine compatibility

This repository is a spec compiler and artifact generator. It does not implement a runtime check evaluation engine.

## What changed for engines

- The compiled descriptor (`dist/descriptor.v1.json`) now contains the canonical check DSL shapes defined in `newspec.md`:
  - `manual.attestation`
  - `dataset.field_compare` (`where`, `assert`, `expect`)
  - `dataset.count_compare` (`where`, `compare`)
  - `dataset.join_count_compare` (`left`, `right`, `where`, `compare`, `on_unmatched_left`)
- The compiler emits a richer requirements index (`dist/index/requirements.json`) that includes check types, value params, and effective dataset versions.

## Runtime ABI in this repo

- The dataset provider runtime ABI is defined in the generated package `gen/go/opensspm/runtime/v1` and remains focused on dataset access, not check evaluation.
- Engines consume compiled rulesets and implement the evaluation semantics described by the check ABI in `newspec.md`.

## Limitations

- No engine evaluation logic or engine test suite exists in this repository, so compatibility validation is limited to:
  - schema validation
  - semantic validation
  - deterministic compilation/hashing
  - requirements index computation
