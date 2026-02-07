<p align="center">
  <img src="./logo.png" alt="Open SSPM" width="520" />
</p>

# Open SSPM Spec Repository (`open-sspm-spec`)

THIS IS WORKING DOCUMENT, I AM STILL WORKING ON IT AND IT WILL CHANGE A LOT!

Source-of-truth repository for Open SSPM **compliance specifications**.

Open SSPM is an open, versioned spec (YAML authoring + JSON Schema semantics) for posture/compliance rulesets and profiles (benchmarks) that tools can evaluate.

Checks can be authored either as:
- structured DSL (`check.type`, `dataset`, `where`, `assert`/`compare`, `expect`), or
- raw CEL (`check.engine: cel`, `check.expression`).

The compiler normalizes structured checks to runtime-ready compiled checks.

## What this repo contains

- YAML specs under `specs/`:
  - rulesets (`opensspm.ruleset`)
  - profiles (`opensspm.profile`)
  - test cases (`opensspm.test_case`, `*.test.yaml`)
- YAML-authored schemas under `metaschema/` (strict top-level validation via JSON Schema)
- Deterministic compiler `osspec` under `tools/osspec`
- Generated, committed distribution artifacts under `dist/`

Hard boundary: this repo does **not** define connectors or dataset contracts. Dataset keys referenced by checks are treated as external/runtime-defined inputs.

## Quickstart

Validate all specs:

```sh
go run ./tools/osspec/cmd/osspec validate
```

Build deterministic outputs into `dist/`:

```sh
go run ./tools/osspec/cmd/osspec build
```

Generate Go output into `gen/go` (committed for downstream consumers):

```sh
go run ./tools/osspec/cmd/osspec codegen --lang go --out gen/go
```

## Docs website

Generate the static documentation site data (renders from the compiled descriptor):

```sh
go run ./tools/osspec/cmd/osspec build
```

This writes `docs/descriptor.v2.yaml` and `docs/metaschema/*.yaml`.

Serve `docs/` using any static file server (opening `docs/index.html` via `file://` will fail because the site loads YAML via `fetch`):

```sh
cd docs && python3 -m http.server 8080
```

GitHub Pages:

- This repo ships a Pages workflow that builds and publishes `docs/` on pushes to `main` or `master`.
- In GitHub repo settings, set Pages source to GitHub Actions.

## Determinism and hashing

- Specs are loaded from `specs/**`:
  - symlinks are rejected
  - `.yaml` only
  - max size 2 MiB per file
- Hashing is stable:
  - normalize objects (stable ordering)
  - canonicalize YAML via the repository canonical emitter
  - SHA-256 hex digest over canonical YAML bytes

## Check evaluation modes

- `engine: cel`: single boolean CEL expression.
- `engine: cel_plan`: runtime row-selection plan used for structured checks that need tri-state semantics (notably `expect.on_empty: unknown`).

`cel_plan` evaluation runs in phases:
1. dataset fetch (with `on_missing_dataset` / `on_permission_denied` / `on_sync_error` policies)
2. row selection via `where_expression`
3. empty-selection handling via `expect.on_empty`
4. assertion/count evaluation (`all`/`any`/`min_selected` or count compare)

## `required_data` policy

`rule.required_data` declares the dataset keys a rule depends on. `osspec validate` enforces that it includes datasets referenced by compiled checks:
- CEL checks: helper references such as `rows("...")` and `has_dataset("...")`
- CEL plan checks: `check.plan.dataset`

## CEL helper semantics (raw CEL checks)

- `rows("dataset")` reads rows for a dataset and is treated as a required dataset reference.
- `has_dataset("dataset")` is an existence check helper and does not, by itself, force runtime failure when the dataset is absent.
- Direct map access like `datasets["dataset"]` is supported at runtime, but dependency extraction for validation/indexing is helper-call based.

## Third-party standards (CIS)

This repository includes a CIS Okta IDaaS STIG example ruleset using only rule IDs and minimal metadata for traceability. It does **not** include the CIS PDF and does **not** copy benchmark prose.
