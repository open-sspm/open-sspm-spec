<p align="center">
  <img src="./logo.png" alt="Open SSPM" width="520" />
</p>

# Open SSPM Spec Repository (`open-sspm-spec`)

THIS IS WORKING DOCUMENT, I AM STILL WORKING ON IT AND IT WILL CHANGE A LOT!

Source-of-truth repository for Open SSPM **compliance specifications**.

Open SSPM is an open, versioned spec (YAML authoring + JSON Schema semantics) for posture/compliance rulesets and profiles (benchmarks) that tools can evaluate.

Executable checks are authored in Rego (`check.engine: rego`). A ruleset can
provide a shared Rego module under `ruleset.policy`, usually by setting
`rego_path` to a `.rego` file beside the YAML, and each automated rule selects
its result with `check.query`.

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

## Check evaluation mode

- `engine: rego`: an OPA/Rego module plus query. Author the module inline with
  `rego` or, preferably, point to a relative `.rego` file with `rego_path`.
  The query must return an object with at least `status` for rule checks.
  Entity policy packs use Rego too, returning `risk_level`, `risk_score`, and
  `signals` as needed.

Rule checks receive input shaped as:

```json
{
  "datasets": {
    "dataset:key": {
      "rows": []
    }
  },
  "params": {},
  "rule": {
    "key": "RULE-ID",
    "required_data": ["dataset:key"]
  }
}
```

Entity policy packs receive `input.entity` and `input.policy`.

## `required_data` policy

`rule.required_data` declares the dataset keys a rule depends on. `osspec validate`
enforces that each declared dataset is present in the ruleset `data_contracts`.

## Third-party standards (CIS)

This repository includes a CIS Okta IDaaS STIG example ruleset using only rule IDs and minimal metadata for traceability. It does **not** include the CIS PDF and does **not** copy benchmark prose.
