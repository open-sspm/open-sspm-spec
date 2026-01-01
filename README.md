<p align="center">
  <img src="./logo.png" alt="Open SSPM" width="520" />
</p>

# Open SSPM Spec Repository (`open-sspm-spec`)

THIS IS WORKING DOCUMENT, I AM STILL WORKING ON IT AND IT WILL CHANGE A LOT!

Source-of-truth repository for Open SSPM specifications.

## What this repo contains

- JSON specs under `specs/`:
  - rulesets (`opensspm.ruleset`)
  - dataset contracts (`opensspm.dataset_contract`)
  - connector manifests (`opensspm.connector_manifest`)
  - profiles (`opensspm.profile`)
- JSON Schemas under `metaschema/` (strict top-level validation)
- Deterministic compiler `osspec` under `tools/osspec`
- Generated, committed distribution artifacts under `dist/`
- Generated language outputs under `gen/` (Go first)

Hard boundary: this repo does **not** generate evaluation logic. It generates only data models, interfaces, and deterministic compiled artifacts.

## Quickstart

Validate all specs:

```sh
go run ./tools/osspec/cmd/osspec validate
```

Build deterministic outputs into `dist/`:

```sh
go run ./tools/osspec/cmd/osspec build
```

Generate Go output into `gen/go`:

```sh
go run ./tools/osspec/cmd/osspec codegen --lang go --out gen/go
```

## Docs website

Generate the static documentation site data (renders from the compiled descriptor):

```sh
go run ./tools/osspec/cmd/osspec build
```

This writes `docs/descriptor.v1.json` and `docs/metaschema/*.json`.

Serve `docs/` using any static file server (opening `docs/index.html` via `file://` will fail because the site loads JSON via `fetch`):

```sh
cd docs && python3 -m http.server 8080
```

GitHub Pages:

- This repo ships a Pages workflow that builds and publishes `docs/` on pushes to `main` or `master`.
- In GitHub repo settings, set Pages source to GitHub Actions.

## Determinism and hashing

- Specs are loaded from `specs/**`:
  - symlinks are rejected
  - `.json` only
  - max size 2 MiB per file
- Hashing is stable:
  - normalize objects (stable ordering)
  - canonicalize JSON using JCS (RFC 8785)
  - SHA-256 hex digest

## `required_data` policy

`ruleset.required_data` is optional. If present, `osspec validate` enforces that it includes every dataset referenced by that ruleset’s checks (dataset+version).

## Third-party standards (CIS)

This repository includes a CIS Okta IDaaS STIG example ruleset using only rule IDs and minimal metadata for traceability. It does **not** include the CIS PDF and does **not** copy benchmark prose.
