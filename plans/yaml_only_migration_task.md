# Open SSPM Spec — YAML-only Authoring Migration (No JSON Sources)

> **Purpose of this document:** This is the complete context + actionable implementation plan for a coding agent to finish migrating the Open SSPM Spec repository from **JSON-authored** specs to **YAML-only** specs, while preserving the existing **canonical JSON build outputs** (unless the repo chooses to stop committing them).
>
> **Hard requirement:** **No JSON spec sources may remain**. Only `.yaml` / `.yml` files are allowed as authoring input.

---

## 0) Scope & Non-goals

### In scope (must do)
- Make the build/validate tool (`tools/osspec`, Go) load and parse **YAML-only** spec inputs.
- Convert remaining JSON-authored artifacts to YAML:
  - `dictionary.json` → `dictionary.yaml`
  - `specs/datasets/**/*.json` → `.yaml`
  - `specs/connectors/*.json` → `.yaml`
  - `specs/profiles/*.json` → `.yaml`
  - If any `specs/rulesets/**/*.json` still exist: **either** convert to YAML (v1 ruleset format) **or** remove v1 ruleset pipeline entirely.
- Enforce the “no JSON sources” rule (CI check and/or loader/compiler hard-fail).

### Out of scope unless explicitly required
- Removing JSON from *build artifacts* (`dist/*.json`). The tool may still generate JSON outputs for determinism/hashing.
- Removing JSON from `metaschema/*.json`. (If the repo truly wants **zero** `.json` files anywhere, see **Section 9**.)

---

## 1) Repository snapshot (conceptual)

```
open-sspm-spec/
├── dictionary.json              # MUST BECOME YAML
├── specs/
│   ├── datasets/                # MUST BECOME YAML
│   ├── connectors/              # MUST BECOME YAML
│   ├── profiles/                # MUST BECOME YAML
│   └── rulesets/                # v2 rulesets already YAML; v1 JSON may still exist
├── dist/                        # compiled output (JSON today)
├── metaschema/                  # JSON Schema files (JSON today)
└── tools/osspec/                # Go build tool
    └── internal/
        ├── compiler/
        ├── loader/
        ├── yamlstrict/          # strict YAML decoder (already present)
        └── v2ruleset/           # v2 YAML ruleset loader/validator (already present)
```

---

## 2) Current state (what is already done)

- **V2 rulesets are already migrated to YAML** (Kubernetes-style `apiVersion: opensspm/v2`, `kind: Ruleset`).
- The repository already includes a **strict YAML decoder** (`tools/osspec/internal/yamlstrict`) that rejects:
  - multi-doc YAML streams
  - anchors / aliases
  - custom tags
  - duplicate mapping keys
  - non-string mapping keys
  - YAML merge keys (`<<`)
- There is already a **v2 ruleset loader** in `tools/osspec/internal/v2ruleset/`.

---

## 3) The new requirement: YAML-only (no JSON remains)

This changes the previous “YAML + fallback to JSON” plan.

### Required behaviors
1. **Spec authoring input must be YAML-only**:
   - Under `specs/**`: accept only `.yaml` / `.yml`.
   - At repo root: accept `dictionary.yaml` / `dictionary.yml`.
2. If any `.json` spec sources remain, the tool should:
   - **Fail fast** with a clear error message, OR
   - Be prevented by CI (preferred), OR
   - Both.

### Ambiguity to resolve in repo policy
- The repo may still *generate* JSON build outputs (`dist/*.json`), but to satisfy “no JSON stays in git”, treat them as **generated artifacts** and **do not commit** (e.g., add to `.gitignore` and/or generate outside repo).

---

## 4) Critical gotchas the implementation must handle

### Gotcha A — YAML decoding into `json.RawMessage` will fail
Some v1 structs use `json.RawMessage` (alias `[]byte`), especially:
- `opensspm.dataset_contract.dataset.schema` is `json.RawMessage`

A YAML mapping like:

```yaml
schema:
  type: object
  properties:
    id:
      type: string
```

**cannot** be unmarshaled directly into `json.RawMessage`. You must:
1. Decode `schema` into `any` (or `map[string]any`) using `yamlstrict`
2. `json.Marshal` it back into bytes
3. Assign those bytes to the `json.RawMessage`

This pattern may also apply to any other spec types that embed free-form JSON blobs.

### Gotcha B — v2 YAML rulesets live under `specs/` and must not break v1 compilation
If the v1 compiler walks `specs/**` and tries to parse everything as v1 (`schema_version` / `kind: opensspm.*`), it will encounter v2 rulesets (`apiVersion`, `kind: Ruleset`).

**Solution:** In the v1 compile loop, after decoding a lightweight header:
- If `schema_version == 0`:
  - If `kind` starts with `opensspm.` ⇒ error (“missing schema_version”)
  - Else ⇒ **ignore** the file (it is likely v2)

This keeps v1 compilation from choking on v2 YAML.

### Gotcha C — Multiline YAML strings can change hashes
If you convert JSON strings to YAML block scalars, use `|-` when you need to avoid adding a trailing newline.

---

## 5) Implementation tasks (Go changes)

### Files to modify
- `tools/osspec/internal/loader/loader.go`
- `tools/osspec/internal/compiler/compiler.go`

You may also need small updates elsewhere if there are other hardcoded `.json` references.

---

## 6) Loader changes — YAML-only

**Goal:** Load only `.yaml` / `.yml` from `specs/**`.

### Required behavior
- Include: `.yaml`, `.yml`
- Exclude test fixtures: `*.test.yaml`, `*.test.yml`
- If a `.json` file is encountered under `specs/**`, **fail** with an actionable error:
  - “JSON spec sources are not allowed; convert to YAML: <path>”

### Suggested code patch (conceptual)
In `WalkDir` file handling:

```go
nameLower := strings.ToLower(d.Name())
ext := strings.ToLower(filepath.Ext(nameLower))

switch ext {
case ".yaml", ".yml":
    // ok
case ".json":
    rel, _ := filepath.Rel(root, path)
    return fmt.Errorf("loader: json spec source not allowed (convert to yaml): %s", filepath.ToSlash(rel))
default:
    return nil
}

if strings.HasSuffix(nameLower, ".test.yaml") || strings.HasSuffix(nameLower, ".test.yml") {
    return nil
}
```

Keep the existing safety checks (symlinks disallowed, max size, repo-root escape prevention, deterministic sort).

---

## 7) Compiler changes — YAML-only + strict

### 7.1 Dictionary loading (YAML-only)
- Remove JSON fallback.
- Load only:
  - `dictionary.yaml` (preferred)
  - `dictionary.yml`
- If `dictionary.json` exists ⇒ error.
- If neither YAML exists ⇒ error.

### 7.2 Spec file decoding
- All spec files provided by the loader are YAML; decode with `yamlstrict.DecodeSingleDocument`.
- If for any reason a `.json` file reaches the compiler loop, treat it as an error.

### 7.3 v1 header decode + v2 skipping rule
Decode a lightweight header (`schema_version`, `kind`) with `KnownFields: false`, then:
- If `schema_version == 0`:
  - If `kind` starts with `opensspm.` ⇒ error
  - Else ⇒ skip file (likely v2)

### 7.4 Decode per-kind (KnownFields: true)
For v1 kinds, decode strictly:
- `opensspm.dataset_contract`
- `opensspm.connector_manifest`
- `opensspm.profile`
- `opensspm.ruleset` (if still supported)

### 7.5 Special decode for DatasetContract schema
For YAML dataset contracts:
- Decode into a temporary struct where `dataset.schema` is `any`
- Marshal `any` to JSON bytes
- Assign bytes into the real `types.DatasetContractDoc.Dataset.Schema` (`json.RawMessage`)

#### Example approach (conceptual)

```go
type datasetContractDocYAML struct {
    SchemaVersion int    `json:"schema_version"`
    Kind          string `json:"kind"`
    Dataset       struct {
        Key                string `json:"key"`
        Version            int    `json:"version"`
        Description        string `json:"description,omitempty"`
        PrimaryKey         string `json:"primary_key,omitempty"`
        RecommendedDisplay string `json:"recommended_display,omitempty"`
        Schema             any    `json:"schema"`
    } `json:"dataset"`
}

var tmp datasetContractDocYAML
if err := yamlstrict.DecodeSingleDocument(f.Bytes, &tmp, yamlstrict.DecodeOptions{KnownFields: true}); err != nil { ... }

schemaJSON, err := json.Marshal(tmp.Dataset.Schema)
if err != nil { ... }

var doc types.DatasetContractDoc
// populate doc fields
// doc.Dataset.Schema = schemaJSON
```

### 7.6 Repeat the same pattern for any other `json.RawMessage` fields
Search for `json.RawMessage` in `tools/osspec/internal/types/` and implement the same YAML→any→json.Marshal conversion as needed.

---

## 8) File conversion plan (JSON → YAML, then delete JSON)

### Rule: never keep both formats for the same artifact
After conversion, delete the `.json` source file.

### Convert these categories
1. **Dictionary**
   - `dictionary.json` → `dictionary.yaml`
2. **Dataset contracts**
   - `specs/datasets/**/v*.json` → `v*.yaml`
3. **Connector manifests**
   - `specs/connectors/*.json` → `*.yaml`
4. **Profiles**
   - `specs/profiles/*.json` → `*.yaml`
5. **Rulesets (v1)**
   - If `opensspm.ruleset` v1 is still required: convert `.json` → `.yaml`.
   - If v1 is not required: delete v1 rulesets and remove/disable v1 compilation.

### YAML formatting guidelines
- Prefer `.yaml` (not `.yml`) for consistency.
- Avoid YAML anchors/aliases/tags; `yamlstrict` rejects them.
- Use quotes for strings that could be misread (`on`, `yes`, `no`, numbers, etc.).
- For multiline strings where exact output matters, use `|-`.

---

## 9) “No JSON anywhere” mode (only if the repo truly means *zero* `.json` files)

If the requirement is literally “no `.json` files exist in the repo at all”, then you must also address:

1. **`dist/*.json`**
   - Option: stop committing `dist/` (gitignore), and generate during releases.
   - If you must keep a committed descriptor, consider committing `dist/*.yaml` *in addition* to JSON, or changing output format (but that breaks current canonical JSON/hashing contract).

2. **`metaschema/*.json`**
   - You can represent JSON Schema documents as YAML files (the data model is still JSON), but the tooling that loads/validates schemas must accept YAML and convert to JSON object internally.
   - This is a larger change; do not attempt unless the repo explicitly requires it.

---

## 10) Verification / acceptance criteria

### Functional verification
- `go test ./...` passes
- `./osspec validate` passes
- `./osspec build` succeeds

### Determinism / compatibility (if dist JSON is still produced)
- Canonical JSON outputs remain deterministic.
- If you temporarily kept old JSON sources to compare, verify that the produced `dist/descriptor*.json` is unchanged after YAML migration.

### Enforcement checks
- `find specs -name '*.json'` returns nothing
- `test -f dictionary.json` should fail (file should not exist)

---

## 11) Appendix — Example YAML conversions

### Dictionary (`dictionary.yaml`)
```yaml
schema_version: 1
kind: opensspm.dictionary

dictionary:
  enums:
    Severity:
      - critical
      - high
      - medium
      - low
      - info
    MonitoringStatus:
      - automated
      - partial
      - manual
      - unsupported

  globals:
    okta:
      allowed_log_stream_types:
        - aws_eventbridge
        - azure_event_hubs
        - splunk_cloud_logstream
```

### Dataset contract (`specs/datasets/okta/policies.sign-on/v1.yaml`)
```yaml
schema_version: 1
kind: opensspm.dataset_contract

dataset:
  key: okta:policies/sign-on
  version: 1
  description: Okta sign-on policy rules.
  primary_key: /id
  recommended_display: /name
  schema:
    $schema: http://json-schema.org/draft-07/schema#
    type: object
    properties:
      id:
        type: string
      name:
        type: string
      priority:
        type: integer
```

### Connector manifest (`specs/connectors/okta.yaml`)
```yaml
schema_version: 1
kind: opensspm.connector_manifest

connector:
  kind: okta
  name: Okta
  provides:
    - dataset: okta:authenticators
      version: 1
    - dataset: okta:log-streams
      version: 1
    - dataset: okta:policies/password
      version: 1
    - dataset: okta:policies/sign-on
      version: 1
```

### Profile (`specs/profiles/cis.okta.idaas_stig.profile.v1.yaml`)
```yaml
schema_version: 1
kind: opensspm.profile

profile:
  key: cis.okta.idaas_stig.profile.v1
  name: CIS Okta IDaaS STIG Profile
  description: Profile bundling the CIS Okta IDaaS STIG ruleset.
  rulesets:
    - key: cis.okta.idaas_stig.v1
      version: v1.0.0
```

---

## 12) Quick checklist for the coding agent

- [ ] Update loader to YAML-only and error on JSON under `specs/`
- [ ] Update compiler dictionary load: YAML-only; error if `dictionary.json` exists
- [ ] Update compiler spec loop: YAML-only; header decode + skip v2 rule
- [ ] Implement dataset-contract schema conversion (`any` → `json.Marshal` → `json.RawMessage`)
- [ ] Search for other `json.RawMessage` fields; handle similarly
- [ ] Convert & delete JSON spec sources
- [ ] Add CI check preventing `*.json` under `specs/` and `dictionary.json`
- [ ] Run tests + validate + build

