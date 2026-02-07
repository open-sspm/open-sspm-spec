# Open SSPM Specification Rewrite Plan

## 1. Executive Summary

This document outlines the architectural rewrite of the Open SSPM Specification (`open-sspm-spec`).

This repository is not “just rulesets”: it contains **rulesets**, **dataset contracts**, **connector manifests**, **profiles**, and a **dictionary**, plus schemas and a deterministic compiler that produces compiled artifacts (`dist/`, `docs/`, `gen/`).

The primary goal is to introduce a human-readable, developer-friendly **YAML authoring format for rulesets** while keeping the **compiled distribution descriptor (JSON)** as the canonical output that bundles *all* spec objects (rulesets + datasets + connectors + profiles + dictionary).

The new design adopts a **"Hybrid" approach** for rule logic: it combines structured configuration (`params`) for usability with **Common Expression Language (CEL)** for flexible, safe, and portable execution logic.

## 2. Core Philosophy

1.  **Simplicity First**: If a human cannot easily read and edit the spec in a text editor, it is too complex.
2.  **One Ruleset, One File**: All *ruleset* metadata, rules, and logic for a specific benchmark (e.g., "CIS Okta STIG") live in a single YAML file (it references datasets/connectors by stable keys + versions rather than embedding schemas).
3.  **Spec as a Checklist**: The spec mirrors compliance documents (like PDF benchmarks). It supports both **Manual** (text instructions) and **Automated** (code logic) checks side-by-side.
4.  **Language Agnostic Logic**: Logic is defined in standard CEL strings, not hardcoded in Go/Python, allowing the same rules to run anywhere.

## 3. The New Specification Format (Authoring vs Distribution)

### 3.1 Spec Objects in V2 (Repository Scope)

V2 keeps the existing top-level spec concepts as first-class, versioned objects:

- `opensspm.ruleset`: benchmark/rules + logic (YAML authoring)
- `opensspm.dataset_contract`: dataset schema + key/version contract (JSON authoring initially)
- `opensspm.connector_manifest`: which datasets a connector provides (JSON authoring initially)
- `opensspm.profile`: bundles/selects rulesets for evaluation (JSON authoring initially)
- `opensspm.dictionary`: shared enums and **versioned globals/constants** used across the spec (JSON authoring initially)

### 3.2 Authoring Format

The rewrite is intentionally incremental:

- **Rulesets move to YAML first** (`specs/rulesets/**/*.yaml`) for human editing.
- Dataset contracts, connector manifests, profiles, and dictionary **may remain JSON** initially (their current shapes are already stable and schema-driven).
- The authoring format can expand later (e.g., YAML for connectors/profiles/dictionary), but consumers should not depend on authoring formats.

### 3.3 Distribution Format (Canonical Output)

The single source of truth for *consumers* is a compiled **JSON descriptor** produced by `osspec build`:

- Bundles **rulesets + dataset contracts + connector manifests + profiles + dictionary**
- Includes indexes and resolved references
- Is deterministic and versionable (fits existing `dist/` and `docs/descriptor…json` patterns)

### 3.4 Example Ruleset (`specs/rulesets/cis/okta/cis.okta.idaas_stig.v2.yaml`)

```yaml
apiVersion: opensspm/v2
kind: Ruleset
metadata:
  name: "CIS Okta IDaaS STIG Benchmark"
  version: "1.0.0"
  description: "Security baseline for Okta organization settings."

spec:
  # Rulesets explicitly declare which dataset contracts they depend on (key + version).
  # `osspec validate` enforces that these dataset contracts exist.
  data_contracts:
    - dataset: "okta:policies/sign-on"
      version: 1
    - dataset: "okta:log-streams"
      version: 1

  rules:
    # -------------------------------------------------------------------------
    # Rule with Parameters (Hybrid Approach)
    # -------------------------------------------------------------------------
    - id: "OKTA-APP-000020"
      title: "Okta must log out a session after a configured period of inactivity."
      severity: "medium"

      # Dataset requirements are explicit and versioned so contracts can evolve
      # without silently changing rule behavior.
      required_data:
        - dataset: "okta:policies/sign-on"
          version: 1
      
      # 1. PARAMETERS: Define configurable values here.
      # This allows users/UI to change thresholds without editing code.
      params:
        max_idle_minutes:
          type: int
          default: 15
          description: "Maximum allowed idle time in minutes."

      # 2. CHECKS: The logic uses the parameters defined above.
      checks:
        - name: "Global Session Idle Timeout"
          dataset: "okta:policies/sign-on"
          dataset_version: 1
          
          # CEL Logic: Standard CEL list macros; `dataset` and `params` are in scope.
          condition: |
            dataset.exists(rule,
              rule.policy.name == "Default Policy" &&
              rule.priority == 1 &&
              rule.name != "Default Rule" &&
              rule.actions.signon.session.maxSessionIdleMinutes <= params.max_idle_minutes
            )

          # Optional evidence selector: returns the failing resources/records for UI/auditing.
          select_failures: |
            dataset.filter(rule,
              rule.policy.name == "Default Policy" &&
              rule.priority == 1 &&
              rule.name != "Default Rule" &&
              rule.actions.signon.session.maxSessionIdleMinutes > params.max_idle_minutes
            )

      evidence:
        affected_resources:
          dataset: "okta:policies/sign-on"
          dataset_version: 1
        summary_templates:
          pass: "Global session idle timeout is within {{ params.max_idle_minutes }} minutes."
          fail: "Global session idle timeout exceeds {{ params.max_idle_minutes }} minutes."
          unknown: "Unable to determine global session idle timeout."

      remediation: |
        1. Go to Security >> Global Session Policy.
        2. Set "Maximum Okta global session idle time" to {{ params.max_idle_minutes }} minutes.

    # -------------------------------------------------------------------------
    # Rule with Multiple Checks
    # -------------------------------------------------------------------------
    - id: "OKTA-LOG-000010"
      title: "Okta must stream audit logs to an external target."
      severity: "medium"

      required_data:
        - dataset: "okta:log-streams"
          version: 1
      
      checks:
        - name: "At Least One Active Log Stream"
          dataset: "okta:log-streams"
          dataset_version: 1
          condition: 'dataset.exists(ls, ls.status == "ACTIVE")'

        - name: "Log Stream Type Allowed"
          dataset: "okta:log-streams"
          dataset_version: 1
          condition: |
            dataset
              .filter(ls, ls.status == "ACTIVE")
              .all(ls, ls.type in globals.okta.allowed_log_stream_types)

          select_failures: |
            dataset.filter(ls,
              ls.status == "ACTIVE" &&
              !(ls.type in globals.okta.allowed_log_stream_types)
            )

      evidence:
        affected_resources:
          dataset: "okta:log-streams"
          dataset_version: 1
        summary_templates:
          pass: "Okta audit logs are streamed to an external target."
          fail: "Okta audit logs are not streamed to an allowed external target."
```

### 3.5 Dataset Versioning + Required Data

Dataset contracts are versioned and can evolve. To avoid silently changing rule meaning:

- Every dataset reference in a check is **(dataset key, dataset version)**.
- Every rule declares its `required_data` as explicit, versioned dataset refs.
- `osspec validate` enforces that checks only reference declared `required_data`, and that every referenced dataset contract exists.

### 3.6 Evidence and Affected Resources

To preserve debuggability and enable useful UIs/reports, checks may optionally include evidence selectors in addition to a boolean `condition`:

- `evidence.summary_templates`: strings for `pass`/`fail`/`unknown`/`error`/`not_applicable` (same concept as v1)
- `evidence.affected_resources`: identifies what dataset the resources come from (dataset key + version; `id_field`/`display_field` default to the dataset contract’s `primary_key` and `recommended_display`)
- `select_failures`: CEL expression returning a list of resources/records to attach when the check fails (best-effort; must not change pass/fail status)

### 3.7 Globals Governance and Versioning

CEL expressions may reference `globals.*` for cross-cutting constants (for example, allow-lists, shared thresholds, or lists like “approved certificate authorities”). To preserve determinism and reproducibility:

- `globals` is **not** an implementation-defined runtime bag of values; it is a **versioned spec artifact** shipped with the spec.
- Canonical evaluation uses the compiled **JSON descriptor**, so `globals` is always resolved from that descriptor (never from out-of-band environment configuration).
- Governance: `globals` values live in `opensspm.dictionary` (for example under `dictionary.globals.*`) and are included in the compiled descriptor with a content hash. Any change to these values is a spec change and must be released like any other contract change.
- Naming: `globals` keys must be namespaced to avoid collisions (for example `globals.okta.allowed_log_stream_types`, `globals.dod.approved_certificate_authorities`).
- Optional ruleset-local constants: if needed, a ruleset may define a small `spec.globals` block for truly ruleset-scoped values, but `osspec validate` must reject key collisions with shared `globals.*` to avoid silent overrides.

## 4. Architecture & Tooling

The repository will continue to provide the "Source of Truth", but the tooling (`osspec`) will change its focus.

### 4.1 The Spec Layer
*   **Format (authoring)**: YAML for `opensspm.ruleset` (initially). Other objects may remain JSON.
*   **Location**:
    *   `specs/rulesets/**/*.yaml` (rulesets)
    *   `specs/datasets/**/vN.json` (dataset contracts)
    *   `specs/connectors/*.json` (connector manifests)
    *   `specs/profiles/*.json` (profiles)
    *   `dictionary.json` (dictionary)
*   **Validation**:
    *   A lightweight schema validates the YAML structure (ensure `id`, `severity`, `checks[].condition` exist).
    *   `osspec validate` enforces **referential integrity** across objects:
        *   Ruleset `data_contracts` point to existing dataset contracts (key + version).
        *   Every dataset reference in a check includes an explicit `dataset_version` and resolves to an existing dataset contract.
        *   `required_data` is explicit and versioned, and `osspec validate` enforces that it covers all datasets referenced by checks (no undeclared dataset dependencies).
        *   Ruleset scope references an existing connector kind, and the connector manifest provides the required datasets.
        *   Profiles reference existing rulesets.
        *   Dictionary keys referenced by CEL (e.g., `globals.*`) exist.
    *   `osspec validate` compiles all CEL expressions as **strict, standard CEL** (`cel-go`) so non-CEL syntax fails fast:
        *   `condition` (must type-check to `bool`)
        *   optional `when` (must type-check to `bool`)
        *   optional evidence selectors like `select_failures` (must type-check to `list`)
        *   all CEL must conform to the **Open SSPM CEL profile** (see 4.3)

### 4.2 Determinism, Canonicalization, and Hashing

The current repository guarantees determinism via canonical JSON (JCS / RFC 8785) and SHA-256 hashes. V2 must keep the same model even if rulesets are authored in YAML.

#### What is Hashed?

Objects are hashed based on their **parsed, normalized data model**, not raw file bytes:

1. Parse source document (JSON or YAML) into the corresponding typed object.
2. Apply the same normalization defaults/sorting rules as today (for stable ordering, default values, etc.).
3. Serialize to JSON and canonicalize using **JCS (RFC 8785)**.
4. Hash canonical JSON bytes with **SHA-256**.

This ensures hashes are stable across formatting-only changes (whitespace, comments, YAML formatting).

#### YAML Subset (Parser Governance)

To avoid parser-dependent behavior, V2 ruleset YAML must use a strict subset:

- YAML **1.2** (JSON-compatible scalars)
- **No anchors/aliases/merge keys**
- **No custom tags**
- **No YAML 1.1 boolean forms** (`yes/no/on/off`) — rejected by validation
- **No duplicate keys** — rejected by validation

The compiled descriptor remains JSON and continues to be written in canonical form.

### 4.3 Open SSPM CEL Profile (Portability Guardrails)

CEL portability requires a strict, versioned feature set. V2 defines an explicit **CEL profile** so that “same expression + same inputs ⇒ same result” across supported runtimes.

#### Profile Versioning

- The profile is versioned (e.g., `opensspm.cel_profile.v1`).
- The compiled JSON descriptor records the profile version, and engines must refuse to evaluate rulesets using an unknown profile.
- The profile’s expected behavior is defined by the conformance vectors; the reference implementation (used by `osspec`) is pinned, and any semantic change requires a profile version bump.

#### Allowed Feature Set (MVP)

- Standard CEL only (no dialect, no transpilation).
- Macros: only the standard list macros (`all`, `exists`, `exists_one`, `filter`, `map`).
- Functions/types: CEL standard library only; **no custom functions** and **no custom types** in the MVP profile.
- Types in scope:
  - `dataset`: list of records (records are maps/structs derived from the dataset contract)
  - `params`: map/object derived from the rule’s parameter schema/defaults
  - `globals`: map/object resolved from the versioned spec artifact (see 3.7)

#### Numeric + Null Semantics

To avoid cross-runtime ambiguity:

- Dataset values are typed according to the dataset contract schema (integers stay integers; floats stay floats; booleans stay booleans).
- Rule authors should avoid relying on implicit numeric conversions; comparisons must be type-consistent under the profile.
- Missing vs null must be handled explicitly in rules (profile guidance + conformance tests).

#### Conformance Test Vectors

Add a repo-level conformance suite that any “supported runtime” must pass:

- Test vectors live in the repo (inputs + expression + expected output/status).
- `osspec verify` (or a dedicated `osspec conformance`) runs these vectors using the reference implementation.
- Other runtimes (Go, Python, TS, etc.) can import and run the same vectors in their CI to prove compatibility before being declared “supported”.

### 4.4 The Code Generator (`osspec codegen`)
Instead of transpiling logic, the generator ensures **Type Safety**.

*   **Input**: Dataset definitions (e.g., `okta_users` schema).
*   **Output**: Native Structs/Classes (Go, Python, TS).
*   **Purpose**: Ensures that if a rule says `user.mfa_enabled`, the `User` struct actually has an `MfaEnabled` field.

**Example Generated Go Code:**
```go
// gen/go/datasets/okta.go
type OktaGlobalSessionPolicy struct {
    Name     string                 `json:"name"`
    Settings SessionPolicySettings  `json:"settings"`
}

type SessionPolicySettings struct {
    IdleTime int `json:"idle_time"`
}
```

### 4.5 The Runtime Engine (Library)
A generic library that consumes the YAML spec and executes it.

1.  **Load**: Parse `ruleset.yaml`.
2.  **Compile**: Compile CEL under the declared **Open SSPM CEL profile** (no custom dialect).
3.  **Execute**:
    *   Fetch data for the requested `dataset` **and version** (no implicit upgrades; rules written against v1 do not silently run against v2).
    *   Create an execution environment: `env = { "dataset": data, "params": rule.params, "globals": <versioned spec globals> }`.
    *   Run `program.Eval(env)`.
    *   (Optional) Evaluate evidence selectors like `select_failures` to attach affected resources and structured evidence without changing the status.

### 4.6 Evaluation Semantics (Result Contract)

V2 keeps the richer outcome semantics from v1. “Pass/Fail” is not sufficient for real SSPM evaluation.

#### Statuses

Every check and rule evaluation produces one of:

- `pass`
- `fail`
- `unknown` (insufficient data to determine)
- `error` (engine/runtime failure)
- `not_applicable` (rule does not apply to this tenant/context)

#### Dataset/Runtime Error Mapping (Error Policies)

The runtime must model dataset acquisition/availability failures explicitly (at minimum: missing dataset, permission denied, sync error). Each check supports policies consistent with v1:

- `on_missing_dataset`: `unknown` (default) or `error`
- `on_permission_denied`: `unknown` (default) or `error`
- `on_sync_error`: `unknown` (default) or `error`

This mapping is part of the evaluation contract so UIs and downstream engines can reliably distinguish “could not evaluate” from “failed”.

#### Manual Checks

Manual checks (v1: `manual.attestation`) remain first-class:

- If no attestation is provided: status = `unknown`
- If an attestation is provided: status = `pass` or `fail` (plus optional notes/evidence)

#### Applicability (`not_applicable`)

Rules and/or checks may include an optional applicability expression (e.g., `when: <CEL bool>`). If `when` evaluates to false, the result is `not_applicable` without evaluating the condition.

#### Combining Multiple Checks

Rules can include multiple checks. Default semantics are **ALL**:

- If any check is `error` → rule = `error`
- Else if any check is `fail` → rule = `fail`
- Else if all checks are `not_applicable` → rule = `not_applicable`
- Else if any check is `unknown` → rule = `unknown`
- Else → rule = `pass`

Future extension: allow an explicit combiner (e.g., `mode: any`) but define the default (ALL) up front for determinism.

#### Evidence / Summaries

V2 retains v1-style evidence templates (`evidence.summary_templates`) and adds optional selectors (e.g., `select_failures`) so outcomes can include:

- a human-readable summary (templated)
- affected resources (derived from dataset contract keys/fields or explicit `evidence.affected_resources`)
- structured evidence payloads for UI/auditing

## 5. Migration Strategy

1.  **Freeze V1**: Mark the current JSON specs as legacy/v1.
2.  **Prototype V2**: Port one benchmark (CIS Okta) to a v2 YAML ruleset alongside v1 (e.g., `specs/rulesets/cis/okta/cis.okta.idaas_stig.v2.yaml`).
3.  **Update Tooling**:
    *   Update `osspec` to parse YAML.
    *   Integrate a CEL compile step into validation:
        *   Compile each `condition` with `cel-go` (macros enabled).
        *   (Future) Compile with a dataset-aware type environment so unknown fields fail at build time.
4.  **Deprecate JSON**: Once the V2 format covers all use cases, remove the complex JSON generation logic.

## 6. Comparison: Old vs. New

| Feature | Old (V1) | New (V2) |
| :--- | :--- | :--- |
| **Format** | JSON (Machine optimized) | YAML (Human optimized) |
| **Logic** | Custom JSON AST (`field_compare`) | Standard CEL (`user.status == "ACTIVE"`) |
| **Structure** | Scattered (Rules, Checks, Datasets separate) | Unified (One Ruleset file) |
| **Parameters** | Complex schema definitions | Simple `params` key-value map |
| **Tooling** | Heavy custom compiler | Lightweight validator + CEL Engine |
