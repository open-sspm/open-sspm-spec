# Open SSPM Ruleset Specification Update

**Document:** `Spec.md` (normative update)
 **Applies to:** `schema_version: 1`, `kind: "opensspm.ruleset"`
 **Status:** Normative

This section refines the `opensspm.ruleset` specification to support a modern SSPM rules DSL (filters, assertions, join predicates, error policies, parameter schemas, evidence/remediation metadata, and lifecycle), while preserving:

- A hard boundary: **`open-sspm-spec` MUST NOT generate evaluation logic**.
   Specs define a **data model and an evaluation ABI**. Engines implement the ABI.
- Deterministic compilation and hashing: **Normalize → JCS (RFC 8785) → SHA-256**.
- A single compiled descriptor artifact: `dist/descriptor.v1.json`, plus a computed requirements index.

This update uses RFC 2119 terms **MUST**, **SHOULD**, **MAY**.

------

## 1. Conformance and document shape

### 1.1 Ruleset document (top-level)

A ruleset document MUST have the following top-level shape:

```

{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": { /* Ruleset */ }
}
```

#### Required fields

- `schema_version` MUST be integer `1`.
- `kind` MUST be string `"opensspm.ruleset"`.
- `ruleset` MUST be present and MUST be an object.

#### Unknown fields

- At the top-level, unknown fields MUST be rejected by conforming compilers (i.e., `additionalProperties: false` at the document level).

------

## 2. Object model

### 2.1 Ruleset

`Ruleset` is the object stored under `ruleset`.

#### Required fields

- `key` (string)
   Globally unique, stable identifier.
- `name` (string)
   Human-friendly name.
- `scope` (object; see **2.2**)
- `rules` (array of `Rule`; see **3**)

#### Optional fields

- `source` (object; see **2.3**)
   SHOULD be present for third-party or externally sourced rulesets; SHOULD be omitted for internal/company rulesets.
- `status` (string enum: `"active" | "deprecated"`)
   Default: `"active"`.
- `description` (string)
   Markdown permitted, but evaluation engines MUST treat it as opaque text.
- `tags` (array of string)
- `references` (array of `Reference`; see **2.4**)
- `framework_mappings` (array of `FrameworkMapping`; see **2.5**)
- `requirements` (object; see **2.6**)
- `data_contracts` (array of `DatasetContractRef`; see **2.7**)
   MUST exist as the ruleset-level mechanism for declaring versioned datasets used by checks.

------

### 2.2 Ruleset scope

`ruleset.scope` MUST be:

```

{
  "kind": "global" | "connector_instance",
  "connector_kind": "string?" 
}
```

Rules:

- If `kind` is `"global"`, `connector_kind` MUST be absent, null, or empty string.
- If `kind` is `"connector_instance"`, `connector_kind` MUST be present and MUST be a non-empty string.

------

### 2.3 Ruleset source

`ruleset.source` is OPTIONAL.

If present, it SHOULD be:

```

{
  "name": "string",
  "version": "string",
  "date": "YYYY-MM-DD",
  "url": "uri"
}
```

Notes:

- `url` SHOULD be a valid URI.
- This spec does not require a `source` for internal/company rulesets.

------

### 2.4 Reference

`Reference` objects MAY appear in `ruleset.references` and `rule.references`.

```

{
  "title": "string",
  "url": "uri",
  "type": "documentation|standard|blog|ticket|other"
}
```

Rules:

- `url` MUST be a valid URI.
- `type` default: `"other"`.

------

### 2.5 Framework mapping

`FrameworkMapping` objects MAY appear in `ruleset.framework_mappings` and `rule.framework_mappings`.

```

{
  "framework": "string",
  "control": "string",
  "enhancement": "string?",
  "coverage": "direct|partial|supporting",
  "notes": "string?"
}
```

Rules:

- `coverage` default: `"supporting"`.

------

### 2.6 Ruleset requirements

`ruleset.requirements` is OPTIONAL:

```

{
  "api_scopes": ["string"],
  "permissions": ["string"],
  "notes": "string?"
}
```

Rules:

- `api_scopes` and `permissions` arrays SHOULD be treated as sets (order not significant).

------

### 2.7 Dataset contract declaration

`ruleset.data_contracts` provides version declarations for datasets used by checks.

```

{
  "dataset": "string",
  "version": 1,
  "description": "string?"
}
```

Rules:

- `dataset` MUST be a non-empty string dataset key.
- `version` MUST be an integer ≥ 1.
- If `ruleset.data_contracts` contains multiple entries with the same `dataset`, then checks referencing that dataset MUST disambiguate via `check.dataset_version` (see **4.1**).

------

## 3. Rule object

Each `ruleset.rules[]` entry MUST be a `Rule` object.

### 3.1 Rule fields

#### Required fields

- `key` (string)
   Unique within the containing ruleset.
- `title` (string)
   REQUIRED.
- `severity` (string enum: `critical|high|medium|low|info`)
- `monitoring` (object; see **3.2**)
- `required_data` (array of string dataset keys)
  - MUST be present (may be empty).
- `lifecycle` is OPTIONAL, but if absent compilers MUST behave as if `is_active=true` (see **3.6**).

#### Optional fields

- `summary` (string)
- `description` (string)
- `category` (string)
- `parameters` (object; see **3.3**)
- `check` (object; see **4**)
  - OPTIONAL for `manual`/`unsupported`
  - REQUIRED for `automated`/`partial` (semantic rule)
- `evidence` (object; see **3.4**)
- `remediation` (object; see **3.5**)
- `references` (array of `Reference`)
- `framework_mappings` (array of `FrameworkMapping`)
- `tags` (array of string)
- `lifecycle` (object; see **3.6**)

------

### 3.2 Monitoring

`rule.monitoring` MUST be:

```

{
  "status": "automated|partial|manual|unsupported",
  "reason": "string?"
}
```

------

### 3.3 Parameters

`rule.parameters` is OPTIONAL.

If present, it MUST contain:

```

{
  "defaults": { "param_name": "any" },
  "schema": {
    "param_name": {
      "type": "string|boolean|integer|number|array|object",
      "description": "string?",
      "minimum": 0,
      "maximum": 0,
      "enum": ["any"]
    }
  }
}
```

Rules:

- `defaults` MUST be an object (map).
- `schema` is OPTIONAL. If present:
  - Each key in `schema` MUST exist in `defaults`.
  - `type` MUST be one of: `string|boolean|integer|number|array|object`.
  - If `enum` is provided, it MUST be a non-empty array.

Notes:

- `open-sspm-spec` compilers are responsible for validating that **any `value_param` used in checks is defined in `defaults`** (see semantic rules).

------

### 3.4 Evidence metadata

`rule.evidence` is OPTIONAL metadata used by UIs and engines for reporting.

```

{
  "affected_resources": {
    "dataset": "string",
    "id_field": "/json/pointer",
    "display_field": "/json/pointer"
  },
  "summary_templates": {
    "pass": "string?",
    "fail": "string?",
    "unknown": "string?",
    "error": "string?",
    "not_applicable": "string?"
  }
}
```

Rules:

- `summary_templates` is purely metadata. Engines MAY ignore it.
- Placeholders in templates (if any) are not standardized in v1.

------

### 3.5 Remediation metadata

`rule.remediation` is OPTIONAL.

```

{
  "instructions": "string",
  "risks": "string?",
  "effort": "low|medium|high?"
}
```

------

### 3.6 Lifecycle

`rule.lifecycle` is OPTIONAL. If absent, engines and compilers MUST treat `is_active` as `true`.

```

{
  "rule_version": "string?",
  "is_active": true,
  "replaced_by": "string?"
}
```

Notes:

- `replaced_by` SHOULD be in the form `<ruleset_key>/<rule_key>`.

------

## 4. Check specification (evaluation ABI)

### 4.1 Check common fields

A `check` object MUST include:

- `type` (string; one of the supported check types)

All checks MAY include these shared optional fields:

- `dataset_version` (integer ≥ 1)
- `on_missing_dataset` (enum: `unknown|error`) default `unknown`
- `on_permission_denied` (enum: `unknown|error`) default `unknown`
- `on_sync_error` (enum: `unknown|error`) default `error`
- `notes` (string)

#### Dataset version resolution

For any dataset reference within a check (e.g., `dataset`, `left.dataset`, `right.dataset`), the compiler MUST compute an **effective dataset version** as follows:

1. If `check.dataset_version` is present, it is the effective version.
2. Else if `ruleset.data_contracts` contains exactly one matching entry for that dataset key, that `version` is the effective version.
3. Else the effective version defaults to `1`.

If `ruleset.data_contracts` contains multiple entries for the same dataset key, then any check referencing that dataset MUST specify `check.dataset_version` (otherwise the version is ambiguous and the ruleset is invalid).

------

### 4.2 Predicate clause

Predicates are used in `where[]` and in `assert`.

#### Shape (non-join predicates)

```

{
  "path": "/json/pointer",
  "op": "eq|neq|lt|lte|gt|gte|exists|absent|in|contains",
  "value": "any?",
  "value_param": "string?"
}
```

Rules:

- `path` MUST be a JSON Pointer string (RFC 6901).
- Exactly one of `value` or `value_param` MAY be set, except:
  - If `op` is `exists` or `absent`, both `value` and `value_param` MUST be absent.
- If `value_param` is set, it MUST reference a key in `rule.parameters.defaults`.

------

### 4.3 Compare clause

Used by `dataset.count_compare` and `dataset.join_count_compare`.

```

{
  "op": "eq|neq|lt|lte|gt|gte",
  "value": 0,
  "value_param": "string?"
}
```

Rules:

- Exactly one of `value` or `value_param` MUST be set.
- If `value_param` is set, it MUST reference a key in `rule.parameters.defaults`.
- `value` MUST be an integer for count-based comparisons.

------

## 5. Check types

### 5.1 `manual.attestation`

#### Shape

```

{
  "type": "manual.attestation"
}
```

Rules:

- No additional fields.

------

### 5.2 `dataset.field_compare`

#### Purpose

Select rows from a dataset (`where[]`), then assert a predicate (`assert`) over each selected row. Apply match semantics and selection expectations.

#### Shape

```

{
  "type": "dataset.field_compare",
  "dataset": "string",
  "where": [ /* Predicate[] */ ],
  "assert": { /* Predicate */ },
  "expect": {
    "match": "all|any|none",
    "min_selected": 0,
    "on_empty": "pass|fail|unknown|error"
  }
}
```

Field requirements:

- `dataset` REQUIRED.
- `assert` REQUIRED.
- `where` OPTIONAL (default empty, meaning select all rows).
- `expect` OPTIONAL, defaults:
  - `match = "all"`
  - `min_selected = 0`
  - `on_empty = "unknown"`

Normative semantics (engine):

- Let `selected` be the rows where all `where` predicates evaluate true.
- If `selected` is empty:
  - Outcome MUST be `expect.on_empty` (default `unknown`).
- Else if `min_selected` is set and `selected.length < min_selected`:
  - Outcome MUST be `fail`.
- Else evaluate `assert` on each selected row to produce booleans.
  - If `match="all"`, pass iff all booleans true.
  - If `match="any"`, pass iff any boolean true.
  - If `match="none"`, pass iff all booleans false.
- Fail otherwise.

------

### 5.3 `dataset.count_compare`

#### Purpose

Count dataset rows that match `where[]`, then compare count to a threshold.

#### Shape

```

{
  "type": "dataset.count_compare",
  "dataset": "string",
  "where": [ /* Predicate[] */ ],
  "compare": { /* Compare */ }
}
```

Field requirements:

- `dataset` REQUIRED.
- `compare` REQUIRED.
- `where` OPTIONAL (default empty, meaning count all rows).

Normative semantics (engine):

- Let `count` be the number of rows satisfying all `where` predicates.
- Evaluate `count compare.op compare.value`.
- Pass iff comparison is true; fail otherwise.

------

### 5.4 `dataset.join_count_compare`

#### Purpose

Join two datasets by key, apply predicates over the joined rows, then count matches and compare.

#### Shape

```

{
  "type": "dataset.join_count_compare",
  "left": { "dataset": "string", "key_path": "/json/pointer" },
  "right": { "dataset": "string", "key_path": "/json/pointer" },
  "where": [
    {
      "left_path": "/json/pointer?",
      "right_path": "/json/pointer?",
      "op": "eq|neq|lt|lte|gt|gte|exists|absent|in|contains",
      "value": "any?",
      "value_param": "string?"
    }
  ],
  "on_unmatched_left": "ignore|count|error",
  "compare": { /* Compare */ }
}
```

Field requirements:

- `left` REQUIRED; contains:
  - `dataset` REQUIRED
  - `key_path` REQUIRED (JSON Pointer)
- `right` REQUIRED; contains:
  - `dataset` REQUIRED
  - `key_path` REQUIRED (JSON Pointer)
- `compare` REQUIRED
- `where` OPTIONAL
- `on_unmatched_left` OPTIONAL, default `"ignore"`

Where clause rules:

- Each `where[]` clause MUST set **exactly one** of `left_path` or `right_path`.
- `value_param` rules match **4.2**.

Unmatched-left semantics:

- `"ignore"`: unmatched left rows are excluded from joined rows.
- `"count"`: unmatched left rows are included with `right = null`.
- `"error"`: if any left row has no matching right row, the check result MUST be `error`.

Right-null predicate rule:

- When `on_unmatched_left="count"` and a joined row has `right = null`, any predicate using `right_path` MUST evaluate to `false`.

------

## 6. Semantic validation rules (compiler MUST enforce)

For every `opensspm.ruleset` document, a conforming compiler MUST enforce:

### 6.1 Identity and uniqueness

1. `ruleset.key` MUST be unique across all compiled rulesets.
2. Within a ruleset, each `rule.key` MUST be unique.

### 6.2 Scope constraints

1. If `ruleset.scope.kind="global"`, `connector_kind` MUST be absent/null/empty.
2. If `ruleset.scope.kind="connector_instance"`, `connector_kind` MUST be present and non-empty.

### 6.3 Monitoring/check constraints

1. If `rule.monitoring.status` is `automated` or `partial`, then `rule.check` MUST exist.
2. If `rule.monitoring.status` is `manual` or `unsupported`, then `rule.check` MAY be absent OR MAY be `{ "type": "manual.attestation" }`.

### 6.4 Supported check types only

1. `rule.check.type` MUST be one of:
   - `dataset.field_compare`
   - `dataset.count_compare`
   - `dataset.join_count_compare`
   - `manual.attestation`
      Unknown check types MUST be rejected.

### 6.5 Required data coverage

1. Every dataset referenced by a rule’s check MUST appear in that rule’s `required_data`.
   - For `dataset.field_compare` and `dataset.count_compare`, `check.dataset` MUST appear in `required_data`.
   - For `dataset.join_count_compare`, both `check.left.dataset` and `check.right.dataset` MUST appear in `required_data`.

### 6.6 Dataset version declarations

1. If `check.dataset_version` is set, then for every dataset referenced by that check there MUST be a matching entry in `ruleset.data_contracts` with `{dataset, version}` equal to `{dataset_key, check.dataset_version}`.
2. If `ruleset.data_contracts` contains multiple entries for the same dataset key, checks referencing that dataset MUST set `check.dataset_version`.

### 6.7 Parameter references

1. Every `value_param` used anywhere in the check MUST exist in `rule.parameters.defaults`.
   - If any `value_param` is used and `rule.parameters` is missing, the rule is invalid.
   - If `rule.parameters.schema` exists, any `value_param` referenced SHOULD have a schema entry; compilers MAY warn if missing.

### 6.8 Predicate structural constraints

1. In any predicate:
   - If `op` is `exists` or `absent`, `value` and `value_param` MUST be absent.
   - Otherwise, at most one of `value` and `value_param` MAY be present.
2. In `dataset.join_count_compare.where[]`:
   - Exactly one of `left_path` or `right_path` MUST be set per clause.

------

## 7. Deterministic normalization rules (compiler MUST apply)

Before hashing and emitting compiled artifacts, the compiler MUST normalize rulesets to ensure deterministic output.

### 7.1 Arrays treated as sets MUST be sorted

The compiler MUST sort the following arrays (stable, deterministic, ascending lexicographic unless stated otherwise):

- `ruleset.tags` (string)
- `ruleset.references` by `(url, title, type)`
- `ruleset.framework_mappings` by `(framework, control, enhancement, coverage, notes)`
- `ruleset.requirements.api_scopes` (string)
- `ruleset.requirements.permissions` (string)
- `ruleset.data_contracts` by `(dataset, version, description)`
- `ruleset.rules` by `rule.key`
- Per rule:
  - `rule.tags` (string)
  - `rule.references` by `(url, title, type)`
  - `rule.framework_mappings` by `(framework, control, enhancement, coverage, notes)`
  - `rule.required_data` (string)
  - `check.where` clauses MUST be sorted deterministically:
    - For non-join predicates: `(path, op, value_param, canonical(value))`
    - For join predicates: `(left_path?, right_path?, op, value_param, canonical(value))`

### 7.2 Canonicalization and hashing

After normalization:

1. Serialize the normalized object to JSON.
2. Canonicalize using **JCS (RFC 8785)**.
3. Compute **SHA-256** over the canonical bytes.
4. Represent as lowercase hex.

**Definition hashing MUST be computed over the normalized canonical representation**, not the source text.

------

## 8. Requirements index (compiler output)

The compiler MUST produce a requirements index consumed by SSPM apps for orchestration and preflight.

### 8.1 Output location

- `dist/index/requirements.json` MUST be produced alongside `dist/descriptor.v1.json`.

### 8.2 Required contents

The requirements index MUST include:

#### Per ruleset

- `ruleset_key`
- `status`
- `scope.kind`
- `scope.connector_kind` (if applicable)
- `datasets[]`: array of `{ dataset, version }` for all datasets referenced by any rule’s check
  - `version` MUST be the **effective dataset version** (see **4.1**).
- `check_types[]`: distinct set of check types used in the ruleset
- `value_params[]`: distinct set of all `value_param` identifiers referenced in any rule’s checks

#### Per rule

- `rule_key`
- `monitoring.status`
- `is_manual` (boolean)
   True iff monitoring.status is `manual` OR check.type is `manual.attestation` OR check is absent.
- `datasets[]`: array of `{ dataset, version }` referenced by that rule’s check
- `check_type` (string or null)
- `value_params[]`: value params referenced in that rule’s check

### 8.3 Computation rules (normative)

- Datasets referenced in `required_data` alone MUST NOT be treated as required inputs unless they are referenced by the check.
   (The check is the authoritative signal of runtime need; `required_data` is a declarative coverage list that must include check datasets.)
- For each dataset reference in a check, compute version using **4.1**.
- `check_types` is the set of `rule.check.type` for rules where `check` exists.
- `value_params` is the set of all `value_param` occurrences in predicates and compares.

------

## 9. Additive vs breaking strategy

### 9.1 Decision: keep `schema_version: 1` and extend additively

This update **does not bump** `schema_version` because the top-level document shape is non-negotiable and because existing ecosystems benefit from schema stability.

Instead:

- The canonical check DSL defined in **sections 4–5** is now normative for new authoring.
- A **legacy minimal check syntax** MAY be accepted by compilers under `schema_version: 1` as a migration aid (see **10**).
- The compiled descriptor (`dist/descriptor.v1.json`) MUST contain only the canonical check shapes, regardless of whether the source used legacy syntax.

### 9.2 Future breaking version

A future `schema_version: 2` MAY remove legacy minimal check syntax entirely. This spec does not define `schema_version: 2`.

------

## 10. Migration from legacy minimal check shape

### 10.1 Legacy check syntax (deprecated, optional input)

The prior minimal shape is characterized by:

- Single-field comparisons using `field/operator/value`
- Joins expressed with fields like `left_dataset/right_dataset` and join keys

Because the legacy syntax was not fully specified here, this section defines a **standard deprecated legacy form** that compilers MAY support.

#### Legacy: field compare

```

{
  "type": "dataset.field_compare",
  "dataset": "okta:policies/sign-on",
  "field": "/session/max_idle_minutes",
  "operator": "lte",
  "value": 15
}
```

#### Legacy: count compare

```

{
  "type": "dataset.count_compare",
  "dataset": "okta:log-streams",
  "operator": "gt",
  "value": 0,
  "where": [
    { "field": "/enabled", "operator": "eq", "value": true }
  ]
}
```

#### Legacy: join count compare

```

{
  "type": "dataset.join_count_compare",
  "left_dataset": "core:identities",
  "right_dataset": "core:entitlement_assignments",
  "left_key": "/email",
  "right_key": "/identity/email",
  "operator": "eq",
  "value": 0,
  "where": [
    { "side": "right", "field": "/entitlement/tags", "operator": "contains", "value": "admin" }
  ]
}
```

### 10.2 Legacy-to-canonical mapping rules (compiler)

If a compiler supports the legacy syntax, it MUST map as follows before hashing and emitting compiled artifacts:

- `field` → canonical predicate `assert.path`
- `operator` → canonical predicate `assert.op`
- `value` → canonical predicate `assert.value`
- Legacy `where[]` clauses with `{field, operator, value}` map to canonical `{path, op, value}`.
- Join legacy:
  - `left_dataset` → `left.dataset`
  - `right_dataset` → `right.dataset`
  - `left_key` → `left.key_path`
  - `right_key` → `right.key_path`
  - Legacy top-level `operator/value` → canonical `compare.op/value`
  - Legacy `where[].side` selects either `left_path` or `right_path`

Compilers SHOULD emit warnings when legacy syntax is used.

### 10.3 Author migration guidance

Authors SHOULD migrate by:

1. Replacing legacy fields with canonical `where/assert/compare` structures.
2. Adding `rule.parameters.defaults` and migrating hard-coded constants to `value_param` where appropriate.
3. Declaring versioned datasets in `ruleset.data_contracts` and setting `check.dataset_version` where needed.
4. Ensuring `rule.required_data` includes every dataset referenced by checks.

------

## 11. JSON examples (one ruleset per check type)

> These are illustrative examples. They use minimal prose and include parameters, error policies, `required_data`, and data contracts.

### 11.1 Example: `manual.attestation` (CIS Okta example)

CIS Okta IDaaS STIG rules are labeled “Manual” in the benchmark. This example shows a single manual attestation rule keying off a CIS rule ID.

```
{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "cis.okta.idaas_stig.v1",
    "name": "CIS Okta IDaaS STIG",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "status": "active",
    "source": {
      "name": "CIS",
      "version": "v1.0.0",
      "date": "2025-08-21",
      "url": "https://www.cisecurity.org/cis-benchmarks/"
    },
    "data_contracts": [],
    "rules": [
      {
        "key": "OKTA-APP-000020",
        "title": "OKTA-APP-000020",
        "severity": "medium",
        "monitoring": { "status": "manual" },
        "required_data": [],
        "check": { "type": "manual.attestation" },
        "summary": "Manual attestation required. Refer to CIS benchmark guidance.",
        "lifecycle": { "rule_version": "1.0.0", "is_active": true }
      }
    ]
  }
}
```

------

### 11.2 Example: `dataset.field_compare`

```

{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.okta.session_idle_timeout.v1",
    "name": "Example Okta session idle timeout",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "data_contracts": [
      { "dataset": "okta:policies/sign-on", "version": 1, "description": "Sign-on policies snapshot" }
    ],
    "rules": [
      {
        "key": "default_signon_policy.max_idle_minutes",
        "title": "Default sign-on policy idle timeout is <= configured maximum",
        "severity": "high",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:policies/sign-on"],
        "parameters": {
          "defaults": { "max_idle_minutes": 15 },
          "schema": {
            "max_idle_minutes": { "type": "integer", "minimum": 1, "maximum": 1440, "description": "Max idle timeout" }
          }
        },
        "check": {
          "type": "dataset.field_compare",
          "dataset": "okta:policies/sign-on",
          "dataset_version": 1,
          "on_missing_dataset": "unknown",
          "on_permission_denied": "unknown",
          "on_sync_error": "error",
          "where": [
            { "path": "/is_default", "op": "eq", "value": true }
          ],
          "assert": {
            "path": "/session/max_idle_minutes",
            "op": "lte",
            "value_param": "max_idle_minutes"
          },
          "expect": { "match": "all", "min_selected": 1, "on_empty": "error" },
          "notes": "If default policy missing, treat as error."
        }
      }
    ]
  }
}
```

------

### 11.3 Example: `dataset.count_compare`

```

{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.okta.log_streams_enabled.v1",
    "name": "Example Okta log streams enabled",
    "scope": { "kind": "connector_instance", "connector_kind": "okta" },
    "data_contracts": [
      { "dataset": "okta:log-streams", "version": 1, "description": "Log streams snapshot" }
    ],
    "rules": [
      {
        "key": "log_streams.at_least_n_enabled",
        "title": "At least N log streams are enabled",
        "severity": "medium",
        "monitoring": { "status": "automated" },
        "required_data": ["okta:log-streams"],
        "parameters": {
          "defaults": { "min_enabled": 1 },
          "schema": {
            "min_enabled": { "type": "integer", "minimum": 1, "maximum": 100 }
          }
        },
        "check": {
          "type": "dataset.count_compare",
          "dataset": "okta:log-streams",
          "dataset_version": 1,
          "on_missing_dataset": "unknown",
          "on_permission_denied": "unknown",
          "on_sync_error": "error",
          "where": [
            { "path": "/enabled", "op": "eq", "value": true }
          ],
          "compare": { "op": "gte", "value_param": "min_enabled" }
        }
      }
    ]
  }
}
```

------

### 11.4 Example: `dataset.join_count_compare`

```

{
  "schema_version": 1,
  "kind": "opensspm.ruleset",
  "ruleset": {
    "key": "example.global.no_admin_entitlements.v1",
    "name": "Example global admin entitlement hygiene",
    "scope": { "kind": "global" },
    "data_contracts": [
      { "dataset": "core:identities", "version": 1 },
      { "dataset": "core:entitlement_assignments", "version": 1 }
    ],
    "rules": [
      {
        "key": "no_admin_entitlements",
        "title": "No identities have admin entitlements",
        "severity": "high",
        "monitoring": { "status": "automated" },
        "required_data": ["core:identities", "core:entitlement_assignments"],
        "parameters": {
          "defaults": { "max_admin_entitlements": 0 },
          "schema": {
            "max_admin_entitlements": { "type": "integer", "minimum": 0 }
          }
        },
        "check": {
          "type": "dataset.join_count_compare",
          "dataset_version": 1,
          "on_missing_dataset": "unknown",
          "on_permission_denied": "unknown",
          "on_sync_error": "error",
          "left": { "dataset": "core:identities", "key_path": "/email" },
          "right": { "dataset": "core:entitlement_assignments", "key_path": "/identity/email" },
          "on_unmatched_left": "ignore",
          "where": [
            { "right_path": "/entitlement/tags", "op": "contains", "value": "admin" }
          ],
          "compare": { "op": "lte", "value_param": "max_admin_entitlements" }
        }
      }
    ]
  }
}
```

------

## 12. Schema changes summary (additions/renames) and rationale

This refined spec is an **additive** update to schema_version 1 (canonical authoring changes + optional legacy support).

### 12.1 Check DSL expansions

- Added canonical `where[]`, `assert`, `expect`, `compare`, `left/right` join sides.
   **Rationale:** express modern SSPM rule logic without embedding engine code.

### 12.2 Shared error policy fields on checks

- Added `dataset_version`, `on_missing_dataset`, `on_permission_denied`, `on_sync_error`, `notes`.
   **Rationale:** standardize behavior under missing data and sync failures.

### 12.3 Dataset contract declarations

- Added `ruleset.data_contracts[]` with `{dataset, version, description?}`.
   **Rationale:** explicit versioned dataset usage required for portability and determinism.

### 12.4 Parameter schemas

- Added `rule.parameters.defaults` and `rule.parameters.schema` entries.
   **Rationale:** enable parameterized rules and validation of `value_param` references.

### 12.5 Evidence/remediation/lifecycle metadata

- Added `rule.evidence`, `rule.remediation`, `rule.lifecycle`.
   **Rationale:** preserve rich SSPM metadata without requiring evaluation logic generation.

### 12.6 Legacy minimal check shape

- Defined as deprecated optional input; compilers MAY support and MUST map to canonical for hashing/descriptor.
   **Rationale:** enable migration without breaking existing adopters.

------

## 13. JSON Schema snippet (illustrative)

The following snippet shows the intended **union** for `rule.check` at a high level. (This is illustrative; full schemas live under `metaschema/`.)

```

{
  "$id": "opensspm.ruleset.schema.json#/definitions/Check",
  "oneOf": [
    { "$ref": "#/definitions/CheckManualAttestation" },
    { "$ref": "#/definitions/CheckDatasetFieldCompare" },
    { "$ref": "#/definitions/CheckDatasetCountCompare" },
    { "$ref": "#/definitions/CheckDatasetJoinCountCompare" }
  ]
}
```

------

## 14. Notes and assumptions

- This spec defines evaluation semantics at the **check ABI** level so multiple engines can implement it consistently. The spec repository MUST NOT generate evaluation logic.
- Legacy check field names are standardized here for migration even if prior minimal implementations differed slightly. Compilers MAY support legacy syntax with warnings and MUST compile to canonical before hashing and emitting `dist/descriptor.v1.json`.

------