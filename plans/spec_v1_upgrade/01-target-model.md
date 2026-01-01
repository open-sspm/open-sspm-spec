# Spec v1 refined upgrade - Target model

This describes the target internal Go model for `kind: opensspm.ruleset` and how compilation canonicalizes, normalizes, and hashes it.

## Go struct layout (names only)

### Top-level document

- `types.RulesetDoc`
  - `SchemaVersion int`
  - `Kind string`
  - `Ruleset types.Ruleset`

### Ruleset

- `types.Ruleset`
  - `Key string` (required)
  - `Name string` (required)
  - `Scope types.Scope` (required)
  - `Status string` (optional, default `"active"`)
  - `Source *types.Source` (optional)
  - `Description string` (optional)
  - `Tags []string` (optional)
  - `References []types.Reference` (optional)
  - `FrameworkMappings []types.FrameworkMapping` (optional)
  - `Requirements *types.RulesetRequirements` (optional)
  - `DataContracts []types.DatasetContractRef` (optional)
  - `Rules []types.Rule` (required)

### Rule

- `types.Rule`
  - `Key string` (required, unique within ruleset)
  - `Title string` (required)
  - `Severity types.Severity` (required)
  - `Monitoring types.Monitoring` (required)
  - `RequiredData []string` (required, may be empty)
  - `Summary string` (optional)
  - `Description string` (optional)
  - `Category string` (optional)
  - `Parameters *types.Parameters` (optional)
  - `Check *types.Check` (optional)
  - `Evidence *types.Evidence` (optional)
  - `Remediation *types.Remediation` (optional)
  - `References []types.Reference` (optional)
  - `FrameworkMappings []types.FrameworkMapping` (optional)
  - `Tags []string` (optional)
  - `Lifecycle *types.Lifecycle` (optional)

### Parameters

- `types.Parameters`
  - `Defaults map[string]any` (required if `parameters` is present)
  - `Schema map[string]types.ParameterSchema` (optional)
- `types.ParameterSchema`
  - `Type string` (required if schema entry exists)
  - `Description string` (optional)
  - `Minimum *float64` (optional)
  - `Maximum *float64` (optional)
  - `Enum []any` (optional)

### Metadata

- `types.Scope` (unchanged shape; semantic rules updated)
- `types.Source` (unchanged fields, now optional on rulesets)
- `types.Reference` - `{title, url, type}`
- `types.FrameworkMapping` - `{framework, control, enhancement?, coverage, notes?}`
- `types.RulesetRequirements` - `{api_scopes, permissions, notes?}`
- `types.DatasetContractRef` - `{dataset, version, description?}`
- `types.Evidence` - `{affected_resources, summary_templates}`
- `types.Remediation` - `{instructions, risks?, effort?}`
- `types.Lifecycle` - `{rule_version?, is_active, replaced_by?}`

## Canonical check model

### Shared check fields

- `types.Check`
  - `Type types.CheckType` (required)
  - `DatasetVersion int` (optional)
  - `OnMissingDataset types.ErrorPolicy` (optional, default `"unknown"`)
  - `OnPermissionDenied types.ErrorPolicy` (optional, default `"unknown"`)
  - `OnSyncError types.ErrorPolicy` (optional, default `"error"`)
  - `Notes string` (optional)

### Check variants (single struct, type-discriminated)

The check struct contains a superset of fields and is validated semantically based on `check.type`:

- `manual.attestation`
  - no additional fields
- `dataset.field_compare`
  - `Dataset string`
  - `Where []types.Predicate` (optional)
  - `Assert *types.Predicate` (required)
  - `Expect *types.FieldCompareExpect` (optional)
- `dataset.count_compare`
  - `Dataset string`
  - `Where []types.Predicate` (optional)
  - `Compare *types.Compare` (required)
- `dataset.join_count_compare`
  - `Left *types.JoinSide` (required)
  - `Right *types.JoinSide` (required)
  - `Where []types.Predicate` (optional, join form)
  - `OnUnmatchedLeft types.OnUnmatchedLeft` (optional, default `"ignore"`)
  - `Compare *types.Compare` (required)

### Predicates and compare

- `types.Predicate`
  - Non-join: `{path, op, value?, value_param?}`
  - Join: `{left_path?, right_path?, op, value?, value_param?}` (exactly one of left_path/right_path)
- `types.Compare`
  - `{op, value?, value_param?}` where exactly one of `value` or `value_param` is set.
- `types.FieldCompareExpect`
  - `{match, min_selected, on_empty}` with defaults `all`, `0`, `unknown`.

## Canonicalization, normalization, hashing

### Normalization

Before hashing and emitting compiled artifacts, the compiler normalizes:

- Sort set-like arrays (ruleset and rule tags/references/framework_mappings/requirements, rules, required_data, data_contracts) per `newspec.md` section 7.
- Sort `check.where[]` deterministically, using a stable key that includes a canonical JSON rendering of `value`.
- Apply default values that are explicitly defined as defaults in `newspec.md` (for consistent hashing when authors omit defaults).

### Hashing

For every compiled object:

1. Normalize the in-memory object.
2. Marshal to JSON.
3. Canonicalize JSON using JCS (RFC 8785).
4. Compute SHA-256 and encode as lowercase hex.

## Effective dataset version resolution

The compiler implements `effectiveDatasetVersion(datasetKey, ruleset.data_contracts, check.dataset_version) -> version` per `newspec.md` section 4.1 and uses it for:

- requirements index dataset `{dataset, version}` output
- semantic validation of ambiguous or undeclared dataset versions
