package types

import "encoding/json"

type Header struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
}

type Version struct {
	Project            string `json:"project"`
	Repo               string `json:"repo"`
	SpecVersion        string `json:"spec_version"`
	SchemaVersion      int    `json:"schema_version"`
	GeneratorMinVersion string `json:"generator_min_version"`
}

type DictionaryDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Dictionary    struct {
		Enums map[string][]string `json:"enums"`
	} `json:"dictionary"`
}

type Reference struct {
	Title string        `json:"title,omitempty"`
	URL   string        `json:"url"`
	Type  ReferenceType `json:"type,omitempty"`
}

type Scope struct {
	Kind          ScopeKind `json:"kind"`
	ConnectorKind string    `json:"connector_kind,omitempty"`
}

type Source struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Date    string `json:"date"`
	URL     string `json:"url,omitempty"`
}

type RulesetDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Ruleset       Ruleset `json:"ruleset"`
}

type Ruleset struct {
	Key               string             `json:"key"`
	Name              string             `json:"name"`
	Scope             Scope              `json:"scope"`
	Source            *Source            `json:"source,omitempty"`
	Status            string             `json:"status,omitempty"`
	Description       string             `json:"description,omitempty"`
	Tags              []string           `json:"tags,omitempty"`
	References        []Reference        `json:"references,omitempty"`
	FrameworkMappings []FrameworkMapping `json:"framework_mappings,omitempty"`
	Requirements      *RulesetRequirements `json:"requirements,omitempty"`
	DataContracts     []DatasetContractRef `json:"data_contracts,omitempty"`
	Rules             []Rule             `json:"rules"`
}

type DatasetRefSpec struct {
	Dataset string `json:"dataset"`
	Version int    `json:"version"`
}

type FrameworkMapping struct {
	Framework   string                `json:"framework"`
	Control     string                `json:"control"`
	Enhancement string                `json:"enhancement,omitempty"`
	Coverage    FrameworkCoverageKind `json:"coverage,omitempty"`
	Notes       string                `json:"notes,omitempty"`
}

type RulesetRequirements struct {
	APIScopes    []string `json:"api_scopes,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Notes        string   `json:"notes,omitempty"`
}

type DatasetContractRef struct {
	Dataset      string `json:"dataset"`
	Version      int    `json:"version"`
	Description  string `json:"description,omitempty"`
}

type Rule struct {
	Key               string             `json:"key"`
	Title             string             `json:"title"`
	Severity          Severity           `json:"severity"`
	Monitoring        Monitoring         `json:"monitoring"`
	RequiredData      []string           `json:"required_data"`
	Summary           string             `json:"summary,omitempty"`
	Description       string             `json:"description,omitempty"`
	Category          string             `json:"category,omitempty"`
	Parameters        *Parameters        `json:"parameters,omitempty"`
	Check             *Check             `json:"check,omitempty"`
	Evidence          *Evidence          `json:"evidence,omitempty"`
	Remediation       *Remediation       `json:"remediation,omitempty"`
	References        []Reference        `json:"references,omitempty"`
	FrameworkMappings []FrameworkMapping `json:"framework_mappings,omitempty"`
	Tags              []string           `json:"tags,omitempty"`
	Lifecycle         *Lifecycle         `json:"lifecycle,omitempty"`
}

type Monitoring struct {
	Status MonitoringStatus `json:"status"`
	Reason string           `json:"reason,omitempty"`
}

type Parameters struct {
	Defaults map[string]any                 `json:"defaults"`
	Schema   map[string]ParameterSchema     `json:"schema,omitempty"`
}

type ParameterSchema struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
	Enum        []any    `json:"enum,omitempty"`
}

type Evidence struct {
	AffectedResources *AffectedResources     `json:"affected_resources,omitempty"`
	SummaryTemplates  *EvidenceSummaryTemplates `json:"summary_templates,omitempty"`
}

type AffectedResources struct {
	Dataset       string `json:"dataset"`
	IDField       string `json:"id_field"`
	DisplayField  string `json:"display_field"`
}

type EvidenceSummaryTemplates struct {
	Pass          string `json:"pass,omitempty"`
	Fail          string `json:"fail,omitempty"`
	Unknown       string `json:"unknown,omitempty"`
	Error         string `json:"error,omitempty"`
	NotApplicable string `json:"not_applicable,omitempty"`
}

type Remediation struct {
	Instructions string         `json:"instructions"`
	Risks        string         `json:"risks,omitempty"`
	Effort       RemediationEffort `json:"effort,omitempty"`
}

type Lifecycle struct {
	RuleVersion string `json:"rule_version,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	ReplacedBy  string `json:"replaced_by,omitempty"`
}

type Check struct {
	Type CheckType `json:"type"`

	// Common (all checks)
	DatasetVersion     int         `json:"dataset_version,omitempty"`
	OnMissingDataset   ErrorPolicy `json:"on_missing_dataset,omitempty"`
	OnPermissionDenied ErrorPolicy `json:"on_permission_denied,omitempty"`
	OnSyncError        ErrorPolicy `json:"on_sync_error,omitempty"`
	Notes              string      `json:"notes,omitempty"`

	// dataset.field_compare, dataset.count_compare
	Dataset string      `json:"dataset,omitempty"`
	Where   []Predicate `json:"where,omitempty"`

	// dataset.field_compare
	Assert *Predicate         `json:"assert,omitempty"`
	Expect *FieldCompareExpect `json:"expect,omitempty"`

	// dataset.count_compare, dataset.join_count_compare
	Compare *Compare `json:"compare,omitempty"`

	// dataset.join_count_compare
	Left            *JoinSide        `json:"left,omitempty"`
	Right           *JoinSide        `json:"right,omitempty"`
	OnUnmatchedLeft OnUnmatchedLeft  `json:"on_unmatched_left,omitempty"`
}

type Predicate struct {
	// Non-join predicate
	Path string `json:"path,omitempty"`

	// Join predicate (exactly one of left_path/right_path)
	LeftPath  string `json:"left_path,omitempty"`
	RightPath string `json:"right_path,omitempty"`

	Op        Operator `json:"op"`
	Value     any      `json:"value,omitempty"`
	ValueParam string  `json:"value_param,omitempty"`
}

type Compare struct {
	Op        CompareOp `json:"op"`
	Value     *int      `json:"value,omitempty"`
	ValueParam string   `json:"value_param,omitempty"`
}

type FieldCompareExpect struct {
	Match       FieldCompareMatch  `json:"match,omitempty"`
	MinSelected int                `json:"min_selected,omitempty"`
	OnEmpty     FieldCompareOnEmpty `json:"on_empty,omitempty"`
}

type JoinSide struct {
	Dataset string `json:"dataset"`
	KeyPath string `json:"key_path"`
}

type DatasetContractDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Dataset       DatasetContract `json:"dataset"`
}

type DatasetContract struct {
	Key               string          `json:"key"`
	Version           int             `json:"version"`
	Description       string          `json:"description,omitempty"`
	PrimaryKey        string          `json:"primary_key,omitempty"`
	RecommendedDisplay string         `json:"recommended_display,omitempty"`
	Schema            json.RawMessage `json:"schema"`
}

type ConnectorManifestDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Connector     ConnectorManifest `json:"connector"`
}

type ConnectorManifest struct {
	Kind     string           `json:"kind"`
	Name     string           `json:"name"`
	Provides []DatasetRefSpec `json:"provides"`
}

type ProfileDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Profile       Profile `json:"profile"`
}

type Profile struct {
	Key         string              `json:"key"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Rulesets    []ProfileRulesetRef `json:"rulesets"`
}

type ProfileRulesetRef struct {
	Key     string `json:"key"`
	Version string `json:"version,omitempty"`
}
