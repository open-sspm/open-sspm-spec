package types

type Header struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
}

type Version struct {
	Project             string `json:"project"`
	Repo                string `json:"repo"`
	SpecVersion         string `json:"spec_version"`
	SchemaVersion       int    `json:"schema_version"`
	GeneratorMinVersion string `json:"generator_min_version"`
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
	SchemaVersion int     `json:"schema_version"`
	Kind          string  `json:"kind"`
	Ruleset       Ruleset `json:"ruleset"`
}

type Ruleset struct {
	Key               string               `json:"key"`
	Name              string               `json:"name"`
	Scope             Scope                `json:"scope"`
	Source            *Source              `json:"source,omitempty"`
	Status            string               `json:"status,omitempty"`
	Description       string               `json:"description,omitempty"`
	Tags              []string             `json:"tags,omitempty"`
	References        []Reference          `json:"references,omitempty"`
	FrameworkMappings []FrameworkMapping   `json:"framework_mappings,omitempty"`
	Requirements      *RulesetRequirements `json:"requirements,omitempty"`
	DataContracts     []DatasetContractRef `json:"data_contracts,omitempty"`
	Rules             []Rule               `json:"rules"`
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
	APIScopes   []string `json:"api_scopes,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

type DatasetContractRef struct {
	Dataset     string `json:"dataset"`
	Version     int    `json:"version"`
	Description string `json:"description,omitempty"`
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
	Defaults map[string]any             `json:"defaults"`
	Schema   map[string]ParameterSchema `json:"schema,omitempty"`
}

type ParameterSchema struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Minimum     *float64 `json:"minimum,omitempty"`
	Maximum     *float64 `json:"maximum,omitempty"`
	Enum        []any    `json:"enum,omitempty"`
}

type Evidence struct {
	AffectedResources *AffectedResources        `json:"affected_resources,omitempty"`
	SummaryTemplates  *EvidenceSummaryTemplates `json:"summary_templates,omitempty"`
}

type AffectedResources struct {
	Dataset      string `json:"dataset"`
	IDField      string `json:"id_field"`
	DisplayField string `json:"display_field"`
}

type EvidenceSummaryTemplates struct {
	Pass          string `json:"pass,omitempty"`
	Fail          string `json:"fail,omitempty"`
	Unknown       string `json:"unknown,omitempty"`
	Error         string `json:"error,omitempty"`
	NotApplicable string `json:"not_applicable,omitempty"`
}

type Remediation struct {
	Instructions string            `json:"instructions"`
	Risks        string            `json:"risks,omitempty"`
	Effort       RemediationEffort `json:"effort,omitempty"`
}

type Lifecycle struct {
	RuleVersion string `json:"rule_version,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
	ReplacedBy  string `json:"replaced_by,omitempty"`
}

type Check struct {
	Engine     CheckEngine `json:"engine"`
	Expression string      `json:"expression,omitempty"`
	Plan       *CheckPlan  `json:"plan,omitempty"`
}

type CheckPlan struct {
	Type               string            `json:"type"`
	Dataset            string            `json:"dataset"`
	WhereExpression    string            `json:"where_expression,omitempty"`
	AssertExpression   string            `json:"assert_expression,omitempty"`
	Expect             *CheckPlanExpect  `json:"expect,omitempty"`
	Compare            *CheckPlanCompare `json:"compare,omitempty"`
	OnMissingDataset   string            `json:"on_missing_dataset,omitempty"`
	OnPermissionDenied string            `json:"on_permission_denied,omitempty"`
	OnSyncError        string            `json:"on_sync_error,omitempty"`
}

type CheckPlanExpect struct {
	Match       string `json:"match,omitempty"`
	MinSelected int    `json:"min_selected,omitempty"`
	OnEmpty     string `json:"on_empty,omitempty"`
}

type CheckPlanCompare struct {
	Op    string `json:"op"`
	Value any    `json:"value"`
}

type ProfileDoc struct {
	SchemaVersion int     `json:"schema_version"`
	Kind          string  `json:"kind"`
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

type TestCaseDoc struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	RuleKey       string           `json:"rule_key"`
	Description   string           `json:"description,omitempty"`
	Parameters    map[string]any   `json:"parameters,omitempty"`
	Inputs        map[string][]any `json:"inputs,omitempty"`
	Expect        string           `json:"expect"`
}
