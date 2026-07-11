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
	Key           string               `json:"key"`
	Name          string               `json:"name"`
	Scope         Scope                `json:"scope"`
	Source        *Source              `json:"source,omitempty"`
	Status        string               `json:"status,omitempty"`
	Description   string               `json:"description,omitempty"`
	Tags          []string             `json:"tags,omitempty"`
	References    []Reference          `json:"references,omitempty"`
	DataContracts []DatasetContractRef `json:"data_contracts,omitempty"`
	Policy        *RegoPolicy          `json:"policy,omitempty"`
	Rules         []Rule               `json:"rules"`
}

type DatasetContractRef struct {
	Dataset     string `json:"dataset"`
	Version     int    `json:"version"`
	Description string `json:"description,omitempty"`
}

type Rule struct {
	Key          string         `json:"key"`
	Title        string         `json:"title"`
	Severity     Severity       `json:"severity"`
	Monitoring   Monitoring     `json:"monitoring"`
	RequiredData []string       `json:"required_data"`
	Summary      string         `json:"summary,omitempty"`
	Description  string         `json:"description,omitempty"`
	Category     string         `json:"category,omitempty"`
	Parameters   map[string]any `json:"parameters,omitempty"`
	Check        *Check         `json:"check,omitempty"`
	References   []Reference    `json:"references,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
}

type Monitoring struct {
	Status MonitoringStatus `json:"status"`
	Reason string           `json:"reason,omitempty"`
}

type Check struct {
	Engine   CheckEngine `json:"engine"`
	Package  string      `json:"package,omitempty"`
	Query    string      `json:"query"`
	Rego     string      `json:"rego,omitempty"`
	RegoPath string      `json:"rego_path,omitempty"`
}

type RegoPolicy struct {
	Engine   CheckEngine `json:"engine"`
	Package  string      `json:"package"`
	Query    string      `json:"query,omitempty"`
	Rego     string      `json:"rego,omitempty"`
	RegoPath string      `json:"rego_path,omitempty"`
}

type EntityPolicyPackDoc struct {
	SchemaVersion    int              `json:"schema_version"`
	Kind             string           `json:"kind"`
	EntityPolicyPack EntityPolicyPack `json:"entity_policy_pack"`
}

type EntityPolicyPack struct {
	Metadata EntityPolicyMetadata `json:"metadata"`
	Inputs   EntityPolicyInputs   `json:"inputs,omitempty"`
	Policy   RegoPolicy           `json:"policy"`
}

type EntityPolicyMetadata struct {
	ID      string             `json:"id"`
	Version string             `json:"version"`
	Domain  EntityPolicyDomain `json:"domain"`
}

type EntityPolicyInputs struct {
	Schema string `json:"schema,omitempty"`
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
	SchemaVersion int                     `json:"schema_version"`
	Kind          string                  `json:"kind"`
	ArtifactKind  string                  `json:"artifact_kind,omitempty"`
	ArtifactKey   string                  `json:"artifact_key,omitempty"`
	RuleKey       string                  `json:"rule_key,omitempty"`
	Description   string                  `json:"description,omitempty"`
	Parameters    map[string]any          `json:"parameters,omitempty"`
	Inputs        map[string][]any        `json:"inputs,omitempty"`
	EntityInput   map[string]any          `json:"entity_input,omitempty"`
	Expect        string                  `json:"expect,omitempty"`
	ExpectEntity  *EntityPolicyTestExpect `json:"expect_entity,omitempty"`
}

type EntityPolicyTestExpect struct {
	RiskLevel string                   `json:"risk_level,omitempty"`
	RiskScore *int                     `json:"risk_score,omitempty"`
	Signals   []EntityPolicyTestSignal `json:"signals,omitempty"`
}

type EntityPolicyTestSignal struct {
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title,omitempty"`
}
