package types

type Artifact struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	SourcePath string `json:"source_path"`
	Hash       string `json:"hash"`
}

type ArtifactsIndex struct {
	SchemaVersion int        `json:"schema_version"`
	Kind          string     `json:"kind"`
	Artifacts     []Artifact `json:"artifacts"`
}

type RequirementsIndex struct {
	SchemaVersion int                  `json:"schema_version"`
	Kind          string               `json:"kind"`
	Rulesets      []RulesetRequirement `json:"rulesets"`
}

type RuleInputRequirement struct {
	Name       string   `json:"name"`
	Type       string   `json:"type,omitempty"`
	Default    any      `json:"default,omitempty"`
	HasDefault bool     `json:"has_default"`
	Sources    []string `json:"sources"`
}

type RulesetInputRequirement struct {
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Sources  []string `json:"sources"`
	RuleKeys []string `json:"rule_keys"`
}

type RulesetRequirement struct {
	RulesetKey         string                    `json:"ruleset_key"`
	Status             string                    `json:"status"`
	Scope              Scope                     `json:"scope"`
	Datasets           []DatasetRefSpec          `json:"datasets"`
	Engines            []CheckEngine             `json:"engines"`
	DatasetsReferenced []string                  `json:"datasets_referenced"`
	ParamsReferenced   []string                  `json:"params_referenced"`
	Inputs             []RulesetInputRequirement `json:"inputs"`
	Rules              []RuleRequirement         `json:"rules"`
}

type RuleRequirementMonitoring struct {
	Status MonitoringStatus `json:"status"`
}

type RuleRequirement struct {
	RuleKey            string                    `json:"rule_key"`
	IsManual           bool                      `json:"is_manual"`
	Datasets           []DatasetRefSpec          `json:"datasets"`
	Engine             *CheckEngine              `json:"engine,omitempty"`
	Expression         string                    `json:"expression,omitempty"`
	ExpressionSHA256   string                    `json:"expression_sha256,omitempty"`
	DatasetsReferenced []string                  `json:"datasets_referenced"`
	ParamsReferenced   []string                  `json:"params_referenced"`
	Inputs             []RuleInputRequirement    `json:"inputs"`
	Monitoring         RuleRequirementMonitoring `json:"monitoring"`
}

type Compiled[T any] struct {
	SourcePath string `json:"source_path"`
	Hash       string `json:"hash"`
	Object     T      `json:"object"`
}

type DescriptorIndex struct {
	Requirements RequirementsIndex `json:"requirements"`
	Artifacts    ArtifactsIndex    `json:"artifacts"`
}

type Descriptor struct {
	SchemaVersion int                    `json:"schema_version"`
	Kind          string                 `json:"kind"`
	Version       Version                `json:"version"`
	Rulesets      []Compiled[RulesetDoc] `json:"rulesets"`
	Profiles      []Compiled[ProfileDoc] `json:"profiles"`
	Index         DescriptorIndex        `json:"index"`
}

type CodegenRequest struct {
	SchemaVersion int        `json:"schema_version"`
	Kind          string     `json:"kind"`
	Language      string     `json:"language"`
	Descriptor    Descriptor `json:"descriptor"`
}

type CodegenResponse struct {
	SchemaVersion int           `json:"schema_version"`
	Kind          string        `json:"kind"`
	Files         []CodegenFile `json:"files"`
}

type CodegenFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
