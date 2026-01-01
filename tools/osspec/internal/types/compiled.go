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

type RulesetRequirement struct {
	RulesetKey  string       `json:"ruleset_key"`
	Status      string       `json:"status"`
	Scope       Scope        `json:"scope"`
	Datasets    []DatasetRefSpec `json:"datasets"`
	CheckTypes  []CheckType  `json:"check_types"`
	ValueParams []string     `json:"value_params"`
	Rules       []RuleRequirement `json:"rules"`
}

type RuleRequirement struct {
	RuleKey          string           `json:"rule_key"`
	IsManual         bool             `json:"is_manual"`
	Datasets         []DatasetRefSpec `json:"datasets"`
	CheckType        *CheckType       `json:"check_type"`
	ValueParams      []string         `json:"value_params"`
	Monitoring       struct {
		Status MonitoringStatus `json:"status"`
	} `json:"monitoring"`
}

type Compiled[T any] struct {
	SourcePath string `json:"source_path"`
	Hash       string `json:"hash"`
	Object     T      `json:"object"`
}

type DescriptorV1 struct {
	SchemaVersion   int              `json:"schema_version"`
	Kind            string           `json:"kind"`
	Version         Version          `json:"version"`
	Dictionary      Compiled[DictionaryDoc] `json:"dictionary"`
	Rulesets        []Compiled[RulesetDoc]  `json:"rulesets"`
	DatasetContracts []Compiled[DatasetContractDoc] `json:"dataset_contracts"`
	Connectors      []Compiled[ConnectorManifestDoc] `json:"connectors"`
	Profiles        []Compiled[ProfileDoc]  `json:"profiles"`
	Index           struct {
		Requirements RequirementsIndex `json:"requirements"`
		Artifacts    ArtifactsIndex    `json:"artifacts"`
	} `json:"index"`
}

type CodegenRequest struct {
	SchemaVersion int         `json:"schema_version"`
	Kind          string      `json:"kind"`
	Language      string      `json:"language"`
	Descriptor    DescriptorV1 `json:"descriptor"`
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
