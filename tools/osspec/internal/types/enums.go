package types

type ScopeKind string

const (
	ScopeKindGlobal            ScopeKind = "global"
	ScopeKindConnectorInstance ScopeKind = "connector_instance"
)

type MonitoringStatus string

const (
	MonitoringStatusAutomated   MonitoringStatus = "automated"
	MonitoringStatusPartial     MonitoringStatus = "partial"
	MonitoringStatusManual      MonitoringStatus = "manual"
	MonitoringStatusUnsupported MonitoringStatus = "unsupported"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type CheckType string

const (
	CheckTypeDatasetFieldCompare     CheckType = "dataset.field_compare"
	CheckTypeDatasetCountCompare     CheckType = "dataset.count_compare"
	CheckTypeDatasetJoinCountCompare CheckType = "dataset.join_count_compare"
	CheckTypeManualAttestation       CheckType = "manual.attestation"
)

type Operator string

const (
	OperatorEq       Operator = "eq"
	OperatorNeq      Operator = "neq"
	OperatorLt       Operator = "lt"
	OperatorLte      Operator = "lte"
	OperatorGt       Operator = "gt"
	OperatorGte      Operator = "gte"
	OperatorExists   Operator = "exists"
	OperatorAbsent   Operator = "absent"
	OperatorIn       Operator = "in"
	OperatorContains Operator = "contains"
)

type CompareOp string

const (
	CompareOpEq  CompareOp = "eq"
	CompareOpNeq CompareOp = "neq"
	CompareOpLt  CompareOp = "lt"
	CompareOpLte CompareOp = "lte"
	CompareOpGt  CompareOp = "gt"
	CompareOpGte CompareOp = "gte"
)

type ErrorPolicy string

const (
	ErrorPolicyUnknown ErrorPolicy = "unknown"
	ErrorPolicyError   ErrorPolicy = "error"
)

type OnUnmatchedLeft string

const (
	OnUnmatchedLeftIgnore OnUnmatchedLeft = "ignore"
	OnUnmatchedLeftCount  OnUnmatchedLeft = "count"
	OnUnmatchedLeftError  OnUnmatchedLeft = "error"
)

type FieldCompareMatch string

const (
	FieldCompareMatchAll  FieldCompareMatch = "all"
	FieldCompareMatchAny  FieldCompareMatch = "any"
	FieldCompareMatchNone FieldCompareMatch = "none"
)

type FieldCompareOnEmpty string

const (
	FieldCompareOnEmptyPass    FieldCompareOnEmpty = "pass"
	FieldCompareOnEmptyFail    FieldCompareOnEmpty = "fail"
	FieldCompareOnEmptyUnknown FieldCompareOnEmpty = "unknown"
	FieldCompareOnEmptyError   FieldCompareOnEmpty = "error"
)

type ReferenceType string

const (
	ReferenceTypeDocumentation ReferenceType = "documentation"
	ReferenceTypeStandard      ReferenceType = "standard"
	ReferenceTypeBlog          ReferenceType = "blog"
	ReferenceTypeTicket        ReferenceType = "ticket"
	ReferenceTypeOther         ReferenceType = "other"
)

type FrameworkCoverageKind string

const (
	FrameworkCoverageDirect     FrameworkCoverageKind = "direct"
	FrameworkCoveragePartial    FrameworkCoverageKind = "partial"
	FrameworkCoverageSupporting FrameworkCoverageKind = "supporting"
)

type RemediationEffort string

const (
	RemediationEffortLow    RemediationEffort = "low"
	RemediationEffortMedium RemediationEffort = "medium"
	RemediationEffortHigh   RemediationEffort = "high"
)

type DatasetErrorKind string

const (
	DatasetErrorKindMissingIntegration DatasetErrorKind = "missing_integration"
	DatasetErrorKindMissingDataset     DatasetErrorKind = "missing_dataset"
	DatasetErrorKindPermissionDenied   DatasetErrorKind = "permission_denied"
	DatasetErrorKindSyncFailed         DatasetErrorKind = "sync_failed"
	DatasetErrorKindEngineError        DatasetErrorKind = "engine_error"
)
