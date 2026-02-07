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

type CheckEngine string

const (
	CheckEngineCEL     CheckEngine = "cel"
	CheckEngineCELPlan CheckEngine = "cel_plan"
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

func enumStrings[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

// EnumValues returns the canonical enum value catalog used by generators.
func EnumValues() map[string][]string {
	return map[string][]string{
		"ScopeKind":             enumStrings([]ScopeKind{ScopeKindGlobal, ScopeKindConnectorInstance}),
		"MonitoringStatus":      enumStrings([]MonitoringStatus{MonitoringStatusAutomated, MonitoringStatusPartial, MonitoringStatusManual, MonitoringStatusUnsupported}),
		"Severity":              enumStrings([]Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}),
		"CheckEngine":           enumStrings([]CheckEngine{CheckEngineCEL, CheckEngineCELPlan}),
		"ReferenceType":         enumStrings([]ReferenceType{ReferenceTypeDocumentation, ReferenceTypeStandard, ReferenceTypeBlog, ReferenceTypeTicket, ReferenceTypeOther}),
		"FrameworkCoverageKind": enumStrings([]FrameworkCoverageKind{FrameworkCoverageDirect, FrameworkCoveragePartial, FrameworkCoverageSupporting}),
		"RemediationEffort":     enumStrings([]RemediationEffort{RemediationEffortLow, RemediationEffortMedium, RemediationEffortHigh}),
		"DatasetErrorKind":      enumStrings([]DatasetErrorKind{DatasetErrorKindMissingIntegration, DatasetErrorKindMissingDataset, DatasetErrorKindPermissionDenied, DatasetErrorKindSyncFailed, DatasetErrorKindEngineError}),
	}
}
