package siem

import (
	"strings"
	"time"

	"basecheck-agent/pkg/controlset"
	"basecheck-agent/pkg/database"
)

// FindingContext provides context for converting a finding to a SIEM event.
type FindingContext struct {
	AgentID        string
	AgentVersion   string
	SystemID       string
	SystemName     string
	DatabaseEngine string
	Environment    string
	ControlPackName    string
	ControlPackVersion string
	Mode           string // siem_only, http, file
	Destination    string // webhook, syslog
}

// ConvertFindings converts control results to SIEM events.
// Returns events for findings with FAIL, REVIEW, or LICENSE status.
func ConvertFindings(results []*controlset.ControlResult, ctx FindingContext) []*Event {
	now := time.Now().UTC()
	var events []*Event

	for _, result := range results {
		for _, proc := range result.Procedures {
			// Only emit events for actionable statuses
			if !isActionableStatus(proc.Status) {
				continue
			}

			for _, finding := range proc.Findings {
				event := convertFinding(result, proc, finding, ctx, now)
				events = append(events, event)
			}
		}
	}

	return events
}

// isActionableStatus returns true for statuses that should generate SIEM events.
func isActionableStatus(status string) bool {
	switch status {
	case "FAIL", "REVIEW", "LICENSE":
		return true
	default:
		return false
	}
}

// convertFinding creates a SIEM event from a single finding.
func convertFinding(
	result *controlset.ControlResult,
	proc controlset.ProcedureResult,
	finding controlset.Finding,
	ctx FindingContext,
	now time.Time,
) *Event {
	// Map procedure status to finding status
	findingStatus := mapFindingStatus(proc.Status)

	// Map finding severity
	severity := mapSeverity(finding.Severity)

	// Build evidence from finding
	evidence := buildEvidence(finding)

	// Prefer the exact control pack that produced this result; fall back to
	// the run-level context only when the result doesn't carry it (e.g. older
	// callers or synthetic results in tests).
	controlPackName := result.ControlPackName
	if controlPackName == "" {
		controlPackName = ctx.ControlPackName
	}
	controlPackVersion := result.ControlPackVersion
	if controlPackVersion == "" {
		controlPackVersion = ctx.ControlPackVersion
	}

	event := &Event{
		Version:        EventVersion,
		EventType:      EventTypeCreated, // Will be updated by lifecycle tracking
		EventTime:      now,
		AgentID:        ctx.AgentID,
		SystemID:       ctx.SystemID,
		SystemName:     ctx.SystemName,
		DatabaseEngine: ctx.DatabaseEngine,
		Environment:    ctx.Environment,
		ControlCode:    result.ControlCode,
		ControlName:    result.Title,
		FindingTitle:   finding.Title,
		Severity:       severity,
		FindingStatus:  findingStatus,
		FirstSeen:      now,
		LastSeen:       now,
		OccurrenceCount: 1,
		Source:         "control_audit",
		Evidence:       evidence,
		Export: &EventExport{
			ControlPackName:    controlPackName,
			ControlPackVersion: controlPackVersion,
			AgentVersion:       ctx.AgentVersion,
			Mode:               ctx.Mode,
			Destination:        ctx.Destination,
		},
	}

	// Set fingerprint and finding ID
	event.SetFingerprint()

	return event
}

// mapFindingStatus converts procedure status to SIEM finding status.
func mapFindingStatus(procStatus string) string {
	switch procStatus {
	case "FAIL":
		return FindingStatusOpen
	case "PASS":
		return FindingStatusRemediated
	case "REVIEW":
		return FindingStatusOpen
	case "LICENSE":
		return FindingStatusOpen
	default:
		return FindingStatusOpen
	}
}

// mapSeverity normalizes severity values to SIEM constants.
func mapSeverity(severity string) string {
	switch severity {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high":
		return SeverityHigh
	case "MEDIUM", "medium":
		return SeverityMedium
	case "LOW", "low":
		return SeverityLow
	case "INFO", "info", "INFORMATIONAL", "informational":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// buildEvidence creates EventEvidence from a finding. Row-count findings nest
// the offending row under the "row" key (see the row-count finding
// construction in pkg/controlset/executor.go) instead of at the top level;
// extract from there when present so identity fields are not silently
// dropped -- a drop that would otherwise collapse distinct row-count findings
// onto the same fingerprint.
func buildEvidence(finding controlset.Finding) *EventEvidence {
	evidence := &EventEvidence{
		Summary: finding.Description,
		Fix:     finding.Remediation,
	}

	source := finding.Evidence
	if nested, ok := extractNestedRowEvidence(finding.Evidence); ok {
		source = nested
	}

	if source != nil {
		source = normalizeEvidenceKeys(source)
		if v, ok := source["schema_name"].(string); ok {
			evidence.SchemaName = v
		}
		if v, ok := source["object_name"].(string); ok {
			evidence.ObjectName = v
		}
		if v, ok := source["role_name"].(string); ok {
			evidence.RoleName = v
		}
		if v, ok := source["user_name"].(string); ok {
			evidence.UserName = v
		}
		if v, ok := source["attribute_name"].(string); ok {
			evidence.AttributeName = v
		}
		if v, ok := source["current_value"].(string); ok {
			evidence.CurrentValue = v
		}
		if v, ok := source["expected_value"].(string); ok {
			evidence.ExpectedValue = v
		}
		if v, ok := source["reason"].(string); ok {
			evidence.Reason = v
		}
	}

	return evidence
}

// normalizeEvidenceKeys returns a copy of source with every key lowercased,
// so evidence extraction matches regardless of the originating database
// driver's column-name casing. Oracle in particular returns unquoted
// identifiers uppercase (e.g. a query aliased "AS schema_name" comes back as
// column "SCHEMA_NAME"), which would otherwise silently miss every lookup
// below and fall the fingerprint back to the (mutable) finding title.
func normalizeEvidenceKeys(source map[string]interface{}) map[string]interface{} {
	normalized := make(map[string]interface{}, len(source))
	for k, v := range source {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}

// extractNestedRowEvidence returns the nested row map from row-count finding
// evidence (stored under the "row" key) so its fields can be extracted the
// same way as a flat finding's evidence.
func extractNestedRowEvidence(ev map[string]interface{}) (map[string]interface{}, bool) {
	if ev == nil {
		return nil, false
	}
	switch row := ev["row"].(type) {
	case database.Row:
		return map[string]interface{}(row), true
	case map[string]interface{}:
		return row, true
	}
	return nil, false
}
