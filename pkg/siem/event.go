// Package siem provides SIEM event output for security findings.
package siem

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EventVersion is the canonical SIEM event schema version.
const EventVersion = "basecheck.siem.v1"

// Lifecycle event types
const (
	EventTypeCreated    = "created"    // First occurrence of this finding
	EventTypeUpdated    = "updated"    // Finding details changed (severity, evidence)
	EventTypeRecurring  = "recurring"  // Finding still present on subsequent run
	EventTypeRemediated = "remediated" // Finding resolved (was FAIL, now PASS)
	EventTypeRegressed  = "regressed"  // Finding returned after remediation
)

// Finding status values
const (
	FindingStatusOpen       = "open"       // Active finding requiring attention
	FindingStatusRemediated = "remediated" // Finding has been fixed
	FindingStatusAccepted   = "accepted"   // Risk accepted, no action needed
	FindingStatusFalsePos   = "false_pos"  // Confirmed false positive
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Event represents a SIEM-consumable security finding.
// Canonical basecheck.siem.v1 contract per AS-0018.
//
// SIEM-only mode deviations from AS-0018 (documented in AS-0020):
// - organization_id: Optional (agent may not know org context)
// - basecheck_url: Optional (no backend in SIEM-only mode)
// - risk_score: Optional (may not be computed locally)
// - environment: Optional (agent may not have this metadata)
//
// Evidence uses nested structure (evidence.summary, evidence.boundary).
// Adapters may flatten to evidence_summary if target SIEM requires it.
type Event struct {
	// Schema version for forward compatibility
	Version string `json:"version"`

	// Lifecycle event type: created, updated, recurring, remediated, regressed
	EventType string `json:"event_type"`

	// Event timestamp (when this event was generated)
	EventTime time.Time `json:"event_time"`

	// Organization context (optional in SIEM-only mode)
	OrganizationID string `json:"organization_id,omitempty"`

	// Agent identification
	AgentID string `json:"agent_id"`

	// System identification (database instance)
	SystemID   string `json:"system_id"`
	SystemName string `json:"system_name"`

	// Database metadata
	DatabaseEngine string `json:"database_engine"`       // oracle, postgres, mssql, sqlite
	Environment    string `json:"environment,omitempty"` // production, staging, development (optional)

	// Finding identification
	// FindingID is deterministic: derived from fingerprint for lifecycle correlation.
	// The same persistent issue gets the same FindingID across runs.
	FindingID   string `json:"finding_id"`
	Fingerprint string `json:"fingerprint"` // Stable hash identifying the persistent issue

	// Control identification
	ControlCode string `json:"control_code"`
	ControlName string `json:"control_name"`

	// Finding details
	FindingTitle  string  `json:"finding_title"`
	Severity      string  `json:"severity"`
	RiskScore     float64 `json:"risk_score,omitempty"` // Optional in SIEM-only mode
	FindingStatus string  `json:"finding_status"`       // open, remediated, accepted, false_pos

	// Lifecycle timestamps. RemediatedAt/RegressedAt are pointers (not plain
	// time.Time) because Go's encoding/json omitempty does not omit a
	// non-nil zero-value struct: a plain time.Time would always serialize,
	// even when unset, as the year-one zero value instead of being absent.
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	RemediatedAt *time.Time `json:"remediated_at,omitempty"`
	RegressedAt  *time.Time `json:"regressed_at,omitempty"`

	// Occurrence tracking
	OccurrenceCount int `json:"occurrence_count"`

	// Source and linking
	Source       string `json:"source"`                  // control_audit, log_mining, active_validation
	BasecheckURL string `json:"basecheck_url,omitempty"` // Optional in SIEM-only mode

	// Evidence (structured for actionable alerts, nested structure)
	Evidence *EventEvidence `json:"evidence,omitempty"`

	// Export metadata (required for delivered events)
	Export *EventExport `json:"export"`

	// Log-derived fields (optional, for log mining findings)
	LogContext *EventLogContext `json:"log_context,omitempty"`
}

// EventEvidence contains structured evidence for actionable alerts.
// Fields follow ADEAS/TRUSTS pattern for SIEM integration.
type EventEvidence struct {
	// Human-readable summary
	Summary string `json:"summary,omitempty"`

	// Object identification
	SchemaName    string `json:"schema_name,omitempty"`
	ObjectName    string `json:"object_name,omitempty"`
	RoleName      string `json:"role_name,omitempty"`
	UserName      string `json:"user_name,omitempty"`
	AttributeName string `json:"attribute_name,omitempty"`

	// Configuration drift
	CurrentValue  string `json:"current_value,omitempty"`
	ExpectedValue string `json:"expected_value,omitempty"`

	// Remediation guidance
	Reason string `json:"reason,omitempty"`
	Fix    string `json:"fix,omitempty"`

	// Evidence boundary (for large result sets)
	Boundary *EvidenceBoundary `json:"boundary,omitempty"`
}

// EvidenceBoundary indicates truncation for large evidence sets.
type EvidenceBoundary struct {
	TotalRows     int    `json:"total_rows"`
	IncludedRows  int    `json:"included_rows"`
	Truncated     bool   `json:"truncated"`
	TruncationMsg string `json:"truncation_msg,omitempty"`
}

// EventExport contains export/delivery metadata.
type EventExport struct {
	ControlPackName      string `json:"control_pack_name"`
	ControlPackVersion   string `json:"control_pack_version"`
	ControlPackSignature string `json:"control_pack_signature,omitempty"`
	AgentVersion         string `json:"agent_version"`
	Mode                 string `json:"mode"`        // siem_only, backend, hybrid
	Destination          string `json:"destination"` // webhook or syslog
	DeliveryID           string `json:"delivery_id"` // Unique ID for this delivery attempt
}

// EventLogContext contains log-mining specific fields.
type EventLogContext struct {
	SourceType      string    `json:"source_type,omitempty"` // alert_log, audit_trail, etc.
	EventCode       string    `json:"event_code,omitempty"`
	EventCategory   string    `json:"event_category,omitempty"`
	EventCount      int       `json:"event_count,omitempty"`
	FirstEventTime  time.Time `json:"first_event_time,omitempty"`
	LastEventTime   time.Time `json:"last_event_time,omitempty"`
	SampleMessage   string    `json:"sample_message,omitempty"`
	RawExcerptTrunc bool      `json:"raw_excerpt_truncated,omitempty"`
}

// NewEvent creates a new SIEM event with defaults and current timestamp.
// FindingID is not set here; it is derived deterministically from the
// fingerprint when SetFingerprint() or Build() is called.
func NewEvent() *Event {
	now := time.Now().UTC()
	return &Event{
		Version:         EventVersion,
		EventTime:       now,
		FirstSeen:       now,
		LastSeen:        now,
		OccurrenceCount: 1,
		FindingStatus:   FindingStatusOpen,
		Source:          "control_audit",
	}
}

// ComputeFingerprint generates a stable hash identifying the persistent issue.
// The fingerprint does NOT include status, occurrence count, or mutable evidence.
// It identifies WHAT the issue is, not its current state. All identity-bearing
// evidence fields are included so two genuinely different findings (e.g. the
// same control flagging two different roles or users on the same object)
// cannot collide onto the same fingerprint.
//
// findingTitle is included ONLY when schema/object/attribute/role/user are
// all empty -- i.e. as an identity of last resort, not unconditionally. Titles
// built via a per-row fallback (see executor.go's buildFallbackTitle) embed
// mutable values like current_value; hashing title unconditionally would mean
// a continuing issue whose measured value changes gets a brand new
// fingerprint every run, which the lifecycle tracker would then report as
// "remediated" (old fingerprint disappeared) plus "newly created" (new
// fingerprint appeared) instead of "recurring"/"updated". When any structured
// evidence field is present, it alone identifies the issue and title is
// excluded so the fingerprint stays stable across value changes.
// Format: SHA256(control_code + system_id + schema_name + object_name + attribute_name + role_name + user_name [+ finding_title, only if all of the above are empty])
func ComputeFingerprint(controlCode, systemID, schemaName, objectName, attributeName, roleName, userName, findingTitle string) string {
	h := sha256.New()

	// Control identity
	h.Write([]byte(strings.ToLower(strings.TrimSpace(controlCode))))
	h.Write([]byte{0})

	// System identity
	h.Write([]byte(strings.ToLower(strings.TrimSpace(systemID))))
	h.Write([]byte{0})

	trimmedSchema := strings.ToLower(strings.TrimSpace(schemaName))
	trimmedObject := strings.ToLower(strings.TrimSpace(objectName))
	trimmedAttribute := strings.ToLower(strings.TrimSpace(attributeName))
	trimmedRole := strings.ToLower(strings.TrimSpace(roleName))
	trimmedUser := strings.ToLower(strings.TrimSpace(userName))

	// Object identity (where the issue exists)
	h.Write([]byte(trimmedSchema))
	h.Write([]byte{0})
	h.Write([]byte(trimmedObject))
	h.Write([]byte{0})
	h.Write([]byte(trimmedAttribute))
	h.Write([]byte{0})

	// Principal identity (who/what the issue is about, when applicable)
	h.Write([]byte(trimmedRole))
	h.Write([]byte{0})
	h.Write([]byte(trimmedUser))

	hasStructuredEvidence := trimmedSchema != "" || trimmedObject != "" || trimmedAttribute != "" ||
		trimmedRole != "" || trimmedUser != ""

	if !hasStructuredEvidence {
		// No other identity evidence at all -- fall back to title as the only
		// available disambiguator (e.g. HTTP/active-validation findings with
		// no database object evidence).
		h.Write([]byte{0})
		h.Write([]byte(strings.ToLower(strings.TrimSpace(findingTitle))))
	}

	return hex.EncodeToString(h.Sum(nil))[:32] // 32 hex chars = 128 bits
}

// SetFingerprint computes and sets both Fingerprint and FindingID from evidence fields.
// FindingID is derived deterministically from the fingerprint to enable lifecycle
// correlation across created, updated, recurring, remediated, and regressed events.
func (e *Event) SetFingerprint() {
	schemaName := ""
	objectName := ""
	attributeName := ""
	roleName := ""
	userName := ""
	if e.Evidence != nil {
		schemaName = e.Evidence.SchemaName
		objectName = e.Evidence.ObjectName
		attributeName = e.Evidence.AttributeName
		roleName = e.Evidence.RoleName
		userName = e.Evidence.UserName
	}
	e.Fingerprint = ComputeFingerprint(e.ControlCode, e.SystemID, schemaName, objectName, attributeName, roleName, userName, e.FindingTitle)
	e.FindingID = "find-" + e.Fingerprint
}

// MarshalJSON implements json.Marshaler with consistent field ordering.
func (e *Event) MarshalJSON() ([]byte, error) {
	type EventAlias Event
	return json.Marshal((*EventAlias)(e))
}

// Validate checks that required fields are present and valid for v1 contract.
func (e *Event) Validate() error {
	var errors []string

	// Version must be exactly v1
	if e.Version != EventVersion {
		errors = append(errors, fmt.Sprintf("version must be %q, got %q", EventVersion, e.Version))
	}

	// Required identity fields
	if e.EventType == "" {
		errors = append(errors, "event_type is required")
	} else if !isValidEventType(e.EventType) {
		errors = append(errors, fmt.Sprintf("invalid event_type: %q", e.EventType))
	}

	if e.EventTime.IsZero() {
		errors = append(errors, "event_time is required")
	}

	if e.AgentID == "" {
		errors = append(errors, "agent_id is required")
	}

	if e.SystemID == "" {
		errors = append(errors, "system_id is required")
	}

	if e.SystemName == "" {
		errors = append(errors, "system_name is required")
	}

	if e.DatabaseEngine == "" {
		errors = append(errors, "database_engine is required")
	}

	if e.FindingID == "" {
		errors = append(errors, "finding_id is required")
	}

	if e.Fingerprint == "" {
		errors = append(errors, "fingerprint is required")
	}

	if e.ControlCode == "" {
		errors = append(errors, "control_code is required")
	}

	if e.ControlName == "" {
		errors = append(errors, "control_name is required")
	}

	if e.FindingTitle == "" {
		errors = append(errors, "finding_title is required")
	}

	if e.Severity == "" {
		errors = append(errors, "severity is required")
	} else if !isValidSeverity(e.Severity) {
		errors = append(errors, fmt.Sprintf("invalid severity: %q", e.Severity))
	}

	if e.FindingStatus == "" {
		errors = append(errors, "finding_status is required")
	} else if !isValidFindingStatus(e.FindingStatus) {
		errors = append(errors, fmt.Sprintf("invalid finding_status: %q", e.FindingStatus))
	}

	if e.FirstSeen.IsZero() {
		errors = append(errors, "first_seen is required")
	}

	if e.LastSeen.IsZero() {
		errors = append(errors, "last_seen is required")
	}

	if e.Source == "" {
		errors = append(errors, "source is required")
	}

	// Export metadata is required for every event that will be delivered;
	// without it, downstream SIEM correlation, schema validation, and replay
	// protection cannot rely on the documented event contract.
	if e.Export == nil {
		errors = append(errors, "export is required")
	} else {
		if e.Export.ControlPackName == "" {
			errors = append(errors, "export.control_pack_name is required")
		}
		if e.Export.ControlPackVersion == "" {
			errors = append(errors, "export.control_pack_version is required")
		}
		if e.Export.AgentVersion == "" {
			errors = append(errors, "export.agent_version is required")
		}
		if e.Export.Mode == "" {
			errors = append(errors, "export.mode is required")
		}
		if e.Export.Destination == "" {
			errors = append(errors, "export.destination is required")
		}
		if e.Export.DeliveryID == "" {
			errors = append(errors, "export.delivery_id is required")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

func isValidEventType(t string) bool {
	switch t {
	case EventTypeCreated, EventTypeUpdated, EventTypeRecurring, EventTypeRemediated, EventTypeRegressed:
		return true
	}
	return false
}

func isValidSeverity(s string) bool {
	switch strings.ToUpper(s) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

func isValidFindingStatus(s string) bool {
	switch s {
	case FindingStatusOpen, FindingStatusRemediated, FindingStatusAccepted, FindingStatusFalsePos:
		return true
	}
	return false
}

// EventBuilder provides a fluent interface for constructing events.
type EventBuilder struct {
	event *Event
}

// NewEventBuilder creates a new event builder with defaults set.
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		event: NewEvent(),
	}
}

// WithEventType sets the lifecycle event type.
func (b *EventBuilder) WithEventType(eventType string) *EventBuilder {
	b.event.EventType = eventType
	return b
}

// WithOrganization sets organization context.
func (b *EventBuilder) WithOrganization(orgID string) *EventBuilder {
	b.event.OrganizationID = orgID
	return b
}

// WithAgent sets agent identification.
func (b *EventBuilder) WithAgent(agentID string) *EventBuilder {
	b.event.AgentID = agentID
	return b
}

// WithSystem sets target system (database instance) information.
func (b *EventBuilder) WithSystem(systemID, systemName, dbEngine, environment string) *EventBuilder {
	b.event.SystemID = systemID
	b.event.SystemName = systemName
	b.event.DatabaseEngine = dbEngine
	b.event.Environment = environment
	return b
}

// WithControl sets control identification.
func (b *EventBuilder) WithControl(controlCode, controlName string) *EventBuilder {
	b.event.ControlCode = controlCode
	b.event.ControlName = controlName
	return b
}

// WithFinding sets finding details.
func (b *EventBuilder) WithFinding(title, severity string, riskScore float64) *EventBuilder {
	b.event.FindingTitle = title
	b.event.Severity = severity
	b.event.RiskScore = riskScore
	return b
}

// WithStatus sets finding status.
func (b *EventBuilder) WithStatus(status string) *EventBuilder {
	b.event.FindingStatus = status
	return b
}

// WithLifecycle sets lifecycle timestamps.
func (b *EventBuilder) WithLifecycle(firstSeen, lastSeen time.Time, occurrenceCount int) *EventBuilder {
	b.event.FirstSeen = firstSeen
	b.event.LastSeen = lastSeen
	b.event.OccurrenceCount = occurrenceCount
	return b
}

// WithSource sets the finding source.
func (b *EventBuilder) WithSource(source string) *EventBuilder {
	b.event.Source = source
	return b
}

// WithEvidence sets structured evidence.
func (b *EventBuilder) WithEvidence(evidence *EventEvidence) *EventBuilder {
	b.event.Evidence = evidence
	return b
}

// WithExport sets export metadata.
func (b *EventBuilder) WithExport(export *EventExport) *EventBuilder {
	b.event.Export = export
	return b
}

// WithLogContext sets log-mining context.
func (b *EventBuilder) WithLogContext(logCtx *EventLogContext) *EventBuilder {
	b.event.LogContext = logCtx
	return b
}

// Build computes fingerprint, validates, and returns the event.
func (b *EventBuilder) Build() (*Event, error) {
	b.event.SetFingerprint()
	if err := b.event.Validate(); err != nil {
		return nil, err
	}
	return b.event, nil
}

// BuildUnchecked returns the event without validation (for testing).
func (b *EventBuilder) BuildUnchecked() *Event {
	b.event.SetFingerprint()
	return b.event
}

// SortEventsByTime sorts events by event_time ascending.
func SortEventsByTime(events []*Event) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})
}
