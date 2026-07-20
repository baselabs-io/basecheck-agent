package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventVersion(t *testing.T) {
	if EventVersion != "basecheck.siem.v1" {
		t.Errorf("EventVersion = %q, want %q", EventVersion, "basecheck.siem.v1")
	}
}

func TestEventTypeConstants(t *testing.T) {
	types := []string{
		EventTypeCreated,
		EventTypeUpdated,
		EventTypeRecurring,
		EventTypeRemediated,
		EventTypeRegressed,
	}
	for _, et := range types {
		if !isValidEventType(et) {
			t.Errorf("event type %q should be valid", et)
		}
	}
	if isValidEventType("invalid") {
		t.Error("invalid event type should not be valid")
	}
}

func TestFindingStatusConstants(t *testing.T) {
	statuses := []string{
		FindingStatusOpen,
		FindingStatusRemediated,
		FindingStatusAccepted,
		FindingStatusFalsePos,
	}
	for _, s := range statuses {
		if !isValidFindingStatus(s) {
			t.Errorf("finding status %q should be valid", s)
		}
	}
	if isValidFindingStatus("invalid") {
		t.Error("invalid finding status should not be valid")
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []string{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
	for _, s := range severities {
		if !isValidSeverity(s) {
			t.Errorf("severity %q should be valid", s)
		}
	}
	if isValidSeverity("invalid") {
		t.Error("invalid severity should not be valid")
	}
}

func TestNewEvent(t *testing.T) {
	e := NewEvent()

	if e.Version != EventVersion {
		t.Errorf("Version = %q, want %q", e.Version, EventVersion)
	}
	// FindingID is not set by NewEvent; it is derived from fingerprint by SetFingerprint()
	if e.FindingID != "" {
		t.Error("FindingID should not be set by NewEvent (derived from fingerprint)")
	}
	if e.EventTime.IsZero() {
		t.Error("EventTime should be set")
	}
	if e.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set")
	}
	if e.LastSeen.IsZero() {
		t.Error("LastSeen should be set")
	}
	if e.OccurrenceCount != 1 {
		t.Errorf("OccurrenceCount = %d, want 1", e.OccurrenceCount)
	}
	if e.FindingStatus != FindingStatusOpen {
		t.Errorf("FindingStatus = %q, want %q", e.FindingStatus, FindingStatusOpen)
	}
	if e.Source != "control_audit" {
		t.Errorf("Source = %q, want %q", e.Source, "control_audit")
	}
}

func TestComputeFingerprint(t *testing.T) {
	// Same inputs should produce same fingerprint
	fp1 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "")
	fp2 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "")

	if fp1 != fp2 {
		t.Error("identical inputs should produce same fingerprint")
	}

	// Different control should produce different fingerprint
	fp3 := ComputeFingerprint("ORA-SEC-002", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "")
	if fp1 == fp3 {
		t.Error("different control should produce different fingerprint")
	}

	// Different system should produce different fingerprint
	fp4 := ComputeFingerprint("ORA-SEC-001", "dev-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "")
	if fp1 == fp4 {
		t.Error("different system should produce different fingerprint")
	}

	// Different object should produce different fingerprint
	fp5 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "DEPARTMENTS", "SALARY", "", "", "")
	if fp1 == fp5 {
		t.Error("different object should produce different fingerprint")
	}

	// Case insensitive
	fp6 := ComputeFingerprint("ora-sec-001", "PROD-ORACLE", "hr", "employees", "SALARY", "", "", "")
	if fp1 != fp6 {
		t.Error("fingerprint should be case insensitive")
	}

	// Whitespace trimmed
	fp7 := ComputeFingerprint("  ORA-SEC-001  ", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "")
	if fp1 != fp7 {
		t.Error("fingerprint should trim whitespace")
	}

	// Different role should produce different fingerprint (same control/system/object)
	fp8 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "DBA_ROLE", "", "")
	if fp1 == fp8 {
		t.Error("different role should produce different fingerprint")
	}
	fp9 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "AUDIT_ROLE", "", "")
	if fp8 == fp9 {
		t.Error("different role values should produce different fingerprints")
	}

	// Different user should produce different fingerprint (same control/system/object)
	fp10 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "alice", "")
	if fp1 == fp10 {
		t.Error("different user should produce different fingerprint")
	}
	fp11 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "bob", "")
	if fp10 == fp11 {
		t.Error("different user values should produce different fingerprints")
	}
}

// TestComputeFingerprintIgnoresTitleWhenStructuredEvidenceExists guards
// against fingerprint instability for a continuing issue whose fallback
// title embeds a changing measured value (e.g. "current_value=42" ->
// "current_value=43" between runs). When schema/object/attribute/role/user
// already identify the issue, title must not also be hashed in, or the same
// underlying issue would get a new fingerprint every time its value changes.
func TestComputeFingerprintIgnoresTitleWhenStructuredEvidenceExists(t *testing.T) {
	fpValue42 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "Excessive value: current_value=42")
	fpValue43 := ComputeFingerprint("ORA-SEC-001", "prod-oracle", "HR", "EMPLOYEES", "SALARY", "", "", "Excessive value: current_value=43")

	if fpValue42 != fpValue43 {
		t.Error("fingerprint must stay stable when only the title's embedded value changes, given structured evidence already identifies the issue")
	}
}

// TestComputeFingerprintUsesTitleAsLastResort confirms title still
// disambiguates findings that have no structured evidence at all (e.g.
// HTTP/active-validation findings), which is the scenario the title
// fallback exists for.
func TestComputeFingerprintUsesTitleAsLastResort(t *testing.T) {
	fpA := ComputeFingerprint("HTTP-CHECK-001", "prod-api", "", "", "", "", "", "Finding A")
	fpB := ComputeFingerprint("HTTP-CHECK-001", "prod-api", "", "", "", "", "", "Finding B")

	if fpA == fpB {
		t.Error("expected different titles to disambiguate findings with no structured evidence")
	}

	fpARepeat := ComputeFingerprint("HTTP-CHECK-001", "prod-api", "", "", "", "", "", "Finding A")
	if fpA != fpARepeat {
		t.Error("expected identical title (no structured evidence) to produce a stable fingerprint")
	}
}

func TestFingerprintLength(t *testing.T) {
	fp := ComputeFingerprint("ORA-SEC-001", "prod", "", "", "", "", "", "")
	if len(fp) != 32 {
		t.Errorf("fingerprint length = %d, want 32", len(fp))
	}
}

func TestFindingIDDeterministic(t *testing.T) {
	// FindingID must be deterministic for lifecycle correlation across events
	// The same issue should get the same FindingID regardless of event_type
	e1 := &Event{
		ControlCode: "ORA-SEC-001",
		SystemID:    "prod-oracle",
		Evidence: &EventEvidence{
			SchemaName: "HR",
			ObjectName: "EMPLOYEES",
		},
	}
	e1.SetFingerprint()

	e2 := &Event{
		ControlCode: "ORA-SEC-001",
		SystemID:    "prod-oracle",
		Evidence: &EventEvidence{
			SchemaName: "HR",
			ObjectName: "EMPLOYEES",
		},
	}
	e2.SetFingerprint()

	if e1.FindingID != e2.FindingID {
		t.Errorf("FindingID should be deterministic: %q != %q", e1.FindingID, e2.FindingID)
	}

	// FindingID should be derived from fingerprint
	expectedPrefix := "find-"
	if !strings.HasPrefix(e1.FindingID, expectedPrefix) {
		t.Errorf("FindingID should start with %q, got %q", expectedPrefix, e1.FindingID)
	}
	if e1.FindingID != expectedPrefix+e1.Fingerprint {
		t.Errorf("FindingID should be %q%s, got %q", expectedPrefix, e1.Fingerprint, e1.FindingID)
	}

	// Different issue should have different FindingID
	e3 := &Event{
		ControlCode: "ORA-SEC-002", // Different control
		SystemID:    "prod-oracle",
		Evidence: &EventEvidence{
			SchemaName: "HR",
			ObjectName: "EMPLOYEES",
		},
	}
	e3.SetFingerprint()

	if e1.FindingID == e3.FindingID {
		t.Error("different control should produce different FindingID")
	}
}

func TestFingerprintDoesNotIncludeMutableState(t *testing.T) {
	// The fingerprint should NOT change based on status, occurrence count, or evidence values
	// It identifies the persistent issue, not its current state

	e1 := &Event{
		ControlCode: "ORA-SEC-001",
		SystemID:    "prod-oracle",
		Evidence: &EventEvidence{
			SchemaName: "HR",
			ObjectName: "EMPLOYEES",
		},
	}
	e1.SetFingerprint()

	e2 := &Event{
		ControlCode:     "ORA-SEC-001",
		SystemID:        "prod-oracle",
		FindingStatus:   FindingStatusRemediated, // Different status
		OccurrenceCount: 100,                     // Different count
		Evidence: &EventEvidence{
			SchemaName:   "HR",
			ObjectName:   "EMPLOYEES",
			CurrentValue: "different value", // Different evidence value
		},
	}
	e2.SetFingerprint()

	if e1.Fingerprint != e2.Fingerprint {
		t.Error("fingerprint should not change based on status, count, or evidence values")
	}
}

func TestEventValidate(t *testing.T) {
	validEvent := func() *Event {
		e := NewEvent()
		e.EventType = EventTypeCreated
		e.AgentID = "agent-123"
		e.SystemID = "sys-456"
		e.SystemName = "prod-oracle"
		e.DatabaseEngine = "oracle"
		e.ControlCode = "ORA-SEC-001"
		e.ControlName = "Default Passwords"
		e.FindingTitle = "Default passwords detected"
		e.Severity = SeverityHigh
		e.Export = &EventExport{
			ControlPackName:    "oracle-security",
			ControlPackVersion: "1.0.0",
			AgentVersion:       "1.0.0",
			Mode:               "siem_only",
			Destination:        "webhook",
			DeliveryID:         "delivery-1",
		}
		// SetFingerprint computes both Fingerprint and FindingID
		e.SetFingerprint()
		return e
	}

	tests := []struct {
		name    string
		modify  func(*Event)
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid event",
			modify:  func(e *Event) {},
			wantErr: false,
		},
		{
			name:    "wrong version",
			modify:  func(e *Event) { e.Version = "basecheck.siem.v2" },
			wantErr: true,
			errMsg:  "version must be",
		},
		{
			name:    "missing event_type",
			modify:  func(e *Event) { e.EventType = "" },
			wantErr: true,
			errMsg:  "event_type is required",
		},
		{
			name:    "invalid event_type",
			modify:  func(e *Event) { e.EventType = "deleted" },
			wantErr: true,
			errMsg:  "invalid event_type",
		},
		{
			name:    "missing agent_id",
			modify:  func(e *Event) { e.AgentID = "" },
			wantErr: true,
			errMsg:  "agent_id is required",
		},
		{
			name:    "missing system_id",
			modify:  func(e *Event) { e.SystemID = "" },
			wantErr: true,
			errMsg:  "system_id is required",
		},
		{
			name:    "missing system_name",
			modify:  func(e *Event) { e.SystemName = "" },
			wantErr: true,
			errMsg:  "system_name is required",
		},
		{
			name:    "missing database_engine",
			modify:  func(e *Event) { e.DatabaseEngine = "" },
			wantErr: true,
			errMsg:  "database_engine is required",
		},
		{
			name:    "missing control_code",
			modify:  func(e *Event) { e.ControlCode = "" },
			wantErr: true,
			errMsg:  "control_code is required",
		},
		{
			name:    "missing control_name",
			modify:  func(e *Event) { e.ControlName = "" },
			wantErr: true,
			errMsg:  "control_name is required",
		},
		{
			name:    "missing finding_title",
			modify:  func(e *Event) { e.FindingTitle = "" },
			wantErr: true,
			errMsg:  "finding_title is required",
		},
		{
			name:    "missing severity",
			modify:  func(e *Event) { e.Severity = "" },
			wantErr: true,
			errMsg:  "severity is required",
		},
		{
			name:    "invalid severity",
			modify:  func(e *Event) { e.Severity = "EXTREME" },
			wantErr: true,
			errMsg:  "invalid severity",
		},
		{
			name:    "missing fingerprint",
			modify:  func(e *Event) { e.Fingerprint = "" },
			wantErr: true,
			errMsg:  "fingerprint is required",
		},
		{
			name:    "missing finding_status",
			modify:  func(e *Event) { e.FindingStatus = "" },
			wantErr: true,
			errMsg:  "finding_status is required",
		},
		{
			name:    "invalid finding_status",
			modify:  func(e *Event) { e.FindingStatus = "pending" },
			wantErr: true,
			errMsg:  "invalid finding_status",
		},
		{
			name:    "valid remediated event",
			modify:  func(e *Event) { e.EventType = EventTypeRemediated; e.FindingStatus = FindingStatusRemediated },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvent()
			tt.modify(e)
			err := e.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEventMarshalJSON(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	e := &Event{
		Version:         EventVersion,
		EventType:       EventTypeCreated,
		EventTime:       now,
		OrganizationID:  "org-123",
		AgentID:         "agent-456",
		SystemID:        "sys-789",
		SystemName:      "prod-oracle-01",
		DatabaseEngine:  "oracle",
		Environment:     "production",
		FindingID:       "find-001",
		Fingerprint:     "abc123def456",
		ControlCode:     "ORA-SEC-001",
		ControlName:     "Default Passwords",
		FindingTitle:    "Default passwords detected",
		Severity:        SeverityHigh,
		RiskScore:       8.5,
		FindingStatus:   FindingStatusOpen,
		FirstSeen:       now.Add(-24 * time.Hour),
		LastSeen:        now,
		OccurrenceCount: 3,
		Source:          "control_audit",
		Evidence: &EventEvidence{
			Summary:       "3 accounts with default passwords",
			SchemaName:    "SYS",
			ObjectName:    "DBA_USERS",
			UserName:      "SCOTT",
			CurrentValue:  "default",
			ExpectedValue: "non-default",
			Reason:        "Account uses well-known default password",
			Fix:           "ALTER USER SCOTT IDENTIFIED BY <new_password>",
		},
		Export: &EventExport{
			ControlPackName:    "oracle-security-baseline",
			ControlPackVersion: "1.0.0",
			AgentVersion:       "2.5.0",
			Mode:               "siem_only",
			Destination:        "webhook",
			DeliveryID:         "del-123",
		},
	}

	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Verify required fields are present
	jsonStr := string(data)
	requiredFields := []string{
		`"version"`,
		`"event_type"`,
		`"event_time"`,
		`"agent_id"`,
		`"system_id"`,
		`"system_name"`,
		`"database_engine"`,
		`"finding_id"`,
		`"fingerprint"`,
		`"control_code"`,
		`"control_name"`,
		`"finding_title"`,
		`"severity"`,
		`"finding_status"`,
		`"first_seen"`,
		`"last_seen"`,
		`"source"`,
	}
	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing required field: %s", field)
		}
	}

	// Verify it can be unmarshaled back
	var parsed Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Version != e.Version {
		t.Errorf("Version = %q, want %q", parsed.Version, e.Version)
	}
	if parsed.EventType != e.EventType {
		t.Errorf("EventType = %q, want %q", parsed.EventType, e.EventType)
	}
	if parsed.Evidence == nil {
		t.Error("Evidence should not be nil")
	} else {
		if parsed.Evidence.UserName != "SCOTT" {
			t.Errorf("Evidence.UserName = %q, want %q", parsed.Evidence.UserName, "SCOTT")
		}
		if parsed.Evidence.Fix == "" {
			t.Error("Evidence.Fix should be set")
		}
	}
	if parsed.Export == nil {
		t.Error("Export should not be nil")
	} else {
		if parsed.Export.Mode != "siem_only" {
			t.Errorf("Export.Mode = %q, want %q", parsed.Export.Mode, "siem_only")
		}
	}
}

func TestEventBuilder(t *testing.T) {
	event, err := NewEventBuilder().
		WithEventType(EventTypeCreated).
		WithOrganization("org-123").
		WithAgent("agent-456").
		WithSystem("sys-789", "prod-oracle", "oracle", "production").
		WithControl("ORA-SEC-001", "Default Passwords").
		WithFinding("Default passwords detected", SeverityHigh, 8.5).
		WithStatus(FindingStatusOpen).
		WithSource("control_audit").
		WithEvidence(&EventEvidence{
			SchemaName: "HR",
			ObjectName: "EMPLOYEES",
		}).
		WithExport(&EventExport{
			ControlPackName:    "oracle-security",
			ControlPackVersion: "1.0.0",
			AgentVersion:       "2.5.0",
			Mode:               "siem_only",
			Destination:        "webhook",
			DeliveryID:         "del-123",
		}).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if event.AgentID != "agent-456" {
		t.Errorf("AgentID = %q, want %q", event.AgentID, "agent-456")
	}
	if event.SystemName != "prod-oracle" {
		t.Errorf("SystemName = %q, want %q", event.SystemName, "prod-oracle")
	}
	if event.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", event.Severity, SeverityHigh)
	}
	if event.Fingerprint == "" {
		t.Error("Fingerprint should be computed")
	}
}

func TestEventBuilderValidation(t *testing.T) {
	// Missing required fields should fail
	_, err := NewEventBuilder().
		WithAgent("agent-123").
		Build()

	if err == nil {
		t.Error("Build should fail with missing required fields")
	}
}

func TestSortEventsByTime(t *testing.T) {
	now := time.Now()
	events := []*Event{
		{EventTime: now.Add(2 * time.Hour)},
		{EventTime: now},
		{EventTime: now.Add(1 * time.Hour)},
	}

	SortEventsByTime(events)

	if !events[0].EventTime.Equal(now) {
		t.Error("first event should be earliest")
	}
	if !events[2].EventTime.Equal(now.Add(2 * time.Hour)) {
		t.Error("last event should be latest")
	}
}

func TestEvidenceBoundary(t *testing.T) {
	e := &Event{
		Evidence: &EventEvidence{
			Summary: "Large result set",
			Boundary: &EvidenceBoundary{
				TotalRows:     1000,
				IncludedRows:  100,
				Truncated:     true,
				TruncationMsg: "First 100 of 1000 rows included",
			},
		},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Evidence.Boundary == nil {
		t.Fatal("Boundary should not be nil")
	}
	if parsed.Evidence.Boundary.TotalRows != 1000 {
		t.Errorf("TotalRows = %d, want 1000", parsed.Evidence.Boundary.TotalRows)
	}
	if !parsed.Evidence.Boundary.Truncated {
		t.Error("Truncated should be true")
	}
}

func TestLogContext(t *testing.T) {
	now := time.Now()
	e := &Event{
		LogContext: &EventLogContext{
			SourceType:      "alert_log",
			EventCode:       "ORA-00600",
			EventCategory:   "internal_error",
			EventCount:      5,
			FirstEventTime:  now.Add(-1 * time.Hour),
			LastEventTime:   now,
			SampleMessage:   "ORA-00600: internal error code...",
			RawExcerptTrunc: true,
		},
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.LogContext == nil {
		t.Fatal("LogContext should not be nil")
	}
	if parsed.LogContext.EventCount != 5 {
		t.Errorf("EventCount = %d, want 5", parsed.LogContext.EventCount)
	}
}
