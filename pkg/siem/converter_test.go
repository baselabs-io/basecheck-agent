package siem

import (
	"testing"
	"time"

	"basecheck-agent/pkg/controlset"
)

func TestConvertFindings(t *testing.T) {
	ctx := FindingContext{
		AgentID:            "agent-123",
		AgentVersion:       "1.0.0",
		SystemID:           "sys-456",
		SystemName:         "prod-db",
		DatabaseEngine:     "postgres",
		Environment:        "production",
		ControlPackName:    "postgres-security",
		ControlPackVersion: "1.2.0",
		Mode:               "siem_only",
		Destination:        "webhook",
	}

	t.Run("converts FAIL findings", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlID:   "ctrl-1",
			ControlCode: "PG-001",
			Title:       "Test Control",
			Status:      "FAIL",
			Procedures: []controlset.ProcedureResult{{
				ProcedureID: "proc-1",
				Status:      "FAIL",
				Findings: []controlset.Finding{{
					Severity:    "HIGH",
					Title:       "Security Issue",
					Description: "Found a security issue",
					Remediation: "Fix it",
					Evidence: map[string]interface{}{
						"schema_name": "public",
						"object_name": "users",
					},
				}},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}

		event := events[0]
		if event.ControlCode != "PG-001" {
			t.Errorf("control code = %q, want %q", event.ControlCode, "PG-001")
		}
		if event.FindingTitle != "Security Issue" {
			t.Errorf("finding title = %q, want %q", event.FindingTitle, "Security Issue")
		}
		if event.Severity != SeverityHigh {
			t.Errorf("severity = %q, want %q", event.Severity, SeverityHigh)
		}
		if event.FindingStatus != FindingStatusOpen {
			t.Errorf("finding status = %q, want %q", event.FindingStatus, FindingStatusOpen)
		}
		if event.AgentID != "agent-123" {
			t.Errorf("agent ID = %q, want %q", event.AgentID, "agent-123")
		}
		if event.Evidence == nil {
			t.Fatal("evidence should not be nil")
		}
		if event.Evidence.SchemaName != "public" {
			t.Errorf("schema name = %q, want %q", event.Evidence.SchemaName, "public")
		}
		if event.Fingerprint == "" {
			t.Error("fingerprint should be set")
		}
		if event.FindingID == "" {
			t.Error("finding ID should be set")
		}
	})

	t.Run("converts REVIEW findings", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-002",
			Title:       "Review Control",
			Procedures: []controlset.ProcedureResult{{
				Status: "REVIEW",
				Findings: []controlset.Finding{{
					Severity: "MEDIUM",
					Title:    "Needs Review",
				}},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		if events[0].Severity != SeverityMedium {
			t.Errorf("severity = %q, want %q", events[0].Severity, SeverityMedium)
		}
	})

	t.Run("converts LICENSE findings", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-003",
			Title:       "License Control",
			Procedures: []controlset.ProcedureResult{{
				Status: "LICENSE",
				Findings: []controlset.Finding{{
					Severity: "INFO",
					Title:    "License Issue",
				}},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
	})

	t.Run("skips PASS findings", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-004",
			Procedures: []controlset.ProcedureResult{{
				Status:   "PASS",
				Findings: []controlset.Finding{},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 0 {
			t.Errorf("expected 0 events for PASS, got %d", len(events))
		}
	})

	t.Run("skips ERROR status", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-005",
			Procedures: []controlset.ProcedureResult{{
				Status: "ERROR",
				Findings: []controlset.Finding{{
					Title: "Should be skipped",
				}},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 0 {
			t.Errorf("expected 0 events for ERROR, got %d", len(events))
		}
	})

	t.Run("handles multiple findings", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-006",
			Title:       "Multi-Finding Control",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{
					{Severity: "HIGH", Title: "Finding 1"},
					{Severity: "MEDIUM", Title: "Finding 2"},
					{Severity: "LOW", Title: "Finding 3"},
				},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 3 {
			t.Fatalf("expected 3 events, got %d", len(events))
		}

		// Distinct findings within a single audit result must never collide
		// onto the same fingerprint -- a collision corrupts dedup/lifecycle
		// state (see HARDQA-ENTERPRISE-READINESS-2026-07-15.md finding 5).
		seen := make(map[string]string)
		for _, event := range events {
			if prevTitle, exists := seen[event.Fingerprint]; exists {
				t.Errorf("fingerprint collision: %q and %q both produced %q",
					prevTitle, event.FindingTitle, event.Fingerprint)
			}
			seen[event.Fingerprint] = event.FindingTitle
		}
	})

	t.Run("row-count findings with different rows get distinct fingerprints", func(t *testing.T) {
		// Row-count findings nest the offending row under the "row" key
		// (see executor.go's row-count finding construction). If that nested
		// evidence is dropped, every row-count finding on the same
		// control/system collapses onto the same fingerprint.
		results := []*controlset.ControlResult{{
			ControlCode: "PG-008",
			Title:       "Row Count Control",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{
					{
						Severity: "HIGH",
						Title:    "Excessive privilege",
						Evidence: map[string]interface{}{
							"row":       map[string]interface{}{"role_name": "DBA_ROLE", "schema_name": "public"},
							"row_count": 2,
							"condition": "row_count == 0",
						},
					},
					{
						Severity: "HIGH",
						Title:    "Excessive privilege",
						Evidence: map[string]interface{}{
							"row":       map[string]interface{}{"role_name": "AUDIT_ROLE", "schema_name": "public"},
							"row_count": 2,
							"condition": "row_count == 0",
						},
					},
				},
			}},
		}}

		events := ConvertFindings(results, ctx)
		if len(events) != 2 {
			t.Fatalf("expected 2 events, got %d", len(events))
		}
		if events[0].Fingerprint == events[1].Fingerprint {
			t.Error("row-count findings for different roles must not share a fingerprint")
		}
		if events[0].Evidence.RoleName != "DBA_ROLE" {
			t.Errorf("expected nested row evidence to be extracted, got role_name=%q", events[0].Evidence.RoleName)
		}
		if events[1].Evidence.RoleName != "AUDIT_ROLE" {
			t.Errorf("expected nested row evidence to be extracted, got role_name=%q", events[1].Evidence.RoleName)
		}
	})

	t.Run("sets export metadata", func(t *testing.T) {
		results := []*controlset.ControlResult{{
			ControlCode: "PG-007",
			Title:       "Export Test",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{{
					Title: "Test",
				}},
			}},
		}}

		events := ConvertFindings(results, ctx)

		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}

		export := events[0].Export
		if export == nil {
			t.Fatal("export should not be nil")
		}
		if export.ControlPackName != "postgres-security" {
			t.Errorf("control pack name = %q, want %q", export.ControlPackName, "postgres-security")
		}
		if export.Mode != "siem_only" {
			t.Errorf("mode = %q, want %q", export.Mode, "siem_only")
		}
		if export.Destination != "webhook" {
			t.Errorf("destination = %q, want %q", export.Destination, "webhook")
		}
	})
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CRITICAL", SeverityCritical},
		{"critical", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"high", SeverityHigh},
		{"MEDIUM", SeverityMedium},
		{"medium", SeverityMedium},
		{"LOW", SeverityLow},
		{"low", SeverityLow},
		{"INFO", SeverityInfo},
		{"info", SeverityInfo},
		{"INFORMATIONAL", SeverityInfo},
		{"unknown", SeverityInfo},
		{"", SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapSeverity(tt.input)
			if got != tt.expected {
				t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapFindingStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"FAIL", FindingStatusOpen},
		{"PASS", FindingStatusRemediated},
		{"REVIEW", FindingStatusOpen},
		{"LICENSE", FindingStatusOpen},
		{"ERROR", FindingStatusOpen},
		{"unknown", FindingStatusOpen},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapFindingStatus(tt.input)
			if got != tt.expected {
				t.Errorf("mapFindingStatus(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildEvidence(t *testing.T) {
	finding := controlset.Finding{
		Description: "Test description",
		Remediation: "Test fix",
		Evidence: map[string]interface{}{
			"schema_name":    "public",
			"object_name":    "users",
			"user_name":      "admin",
			"current_value":  "weak",
			"expected_value": "strong",
			"reason":         "Password too weak",
			"attribute_name": "password_strength",
		},
	}

	evidence := buildEvidence(finding)

	if evidence.Summary != "Test description" {
		t.Errorf("summary = %q, want %q", evidence.Summary, "Test description")
	}
	if evidence.Fix != "Test fix" {
		t.Errorf("fix = %q, want %q", evidence.Fix, "Test fix")
	}
	if evidence.SchemaName != "public" {
		t.Errorf("schema_name = %q, want %q", evidence.SchemaName, "public")
	}
	if evidence.ObjectName != "users" {
		t.Errorf("object_name = %q, want %q", evidence.ObjectName, "users")
	}
	if evidence.UserName != "admin" {
		t.Errorf("user_name = %q, want %q", evidence.UserName, "admin")
	}
	if evidence.CurrentValue != "weak" {
		t.Errorf("current_value = %q, want %q", evidence.CurrentValue, "weak")
	}
	if evidence.ExpectedValue != "strong" {
		t.Errorf("expected_value = %q, want %q", evidence.ExpectedValue, "strong")
	}
	if evidence.Reason != "Password too weak" {
		t.Errorf("reason = %q, want %q", evidence.Reason, "Password too weak")
	}
	if evidence.AttributeName != "password_strength" {
		t.Errorf("attribute_name = %q, want %q", evidence.AttributeName, "password_strength")
	}
}

// TestBuildEvidenceUppercaseKeys guards against Oracle's default column-name
// casing: an unquoted "AS schema_name" alias comes back from the driver as
// "SCHEMA_NAME", not "schema_name". Evidence extraction must be
// case-insensitive or structured evidence is silently dropped, which falls
// the fingerprint back to the (mutable) finding title and destabilizes
// lifecycle identity across runs.
func TestBuildEvidenceUppercaseKeys(t *testing.T) {
	finding := controlset.Finding{
		Evidence: map[string]interface{}{
			"SCHEMA_NAME": "SYS",
			"OBJECT_NAME": "DBA_USERS",
			"ROLE_NAME":   "DBA",
		},
	}

	evidence := buildEvidence(finding)

	if evidence.SchemaName != "SYS" {
		t.Errorf("schema_name = %q, want %q", evidence.SchemaName, "SYS")
	}
	if evidence.ObjectName != "DBA_USERS" {
		t.Errorf("object_name = %q, want %q", evidence.ObjectName, "DBA_USERS")
	}
	if evidence.RoleName != "DBA" {
		t.Errorf("role_name = %q, want %q", evidence.RoleName, "DBA")
	}
}

// TestConvertFindingsStableFingerprintDespiteVolatileMeasurements guards
// against a control whose row carries a stable identity column (e.g.
// Oracle's ORA-POL-005 "Recovery Area Usage Threshold", aliasing the FRA
// destination's NAME to object_name) alongside columns that legitimately
// fluctuate between runs (usage percentages, byte counts). Without a
// structured identity field, ComputeFingerprint falls back to hashing the
// finding title, and buildFallbackTitle folds those volatile columns into
// the title -- so the same continuing issue would get a new fingerprint
// every run purely because usage changed, and the lifecycle tracker would
// report it as remediated-then-recreated instead of recurring. With
// object_name present, the fingerprint must stay identical across runs even
// though the measurement values (and therefore the title, if it were used)
// differ.
func TestConvertFindingsStableFingerprintDespiteVolatileMeasurements(t *testing.T) {
	ctx := FindingContext{
		AgentID:        "agent-1",
		SystemID:       "sys-1",
		DatabaseEngine: "oracle",
	}

	newRun := func(spaceUsed string) []*controlset.ControlResult {
		return []*controlset.ControlResult{{
			ControlCode: "ORA-POL-005",
			Title:       "Recovery Area Usage Threshold",
			Status:      "FAIL",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{{
					Severity: "MEDIUM",
					Title:    "Recovery Area Usage Threshold",
					Evidence: map[string]interface{}{
						"OBJECT_NAME":       "/u01/app/oracle/fast_recovery_area",
						"SPACE_LIMIT":       "107374182400",
						"SPACE_USED":        spaceUsed,
						"SPACE_RECLAIMABLE": "0",
						"USED_PCT":          spaceUsed,
					},
				}},
			}},
		}}
	}

	run1 := ConvertFindings(newRun("92.10"), ctx)
	run2 := ConvertFindings(newRun("97.55"), ctx)

	if len(run1) != 1 || len(run2) != 1 {
		t.Fatalf("expected 1 event per run, got %d and %d", len(run1), len(run2))
	}
	if run1[0].Evidence.ObjectName != "/u01/app/oracle/fast_recovery_area" {
		t.Fatalf("object_name not populated: %+v", run1[0].Evidence)
	}
	if run1[0].Fingerprint != run2[0].Fingerprint {
		t.Errorf("fingerprint changed across runs despite stable object_name: %q vs %q",
			run1[0].Fingerprint, run2[0].Fingerprint)
	}
}

// TestConvertFindingsStableFingerprintDespiteMutableConfigValue guards
// against the same class of bug as
// TestConvertFindingsStableFingerprintDespiteVolatileMeasurements, for
// SQLite's SQLITE-SEC-001 and SQLITE-SEC-005: their finding_title embeds the
// live agent-connection setting being reviewed (e.g. "agent connection
// reports {AGENT_CONNECTION_FK_ENABLED}"), which is expected to change --
// that's the point of a review-required control. Without a structured
// identity field, that value change would mint a new fingerprint every time
// the observed setting flips, so the lifecycle tracker would report the same
// "review this setting" issue as remediated-then-recreated instead of
// updated. The control now aliases a stable literal to attribute_name (see
// control-sets/sqlite-controls-baseline-v1.0.0.yaml); the fingerprint must
// stay identical across runs even though the observed value differs.
func TestConvertFindingsStableFingerprintDespiteMutableConfigValue(t *testing.T) {
	ctx := FindingContext{
		AgentID:        "agent-1",
		SystemID:       "sys-1",
		DatabaseEngine: "sqlite",
	}

	newRun := func(fkEnabled, title string) []*controlset.ControlResult {
		return []*controlset.ControlResult{{
			ControlCode: "SQLITE-SEC-001",
			Title:       "Foreign Key Enforcement Configuration Review",
			Status:      "REVIEW",
			Procedures: []controlset.ProcedureResult{{
				Status: "REVIEW",
				Findings: []controlset.Finding{{
					Severity: "MEDIUM",
					Title:    title,
					Evidence: map[string]interface{}{
						"attribute_name":              "foreign_keys",
						"AGENT_CONNECTION_FK_ENABLED": fkEnabled,
					},
				}},
			}},
		}}
	}

	run1 := ConvertFindings(newRun("0", "Review application foreign-key enforcement (agent connection reports 0)"), ctx)
	run2 := ConvertFindings(newRun("1", "Review application foreign-key enforcement (agent connection reports 1)"), ctx)

	if len(run1) != 1 || len(run2) != 1 {
		t.Fatalf("expected 1 event per run, got %d and %d", len(run1), len(run2))
	}
	if run1[0].Evidence.AttributeName != "foreign_keys" {
		t.Fatalf("attribute_name not populated: %+v", run1[0].Evidence)
	}
	if run1[0].Fingerprint != run2[0].Fingerprint {
		t.Errorf("fingerprint changed across runs despite stable attribute_name: %q vs %q",
			run1[0].Fingerprint, run2[0].Fingerprint)
	}
}

func TestConvertFindingsPreservesEventTime(t *testing.T) {
	ctx := FindingContext{
		AgentID:    "agent-1",
		SystemID:   "sys-1",
		SystemName: "test-db",
	}

	results := []*controlset.ControlResult{{
		ControlCode: "TEST-001",
		ExecutedAt:  time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		Procedures: []controlset.ProcedureResult{{
			Status:     "FAIL",
			ExecutedAt: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
			Findings: []controlset.Finding{{
				Title: "Test Finding",
			}},
		}},
	}}

	before := time.Now().UTC()
	events := ConvertFindings(results, ctx)
	after := time.Now().UTC()

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Event time should be around now (not the control's ExecutedAt)
	eventTime := events[0].EventTime
	if eventTime.Before(before) || eventTime.After(after) {
		t.Errorf("event time %v not between %v and %v", eventTime, before, after)
	}
}
