package controlset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateControlSetRejectsMalformedCondition guards against control-set
// loading silently accepting a criterion condition it cannot evaluate. A
// malformed or unsupported condition must be rejected at load time, before any
// customer database is queried, instead of behaving as a silent PASS later.
func TestValidateControlSetRejectsMalformedCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
	}{
		{"unsupported operator", "username LIKE 'SCOTT%'"},
		{"lowercase or is not a recognized keyword", "username == 'a' or username == 'b'"},
		{"empty condition", ""},
		{"dangling comparison operator", "username =="},
		{"malformed IN with no value list", "username IN"},
		{"malformed CONTAINS with no column", " CONTAINS 'x'"},
		{"malformed row_count operand", "row_count > many"},
		{"row_count comparing wrong column", "row_count_total > 5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := &ControlSet{
				Metadata: Metadata{ControlSetID: "test-set", DatabaseType: "oracle"},
				Controls: []Control{
					{
						ControlID: "C-1",
						Procedures: []ControlProcedure{
							{
								ProcedureID: "P-1",
								Tests:       "SELECT 1",
								Criteria: []ControlCriteria{
									{Condition: tt.condition, Severity: "HIGH"},
								},
							},
						},
					},
				},
			}

			if err := validateControlSet(set); err == nil {
				t.Fatalf("expected validation to reject condition %q, got no error", tt.condition)
			}
		})
	}
}

// TestValidateControlSetAcceptsSupportedConditions confirms load-time
// validation does not regress any currently-supported condition form.
func TestValidateControlSetAcceptsSupportedConditions(t *testing.T) {
	tests := []string{
		"username == 'SCOTT'",
		"username != 'SCOTT'",
		"row_count > 0",
		"row_count >= 5",
		"username CONTAINS 'adm'",
		"username IN ('a', 'b')",
		"username == 'a' AND status == 'active'",
		"username == 'a' OR username == 'b'",
		"review_required",
		"license_required",
		"informational",
	}

	for _, condition := range tests {
		t.Run(condition, func(t *testing.T) {
			set := &ControlSet{
				Metadata: Metadata{ControlSetID: "test-set", DatabaseType: "oracle"},
				Controls: []Control{
					{
						ControlID: "C-1",
						Procedures: []ControlProcedure{
							{
								ProcedureID: "P-1",
								Tests:       "SELECT 1",
								Criteria: []ControlCriteria{
									{Condition: condition, Severity: "HIGH"},
								},
							},
						},
					},
				},
			}

			if err := validateControlSet(set); err != nil {
				t.Fatalf("expected condition %q to be accepted, got: %v", condition, err)
			}
		})
	}
}

// TestBundledControlPacksLoadSuccessfully confirms every real control pack
// shipped in control-sets/*.yaml passes load-time condition validation. If
// this fails after tightening validation, the affected pack's condition needs
// fixing, not the validator relaxing.
func TestBundledControlPacksLoadSuccessfully(t *testing.T) {
	controlSetsDir := "../../control-sets"
	if _, err := os.Stat(controlSetsDir); os.IsNotExist(err) {
		t.Skip("control-sets directory not found (running from different directory)")
	}

	entries, err := os.ReadDir(controlSetsDir)
	if err != nil {
		t.Fatalf("failed to read control-sets directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filename := entry.Name()
		t.Run(filename, func(t *testing.T) {
			path := filepath.Join(controlSetsDir, filename)
			if _, err := LoadControlSet(path); err != nil {
				t.Fatalf("failed to load %s: %v", filename, err)
			}
		})
	}
}

// TestSQLiteConnectionScopedControlsRemainReviews ensures controls based only on
// the agent's SQLite connection never become confirmed database findings.
func TestSQLiteConnectionScopedControlsRemainReviews(t *testing.T) {
	set, err := LoadControlSet("../../control-sets/sqlite-controls-baseline-v1.0.0.yaml")
	if err != nil {
		t.Fatalf("failed to load SQLite control set: %v", err)
	}

	for controlID, field := range map[string]string{
		"SQLITE-SEC-001": "AGENT_CONNECTION_FK_ENABLED",
		"SQLITE-SEC-005": "AGENT_CONNECTION_SYNCHRONOUS",
	} {
		found := false
		for _, control := range set.Controls {
			if control.ControlID != controlID {
				continue
			}
			found = true
			if control.Procedures[0].Criteria[0].Condition != "review_required" {
				t.Fatalf("%s must remain a review control", controlID)
			}
			if !strings.Contains(control.Description, "Evidence boundary:") {
				t.Fatalf("%s must state its evidence boundary", controlID)
			}
			if !strings.Contains(control.Procedures[0].Tests, "AS "+field) || !strings.Contains(control.Procedures[0].Criteria[0].FindingTitle, "{"+field+"}") {
				t.Fatalf("%s must render its observed agent-connection value", controlID)
			}
			break
		}
		if !found {
			t.Fatalf("%s is missing from the SQLite control set", controlID)
		}
	}
}
