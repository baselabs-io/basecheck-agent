package controlset

import (
	"basecheck-agent/pkg/config"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"basecheck-agent/pkg/database"
)

type mockDB struct {
	rows      []database.Row
	err       error
	lastSQL   string
	callCount int
}

func (m *mockDB) Connect() error {
	return nil
}

func (m *mockDB) ExecuteQuery(_ context.Context, sql string) ([]database.Row, error) {
	m.callCount++
	m.lastSQL = sql
	return m.rows, m.err
}

func (m *mockDB) GetVersion() (string, error) {
	return "test", nil
}

func (m *mockDB) GetInstanceInfo() (*database.InstanceInfo, error) {
	return &database.InstanceInfo{}, nil
}

func (m *mockDB) Close() error {
	return nil
}

func TestExecuteControl_RowCountEqualsZeroFailsWhenRowsReturned(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{"USERNAME": "SCOTT"}},
	})

	control := &Control{
		ControlID:   "C-1",
		ControlCode: "C-1",
		Title:       "Test Control",
		Description: "Test Description",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-1",
				SystemType:  "oracle",
				Tests:       "SELECT 1 FROM dual",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if len(result.Procedures) != 1 {
		t.Fatalf("expected 1 procedure result, got %d", len(result.Procedures))
	}
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Procedures[0].Findings))
	}
	if result.Procedures[0].Findings[0].Title != "Test Control: username=SCOTT" {
		t.Fatalf("expected ADEAS fallback title, got %q", result.Procedures[0].Findings[0].Title)
	}
	if evidenceRows, ok := result.Procedures[0].Findings[0].Evidence["row"]; !ok || evidenceRows == nil {
		t.Fatalf("expected row evidence for row_count failure")
	}
}

func TestExecuteControl_RowCountEqualsZeroPassesWhenNoRowsReturned(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{},
	})

	control := &Control{
		ControlID:   "C-2",
		ControlCode: "C-2",
		Title:       "Test Control",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-2",
				SystemType:  "oracle",
				Tests:       "SELECT 1 FROM dual WHERE 1=0",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "PASS" {
		t.Fatalf("expected PASS status, got %s", result.Status)
	}
	if len(result.Procedures[0].Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Procedures[0].Findings))
	}
}

func TestExecuteControl_ReviewRequiredCreatesFinding(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{"ITEM": "X"}},
	})

	control := &Control{
		ControlID:   "C-3",
		ControlCode: "C-3",
		Title:       "Review Control",
		Description: "Requires manual review",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-3",
				SystemType:  "oracle",
				Tests:       "SELECT 'X' AS ITEM FROM dual",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "MEDIUM"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "REVIEW" {
		t.Fatalf("expected REVIEW status, got %s", result.Status)
	}
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Procedures[0].Findings))
	}
	if result.Procedures[0].Findings[0].Status != "Review Required" {
		t.Fatalf("expected Review Required finding status, got %q", result.Procedures[0].Findings[0].Status)
	}
	if len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected procedure rows to be preserved, got %d", len(result.Procedures[0].Rows))
	}
}

func TestExecuteControl_ReviewRequiredFormatsByteValuesInTitle(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{
			"schema_name":   "storage",
			"function_name": []byte("operation"),
		}},
	})

	control := &Control{
		ControlID:   "SB-VAL-003",
		ControlCode: "SB-VAL-003",
		Title:       "Client-Executable RPC Authorization Validation",
		Description: "Review control",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "sb-val-003-review",
				SystemType:  "supabase",
				Tests:       "SELECT 1",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "MEDIUM"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Procedures[0].Findings))
	}
	if strings.Contains(result.Procedures[0].Findings[0].Title, "[111 112 101") {
		t.Fatalf("expected normalized title, got %q", result.Procedures[0].Findings[0].Title)
	}
	if !strings.Contains(result.Procedures[0].Findings[0].Title, "function_name=operation") {
		t.Fatalf("expected readable function name in title, got %q", result.Procedures[0].Findings[0].Title)
	}
}

func TestExecuteControl_ConditionMatchingIsCaseInsensitive(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{"USERNAME": "SCOTT"}},
	})

	control := &Control{
		ControlID:   "C-4",
		ControlCode: "C-4",
		Title:       "Case Test",
		Description: "Column name matching should be case-insensitive",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-4",
				SystemType:  "oracle",
				Tests:       "SELECT 'SCOTT' AS USERNAME FROM dual",
				Criteria: []ControlCriteria{
					{Condition: "username == 'SCOTT'", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Procedures[0].Findings))
	}
}

// TestExecuteControl_UnrecognizedConditionFailsClosed guards against a malformed
// or unsupported condition silently behaving as a non-match and leaving the
// procedure at its initial PASS status. An unrecognized condition that somehow
// reaches execution must produce ERROR, never PASS.
func TestExecuteControl_UnrecognizedConditionFailsClosed(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{"USERNAME": "SCOTT"}},
	})

	control := &Control{
		ControlID:   "C-BAD-COND",
		ControlCode: "C-BAD-COND",
		Title:       "Bad Condition Test",
		Description: "Condition uses an unrecognized operator",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-BAD-COND",
				SystemType:  "oracle",
				Tests:       "SELECT 'SCOTT' AS USERNAME FROM dual",
				Criteria: []ControlCriteria{
					// "LIKE" is not a supported operator; this must never be
					// silently treated as a non-match (which would leave the
					// procedure at PASS).
					{Condition: "username LIKE 'SCO%'", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status for unrecognized condition, got %s", result.Status)
	}
	if result.Procedures[0].Status != "ERROR" {
		t.Fatalf("expected procedure ERROR status for unrecognized condition, got %s", result.Procedures[0].Status)
	}
	if result.Procedures[0].Error == nil {
		t.Fatal("expected procedure error to be set for unrecognized condition")
	}
}

func TestExecuteControl_ContainsConditionMatchesResponseBody(t *testing.T) {
	executor := NewExecutor(&mockDB{
		rows: []database.Row{{"response_body": "{\"error\":\"stack trace leaked\"}"}},
	})

	control := &Control{
		ControlID:   "C-4B",
		ControlCode: "C-4B",
		Title:       "Contains Test",
		Description: "Contains operator should match response text",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-4B",
				SystemType:  "oracle",
				Tests:       "SELECT 1",
				Criteria: []ControlCriteria{
					{Condition: "response_body CONTAINS 'stack trace'", Severity: "MEDIUM"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Procedures[0].Findings))
	}
}

func TestBuildFallbackTitleUsesRowValues(t *testing.T) {
	executor := NewExecutor(&mockDB{})

	title := executor.buildFallbackTitle("Role Validation", database.Row{
		"ROLE_NAME":      "authenticated",
		"ATTRIBUTE_NAME": "rolbypassrls",
		"CURRENT_VALUE":  true,
		"EXPECTED_VALUE": false,
	})

	if title != "Role Validation: role_name=authenticated, attribute_name=rolbypassrls, current_value=true, expected_value=false" {
		t.Fatalf("unexpected fallback title %q", title)
	}
}

func TestBuildIncrementalEvidenceSQLOracleUnified(t *testing.T) {
	sql := "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}} ORDER BY EVENT_TIMESTAMP ASC"
	watermark := `{"event_timestamp":"2026-03-20T10:00:00","entry_id":10,"statement_id":20}`

	result := buildIncrementalEvidenceSQL("oracle", "audit_operations", sql, watermark)

	if result == sql {
		t.Fatalf("expected watermark placeholder to be replaced")
	}
	if !strings.Contains(result, "ENTRY_ID") || !strings.Contains(result, "STATEMENT_ID") {
		t.Fatalf("expected Oracle composite watermark condition, got %s", result)
	}
}

func TestBuildIncrementalEvidenceSQLFallsBackToDefaultWindow(t *testing.T) {
	sql := "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}"

	result := buildIncrementalEvidenceSQL("oracle", "audit_operations", sql, "")

	if !strings.Contains(result, "SYSTIMESTAMP - INTERVAL '30' DAY") {
		t.Fatalf("expected default history window, got %s", result)
	}
}

func TestBuildIncrementalEvidenceSQLInvalidWatermarkFallsBackToDefaultWindow(t *testing.T) {
	sql := "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}"

	result := buildIncrementalEvidenceSQL("oracle", "audit_operations", sql, "{invalid")

	if !strings.Contains(result, "SYSTIMESTAMP - INTERVAL '30' DAY") {
		t.Fatalf("expected invalid watermark to fall back to default history window, got %s", result)
	}
}

func TestExecuteControl_InterpolatesControlVariablesInSQL(t *testing.T) {
	db := &mockDB{}
	executor := NewExecutor(db)
	executor.ConfigureControlVariables(map[string]string{
		"ORA_MAX_TRANSPORT_LAG_SECONDS": "300",
		"ORA_APPROVED_PROTECTION_MODE":  "MAXIMUM AVAILABILITY",
	})

	control := &Control{
		ControlID:   "C-5",
		ControlCode: "C-5",
		Title:       "Variable Test",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-5",
				SystemType:  "oracle",
				Tests:       "SELECT {{ORA_MAX_TRANSPORT_LAG_SECONDS}} AS max_lag, '{{ORA_APPROVED_PROTECTION_MODE}}' AS protection_mode FROM dual",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH"},
				},
			},
		},
	}

	executor.ExecuteControl(context.Background(), control)

	expectedSQL := "SELECT 300 AS max_lag, 'MAXIMUM AVAILABILITY' AS protection_mode FROM dual"
	if db.lastSQL != expectedSQL {
		t.Fatalf("expected interpolated SQL %q, got %q", expectedSQL, db.lastSQL)
	}
}

func TestExecuteControl_InterpolatesControlVariableDefaultsInSQL(t *testing.T) {
	db := &mockDB{}
	executor := NewExecutor(db)
	executor.ConfigureControlVariables(map[string]string{
		"MS_PROD_NAME_INCLUDE_PATTERN": "%prod%",
	})

	control := &Control{
		ControlID:   "C-5A",
		ControlCode: "C-5A",
		Title:       "Variable Default Test",
		Procedures: []ControlProcedure{
			{
				ProcedureID: "P-5A",
				SystemType:  "mssql",
				Tests:       "SELECT '{{MS_PROD_NAME_INCLUDE_PATTERN|%}}' AS include_pattern, '{{MS_NONPROD_NAME_EXCLUDE_PATTERN|%test%}}' AS exclude_pattern",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH"},
				},
			},
		},
	}

	executor.ExecuteControl(context.Background(), control)

	expectedSQL := "SELECT '%prod%' AS include_pattern, '%test%' AS exclude_pattern"
	if db.lastSQL != expectedSQL {
		t.Fatalf("expected interpolated SQL %q, got %q", expectedSQL, db.lastSQL)
	}
}

func TestBuildIncrementalEvidenceSQLSupabaseAuthAudit(t *testing.T) {
	sql := "SELECT * FROM auth.audit_log_entries WHERE {{BASECHECK_SUPABASE_AUTH_AUDIT_WATERMARK}} ORDER BY created_at ASC"
	watermark := `{"event_timestamp":"2026-03-20T10:00:00","event_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

	result := buildIncrementalEvidenceSQL("supabase", "audit_operations_auth", sql, watermark)

	if result == sql {
		t.Fatalf("expected Supabase auth audit watermark placeholder to be replaced")
	}
	if !strings.Contains(result, "md5(COALESCE(payload::text, ''))") || !strings.Contains(result, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("expected Supabase auth audit watermark condition, got %s", result)
	}
}

func TestBuildIncrementalEvidenceSQLInvalidTimestampFallsBackToDefaultWindow(t *testing.T) {
	sql := "SELECT * FROM auth.audit_log_entries WHERE {{BASECHECK_SUPABASE_AUTH_AUDIT_WATERMARK}} ORDER BY created_at ASC"
	watermark := `{"event_timestamp":"2026-03-20T10:00:00' OR 1=1 --","event_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

	result := buildIncrementalEvidenceSQL("supabase", "audit_operations_auth", sql, watermark)

	if !strings.Contains(result, "created_at > NOW() - INTERVAL '30 days'") {
		t.Fatalf("expected invalid timestamp to fall back to default window, got %s", result)
	}
}

func TestExecuteControlHTTPProcedureCreatesFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/proj-ref/config" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "proj-ref",
			"name": "prod-project",
		})
	}))
	defer server.Close()

	executorDB := &mockDB{}
	executor := NewExecutor(executorDB)
	executor.ConfigureManagementAPI("proj-ref", "token-123", server.URL, true)

	control := &Control{
		ControlID:   "SB-PLAT-001",
		ControlCode: "SB-PLAT-001",
		Title:       "Management API Coverage Review",
		Description: "Review project configuration",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-plat-001-check",
				SystemType:    "supabase",
				ExecutionMode: "http",
				Tests:         "method: GET\npath: /v1/projects/{{PROJECT_REF}}/config\n",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "REVIEW" {
		t.Fatalf("expected REVIEW status, got %s", result.Status)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one HTTP procedure row")
	}
	if executorDB.callCount != 0 {
		t.Fatalf("expected SQL database to be unused, got %d calls", executorDB.callCount)
	}
}

func TestExecuteControlHTTPProcedureRequiresManagementToken(t *testing.T) {
	executor := NewExecutor(&mockDB{})
	control := &Control{
		ControlID:   "SB-PLAT-002",
		ControlCode: "SB-PLAT-002",
		Title:       "Backup Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-plat-002-check",
				SystemType:    "supabase",
				ExecutionMode: "http",
				Tests:         "method: GET\npath: /v1/projects/{{PROJECT_REF}}/database/backups\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "missing Supabase Management API token") {
		t.Fatalf("expected missing token error, got %v", result.Procedures[0].Error)
	}
}

func TestExecuteControlHTTPProcedureSupportsRowPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/proj-ref/analytics/endpoints/logs.all" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []map[string]interface{}{
				{"event_message": "first"},
				{"event_message": "second"},
			},
		})
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureManagementAPI("proj-ref", "token-123", server.URL, true)

	control := &Control{
		ControlID:   "SB-PLAT-006",
		ControlCode: "SB-PLAT-006",
		Title:       "Platform Audit Log Export and Retention Review",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-plat-006-check",
				SystemType:    "supabase",
				ExecutionMode: "http",
				Tests:         "method: GET\npath: /v1/projects/{{PROJECT_REF}}/analytics/endpoints/logs.all\nrow_path: result\n",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "MEDIUM"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "REVIEW" {
		t.Fatalf("expected REVIEW status, got %s", result.Status)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 2 {
		t.Fatalf("expected two rows from row_path selection, got %+v", result.Procedures)
	}
}

func TestExecuteControlHTTPProcedureRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"blob":"` + strings.Repeat("a", 256*1024) + `"}`))
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureManagementAPI("proj-ref", "token-123", server.URL, true)

	control := &Control{
		ControlID:   "SB-PLAT-001",
		ControlCode: "SB-PLAT-001",
		Title:       "Management API Coverage Review",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-plat-001-check",
				SystemType:    "supabase",
				ExecutionMode: "http",
				Tests:         "method: GET\npath: /v1/projects/{{PROJECT_REF}}/config\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "exceeded maximum size") {
		t.Fatalf("expected oversized response error, got %v", result.Procedures[0].Error)
	}
}

func TestExecuteControlSourceScanProcedureCreatesFindings(t *testing.T) {
	dir := t.TempDir()
	functionDir := filepath.Join(dir, "user-admin")
	if err := os.MkdirAll(functionDir, 0o755); err != nil {
		t.Fatalf("failed to create function dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(functionDir, "index.ts"), []byte("const key = 'eyJhbGci-service-role'\n"), 0o644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	executor := NewExecutor(&mockDB{})
	executor.ConfigureSourceScan(dir)

	control := &Control{
		ControlID:   "SB-EDGE-001",
		ControlCode: "SB-EDGE-001",
		Title:       "Edge Function Service Role Secret Review",
		Description: "Review hardcoded service-role secret handling",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-edge-001-check",
				SystemType:    "supabase",
				ExecutionMode: "source_scan",
				Tests: "patterns:\n" +
					"  - name: hardcoded_service_role_secret\n" +
					"    regex: \"eyJ[a-zA-Z0-9._-]*service-role\"\n" +
					"    expected_value: environment_or_secret_manager_reference\n" +
					"    reason: service-role credential is embedded in source\n" +
					"    fix: move credential to approved secret-delivery path and rotate exposed key\n",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "CRITICAL", FindingTitle: "Hardcoded service-role secret in {function_name}"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one source-scan row, got %+v", result.Procedures)
	}
	row := result.Procedures[0].Rows[0]
	if row["function_name"] != "user-admin" {
		t.Fatalf("expected function_name=user-admin, got %+v", row)
	}
	if row["matched_pattern"] != "hardcoded_service_role_secret" {
		t.Fatalf("expected matched_pattern to be set, got %+v", row)
	}
	if len(result.Procedures[0].Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", result.Procedures[0].Findings)
	}
	if result.Procedures[0].Findings[0].Title != "Hardcoded service-role secret in user-admin" {
		t.Fatalf("unexpected finding title %q", result.Procedures[0].Findings[0].Title)
	}
}

func TestExecuteControlSourceScanProcedureSkipsWhenRootPathMissing(t *testing.T) {
	executor := NewExecutor(&mockDB{})

	control := &Control{
		ControlID:   "SB-EDGE-005",
		ControlCode: "SB-EDGE-005",
		Title:       "Edge Function Secret Management Review",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-edge-005-check",
				SystemType:    "supabase",
				ExecutionMode: "source_scan",
				Tests: "patterns:\n" +
					"  - name: hardcoded_secret_literal\n" +
					"    regex: \"secret\"\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "PASS" {
		t.Fatalf("expected PASS status, got %s", result.Status)
	}
	if result.Procedures[0].Error != nil {
		t.Fatalf("expected no error, got %v", result.Procedures[0].Error)
	}
	if len(result.Procedures[0].Rows) != 0 {
		t.Fatalf("expected no source scan rows, got %+v", result.Procedures[0].Rows)
	}
}

func TestExecuteControlSourceScanProcedureCreatesFindingFromFileRule(t *testing.T) {
	dir := t.TempDir()
	functionDir := filepath.Join(dir, "admin-report")
	if err := os.MkdirAll(functionDir, 0o755); err != nil {
		t.Fatalf("failed to create function dir: %v", err)
	}
	content := "const serviceClient = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)\nawait serviceClient.from('reports').select('*')\n"
	if err := os.WriteFile(filepath.Join(functionDir, "index.ts"), []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	executor := NewExecutor(&mockDB{})
	executor.ConfigureSourceScan(dir)

	control := &Control{
		ControlID:   "SB-EDGE-008",
		ControlCode: "SB-EDGE-008",
		Title:       "Edge Function Permission Boundary Review",
		Description: "Review elevated client authorization boundaries",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-edge-008-source-scan",
				SystemType:    "supabase",
				ExecutionMode: "source_scan",
				Tests: "file_rules:\n" +
					"  - name: elevated_client_without_visible_manual_boundary\n" +
					"    sink_regex: \"SUPABASE_SERVICE_ROLE_KEY|serviceClient\"\n" +
					"    required_regexes:\n" +
					"      - \"auth\\\\.getUser\\\\(\\\\)\"\n" +
					"      - \"user_id\"\n" +
					"      - \"tenant_id\"\n" +
					"    current_value: elevated_client_without_visible_manual_boundary\n" +
					"    expected_value: elevated_client_with_explicit_authorization_boundary\n" +
					"    reason: privileged client use is not bounded by visible manual authorization logic\n" +
					"    fix: add explicit validated-user or validated-tenant authorization checks before privileged access\n",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH", FindingTitle: "Edge Function {function_name} lacks visible authorization boundary"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one source-scan row, got %+v", result.Procedures[0].Rows)
	}
	if result.Procedures[0].Rows[0]["matched_pattern"] != "elevated_client_without_visible_manual_boundary" {
		t.Fatalf("unexpected row %+v", result.Procedures[0].Rows[0])
	}
}

func TestExecuteControlSourceScanProcedureMergesMetadataFile(t *testing.T) {
	dir := t.TempDir()
	functionDir := filepath.Join(dir, "orders")
	if err := os.MkdirAll(functionDir, 0o755); err != nil {
		t.Fatalf("failed to create function dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(functionDir, "index.ts"), []byte("const corsHeaders = { 'Access-Control-Allow-Origin': '*' }\n"), 0o644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	metadata := "functions:\n  orders:\n    cors_runtime_path: /orders/preflight\n    cors_runtime_method: OPTIONS\n    error_runtime_path: /orders/fail\n"
	if err := os.WriteFile(filepath.Join(dir, ".basecheck-edge-routes.yaml"), []byte(metadata), 0o644); err != nil {
		t.Fatalf("failed to write metadata file: %v", err)
	}

	executor := NewExecutor(&mockDB{})
	executor.ConfigureSourceScan(dir)

	control := &Control{
		ControlID:   "SB-EDGE-004",
		ControlCode: "SB-EDGE-004",
		Title:       "Edge Function CORS Review",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-edge-004-source-scan",
				SystemType:    "supabase",
				ExecutionMode: "source_scan",
				Tests: "metadata_file: .basecheck-edge-routes.yaml\npatterns:\n" +
					"  - name: wildcard_cors_origin\n" +
					"    regex: \"Access-Control-Allow-Origin\"\n",
				Criteria: []ControlCriteria{
					{Condition: "row_count = 0", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	row := result.Procedures[0].Rows[0]
	if row["cors_runtime_path"] != "/orders/preflight" {
		t.Fatalf("expected cors_runtime_path from metadata, got %+v", row)
	}
	if row["cors_runtime_method"] != "OPTIONS" {
		t.Fatalf("expected cors_runtime_method from metadata, got %+v", row)
	}
	if row["error_runtime_path"] != "/orders/fail" {
		t.Fatalf("expected error_runtime_path from metadata, got %+v", row)
	}
	if row["auth_runtime_path"] != "/orders" {
		t.Fatalf("expected default auth_runtime_path, got %+v", row)
	}
}

func TestExecuteControlActiveValidationProcedureUsesAllowlistedTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/storage/v1/object/sign/private-bucket/test.txt" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "forbidden",
		})
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/storage/v1/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-001",
		ControlCode: "SB-VAL-001",
		Title:       "Signed URL Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-001-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-api\nmethod: GET\npath: /storage/v1/object/sign/private-bucket/test.txt\nexpected_status:\n  - 403\n",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "REVIEW" {
		t.Fatalf("expected REVIEW status, got %s", result.Status)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one active validation row, got %+v", result.Procedures)
	}
	if result.Procedures[0].Rows[0]["status_code"] != 403 {
		t.Fatalf("expected status_code 403, got %+v", result.Procedures[0].Rows[0])
	}
}

func TestExecuteControlActiveValidationProcedureUsesSeedSQLAndTargetHeaders(t *testing.T) {
	executorDB := &mockDB{
		rows: []database.Row{
			{
				"bucket_name": "private-bucket",
				"object_name": "folder/test file.txt",
			},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/storage/v1/object/public/private-bucket/folder%2Ftest%20file.txt" {
			t.Fatalf("unexpected request path: %s", r.URL.EscapedPath())
		}
		if got := r.Header.Get("apikey"); got != "anon-key-1" {
			t.Fatalf("unexpected apikey header: %s", got)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"reachable": true,
		})
	}))
	defer server.Close()

	executor := NewExecutor(executorDB)
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Identities: []config.ActiveValidationIdentity{
			{
				Name: "anon",
				Headers: map[string]string{
					"apikey": "anon-key-1",
				},
			},
		},
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-anon-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/storage/v1/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-011",
		ControlCode: "SB-VAL-011",
		Title:       "Public URL Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-011-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "identity: anon\ntarget: supabase-anon-api\nmethod: GET\npath: /storage/v1/object/public/{{bucket_name}}/{{object_name}}\nseed_sql: |\n  SELECT 'private-bucket' AS bucket_name,\n         'folder/test file.txt' AS object_name\nexpected_status:\n  - 200\n",
				Criteria: []ControlCriteria{
					{Condition: "status_code == 200", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if executorDB.callCount != 1 {
		t.Fatalf("expected seed SQL to execute once, got %d", executorDB.callCount)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one result row, got %+v", result.Procedures)
	}
}

func TestExecuteControlActiveValidationProcedureInterpolatesMethodAndPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			t.Fatalf("unexpected request method: %s", r.Method)
		}
		if r.URL.Path != "/orders/preflight" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	executorDB := &mockDB{
		rows: []database.Row{
			{
				"cors_runtime_method": "OPTIONS",
				"cors_runtime_path":   "/orders/preflight",
				"function_name":       "orders",
			},
		},
	}
	executor := NewExecutor(executorDB)
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-edge-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/orders/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-EDGE-004",
		ControlCode: "SB-EDGE-004",
		Title:       "Edge Function CORS Review",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-edge-004-runtime-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-edge-api\nmethod: \"{{cors_runtime_method}}\"\npath: \"{{cors_runtime_path}}\"\nseed_sql: |\n  SELECT 'OPTIONS' AS cors_runtime_method,\n         '/orders/preflight' AS cors_runtime_path,\n         'orders' AS function_name\nexpected_status:\n  - 204\n",
				Criteria: []ControlCriteria{
					{Condition: "response_header_access_control_allow_origin == '*'", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "FAIL" {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	row := result.Procedures[0].Rows[0]
	if row["request_path"] != "/orders/preflight" {
		t.Fatalf("expected templated request_path, got %+v", row)
	}
}

func TestExecuteControlActiveValidationProcedureUsesIdentityHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer auth-token-1" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "forbidden",
		})
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Identities: []config.ActiveValidationIdentity{
			{
				Name: "authenticated",
				Headers: map[string]string{
					"Authorization": "Bearer auth-token-1",
				},
			},
		},
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-rest-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/rest/v1/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-012",
		ControlCode: "SB-VAL-012",
		Title:       "Role Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-012-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "identity: authenticated\ntarget: supabase-rest-api\nmethod: GET\npath: /rest/v1/orders?select=id\nexpected_status:\n  - 403\n",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "REVIEW" {
		t.Fatalf("expected REVIEW status, got %s", result.Status)
	}
}

func TestExecuteControlActiveValidationProcedureRejectsHeaderInjection(t *testing.T) {
	executorDB := &mockDB{
		rows: []database.Row{
			{
				"bad_header": "ok\r\nInjected: evil",
			},
		},
	}

	executor := NewExecutor(executorDB)
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-rest-api",
				BaseURL:      "https://example.supabase.co",
				AllowedPaths: []string{"/rest/v1/"},
			},
		},
	}, false)

	control := &Control{
		ControlID:   "SB-VAL-012",
		ControlCode: "SB-VAL-012",
		Title:       "Role Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-012-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-rest-api\nmethod: GET\npath: /rest/v1/orders?select=id\nheaders:\n  X-Test: \"{{bad_header}}\"\nseed_sql: |\n  SELECT 'ok\r\nInjected: evil' AS bad_header\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "header value is invalid") {
		t.Fatalf("expected header validation error, got %v", result.Procedures[0].Error)
	}
}

func TestExecuteControlActiveValidationSignedURLFlow(t *testing.T) {
	executorDB := &mockDB{
		rows: []database.Row{
			{
				"bucket_name":         "private-bucket",
				"object_name":         "folder/test.txt",
				"sibling_object_name": "folder/other.txt",
			},
		},
	}

	var fetchCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.EscapedPath() == "/storage/v1/object/sign/private-bucket/folder%2Ftest.txt":
			if got := r.Header.Get("Authorization"); got != "Bearer signer-token" {
				t.Fatalf("unexpected signer authorization header: %s", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"signedURL": "/storage/v1/object/sign/private-bucket/folder/test.txt?token=abc",
			})
		case r.Method == http.MethodGet && r.URL.RequestURI() == "/storage/v1/object/sign/private-bucket/folder/test.txt?token=abc":
			fetchCount++
			if fetchCount == 1 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("expired"))
		case r.Method == http.MethodGet && r.URL.RequestURI() == "/storage/v1/object/sign/private-bucket/folder/other.txt?token=abc":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("replay denied"))
		default:
			t.Fatalf("unexpected signed-url flow request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer server.Close()

	executor := NewExecutor(executorDB)
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Identities: []config.ActiveValidationIdentity{
			{
				Name: "signer",
				Headers: map[string]string{
					"Authorization": "Bearer signer-token",
				},
			},
		},
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-storage-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/storage/v1/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-010",
		ControlCode: "SB-VAL-010",
		Title:       "Signed URL Replay",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-010-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "flow: signed_url\nseed_sql: |\n  SELECT 'private-bucket' AS bucket_name,\n         'folder/test.txt' AS object_name,\n         'folder/other.txt' AS sibling_object_name\nmax_targets: 1\nmint_target: supabase-storage-api\nmint_identity: signer\nmint_method: POST\nmint_path: /storage/v1/object/sign/{{bucket_name}}/{{object_name}}\nmint_body:\n  expiresIn: 1\nfetch_expected_status:\n  - 200\nreplay_path: /storage/v1/object/sign/{{bucket_name}}/{{sibling_object_name}}\nreplay_expected_status:\n  - 401\n  - 403\n  - 404\nexpiry_wait_seconds: 1\nexpiry_expected_status:\n  - 401\n  - 403\n  - 404\n",
				Criteria: []ControlCriteria{
					{Condition: "replay_status == 200", Severity: "HIGH"},
					{Condition: "expiry_status == 200", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "PASS" {
		t.Fatalf("expected PASS status, got %s", result.Status)
	}
	if executorDB.callCount != 1 {
		t.Fatalf("expected seed SQL once, got %d", executorDB.callCount)
	}
	if len(result.Procedures) != 1 || len(result.Procedures[0].Rows) != 1 {
		t.Fatalf("expected one signed-url result row, got %+v", result.Procedures)
	}
	currentRow := result.Procedures[0].Rows[0]
	if currentRow["immediate_status"] != 200 || currentRow["replay_status"] != 403 || currentRow["expiry_status"] != 403 {
		t.Fatalf("unexpected signed-url statuses: %+v", currentRow)
	}
}

func TestMutateSignedURLPathRejectsTraversal(t *testing.T) {
	signedURL := "https://example.supabase.co/storage/v1/object/sign/private-bucket/folder/test.txt?token=abc"

	result := mutateSignedURLPath(signedURL, "/storage/v1/object/sign/private-bucket/../../admin.txt")

	if result != signedURL {
		t.Fatalf("expected traversal replay path to be rejected, got %s", result)
	}
}

func TestExecuteControlActiveValidationCallbackFlow(t *testing.T) {
	var callbackReceived bool
	var registeredURL string
	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sink/register":
			registeredURL = server.URL + "/sink/callback/abc123"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"callback_url":   registeredURL,
				"callback_token": "abc123",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/trigger":
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if fmt.Sprintf("%v", payload["callback_url"]) != registeredURL {
				t.Fatalf("unexpected callback_url in trigger payload: %+v", payload)
			}
			callbackReceived = true
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("{}"))
		case r.Method == http.MethodGet && r.URL.Path == "/sink/events/abc123":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"received": callbackReceived,
			})
		default:
			t.Fatalf("unexpected callback flow request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled:          true,
		AllowStateChange: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "callback-sink",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/sink/"},
			},
			{
				Name:         "supabase-trigger",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/trigger"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-005",
		ControlCode: "SB-VAL-005",
		Title:       "Webhook Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-005-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "flow: callback_http\ncallback_target: callback-sink\ncallback_register_method: POST\ncallback_register_path: /sink/register\ncallback_url_path: callback_url\ncallback_token_path: callback_token\ncallback_poll_method: GET\ncallback_poll_path: /sink/events/{{callback_token}}\ncallback_poll_row_path: .\ncallback_poll_expected_status:\n  - 200\ntrigger_target: supabase-trigger\ntrigger_method: POST\ntrigger_path: /trigger\ntrigger_body:\n  callback_url: \"{{callback_url}}\"\ntrigger_expected_status:\n  - 202\n",
				Criteria: []ControlCriteria{
					{Condition: "callback_received == false", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "PASS" {
		t.Fatalf("expected PASS status, got %s", result.Status)
	}
}

func TestExecuteControlActiveValidationProcedureBlocksPathOutsideAllowlist(t *testing.T) {
	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-api",
				BaseURL:      "https://example.supabase.co",
				AllowedPaths: []string{"/storage/v1/"},
			},
		},
	}, false)

	control := &Control{
		ControlID:   "SB-VAL-003",
		ControlCode: "SB-VAL-003",
		Title:       "RPC Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-003-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-api\nmethod: GET\npath: /rest/v1/rpc/run_sensitive_rpc\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", result.Procedures[0].Error)
	}
}

// TestExecuteControlActiveValidationProcedureBlocksPrefixConfusion guards
// against a raw-string prefix match treating "/api/safe-admin" as covered by
// an allowlist entry of "/api/safe": the allowlist must match on "/"
// boundaries, not arbitrary string prefixes.
func TestExecuteControlActiveValidationProcedureBlocksPrefixConfusion(t *testing.T) {
	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "api",
				BaseURL:      "https://example.com",
				AllowedPaths: []string{"/api/safe"},
			},
		},
	}, false)

	control := &Control{
		ControlID:   "PREFIX-001",
		ControlCode: "PREFIX-001",
		Title:       "Prefix confusion check",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "prefix-001-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: api\nmethod: GET\npath: /api/safe-admin/data\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status for prefix-confused path, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", result.Procedures[0].Error)
	}
}

// TestExecuteControlActiveValidationProcedureBlocksTraversalBypass guards
// against a path containing ".." segments passing a raw-string prefix check
// against an allowlisted path while actually resolving outside it.
func TestExecuteControlActiveValidationProcedureBlocksTraversalBypass(t *testing.T) {
	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "api",
				BaseURL:      "https://example.com",
				AllowedPaths: []string{"/api/safe"},
			},
		},
	}, false)

	control := &Control{
		ControlID:   "TRAVERSAL-001",
		ControlCode: "TRAVERSAL-001",
		Title:       "Traversal bypass check",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "traversal-001-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: api\nmethod: GET\npath: /api/safe/../../admin\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status for traversal path, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", result.Procedures[0].Error)
	}
}

// TestExecuteControlActiveValidationCallbackFlowBlocksPathOutsideAllowlist
// guards against the callback flow's register/trigger/poll requests reaching
// the raw request executor without the same allowlist enforcement the normal
// flow applies. The poll path here is deliberately outside the callback
// target's allowlist.
func TestExecuteControlActiveValidationCallbackFlowBlocksPathOutsideAllowlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/sink/register":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"callback_url":   "http://sink.example/sink/callback/abc123",
				"callback_token": "abc123",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/trigger":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("{}"))
		default:
			t.Fatalf("unexpected callback flow request reached the server: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled:          true,
		AllowStateChange: true,
		Targets: []config.ActiveValidationTarget{
			{
				// Only the register path is allowlisted; poll (/sink/events/...)
				// is not, so the poll request must be rejected before any
				// request reaches the server.
				Name:         "callback-sink",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/sink/register"},
			},
			{
				Name:         "supabase-trigger",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/trigger"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-006",
		ControlCode: "SB-VAL-006",
		Title:       "Webhook Validation Allowlist",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-006-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "flow: callback_http\ncallback_target: callback-sink\ncallback_register_method: POST\ncallback_register_path: /sink/register\ncallback_url_path: callback_url\ncallback_token_path: callback_token\ncallback_poll_method: GET\ncallback_poll_path: /sink/events/{{callback_token}}\ncallback_poll_row_path: .\ncallback_poll_expected_status:\n  - 200\ntrigger_target: supabase-trigger\ntrigger_method: POST\ntrigger_path: /trigger\ntrigger_body:\n  callback_url: \"{{callback_url}}\"\ntrigger_expected_status:\n  - 202\n",
				Criteria: []ControlCriteria{
					{Condition: "callback_received == false", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status for poll path outside allowlist, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", result.Procedures[0].Error)
	}
}

// TestExecuteControlActiveValidationCallbackFlowBlocksStateChangeByDefault
// guards against the callback flow bypassing allow_state_change: its
// register/trigger requests use POST, which must be rejected when state
// -changing requests are not explicitly enabled, exactly like the normal
// flow already enforces.
func TestExecuteControlActiveValidationCallbackFlowBlocksStateChangeByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected callback flow request reached the server: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true, // AllowStateChange intentionally left false (default)
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "callback-sink",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/sink/"},
			},
			{
				Name:         "supabase-trigger",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/trigger"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-007",
		ControlCode: "SB-VAL-007",
		Title:       "Webhook Validation State Change Policy",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-007-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "flow: callback_http\ncallback_target: callback-sink\ncallback_register_method: POST\ncallback_register_path: /sink/register\ncallback_url_path: callback_url\ncallback_token_path: callback_token\ncallback_poll_method: GET\ncallback_poll_path: /sink/events/{{callback_token}}\ncallback_poll_row_path: .\ncallback_poll_expected_status:\n  - 200\ntrigger_target: supabase-trigger\ntrigger_method: POST\ntrigger_path: /trigger\ntrigger_body:\n  callback_url: \"{{callback_url}}\"\ntrigger_expected_status:\n  - 202\n",
				Criteria: []ControlCriteria{
					{Condition: "callback_received == false", Severity: "HIGH"},
				},
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status when state-changing callback requests are disabled, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "state-changing active validation requests are disabled") {
		t.Fatalf("expected state-change policy error, got %v", result.Procedures[0].Error)
	}
}

func TestExecuteControlActiveValidationProcedureBlocksStateChangeByDefault(t *testing.T) {
	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled: true,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-api",
				BaseURL:      "https://example.supabase.co",
				AllowedPaths: []string{"/rest/v1/rpc/"},
			},
		},
	}, false)

	control := &Control{
		ControlID:   "SB-VAL-004",
		ControlCode: "SB-VAL-004",
		Title:       "State Change Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-004-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-api\nmethod: POST\npath: /rest/v1/rpc/run_sensitive_rpc\nbody:\n  sample: value\n",
			},
		},
	}

	result := executor.ExecuteControl(context.Background(), control)
	if result.Status != "ERROR" {
		t.Fatalf("expected ERROR status, got %s", result.Status)
	}
	if result.Procedures[0].Error == nil || !strings.Contains(result.Procedures[0].Error.Error(), "state-changing") {
		t.Fatalf("expected state-change error, got %v", result.Procedures[0].Error)
	}
}

func TestExecuteControlActiveValidationProcedureEnforcesRequestBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
		})
	}))
	defer server.Close()

	executor := NewExecutor(&mockDB{})
	executor.ConfigureActiveValidation(config.ActiveValidationConfig{
		Enabled:           true,
		MaxRequestsPerRun: 1,
		Targets: []config.ActiveValidationTarget{
			{
				Name:         "supabase-api",
				BaseURL:      server.URL,
				AllowedPaths: []string{"/storage/v1/"},
			},
		},
	}, true)

	control := &Control{
		ControlID:   "SB-VAL-005",
		ControlCode: "SB-VAL-005",
		Title:       "Budget Validation",
		Procedures: []ControlProcedure{
			{
				ProcedureID:   "sb-val-005-check",
				SystemType:    "supabase",
				ExecutionMode: "active_validation",
				Tests:         "target: supabase-api\nmethod: GET\npath: /storage/v1/object/sign/private-bucket/test.txt\n",
				Criteria: []ControlCriteria{
					{Condition: "review_required", Severity: "HIGH"},
				},
			},
		},
	}

	first := executor.ExecuteControl(context.Background(), control)
	if first.Status != "REVIEW" {
		t.Fatalf("expected first execution to return REVIEW, got %s", first.Status)
	}

	second := executor.ExecuteControl(context.Background(), control)
	if second.Status != "ERROR" {
		t.Fatalf("expected second execution to fail on budget, got %s", second.Status)
	}
	if second.Procedures[0].Error == nil || !strings.Contains(second.Procedures[0].Error.Error(), "budget exceeded") {
		t.Fatalf("expected budget error, got %v", second.Procedures[0].Error)
	}
}

func TestCalculateEvidenceWatermarkSupabaseAuthAudit(t *testing.T) {
	data := []map[string]interface{}{{
		"EVENT_TIMESTAMP": "2026-03-20T10:00:01",
		"EVENT_HASH":      "def456",
	}}

	result := calculateEvidenceWatermark("supabase", "audit_operations_auth", data, "")

	if !strings.Contains(result, "\"event_hash\":\"def456\"") {
		t.Fatalf("expected auth audit watermark to include event hash, got %s", result)
	}
}

func TestExecuteEvidenceCaptureFallsBackWhenLeaseEndpointFails(t *testing.T) {
	executorDB := &mockDB{
		rows: []database.Row{{"EVENT_TIMESTAMP": "2026-03-20T10:00:00", "ENTRY_ID": 1, "STATEMENT_ID": 2}},
	}
	executor := NewExecutor(executorDB)
	executor.ConfigureIngestionState("http://127.0.0.1:1", "token", "oracle", "oracle-prod", true, true)

	result := executor.executeEvidenceCapture(context.Background(), Evidence{
		Type:        "audit_operations",
		Description: "Recent operations",
		SQL:         "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}",
	})

	if result.Error != nil {
		t.Fatalf("expected fallback without error, got %v", result.Error)
	}
	if result.Skipped {
		t.Fatalf("expected direct query fallback, not skipped result")
	}
	if executorDB.callCount != 1 {
		t.Fatalf("expected 1 query execution, got %d", executorDB.callCount)
	}
	if strings.Contains(executorDB.lastSQL, "{{BASECHECK_ORACLE_UNIFIED_WATERMARK}}") {
		t.Fatalf("expected SQL placeholder to be replaced during fallback, got %s", executorDB.lastSQL)
	}
}

func TestExecuteEvidenceCaptureSkipsWhenLeaseHeldByAnotherAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	executorDB := &mockDB{
		rows: []database.Row{{"EVENT_TIMESTAMP": "2026-03-20T10:00:00", "ENTRY_ID": 1, "STATEMENT_ID": 2}},
	}
	executor := NewExecutor(executorDB)
	executor.ConfigureIngestionState(server.URL, "token", "oracle", "oracle-prod", true, true)

	result := executor.executeEvidenceCapture(context.Background(), Evidence{
		Type:        "audit_operations",
		Description: "Recent operations",
		SQL:         "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}",
	})

	if !result.Skipped {
		t.Fatalf("expected skipped result when lease is held by another agent")
	}
	if executorDB.callCount != 0 {
		t.Fatalf("expected no query execution on lease conflict, got %d", executorDB.callCount)
	}
}

func TestExecuteEvidenceCaptureUsesLeaseWatermark(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&request)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"source_key":       request["source_key"],
			"source_mode":      "history",
			"lease_token":      "lease-1",
			"watermark_json":   `{"event_timestamp":"2026-03-20T10:00:00","entry_id":10,"statement_id":20}`,
			"last_offset":      0,
			"last_line_number": 0,
		})
	}))
	defer server.Close()

	executorDB := &mockDB{
		rows: []database.Row{{
			"EVENT_TIMESTAMP": "2026-03-20T10:00:01",
			"ENTRY_ID":        11,
			"STATEMENT_ID":    21,
		}},
	}
	executor := NewExecutor(executorDB)
	executor.ConfigureIngestionState(server.URL, "token", "oracle", "oracle-prod", true, true)

	result := executor.executeEvidenceCapture(context.Background(), Evidence{
		Type:        "audit_operations",
		Description: "Recent operations",
		SQL:         "SELECT * FROM UNIFIED_AUDIT_TRAIL WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}",
	})

	if result.Error != nil {
		t.Fatalf("expected successful evidence capture, got %v", result.Error)
	}
	if result.LeaseToken != "lease-1" {
		t.Fatalf("expected lease token to propagate, got %s", result.LeaseToken)
	}
	if !strings.Contains(executorDB.lastSQL, "ENTRY_ID") || !strings.Contains(executorDB.lastSQL, "STATEMENT_ID") {
		t.Fatalf("expected lease watermark SQL to be applied, got %s", executorDB.lastSQL)
	}
	if result.Watermark == "" || !strings.Contains(result.Watermark, "\"entry_id\":11") {
		t.Fatalf("expected watermark advancement, got %s", result.Watermark)
	}
}

func TestExecuteEvidenceCaptureActivityRunsWithoutLease(t *testing.T) {
	executorDB := &mockDB{
		rows: []database.Row{{
			"EVENT_TIMESTAMP": "2026-03-20T10:00:00",
			"PID":             123,
			"DBUSERNAME":      "app_user",
			"OPERATION":       "SELECT",
		}},
	}
	executor := NewExecutor(executorDB)
	executor.ConfigureIngestionState("http://127.0.0.1:1", "token", "postgres", "postgres-prod", true, true)

	result := executor.executeEvidenceCapture(context.Background(), Evidence{
		Type:        "audit_operations_live",
		Description: "Current client operations",
		SourceMode:  "activity",
		SourcePath:  "pg_stat_activity",
		SQL:         "SELECT NOW() AS EVENT_TIMESTAMP, pid AS PID, usename AS DBUSERNAME, 'SELECT' AS OPERATION FROM pg_stat_activity",
	})

	if result.Error != nil {
		t.Fatalf("expected activity evidence capture to succeed, got %v", result.Error)
	}
	if result.Skipped {
		t.Fatalf("expected activity evidence capture to execute without lease skip")
	}
	if executorDB.callCount != 1 {
		t.Fatalf("expected 1 query execution for activity evidence, got %d", executorDB.callCount)
	}
	if result.LeaseToken != "" {
		t.Fatalf("expected no lease token for activity evidence, got %s", result.LeaseToken)
	}
}
