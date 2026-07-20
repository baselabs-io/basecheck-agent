package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectOperation(t *testing.T) {
	tests := []struct {
		statement string
		want      string
	}{
		{"CREATE TABLE users (id int)", "CREATE"},
		{"create table users (id int)", "CREATE"},
		{"ALTER TABLE users ADD COLUMN email text", "ALTER"},
		{"DROP TABLE users", "DROP"},
		{"TRUNCATE TABLE users", "TRUNCATE"},
		{"GRANT SELECT ON users TO alice", "GRANT"},
		{"REVOKE INSERT ON users FROM bob", "REVOKE"},
		{"INSERT INTO users VALUES (1)", "INSERT"},
		{"UPDATE users SET email='test@test.com'", "UPDATE"},
		{"DELETE FROM users WHERE id=1", "DELETE"},
		{"SELECT * FROM users", "SELECT"},
		{"EXPLAIN SELECT * FROM users", "OTHER"},
		{"", "OTHER"},
		{"   ", "OTHER"},
	}

	for _, tt := range tests {
		t.Run(tt.statement, func(t *testing.T) {
			got := DetectOperation(tt.statement)
			if got != tt.want {
				t.Errorf("DetectOperation(%q) = %q, want %q", tt.statement, got, tt.want)
			}
		})
	}
}

func TestFormatRecord(t *testing.T) {
	tests := []struct {
		name   string
		record []string
		want   string
	}{
		{
			name:   "simple record",
			record: []string{"value1", "value2", "value3"},
			want:   "value1,value2,value3",
		},
		{
			name:   "record with quotes",
			record: []string{"val,ue1", "value2"},
			want:   `"val,ue1",value2`,
		},
		{
			name:   "empty record",
			record: []string{},
			want:   "",
		},
		{
			name:   "single value",
			record: []string{"value1"},
			want:   "value1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatRecord(tt.record)
			if got != tt.want {
				t.Errorf("FormatRecord() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHashEvent(t *testing.T) {
	logPath := "/var/log/postgresql/test.csv"
	lineNumber := int64(42)
	rawRecord := "col1,col2,col3"

	hash1 := HashEvent(logPath, lineNumber, rawRecord)
	hash2 := HashEvent(logPath, lineNumber, rawRecord)

	// Same inputs should produce same hash
	if hash1 != hash2 {
		t.Error("HashEvent() should be deterministic")
	}

	// Different inputs should produce different hash
	hash3 := HashEvent(logPath, lineNumber+1, rawRecord)
	if hash1 == hash3 {
		t.Error("HashEvent() should produce different hashes for different inputs")
	}

	// Hash should be hex string
	if len(hash1) != 64 { // SHA256 = 64 hex chars
		t.Errorf("HashEvent() should return 64 char hex string, got %d", len(hash1))
	}
}

func TestBuildSourceFingerprint(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.csv")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat test file: %v", err)
	}

	fingerprint := BuildSourceFingerprint(info)
	if fingerprint == "" {
		t.Error("BuildSourceFingerprint() should return non-empty string")
	}

	// Should contain dash separator (size-mtime format)
	if !strings.Contains(fingerprint, "-") {
		t.Error("BuildSourceFingerprint() should contain dash separator")
	}

	// Same file should produce same fingerprint
	info2, _ := os.Stat(tmpFile)
	fingerprint2 := BuildSourceFingerprint(info2)
	if fingerprint != fingerprint2 {
		t.Error("BuildSourceFingerprint() should be deterministic")
	}
}

func TestSanitizeFilePart(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with-dashes", "with-dashes"},
		{"with_underscores", "with_underscores"},
		{"with spaces", "with_spaces"},
		{"with/slashes", "with_slashes"},
		{"with\\backslashes", "with_backslashes"},
		{"UPPERCASE", "UPPERCASE"},
		{"123numbers", "123numbers"},
		{"special!@#$%chars", "special_____chars"},
		{"", "database"},
		{"   ", "___"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SanitizeFilePart(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeFilePart(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSaveAndLoadState(t *testing.T) {
	// Change to temp directory for test
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	state := State{
		SourcePath:         "/var/log/postgresql/test.csv",
		SourceFingerprint:  "test-fingerprint",
		LastOffset:         1024,
		LastLineNumber:     42,
		LastEventTimestamp: "2024-01-15T10:30:00Z",
		Headers:            []string{"log_time", "user_name", "database_name"},
	}

	// Load to get state file path
	_, stateFile, err := LoadState("testdb")
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}

	// Save state
	err = SaveState(stateFile, &state)
	if err != nil {
		t.Fatalf("SaveState() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(stateFile); err != nil {
		t.Errorf("State file not created: %v", err)
	}

	// Load state
	loaded, _, err := LoadState("testdb")
	if err != nil {
		t.Fatalf("LoadState() failed: %v", err)
	}

	// Compare
	if loaded.SourcePath != state.SourcePath {
		t.Errorf("SourcePath: got %q, want %q", loaded.SourcePath, state.SourcePath)
	}
	if loaded.SourceFingerprint != state.SourceFingerprint {
		t.Errorf("SourceFingerprint: got %q, want %q", loaded.SourceFingerprint, state.SourceFingerprint)
	}
	if loaded.LastOffset != state.LastOffset {
		t.Errorf("LastOffset: got %d, want %d", loaded.LastOffset, state.LastOffset)
	}
	if loaded.LastLineNumber != state.LastLineNumber {
		t.Errorf("LastLineNumber: got %d, want %d", loaded.LastLineNumber, state.LastLineNumber)
	}
	if loaded.LastEventTimestamp != state.LastEventTimestamp {
		t.Errorf("LastEventTimestamp: got %q, want %q", loaded.LastEventTimestamp, state.LastEventTimestamp)
	}
	if len(loaded.Headers) != len(state.Headers) {
		t.Errorf("Headers length: got %d, want %d", len(loaded.Headers), len(state.Headers))
	}
}

func TestLoadStateNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Loading non-existent state should return empty state, no error
	state, stateFile, err := LoadState("nonexistent")
	if err != nil {
		t.Errorf("LoadState() should not error for nonexistent file: %v", err)
	}
	if state.SourcePath != "" {
		t.Error("LoadState() should return empty state for nonexistent file")
	}
	if stateFile == "" {
		t.Error("LoadState() should return state file path")
	}
}

func TestMapEvent(t *testing.T) {
	headers := []string{"log_time", "user_name", "database_name", "command_tag", "query"}
	record := []string{
		"2024-01-15 10:30:00 UTC",
		"postgres",
		"testdb",
		"SELECT",
		"SELECT * FROM users",
	}

	cfg := CollectorConfig{
		DatabaseName: "testdb",
		DatabaseType: "postgres",
		DefaultDB:    "testdb",
	}

	event, timestamp := MapEvent(
		cfg,
		"/var/log/postgresql/test.csv",
		42,
		1024,
		headers,
		record,
	)

	// Check required fields
	if event["EventHash"] == nil || event["EventHash"] == "" {
		t.Error("MapEvent() should set EventHash")
	}
	if event["EventTimestamp"] != "2024-01-15 10:30:00 UTC" {
		t.Errorf("EventTimestamp: got %v", event["EventTimestamp"])
	}
	if event["DatabaseType"] != "postgres" {
		t.Errorf("DatabaseType: got %v", event["DatabaseType"])
	}
	if event["DatabaseName"] != "testdb" {
		t.Errorf("DatabaseName: got %v", event["DatabaseName"])
	}
	if event["SourceType"] != "csvlog" {
		t.Errorf("SourceType: got %v", event["SourceType"])
	}
	if event["SourcePath"] != "/var/log/postgresql/test.csv" {
		t.Errorf("SourcePath: got %v", event["SourcePath"])
	}
	if event["SourceLineNumber"] != int64(42) {
		t.Errorf("SourceLineNumber: got %v", event["SourceLineNumber"])
	}
	if event["SourceOffset"] != int64(1024) {
		t.Errorf("SourceOffset: got %v", event["SourceOffset"])
	}
	if event["DatabaseUser"] != "postgres" {
		t.Errorf("DatabaseUser: got %v", event["DatabaseUser"])
	}
	if event["Operation"] != "SELECT" {
		t.Errorf("Operation: got %v", event["Operation"])
	}
	if event["Statement"] != "SELECT * FROM users" {
		t.Errorf("Statement: got %v", event["Statement"])
	}

	// Check timestamp return value
	if timestamp != "2024-01-15 10:30:00 UTC" {
		t.Errorf("Returned timestamp: got %q, want %q", timestamp, "2024-01-15 10:30:00 UTC")
	}

	// Check ParsedRecord
	parsed, ok := event["ParsedRecord"].(map[string]interface{})
	if !ok {
		t.Fatal("ParsedRecord should be map[string]interface{}")
	}
	if parsed["log_time"] != "2024-01-15 10:30:00 UTC" {
		t.Error("ParsedRecord should contain log_time")
	}
}

func TestMapEventWithDefaultDatabase(t *testing.T) {
	headers := []string{"log_time", "database_name"}
	record := []string{"2024-01-15 10:30:00 UTC", ""} // Empty database_name

	cfg := CollectorConfig{
		DatabaseName: "testdb",
		DatabaseType: "postgres",
		DefaultDB:    "defaultdb",
	}

	event, _ := MapEvent(
		cfg,
		"/var/log/postgresql/test.csv",
		1,
		0,
		headers,
		record,
	)

	// Should use defaultDB when database_name is empty
	if event["DatabaseName"] != "defaultdb" {
		t.Errorf("DatabaseName should default to %q, got %v", "defaultdb", event["DatabaseName"])
	}
}

func TestMapEventOperationDetection(t *testing.T) {
	headers := []string{"log_time", "command_tag", "query", "message"}

	cfg := CollectorConfig{
		DatabaseName: "testdb",
		DatabaseType: "postgres",
		DefaultDB:    "testdb",
	}

	tests := []struct {
		name      string
		record    []string
		wantOp    string
	}{
		{
			name:   "operation from command_tag",
			record: []string{"2024-01-15 10:30:00", "INSERT", "", ""},
			wantOp: "INSERT",
		},
		{
			name:   "operation detected from query",
			record: []string{"2024-01-15 10:30:00", "", "DELETE FROM users", ""},
			wantOp: "DELETE",
		},
		{
			name:   "operation detected from message",
			record: []string{"2024-01-15 10:30:00", "", "", "CREATE TABLE users"},
			wantOp: "CREATE",
		},
		{
			name:   "no operation",
			record: []string{"2024-01-15 10:30:00", "", "", "some log message"},
			wantOp: "OTHER",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, _ := MapEvent(
				cfg,
				"/test.csv",
				1,
				0,
				headers,
				tt.record,
			)

			if event["Operation"] != tt.wantOp {
				t.Errorf("Operation = %v, want %v", event["Operation"], tt.wantOp)
			}
		})
	}
}
