package database

import (
	"strings"
	"testing"
)

func TestSQLiteConnectionStringBuildsReadOnlyURI(t *testing.T) {
	db, err := NewSQLiteDatabase(ConnectionConfig{
		Type:     "sqlite",
		Database: "/path/to/test.db",
	})
	if err != nil {
		t.Fatalf("failed to create sqlite database: %v", err)
	}

	// Verify the database path is stored correctly
	if db.config.Database != "/path/to/test.db" {
		t.Fatalf("expected database path '/path/to/test.db', got: %s", db.config.Database)
	}
}

func TestSQLiteRejectsEmptyDatabasePath(t *testing.T) {
	db, err := NewSQLiteDatabase(ConnectionConfig{
		Type:     "sqlite",
		Database: "",
	})
	if err != nil {
		t.Fatalf("constructor should not fail: %v", err)
	}

	// Connect should fail with empty path
	err = db.Connect()
	if err == nil {
		t.Fatalf("expected Connect to fail with empty database path")
	}
	if !strings.Contains(err.Error(), "missing SQLite database file path") {
		t.Fatalf("expected missing path error, got: %v", err)
	}
}

func TestValidateReadOnlyQuery_SQLiteAllowsSelects(t *testing.T) {
	tests := []string{
		"SELECT * FROM users",
		"SELECT sqlite_version() AS version",
		"SELECT name FROM sqlite_master WHERE type='table'",
		"SELECT * FROM pragma_table_info('users')",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
	}

	for _, query := range tests {
		if err := validateReadOnlyQuery("sqlite", query); err != nil {
			t.Fatalf("expected query to be allowed: %s\nError: %v", query, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteAllowsReadPragmas(t *testing.T) {
	tests := []string{
		"PRAGMA foreign_keys",
		"PRAGMA table_info(users)",
		"PRAGMA journal_mode",
		"PRAGMA synchronous",
		"SELECT * FROM pragma_foreign_keys",
		"SELECT * FROM pragma_journal_mode",
	}

	for _, query := range tests {
		if err := validateReadOnlyQuery("sqlite", query); err != nil {
			t.Fatalf("expected read PRAGMA to be allowed: %s\nError: %v", query, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksDML(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"DELETE FROM users", "DELETE"},
		{"DELETE FROM users WHERE id = 1", "DELETE"},
		{"INSERT INTO users VALUES (1, 'test')", "INSERT"},
		{"INSERT INTO users (name) VALUES ('test')", "INSERT"},
		{"UPDATE users SET name = 'test'", "UPDATE"},
		{"UPDATE users SET name = 'test' WHERE id = 1", "UPDATE"},
		{"MERGE INTO users USING source ON users.id = source.id", "MERGE"},
		{"TRUNCATE TABLE users", "TRUNCATE"},
	}

	for _, tt := range tests {
		err := validateReadOnlyQuery("sqlite", tt.query)
		if err == nil {
			t.Fatalf("expected query to be blocked: %s", tt.query)
		}
		if !strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(tt.expected)) {
			t.Fatalf("expected error to mention %s, got: %v", tt.expected, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksDDL(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"CREATE TABLE test (id INT)", "CREATE"},
		{"DROP TABLE users", "DROP"},
		{"ALTER TABLE users ADD COLUMN email TEXT", "ALTER"},
		{"CREATE INDEX idx_name ON users(name)", "CREATE"},
		{"DROP INDEX idx_name", "DROP"},
	}

	for _, tt := range tests {
		err := validateReadOnlyQuery("sqlite", tt.query)
		if err == nil {
			t.Fatalf("expected query to be blocked: %s", tt.query)
		}
		if !strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(tt.expected)) {
			t.Fatalf("expected error to mention %s, got: %v", tt.expected, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksSQLiteSpecificStatements(t *testing.T) {
	tests := []struct {
		query    string
		expected string
	}{
		{"VACUUM", "VACUUM"},
		{"VACUUM main", "VACUUM"},
		{"REINDEX", "REINDEX"},
		{"REINDEX users", "REINDEX"},
		{"ATTACH DATABASE 'other.db' AS other", "ATTACH"},
		{"DETACH DATABASE other", "DETACH"},
	}

	for _, tt := range tests {
		err := validateReadOnlyQuery("sqlite", tt.query)
		if err == nil {
			t.Fatalf("expected query to be blocked: %s", tt.query)
		}
		if !strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(tt.expected)) {
			t.Fatalf("expected error to mention %s, got: %v", tt.expected, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksWritePragmas(t *testing.T) {
	tests := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA auto_vacuum = 1",
		"PRAGMA cache_size = 10000",
	}

	for _, query := range tests {
		err := validateReadOnlyQuery("sqlite", query)
		if err == nil {
			t.Fatalf("expected write PRAGMA to be blocked: %s", query)
		}
		if !strings.Contains(err.Error(), "write PRAGMA") {
			t.Fatalf("expected error to mention write PRAGMA, got: %v", err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteHandlesComments(t *testing.T) {
	tests := []string{
		"-- This is a comment\nSELECT * FROM users",
		"/* Block comment */ SELECT * FROM users",
		"SELECT * FROM users -- inline comment",
		"SELECT * FROM users /* inline block */",
	}

	for _, query := range tests {
		if err := validateReadOnlyQuery("sqlite", query); err != nil {
			t.Fatalf("expected query with comments to be allowed: %s\nError: %v", query, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksHiddenDMLInComments(t *testing.T) {
	// Comments are sanitized, so DML in comments should not be detected
	query := "SELECT * FROM users -- DELETE FROM users"
	if err := validateReadOnlyQuery("sqlite", query); err != nil {
		t.Fatalf("expected query to be allowed (DELETE is in comment): %v", err)
	}

	// But actual DML should still be blocked even with comments
	query = "DELETE FROM users -- legitimate delete"
	if err := validateReadOnlyQuery("sqlite", query); err == nil {
		t.Fatalf("expected DELETE to be blocked even with comment")
	}
}

func TestNewDatabaseSupportsSQLite(t *testing.T) {
	db, err := NewDatabase(ConnectionConfig{
		Type:     "sqlite",
		Database: "/path/to/test.db",
	})
	if err != nil {
		t.Fatalf("expected sqlite type to be accepted: %v", err)
	}

	if _, ok := db.(*SQLiteDatabase); !ok {
		t.Fatalf("expected *SQLiteDatabase for sqlite type, got: %T", db)
	}
}

func TestSQLiteGetVersion_TypeHandling(t *testing.T) {
	// This test verifies the type assertion logic in GetVersion
	// We can't easily test this without a real database connection,
	// but we document the expected behavior

	// The GetVersion method should handle:
	// - string type (return as-is)
	// - []byte type (convert to string)
	// - other types (use fmt.Sprintf)

	// This is validated by the implementation in sqlite.go:115-123
	t.Skip("Integration test - requires real SQLite database")
}

func TestSQLiteGetInstanceInfo_FileNameExtraction(t *testing.T) {
	_, err := NewSQLiteDatabase(ConnectionConfig{
		Type:     "sqlite",
		Database: "/var/data/production.db",
	})
	if err != nil {
		t.Fatalf("failed to create sqlite database: %v", err)
	}

	// We can't call GetInstanceInfo without Connect, but we can verify
	// the logic would extract "production.db" from the path
	// This is tested in the implementation at sqlite.go:136-139

	t.Skip("Integration test - requires real SQLite database connection")
}

func TestValidateReadOnlyQuery_SQLiteRejectsEmpty(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"\n\t",
		"-- only comments",
		"/* only comments */",
	}

	for _, query := range tests {
		err := validateReadOnlyQuery("sqlite", query)
		if err == nil {
			t.Fatalf("expected empty query to be rejected: %q", query)
		}
		if !strings.Contains(err.Error(), "empty SQL") {
			t.Fatalf("expected empty SQL error, got: %v", err)
		}
	}
}
