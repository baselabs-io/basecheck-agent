package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDatabase implements the Database interface for SQLite.
type SQLiteDatabase struct {
	config ConnectionConfig
	db     *sql.DB
}

// NewSQLiteDatabase creates a new SQLite database connection.
func NewSQLiteDatabase(config ConnectionConfig) (*SQLiteDatabase, error) {
	return &SQLiteDatabase{
		config: config,
	}, nil
}

// Connect establishes connection to SQLite database.
func (s *SQLiteDatabase) Connect() error {
	dbPath := strings.TrimSpace(s.config.Database)
	if dbPath == "" {
		return fmt.Errorf("missing SQLite database file path")
	}

	dsn := fmt.Sprintf("file:%s?mode=ro", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open SQLite connection: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	s.db = db

	// Verify read-only mode is enforced
	if err := s.verifyReadOnlyMode(ctx); err != nil {
		db.Close()
		return fmt.Errorf("read-only verification failed: %w", err)
	}

	return nil
}

// verifyReadOnlyMode attempts a write operation to confirm read-only enforcement.
func (s *SQLiteDatabase) verifyReadOnlyMode(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "CREATE TABLE __basecheck_ro_test(id INTEGER)")
	if err == nil {
		return fmt.Errorf("database is not in read-only mode: write operation succeeded")
	}
	// Expected error: "attempt to write a readonly database"
	if !strings.Contains(strings.ToLower(err.Error()), "readonly") {
		return fmt.Errorf("unexpected error during read-only verification: %w", err)
	}
	return nil
}

// ExecuteQuery executes a SQL query and returns results.
func (s *SQLiteDatabase) ExecuteQuery(ctx context.Context, sqlText string) ([]Row, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	if err := validateReadOnlyQuery("sqlite", sqlText); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, sqlText)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	results := make([]Row, 0)
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		rowMap := make(Row)
		for i, col := range columns {
			rowMap[col] = values[i]
		}
		results = append(results, rowMap)
		if len(results) >= maxQueryRows {
			return nil, fmt.Errorf("query exceeded max rows limit (%d)", maxQueryRows)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return results, nil
}

// GetVersion returns SQLite version.
func (s *SQLiteDatabase) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.ExecuteQuery(ctx, "SELECT sqlite_version() AS version")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("no version information found")
	}

	if value, ok := rows[0]["version"]; ok {
		switch currentValue := value.(type) {
		case string:
			return currentValue, nil
		case []byte:
			return string(currentValue), nil
		default:
			return fmt.Sprintf("%v", currentValue), nil
		}
	}

	return "", fmt.Errorf("invalid version result")
}

// GetInstanceInfo returns instance information.
func (s *SQLiteDatabase) GetInstanceInfo() (*InstanceInfo, error) {
	version, err := s.GetVersion()
	if err != nil {
		return nil, err
	}

	dbFile := filepath.Base(strings.TrimSpace(s.config.Database))
	if dbFile == "" {
		dbFile = "sqlite"
	}

	return &InstanceInfo{
		InstanceName: dbFile,
		HostName:     "localhost",
		Version:      version,
		DatabaseType: "sqlite",
		CollectedAt:  time.Now(),
	}, nil
}

// Close closes the database connection.
func (s *SQLiteDatabase) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
