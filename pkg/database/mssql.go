package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

// MSSQLDatabase implements the Database interface for MS SQL Server
type MSSQLDatabase struct {
	config ConnectionConfig
	db     *sql.DB
}

// NewMSSQLDatabase creates a new MS SQL Server database connection
func NewMSSQLDatabase(config ConnectionConfig) (*MSSQLDatabase, error) {
	return &MSSQLDatabase{
		config: config,
	}, nil
}

// Connect establishes connection to MS SQL Server database
func (m *MSSQLDatabase) Connect() error {
	connStr := m.buildConnectionString()

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return fmt.Errorf("failed to open MS SQL Server connection: %w", err)
	}

	// Limit to single connection to ensure read-only mode applies to all queries
	// (prevents connection pool from using different connections)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping MS SQL Server database: %w", err)
	}

	m.db = db

	// Set transaction isolation level to READ UNCOMMITTED for minimal locking
	// impact. This is NOT a read-only guarantee -- SQL Server has no session-
	// level equivalent of Oracle's "ALTER SESSION SET READ ONLY" or
	// Postgres's "default_transaction_read_only". The actual read-only
	// enforcement for MSSQL is the query guard (validateReadOnlyQuery) plus
	// a least-privilege (read-only) database account.
	if err := m.setLowLockIsolationLevel(ctx); err != nil {
		return fmt.Errorf("failed to set isolation level: %w", err)
	}

	return nil
}

// setLowLockIsolationLevel sets READ UNCOMMITTED to minimize locking
// contention. This does not prevent writes; see the read-only note in
// Connect above.
func (m *MSSQLDatabase) setLowLockIsolationLevel(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
	if err != nil {
		return fmt.Errorf("failed to set isolation level: %w", err)
	}
	return nil
}

// ExecuteQuery executes a SQL query and returns results
func (m *MSSQLDatabase) ExecuteQuery(ctx context.Context, sql string) ([]Row, error) {
	if m.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	if err := validateReadOnlyQuery("mssql", sql); err != nil {
		return nil, err
	}

	rows, err := m.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Build result set
	var results []Row
	for rows.Next() {
		// Create slice for row values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Build map
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

// GetVersion returns the MS SQL Server version
func (m *MSSQLDatabase) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := m.ExecuteQuery(ctx, "SELECT @@VERSION AS VERSION")
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", fmt.Errorf("no version information found")
	}

	version, ok := rows[0]["VERSION"].(string)
	if !ok {
		// Try byte array conversion (mssql driver sometimes returns []byte)
		if versionBytes, ok := rows[0]["VERSION"].([]byte); ok {
			version = string(versionBytes)
		} else {
			return "", fmt.Errorf("invalid version type")
		}
	}

	return version, nil
}

// GetInstanceInfo returns instance information
func (m *MSSQLDatabase) GetInstanceInfo() (*InstanceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT
			SERVERPROPERTY('ServerName') AS SERVER_NAME,
			SERVERPROPERTY('InstanceName') AS INSTANCE_NAME,
			SERVERPROPERTY('Edition') AS EDITION,
			@@VERSION AS VERSION
	`
	rows, err := m.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("no instance information found")
	}

	row := rows[0]
	return &InstanceInfo{
		InstanceName: getStringValue(row, "INSTANCE_NAME"),
		HostName:     getStringValue(row, "SERVER_NAME"),
		Version:      getStringValue(row, "VERSION"),
		DatabaseType: "mssql",
		CollectedAt:  time.Now(),
	}, nil
}

// Close closes the database connection
func (m *MSSQLDatabase) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// buildConnectionString builds MS SQL Server connection string
func (m *MSSQLDatabase) buildConnectionString() string {
	// Format: sqlserver://username:password@host:port?database=dbname&encrypt=true

	query := url.Values{}
	if m.config.Database != "" {
		query.Add("database", m.config.Database)
	}

	// Enable encryption by default for security
	if m.config.SSLMode == "disable" {
		query.Add("encrypt", "disable")
		query.Add("TrustServerCertificate", "true")
	} else {
		query.Add("encrypt", "true")
		query.Add("TrustServerCertificate", "false")
	}

	// Build connection string
	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(m.config.Username, m.config.Password),
		Host:     fmt.Sprintf("%s:%d", m.config.Host, m.config.Port),
		RawQuery: query.Encode(),
	}

	return u.String()
}

// getStringValue safely gets string value from row (handles string and []byte)
func getStringValue(row Row, key string) string {
	if val, ok := row[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
		if bytes, ok := val.([]byte); ok {
			return string(bytes)
		}
	}
	return ""
}
