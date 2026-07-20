package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/godror/godror"
)

// OracleDatabase implements the Database interface for Oracle
type OracleDatabase struct {
	config ConnectionConfig
	db     *sql.DB
}

// NewOracleDatabase creates a new Oracle database connection
func NewOracleDatabase(config ConnectionConfig) (*OracleDatabase, error) {
	return &OracleDatabase{
		config: config,
	}, nil
}

// Connect establishes connection to Oracle database
func (o *OracleDatabase) Connect() error {
	if strings.EqualFold(strings.TrimSpace(o.config.Username), "sys") {
		return fmt.Errorf("oracle SYS user is not allowed for agent connections")
	}
	if o.config.AsSysDBA {
		return fmt.Errorf("oracle SYSDBA mode is not allowed for agent connections")
	}

	connStr := o.buildConnectionString()

	db, err := sql.Open("godror", connStr)
	if err != nil {
		return fmt.Errorf("failed to open Oracle connection: %w", err)
	}

	// Limit to single connection to ensure read-only mode applies to all queries
	// (prevents connection pool from using different connections)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping Oracle database: %w", err)
	}

	o.db = db

	// Set session to read-only mode (production safety)
	if err := classifyReadOnlyModeError(o.setReadOnly(ctx), o.config.AllowReadOnlyFallback, o.config.Host); err != nil {
		return err
	}

	return nil
}

// classifyReadOnlyModeError decides how to react to a failure to set the
// Oracle session read-only via ALTER SESSION SET READ ONLY. Any error other
// than ORA-02248 is always fatal. ORA-02248 specifically means session-level
// read-only isn't supported on this database (e.g. some autonomous/pluggable
// database configurations) -- a reduced security guarantee, since the
// connection would then rely solely on the query guard (validateReadOnlyQuery)
// rather than database-enforced read-only mode. Fail closed on ORA-02248
// unless the operator has explicitly acknowledged that reduced guarantee via
// allow_read_only_fallback; a silent warning-only fallback let a
// misconfigured or downgraded Oracle target quietly lose its database-level
// enforcement layer.
func classifyReadOnlyModeError(err error, allowFallback bool, host string) error {
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "ORA-02248") {
		return fmt.Errorf("failed to set read-only mode: %w", err)
	}
	if !allowFallback {
		return fmt.Errorf("oracle session read-only mode is not supported on this database (ORA-02248) and allow_read_only_fallback is not set for this connection; " +
			"refusing to connect without database-enforced read-only mode. Set database.allow_read_only_fallback: true to explicitly " +
			"acknowledge this connection relies solely on query-guard enforcement, and ensure the agent database account is least-privilege")
	}
	log.Printf("⚠ WARNING: Oracle session read-only mode is not supported on this database (ORA-02248). "+
		"Falling back to query-guard enforcement only (host=%s) -- ensure the agent database account is least-privilege.", host)
	return nil
}

// setReadOnly sets the Oracle session to read-only mode
func (o *OracleDatabase) setReadOnly(ctx context.Context) error {
	_, err := o.db.ExecContext(ctx, "ALTER SESSION SET READ ONLY")
	if err != nil {
		return fmt.Errorf("failed to execute ALTER SESSION SET READ ONLY: %w", err)
	}
	return nil
}

// ExecuteQuery executes a SQL query and returns results
func (o *OracleDatabase) ExecuteQuery(ctx context.Context, sql string) ([]Row, error) {
	if o.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	if err := validateReadOnlyQuery("oracle", sql); err != nil {
		return nil, err
	}

	rows, err := o.db.QueryContext(ctx, sql)
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

// GetVersion returns the Oracle version
func (o *OracleDatabase) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := o.ExecuteQuery(ctx, "SELECT version FROM v$instance")
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", fmt.Errorf("no version information found")
	}

	version, ok := rows[0]["VERSION"].(string)
	if !ok {
		return "", fmt.Errorf("invalid version type")
	}

	return version, nil
}

// GetInstanceInfo returns instance information
func (o *OracleDatabase) GetInstanceInfo() (*InstanceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `SELECT instance_name, host_name, version FROM v$instance`
	rows, err := o.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("no instance information found")
	}

	row := rows[0]
	return &InstanceInfo{
		InstanceName: getString(row, "INSTANCE_NAME"),
		HostName:     getString(row, "HOST_NAME"),
		Version:      getString(row, "VERSION"),
		DatabaseType: "oracle",
		CollectedAt:  time.Now(),
	}, nil
}

// Close closes the database connection
func (o *OracleDatabase) Close() error {
	if o.db != nil {
		return o.db.Close()
	}
	return nil
}

// buildConnectionString builds Oracle connection string
func (o *OracleDatabase) buildConnectionString() string {
	// Format: user/password@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=host)(PORT=port))(CONNECT_DATA=(SID=sid)))
	// Or: user/password@host:port/service_name

	var connStr string
	if o.config.ServiceName != "" {
		connStr = fmt.Sprintf("%s/%s@%s:%d/%s",
			o.config.Username,
			o.config.Password,
			o.config.Host,
			o.config.Port,
			o.config.ServiceName,
		)
	} else {
		connStr = fmt.Sprintf("%s/%s@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d))(CONNECT_DATA=(SID=%s)))",
			o.config.Username,
			o.config.Password,
			o.config.Host,
			o.config.Port,
			o.config.SID,
		)
	}

	return connStr
}

// getString safely gets string value from row
func getString(row Row, key string) string {
	if val, ok := row[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
