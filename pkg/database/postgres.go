package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PostgresDatabase implements the Database interface for PostgreSQL
type PostgresDatabase struct {
	config ConnectionConfig
	db     *sql.DB
}

// NewPostgresDatabase creates a new Postgres database connection
func NewPostgresDatabase(config ConnectionConfig) (*PostgresDatabase, error) {
	return &PostgresDatabase{
		config: config,
	}, nil
}

// Connect establishes connection to Postgres database
func (p *PostgresDatabase) Connect() error {
	connStr := p.buildConnectionString()

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open Postgres connection: %w", err)
	}

	// Limit to single connection to ensure read-only mode applies to all queries
	// (prevents connection pool from using different connections)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping Postgres database: %w", err)
	}

	p.db = db

	if err := p.setReadOnlyMode(ctx); err != nil {
		return fmt.Errorf("failed to set read-only mode: %w", err)
	}

	return nil
}

// ExecuteQuery executes a SQL query and returns results
func (p *PostgresDatabase) ExecuteQuery(ctx context.Context, sql string) ([]Row, error) {
	if p.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	if err := validateReadOnlyQuery("postgres", sql); err != nil {
		return nil, err
	}

	rows, err := p.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	var results []Row
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
			if currentValue, ok := values[i].([]byte); ok {
				rowMap[col] = string(currentValue)
				continue
			}
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

// GetVersion returns the Postgres version
func (p *PostgresDatabase) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.ExecuteQuery(ctx, "SELECT current_setting('server_version') AS VERSION")
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", fmt.Errorf("no version information found")
	}

	version := getPostgresStringValue(rows[0], "version")
	if version == "" {
		version = getPostgresStringValue(rows[0], "VERSION")
	}
	if version == "" {
		return "", fmt.Errorf("invalid version type")
	}

	return version, nil
}

// GetInstanceInfo returns instance information
func (p *PostgresDatabase) GetInstanceInfo() (*InstanceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT
			current_database() AS instance_name,
			COALESCE(inet_server_addr()::text, 'localhost') AS host_name,
			current_setting('server_version') AS version
	`
	rows, err := p.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("no instance information found")
	}

	row := rows[0]
	return &InstanceInfo{
		InstanceName: getPostgresStringValue(row, "instance_name"),
		HostName:     getPostgresStringValue(row, "host_name"),
		Version:      getPostgresStringValue(row, "version"),
		DatabaseType: "postgres",
		CollectedAt:  time.Now(),
	}, nil
}

// Close closes the database connection
func (p *PostgresDatabase) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *PostgresDatabase) setReadOnlyMode(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, "SET default_transaction_read_only = on")
	if err != nil {
		return fmt.Errorf("failed to set default_transaction_read_only: %w", err)
	}
	return nil
}

func (p *PostgresDatabase) buildConnectionString() string {
	sslMode := strings.TrimSpace(p.config.SSLMode)
	if sslMode == "" {
		sslMode = "require"
	}

	query := url.Values{}
	query.Set("sslmode", sslMode)
	query.Set("connect_timeout", "10")

	connectionURL := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(p.config.Username, p.config.Password),
		Host:     fmt.Sprintf("%s:%d", p.config.Host, p.config.Port),
		Path:     p.config.Database,
		RawQuery: query.Encode(),
	}

	return connectionURL.String()
}

func getPostgresStringValue(row Row, key string) string {
	if value, ok := row[key]; ok {
		if currentValue, ok := value.(string); ok {
			return currentValue
		}
		if currentValue, ok := value.([]byte); ok {
			return string(currentValue)
		}
	}
	return ""
}
