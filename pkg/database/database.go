package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Database represents a generic database connection
type Database interface {
	Connect() error
	ExecuteQuery(ctx context.Context, sql string) ([]Row, error)
	GetVersion() (string, error)
	GetInstanceInfo() (*InstanceInfo, error)
	Close() error
}

// Row represents a single row from query results
type Row map[string]interface{}

const maxQueryRows = 50000

// InstanceInfo contains basic database instance information
type InstanceInfo struct {
	InstanceName string
	HostName     string
	Version      string
	DatabaseType string
	CollectedAt  time.Time
}

// ConnectionConfig holds database connection parameters
type ConnectionConfig struct {
	Type        string // oracle, postgres, supabase, mssql, sqlite
	Host        string
	Port        int
	Database    string // For Postgres, MSSQL, SQLite file path
	ServiceName string // For Oracle
	SID         string // For Oracle (alternative to ServiceName)
	Username    string
	Password    string
	SSLMode     string // For Postgres (disable, require, verify-full)
	AsSysDBA    bool   // For Oracle SYS user

	// AllowReadOnlyFallback is an explicit operator acknowledgement that this
	// Oracle connection may proceed when the database doesn't support
	// session-level read-only mode (ORA-02248), relying solely on the query
	// guard for write protection. Defaults to false (fail closed): Connect
	// refuses such databases unless this is set. Ignored for other engines.
	AllowReadOnlyFallback bool
}

// NewDatabase creates a new database connection based on type
func NewDatabase(config ConnectionConfig) (Database, error) {
	switch strings.ToLower(config.Type) {
	case "oracle":
		return NewOracleDatabase(config)
	case "postgres", "postgresql", "supabase":
		return NewPostgresDatabase(config)
	case "mssql", "sqlserver":
		return NewMSSQLDatabase(config)
	case "sqlite":
		return NewSQLiteDatabase(config)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}
