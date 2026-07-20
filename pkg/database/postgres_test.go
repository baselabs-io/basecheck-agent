package database

import (
	"strings"
	"testing"
)

func TestPostgresConnectionStringDefaultsSSLMode(t *testing.T) {
	currentDatabase, err := NewPostgresDatabase(ConnectionConfig{
		Type:     "postgres",
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		Username: "basecheck_agent",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("failed to create postgres database: %v", err)
	}

	connectionString := currentDatabase.buildConnectionString()
	if !strings.Contains(connectionString, "sslmode=require") {
		t.Fatalf("expected default sslmode=require, got: %s", connectionString)
	}
}

func TestValidateReadOnlyQuery_PostgresGuards(t *testing.T) {
	if err := validateReadOnlyQuery("postgres", "SELECT current_database()"); err != nil {
		t.Fatalf("expected postgres SELECT to be allowed: %v", err)
	}

	if err := validateReadOnlyQuery("postgres", "DELETE FROM public.users"); err == nil {
		t.Fatalf("expected postgres DELETE to be blocked")
	}
}

func TestNewDatabaseSupportsPostgresqlAlias(t *testing.T) {
	currentDatabase, err := NewDatabase(ConnectionConfig{
		Type:     "postgresql",
		Host:     "localhost",
		Port:     5432,
		Database: "postgres",
		Username: "basecheck_agent",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("expected postgresql alias to be accepted: %v", err)
	}

	if _, ok := currentDatabase.(*PostgresDatabase); !ok {
		t.Fatalf("expected *PostgresDatabase for postgresql alias")
	}
}
