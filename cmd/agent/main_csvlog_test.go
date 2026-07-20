package main

import (
	"basecheck-agent/pkg/config"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectPostgresCSVLogs(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current dir: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to switch to temp dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	logPath := filepath.Join(tempDir, "postgresql.csv")
	csvContent := "log_time,user_name,database_name,command_tag,query,message,error_severity\n" +
		"2026-02-27 10:00:00.000 UTC,basecheck_ro,appdb,SELECT,SELECT 1,,LOG\n"
	if err := os.WriteFile(logPath, []byte(csvContent), 0600); err != nil {
		t.Fatalf("failed to write test csv file: %v", err)
	}

	dbCfg := config.DatabaseConfig{
		Name:            "postgres-prod",
		Type:            "postgres",
		Database:        "appdb",
		AuditLogPath:    logPath,
		AuditLogMaxRows: 100,
	}

	ingestionState, rawEvents, err := collectPostgresCSVLogs(dbCfg, &config.Config{}, nil)
	if err != nil {
		t.Fatalf("collectPostgresCSVLogs failed: %v", err)
	}
	if ingestionState == nil {
		t.Fatalf("expected ingestion state")
	}
	if len(rawEvents) != 1 {
		t.Fatalf("expected 1 raw event, got %d", len(rawEvents))
	}

	currentEvent := rawEvents[0]
	if currentEvent["DatabaseType"] != "postgres" {
		t.Fatalf("expected DatabaseType postgres, got %v", currentEvent["DatabaseType"])
	}
	if currentEvent["DatabaseName"] != "appdb" {
		t.Fatalf("expected DatabaseName appdb, got %v", currentEvent["DatabaseName"])
	}
	if currentEvent["Operation"] != "SELECT" {
		t.Fatalf("expected Operation SELECT, got %v", currentEvent["Operation"])
	}
	if currentEvent["EventHash"] == "" {
		t.Fatalf("expected EventHash to be populated")
	}

	// Second run should not duplicate event because state checkpoint is saved.
	ingestionState2, rawEvents2, err := collectPostgresCSVLogs(dbCfg, &config.Config{}, nil)
	if err != nil {
		t.Fatalf("second collectPostgresCSVLogs failed: %v", err)
	}
	if ingestionState2 == nil {
		t.Fatalf("expected ingestion state on second run even with no new records")
	}
	if len(rawEvents2) != 0 {
		t.Fatalf("expected 0 raw events on second run, got %d", len(rawEvents2))
	}
}
