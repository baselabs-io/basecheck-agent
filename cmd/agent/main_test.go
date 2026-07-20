package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"basecheck-agent/pkg/config"
	"basecheck-agent/pkg/database"
)

func TestRunOutcomeCode(t *testing.T) {
	tests := []struct {
		name string
		o    runOutcome
		want int
	}{
		{"all databases succeed, no siem", runOutcome{dbTotal: 3, dbFailed: 0}, exitSuccess},
		{"all databases succeed, siem delivered", runOutcome{dbTotal: 2, dbFailed: 0, siemAttempted: true}, exitSuccess},
		{"all databases fail", runOutcome{dbTotal: 2, dbFailed: 2}, exitFailure},
		{"single database, fails", runOutcome{dbTotal: 1, dbFailed: 1}, exitFailure},
		{"siem delivery error with successful databases", runOutcome{dbTotal: 2, dbFailed: 0, siemAttempted: true, siemDeliveryErr: true}, exitFailure},
		{"partial database failure", runOutcome{dbTotal: 3, dbFailed: 1}, exitDegraded},
		{"siem events pending but no delivery error", runOutcome{dbTotal: 1, dbFailed: 0, siemAttempted: true, siemPending: 5}, exitDegraded},
		{"siem events rejected but otherwise clean run", runOutcome{dbTotal: 1, dbFailed: 0, siemAttempted: true, siemRejected: 3}, exitDegraded},
		{"no databases configured", runOutcome{dbTotal: 0}, exitSuccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.o.code(); got != tt.want {
				t.Errorf("code() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRunOutcomeSummary(t *testing.T) {
	failAll := runOutcome{dbTotal: 2, dbFailed: 2}
	if got := failAll.summary(); got == "✓ Agent completed successfully" {
		t.Errorf("summary() for total failure should not claim success, got %q", got)
	}

	degraded := runOutcome{dbTotal: 3, dbFailed: 1}
	if got := degraded.summary(); got == "✓ Agent completed successfully" {
		t.Errorf("summary() for degraded run should not claim success, got %q", got)
	}

	success := runOutcome{dbTotal: 2, dbFailed: 0}
	if got := success.summary(); got != "✓ Agent completed successfully" {
		t.Errorf("summary() for fully successful run = %q, want success message", got)
	}
}

type mockDatabase struct {
	rowsByQuery map[string][]database.Row
}

func (m *mockDatabase) Connect() error {
	return nil
}

func (m *mockDatabase) ExecuteQuery(_ context.Context, sql string) ([]database.Row, error) {
	return m.rowsByQuery[sql], nil
}

func (m *mockDatabase) GetVersion() (string, error) {
	return "test", nil
}

func (m *mockDatabase) GetInstanceInfo() (*database.InstanceInfo, error) {
	return &database.InstanceInfo{}, nil
}

func (m *mockDatabase) Close() error {
	return nil
}

func TestCollectConfiguredLogSourcesOracle(t *testing.T) {
	stateDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "alert.log")

	content := `Thu Mar 14 10:12:33 2026
Errors in file /u01/diag/rdbms/trace/ora_123.trc:
ORA-1691: unable to extend lob segment
Additional detail line
Thu Mar 14 10:15:01 2026
TNS-12543: TNS:destination host unreachable
Listener refused connection`

	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	cfg := &config.Config{
		LogMining: config.LogMiningConfig{
			Enabled:         true,
			StatePath:       stateDir,
			MaxExcerptBytes: 4096,
			MaxEntryBytes:   65536,
		},
	}

	dbCfg := config.DatabaseConfig{
		Name: "oracle-prod",
		Type: "oracle",
		LogSources: []config.LogSourceConfig{
			{
				Name:          "alert-log",
				Type:          "oracle_alert_log",
				Path:          logPath,
				Enabled:       true,
				MultilineMode: "timestamp",
			},
		},
	}

	ingestionState, rawEvents, err := collectConfiguredLogSources(dbCfg, cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("collectConfiguredLogSources failed: %v", err)
	}

	if ingestionState == nil {
		t.Fatalf("expected ingestion state")
	}
	if ingestionState["SourceType"] != "oracle_alert_log" {
		t.Fatalf("unexpected source type: %v", ingestionState["SourceType"])
	}
	if len(rawEvents) != 2 {
		t.Fatalf("expected 2 raw events, got %d", len(rawEvents))
	}
	if rawEvents[0]["Operation"] != "storage_capacity" {
		t.Fatalf("unexpected first operation: %v", rawEvents[0]["Operation"])
	}
	if rawEvents[1]["Operation"] != "listener_network" {
		t.Fatalf("unexpected second operation: %v", rawEvents[1]["Operation"])
	}
}

func TestCollectConfiguredLogSourcesIncrementalOffset(t *testing.T) {
	stateDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "alert.log")

	initial := `Thu Mar 14 10:12:33 2026
ORA-1691: unable to extend lob segment`
	if err := os.WriteFile(logPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	cfg := &config.Config{
		LogMining: config.LogMiningConfig{
			Enabled:         true,
			StatePath:       stateDir,
			MaxExcerptBytes: 4096,
		},
	}

	dbCfg := config.DatabaseConfig{
		Name: "oracle-prod",
		Type: "oracle",
		LogSources: []config.LogSourceConfig{
			{
				Name:    "alert-log",
				Type:    "oracle_alert_log",
				Path:    logPath,
				Enabled: true,
			},
		},
	}

	_, rawEvents, err := collectConfiguredLogSources(dbCfg, cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("first collection failed: %v", err)
	}
	if len(rawEvents) != 1 {
		t.Fatalf("expected 1 event on first collection, got %d", len(rawEvents))
	}

	additional := `
Thu Mar 14 10:15:01 2026
TNS-12543: TNS:destination host unreachable`
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("failed to open test log for append: %v", err)
	}
	if _, err := file.WriteString(additional); err != nil {
		file.Close()
		t.Fatalf("failed to append test log: %v", err)
	}
	file.Close()

	_, rawEvents, err = collectConfiguredLogSources(dbCfg, cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("second collection failed: %v", err)
	}
	if len(rawEvents) != 1 {
		t.Fatalf("expected 1 new event on second collection, got %d", len(rawEvents))
	}
	if rawEvents[0]["Operation"] != "listener_network" {
		t.Fatalf("unexpected incremental event operation: %v", rawEvents[0]["Operation"])
	}
}

func TestCollectConfiguredLogSourcesOracleAutodiscovery(t *testing.T) {
	stateDir := t.TempDir()
	traceDir := t.TempDir()
	logPath := filepath.Join(traceDir, "alert_ORCL.log")

	content := `Thu Mar 14 10:12:33 2026
ORA-1691: unable to extend lob segment`
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	cfg := &config.Config{
		LogMining: config.LogMiningConfig{
			Enabled:   true,
			StatePath: stateDir,
		},
	}

	dbCfg := config.DatabaseConfig{
		Name: "oracle-prod",
		Type: "oracle",
	}

	db := &mockDatabase{
		rowsByQuery: map[string][]database.Row{
			"SELECT value FROM v$diag_info WHERE name = 'Diag Trace'": {
				{"VALUE": traceDir},
			},
		},
	}

	ingestionState, rawEvents, err := collectConfiguredLogSources(dbCfg, cfg, nil, db, &database.InstanceInfo{
		InstanceName: "ORCL",
	})
	if err != nil {
		t.Fatalf("collectConfiguredLogSources failed: %v", err)
	}

	if ingestionState == nil {
		t.Fatalf("expected ingestion state")
	}
	if ingestionState["SourcePath"] != logPath {
		t.Fatalf("expected autodiscovered path %s, got %v", logPath, ingestionState["SourcePath"])
	}
	if len(rawEvents) != 1 {
		t.Fatalf("expected 1 raw event, got %d", len(rawEvents))
	}
}
