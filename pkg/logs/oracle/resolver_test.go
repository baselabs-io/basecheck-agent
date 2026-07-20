package oracle

import (
	"context"
	"testing"

	"basecheck-agent/pkg/database"
)

type mockDB struct {
	rowsByQuery map[string][]database.Row
}

func (m *mockDB) Connect() error {
	return nil
}

func (m *mockDB) ExecuteQuery(_ context.Context, sql string) ([]database.Row, error) {
	return m.rowsByQuery[sql], nil
}

func (m *mockDB) GetVersion() (string, error) {
	return "test", nil
}

func (m *mockDB) GetInstanceInfo() (*database.InstanceInfo, error) {
	return &database.InstanceInfo{}, nil
}

func (m *mockDB) Close() error {
	return nil
}

func TestResolveAlertLogPathUsesDiagTrace(t *testing.T) {
	resolver := Resolver{}
	path, err := resolver.ResolveAlertLogPath(context.Background(), &mockDB{
		rowsByQuery: map[string][]database.Row{
			"SELECT value FROM v$diag_info WHERE name = 'Diag Trace'": {
				{"VALUE": "/u01/app/oracle/diag/rdbms/orcl/ORCL/trace"},
			},
		},
	}, "ORCL")
	if err != nil {
		t.Fatalf("expected resolver to succeed, got %v", err)
	}

	expected := "/u01/app/oracle/diag/rdbms/orcl/ORCL/trace/alert_ORCL.log"
	if path != expected {
		t.Fatalf("expected %s, got %s", expected, path)
	}
}

func TestResolveAlertLogPathFallsBackToBackgroundDumpDest(t *testing.T) {
	resolver := Resolver{}
	path, err := resolver.ResolveAlertLogPath(context.Background(), &mockDB{
		rowsByQuery: map[string][]database.Row{
			"SELECT value FROM v$diag_info WHERE name = 'Diag Trace'": {},
			"SELECT value FROM v$parameter WHERE name = 'background_dump_dest'": {
				{"VALUE": "/u01/app/oracle/admin/orcl/bdump"},
			},
		},
	}, "ORCL")
	if err != nil {
		t.Fatalf("expected resolver to succeed, got %v", err)
	}

	expected := "/u01/app/oracle/admin/orcl/bdump/alert_ORCL.log"
	if path != expected {
		t.Fatalf("expected %s, got %s", expected, path)
	}
}
