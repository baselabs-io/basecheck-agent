package database

import "testing"

func TestValidateReadOnlyQuery_AllowsReadOnlyPatterns(t *testing.T) {
	tests := []string{
		"SELECT @@VERSION AS VERSION",
		"EXEC xp_loginconfig 'audit level';",
		"SELECT 'DROP TABLE x' AS note",
		"/* DROP TABLE test */ SELECT 1",
		"DECLARE @t TABLE (id int); INSERT INTO @t VALUES (1); DELETE FROM @t;",
		"SELECT SERVERPROPERTY('ProductUpdateLevel') AS update_level",
		"DBCC LOGINFO([tempdb])",
	}

	for _, sqlText := range tests {
		if err := validateReadOnlyQuery("mssql", sqlText); err != nil {
			t.Fatalf("expected query to be allowed, got error for %q: %v", sqlText, err)
		}
	}
}

func TestValidateReadOnlyQuery_BlocksWriteOrUnsafePatterns(t *testing.T) {
	tests := []string{
		"DELETE FROM sys.objects",
		"DROP TABLE t1",
		"ALTER LOGIN sa DISABLE",
		"EXEC xp_cmdshell 'dir'",
		"EXEC (@sql)",
		"DECLARE @sql nvarchar(max)=N'DELETE FROM dbo.users'; EXEC sp_executesql @sql;",
		"INSERT INTO dbo.users(id) VALUES(1)",
	}

	for _, sqlText := range tests {
		if err := validateReadOnlyQuery("mssql", sqlText); err == nil {
			t.Fatalf("expected query to be blocked: %q", sqlText)
		}
	}
}

// TestValidateReadOnlyQueryMSSQLBlocksDynamicSQL guards against every form of
// dynamic SQL execution via sp_executesql -- a single literal, a keyword
// split across literals joined by "+", and a keyword assembled through a
// variable, which no lexical scanner can distinguish from an innocuous
// concatenation ahead of time. sp_executesql is rejected outright (see
// isAllowedExecTarget) rather than scanned, so all of these are blocked for
// the same reason regardless of how the payload is assembled.
func TestValidateReadOnlyQueryMSSQLBlocksDynamicSQL(t *testing.T) {
	tests := []string{
		"DECLARE @sql nvarchar(max) = N'SELECT 1'; EXEC sp_executesql @sql;",
		"DECLARE @sql nvarchar(200) = 'DR' + 'OP TABLE users'; EXEC sp_executesql @sql;",
		"DECLARE @sql nvarchar(200) = 'DROP ' + 'TABLE ' + 'users'; EXEC sp_executesql @sql;",
		"DECLARE @sql nvarchar(200) = 'DR'\n+\n'OP TABLE users'; EXEC sp_executesql @sql;",
		"DECLARE @a nvarchar(20) = 'DR'; DECLARE @sql nvarchar(200) = @a + 'OP TABLE users'; EXEC sp_executesql @sql;",
	}
	for _, sqlText := range tests {
		if err := validateReadOnlyQuery("mssql", sqlText); err == nil {
			t.Fatalf("expected dynamic SQL via sp_executesql to be blocked: %q", sqlText)
		}
	}
}

func TestValidateReadOnlyQuery_OracleBlocksDML(t *testing.T) {
	if err := validateReadOnlyQuery("oracle", "SELECT * FROM v$instance"); err != nil {
		t.Fatalf("expected oracle SELECT to be allowed: %v", err)
	}

	if err := validateReadOnlyQuery("oracle", "DELETE FROM dba_users"); err == nil {
		t.Fatalf("expected oracle DELETE to be blocked")
	}
}

func TestValidateReadOnlyQuery_SQLiteAllowsReadOnly(t *testing.T) {
	tests := []string{
		"SELECT sqlite_version() AS version",
		"SELECT foreign_keys FROM pragma_foreign_keys",
		"SELECT detail FROM EXPLAIN QUERY PLAN SELECT * FROM users WHERE email = 'a@b.com'",
	}

	for _, sqlText := range tests {
		if err := validateReadOnlyQuery("sqlite", sqlText); err != nil {
			t.Fatalf("expected sqlite query to be allowed, got error for %q: %v", sqlText, err)
		}
	}
}

func TestValidateReadOnlyQuery_SQLiteBlocksWrites(t *testing.T) {
	tests := []string{
		"INSERT INTO users(id) VALUES(1)",
		"PRAGMA journal_mode = WAL",
		"VACUUM",
	}

	for _, sqlText := range tests {
		if err := validateReadOnlyQuery("sqlite", sqlText); err == nil {
			t.Fatalf("expected sqlite query to be blocked: %q", sqlText)
		}
	}
}
