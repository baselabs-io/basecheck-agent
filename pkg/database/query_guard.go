package database

import (
	"fmt"
	"regexp"
	"strings"
)

// forbiddenAdminStatementPattern blocks administrative/state-changing
// constructs with no legitimate read-only use in evidence-gathering SQL.
// KILL and RECONFIGURE are MSSQL-specific but harmless to block globally:
// KILL terminates another session's query and RECONFIGURE applies
// server-wide configuration changes -- neither word appears in legitimate
// read-only SQL for any supported engine. DBCC is deliberately NOT here: it
// has both destructive subcommands (CHECKIDENT ... RESEED, SHRINKDATABASE)
// and genuinely read-only diagnostic ones (LOGINFO, INPUTBUFFER, OPENTRAN)
// that legitimate evidence-gathering SQL uses, so it needs the dedicated
// subcommand allowlist in validateMSSQLDBCC instead of a blanket ban.
var forbiddenAdminStatementPattern = regexp.MustCompile(`(?i)\b(DROP|ALTER|CREATE|GRANT|REVOKE|DENY|BACKUP|RESTORE|SHUTDOWN|KILL|RECONFIGURE)\b`)

var forbiddenDMLStatementPattern = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE)\b`)

// forbiddenProcedureInvocationPattern blocks stored procedure/function
// invocation, which can perform arbitrary writes without any DML keyword
// appearing lexically in the calling statement.
var forbiddenProcedureInvocationPattern = regexp.MustCompile(`(?i)\bCALL\b`)

// forbiddenOracleDynamicSQLPattern blocks Oracle dynamic SQL. EXECUTE
// IMMEDIATE runs a string as SQL/PLSQL; since string literal contents are
// stripped before this pattern is matched, a dynamic statement's real
// content is invisible to keyword scanning, so the construct itself must be
// forbidden outright.
var forbiddenOracleDynamicSQLPattern = regexp.MustCompile(`(?i)\bEXECUTE\s+IMMEDIATE\b`)

// forbiddenPostgresStatementPattern blocks Postgres/Supabase constructs that
// can mutate state or execute arbitrary code without a DML keyword:
// COPY ... TO/FROM PROGRAM, DO (anonymous PL/pgSQL blocks), LISTEN/NOTIFY,
// and maintenance commands that are neither reads nor covered elsewhere.
var forbiddenPostgresStatementPattern = regexp.MustCompile(`(?i)\b(COPY|DO|LISTEN|NOTIFY|REFRESH|CLUSTER)\b`)

// forbiddenBareIntoPattern blocks "SELECT ... INTO <target>", which creates a
// new table as a side effect of an apparently read-only SELECT. Oracle,
// Postgres, and Supabase queries never legitimately need INTO at the
// top-level statement scope in this codebase's evidence-gathering usage.
var forbiddenBareIntoPattern = regexp.MustCompile(`(?i)\bINTO\b`)

// standardReadOnlyLeadingPattern requires the statement to begin with a
// recognized read-only verb. Combined with the forbidden-keyword scans above,
// this moves the guard from "block known-bad keywords anywhere" to "require a
// known-good statement shape, then still block known-bad keywords as
// defense-in-depth" (e.g. a data-modifying CTE like
// "WITH t AS (DELETE FROM x RETURNING *) SELECT * FROM t" still starts with
// the allowed "WITH" but is caught by the DELETE keyword scan below).
var standardReadOnlyLeadingPattern = regexp.MustCompile(`(?i)^(SELECT|WITH|EXPLAIN)\b`)

// sqliteReadOnlyLeadingPattern additionally allows PRAGMA, since read-form
// PRAGMA statements (no "=") are a legitimate SQLite introspection mechanism.
var sqliteReadOnlyLeadingPattern = regexp.MustCompile(`(?i)^(SELECT|WITH|EXPLAIN|PRAGMA)\b`)

// mssqlSelectIntoPattern detects "SELECT ... INTO <target>" (T-SQL table
// creation) as distinct from "INSERT INTO <target> ... SELECT ...", which is
// already governed by the temp-target INSERT check.
var mssqlSelectIntoPattern = regexp.MustCompile(`(?i)\bSELECT\b[\s\S]*?\bINTO\s+([#@]?[\[\]A-Za-z0-9_.]+)`)

var mssqlExecKeywordPattern = regexp.MustCompile(`(?i)\bEXEC(?:UTE)?\b`)

var mssqlExecTargetPattern = regexp.MustCompile(`(?i)\bEXEC(?:UTE)?\s+([A-Za-z0-9_\.\[\]]+)`)

var mssqlInsertIntoPattern = regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+([#@]?[A-Za-z0-9_\.\[\]]+)`)

var mssqlDeleteFromPattern = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+([#@]?[A-Za-z0-9_\.\[\]]+)`)

var mssqlUpdatePattern = regexp.MustCompile(`(?i)\bUPDATE\s+([#@]?[A-Za-z0-9_\.\[\]]+)`)

var mssqlInsertKeywordPattern = regexp.MustCompile(`(?i)\bINSERT\b`)

var mssqlDeleteKeywordPattern = regexp.MustCompile(`(?i)\bDELETE\b`)

var mssqlUpdateKeywordPattern = regexp.MustCompile(`(?i)\bUPDATE\b`)

var mssqlMergeKeywordPattern = regexp.MustCompile(`(?i)\bMERGE\b`)

var mssqlTruncateKeywordPattern = regexp.MustCompile(`(?i)\bTRUNCATE\b`)

// mssqlDBCCPattern extracts the subcommand name following a DBCC keyword so
// it can be checked against mssqlAllowedDBCCCommands. DBCC subcommands are
// mixed: some are read-only diagnostics (LOGINFO, INPUTBUFFER, OPENTRAN),
// others are destructive administrative actions (CHECKIDENT ... RESEED,
// SHRINKDATABASE, FREEPROCCACHE), so DBCC as a whole cannot be blocked or
// allowed outright -- each invocation's subcommand must be checked.
var mssqlDBCCPattern = regexp.MustCompile(`(?i)\bDBCC\s+([A-Za-z_]+)`)

// mssqlAllowedDBCCCommands lists DBCC subcommands with no side effects, used
// only to inspect server/database diagnostic state during evidence
// gathering. Every other DBCC subcommand is rejected by default (fail
// closed), including ones not yet enumerated here.
var mssqlAllowedDBCCCommands = map[string]bool{
	"loginfo":         true,
	"inputbuffer":     true,
	"opentran":        true,
	"sqlperf":         true,
	"show_statistics": true,
	"useroptions":     true,
	"showcontig":      true,
	"proccache":       true,
}

var sqliteForbiddenStatementPattern = regexp.MustCompile(`(?i)\b(VACUUM|REINDEX|ATTACH|DETACH)\b`)

var sqliteWritePragmaPattern = regexp.MustCompile(`(?i)\bPRAGMA\s+[^;]*=`)

func validateReadOnlyQuery(dbType, sqlText string) error {
	sanitized := sanitizeSQL(sqlText)
	if strings.TrimSpace(sanitized) == "" {
		return fmt.Errorf("query validation failed: empty SQL")
	}

	if match := forbiddenAdminStatementPattern.FindString(sanitized); match != "" {
		return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
	}

	switch dbType {
	case "mssql":
		// MSSQL evidence queries legitimately use multi-statement T-SQL
		// batches (DECLARE + temp-table staging), so it keeps its own
		// statement-level allowlist model rather than the
		// single-statement/leading-keyword requirement below. EXEC
		// sp_executesql is not part of that legitimate pattern -- see
		// isAllowedExecTarget -- so it is rejected outright.
		if err := validateMSSQLReadOnlyQuery(sanitized); err != nil {
			return err
		}
	case "oracle", "postgres", "supabase":
		if err := requireSingleStatement(sanitized); err != nil {
			return err
		}
		if match := forbiddenDMLStatementPattern.FindString(sanitized); match != "" {
			return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
		}
		if match := forbiddenProcedureInvocationPattern.FindString(sanitized); match != "" {
			return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
		}
		if match := forbiddenBareIntoPattern.FindString(sanitized); match != "" {
			return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
		}
		if dbType == "oracle" {
			if match := forbiddenOracleDynamicSQLPattern.FindString(sanitized); match != "" {
				return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
			}
		} else {
			if match := forbiddenPostgresStatementPattern.FindString(sanitized); match != "" {
				return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
			}
		}
		if !standardReadOnlyLeadingPattern.MatchString(strings.TrimSpace(sanitized)) {
			return fmt.Errorf("query validation failed: statement must begin with SELECT, WITH, or EXPLAIN")
		}
	case "sqlite":
		if err := validateSQLiteReadOnlyQuery(sanitized); err != nil {
			return err
		}
	default:
		return fmt.Errorf("query validation failed: unsupported database type for guard (%s)", dbType)
	}

	return nil
}

// requireSingleStatement rejects stacked queries (multiple ";"-separated
// statements). Safe to split the sanitized text on ";": sanitizeSQL removes
// string-literal and comment contents entirely, so any ";" remaining is a
// genuine top-level statement separator, never one embedded in a literal.
func requireSingleStatement(sanitized string) error {
	statementCount := 0
	for _, part := range strings.Split(sanitized, ";") {
		if strings.TrimSpace(part) != "" {
			statementCount++
		}
	}
	if statementCount > 1 {
		return fmt.Errorf("query validation failed: multiple statements are not allowed")
	}
	return nil
}

func validateSQLiteReadOnlyQuery(sanitized string) error {
	if err := requireSingleStatement(sanitized); err != nil {
		return err
	}

	if match := forbiddenDMLStatementPattern.FindString(sanitized); match != "" {
		return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
	}

	if match := sqliteForbiddenStatementPattern.FindString(sanitized); match != "" {
		return fmt.Errorf("query validation failed: forbidden statement detected (%s)", strings.ToUpper(match))
	}

	if sqliteWritePragmaPattern.MatchString(sanitized) {
		return fmt.Errorf("query validation failed: write PRAGMA statements are not allowed")
	}

	if !sqliteReadOnlyLeadingPattern.MatchString(strings.TrimSpace(sanitized)) {
		return fmt.Errorf("query validation failed: statement must begin with SELECT, WITH, EXPLAIN, or PRAGMA")
	}

	return nil
}

func validateMSSQLReadOnlyQuery(sanitized string) error {
	if err := validateMSSQLDML(sanitized); err != nil {
		return err
	}

	if err := validateMSSQLDBCC(sanitized); err != nil {
		return err
	}

	// "SELECT ... INTO <target>" creates a new table as a side effect; this
	// is distinct from "INSERT INTO <target> ... SELECT ...", which the
	// temp-target INSERT check above already governs.
	if matches := mssqlSelectIntoPattern.FindAllStringSubmatch(sanitized, -1); len(matches) > 0 {
		for _, match := range matches {
			if len(match) < 2 {
				return fmt.Errorf("query validation failed: SELECT INTO is not allowed")
			}
			target := normalizeExecTarget(match[1])
			if !isTempTarget(target) {
				return fmt.Errorf("query validation failed: SELECT INTO is not allowed (creates a table: %s)", target)
			}
		}
	}

	if mssqlExecKeywordPattern.MatchString(sanitized) {
		matches := mssqlExecTargetPattern.FindAllStringSubmatch(sanitized, -1)
		if len(matches) == 0 {
			return fmt.Errorf("query validation failed: EXEC format is not allowed")
		}

		for _, match := range matches {
			if len(match) < 2 {
				return fmt.Errorf("query validation failed: EXEC format is not allowed")
			}

			target := normalizeExecTarget(match[1])
			if !isAllowedExecTarget(target) {
				return fmt.Errorf("query validation failed: EXEC target is not allowed (%s)", target)
			}
		}
	}

	return nil
}

// validateMSSQLDBCC rejects any DBCC invocation whose subcommand is not on
// the read-only allowlist above (or whose subcommand could not be parsed at
// all), so a query like "DBCC CHECKIDENT ('users', RESEED, 0)" -- which
// resets an identity column -- is blocked while "DBCC LOGINFO([tempdb])", a
// genuinely read-only VLF diagnostic used by real evidence-gathering SQL, is
// allowed.
func validateMSSQLDBCC(sanitized string) error {
	matches := mssqlDBCCPattern.FindAllStringSubmatch(sanitized, -1)
	for _, match := range matches {
		if len(match) < 2 {
			return fmt.Errorf("query validation failed: forbidden statement detected (DBCC)")
		}
		command := strings.ToLower(match[1])
		if !mssqlAllowedDBCCCommands[command] {
			return fmt.Errorf("query validation failed: DBCC command is not allowed (%s)", strings.ToUpper(command))
		}
	}
	return nil
}

func validateMSSQLDML(sanitized string) error {
	if mssqlMergeKeywordPattern.MatchString(sanitized) {
		return fmt.Errorf("query validation failed: forbidden statement detected (MERGE)")
	}

	if mssqlTruncateKeywordPattern.MatchString(sanitized) {
		return fmt.Errorf("query validation failed: forbidden statement detected (TRUNCATE)")
	}

	if mssqlInsertKeywordPattern.MatchString(sanitized) {
		matches := mssqlInsertIntoPattern.FindAllStringSubmatch(sanitized, -1)
		if len(matches) == 0 {
			return fmt.Errorf("query validation failed: forbidden statement detected (INSERT)")
		}
		for _, match := range matches {
			if len(match) < 2 || !isTempTarget(match[1]) {
				return fmt.Errorf("query validation failed: forbidden statement detected (INSERT)")
			}
		}
	}

	if mssqlDeleteKeywordPattern.MatchString(sanitized) {
		matches := mssqlDeleteFromPattern.FindAllStringSubmatch(sanitized, -1)
		if len(matches) == 0 {
			return fmt.Errorf("query validation failed: forbidden statement detected (DELETE)")
		}
		for _, match := range matches {
			if len(match) < 2 || !isTempTarget(match[1]) {
				return fmt.Errorf("query validation failed: forbidden statement detected (DELETE)")
			}
		}
	}

	if mssqlUpdateKeywordPattern.MatchString(sanitized) {
		matches := mssqlUpdatePattern.FindAllStringSubmatch(sanitized, -1)
		if len(matches) == 0 {
			return fmt.Errorf("query validation failed: forbidden statement detected (UPDATE)")
		}
		for _, match := range matches {
			if len(match) < 2 || !isTempTarget(match[1]) {
				return fmt.Errorf("query validation failed: forbidden statement detected (UPDATE)")
			}
		}
	}

	return nil
}

// isAllowedExecTarget deliberately excludes sp_executesql (and its
// three/four-part-name variants): its argument is an arbitrary T-SQL string
// built at runtime from variables and expressions, not just adjacent string
// literals, so no lexical scanner can prove what it will execute --
// "DECLARE @a = 'DR'; EXEC sp_executesql @a + 'OP TABLE users'" reconstructs
// a forbidden statement without ever presenting it as a scannable literal.
// No bundled control uses sp_executesql, so it is forbidden outright, the
// same fail-closed treatment already given to Oracle's EXECUTE IMMEDIATE
// (see forbiddenOracleDynamicSQLPattern) for the identical reason.
func isAllowedExecTarget(target string) bool {
	switch target {
	case "xp_loginconfig", "dbo.xp_loginconfig", "master..xp_loginconfig", "master.dbo.xp_loginconfig":
		return true
	default:
		return false
	}
}

func normalizeExecTarget(target string) string {
	cleaned := strings.ReplaceAll(target, "[", "")
	cleaned = strings.ReplaceAll(cleaned, "]", "")
	return strings.ToLower(strings.TrimSpace(cleaned))
}

func isTempTarget(target string) bool {
	normalized := strings.TrimSpace(target)
	normalized = strings.ReplaceAll(normalized, "[", "")
	normalized = strings.ReplaceAll(normalized, "]", "")
	return strings.HasPrefix(normalized, "@") || strings.HasPrefix(normalized, "#")
}

func sanitizeSQL(sqlText string) string {
	var builder strings.Builder
	builder.Grow(len(sqlText))

	inLineComment := false
	inBlockComment := false
	inString := false

	for i := 0; i < len(sqlText); {
		ch := sqlText[i]

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				builder.WriteByte(' ')
			}
			i++
			continue
		}

		if inBlockComment {
			if i+1 < len(sqlText) && ch == '*' && sqlText[i+1] == '/' {
				inBlockComment = false
				builder.WriteByte(' ')
				i += 2
				continue
			}
			i++
			continue
		}

		if inString {
			if ch == '\'' {
				if i+1 < len(sqlText) && sqlText[i+1] == '\'' {
					i += 2
					continue
				}
				inString = false
				builder.WriteByte(' ')
				i++
				continue
			}
			i++
			continue
		}

		if i+1 < len(sqlText) && ch == '-' && sqlText[i+1] == '-' {
			inLineComment = true
			i += 2
			continue
		}

		if i+1 < len(sqlText) && ch == '/' && sqlText[i+1] == '*' {
			inBlockComment = true
			i += 2
			continue
		}

		if ch == '\'' {
			inString = true
			builder.WriteByte(' ')
			i++
			continue
		}

		builder.WriteByte(ch)
		i++
	}

	return builder.String()
}
