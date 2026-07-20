package config

import "errors"

var (
	ErrInvalidDatabaseType     = errors.New("invalid database type")
	ErrMissingHost             = errors.New("missing database host")
	ErrMissingPort             = errors.New("missing database port")
	ErrMissingUsername         = errors.New("missing database username")
	ErrMissingOracleService    = errors.New("missing Oracle service_name or sid")
	ErrOracleSysUserNotAllowed = errors.New("Oracle SYS user is not allowed for agent connections")
	ErrOracleSysDBANotAllowed  = errors.New("Oracle SYSDBA mode is not allowed for agent connections")
	ErrMissingPostgresDatabase = errors.New("missing Postgres/Supabase database name")
	ErrMissingSQLitePath       = errors.New("missing SQLite database file path")
	ErrMissingLogSourceName    = errors.New("missing log source name")
	ErrMissingLogSourceType    = errors.New("missing log source type")
	ErrMissingLogSourcePath    = errors.New("missing log source path")
	ErrNoDatabases             = errors.New("no databases configured")
	ErrInvalidConfig           = errors.New("invalid configuration")

	// SIEM-only mode errors
	ErrSIEMMissingDestination = errors.New("output.siem.destination is required for siem_only mode")
	ErrSIEMMissingWebhookURL  = errors.New("output.siem.webhook.url is required for webhook destination")
	ErrSIEMInsecureWebhook    = errors.New("output.siem.webhook.url uses insecure HTTP; set security.allow_http to permit")
	ErrSIEMMissingSyslogHost  = errors.New("output.siem.syslog.host is required for syslog destination")
)
