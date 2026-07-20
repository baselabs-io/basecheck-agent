package config

import (
	"fmt"
	"net/url"
	"strings"

	"basecheck-agent/pkg/security"
)

// Config represents the agent configuration
type Config struct {
	Agent            AgentConfig            `yaml:"agent"`
	Databases        []DatabaseConfig       `yaml:"databases"`
	ControlSets      ControlSetConfig       `yaml:"control_sets"`
	Entitlement      EntitlementConfig      `yaml:"entitlement"`
	Output           OutputConfig           `yaml:"output"`
	Logging          LoggingConfig          `yaml:"logging"`
	LogMining        LogMiningConfig        `yaml:"log_mining"`
	ActiveValidation ActiveValidationConfig `yaml:"active_validation"`
	AuditPolicies    AuditPoliciesConfig    `yaml:"audit_policies"`
	Security         SecurityConfig         `yaml:"security"`
}

// AgentConfig contains agent-specific settings
type AgentConfig struct {
	Name      string `yaml:"name"`       // Agent name (identifier)
	Token     string `yaml:"token"`      // Agent token (from registration)
	TokenFile string `yaml:"token_file"` // Path to save token
	Hostname  string `yaml:"hostname"`   // Server hostname
	Version   string `yaml:"version"`    // Agent version
	AgentID   string `yaml:"agent_id"`   // Backend-assigned agent ID (for entitlement binding)
}

// ControlSetConfig contains control set source settings
type ControlSetConfig struct {
	Source     string `yaml:"source"`      // local, http
	LocalPath  string `yaml:"local_path"`  // Path to local control set directory
	BackendURL string `yaml:"backend_url"` // URL to backend API
	CachePath  string `yaml:"cache_path"`  // Path to cache downloaded control sets
}

// EntitlementConfig contains entitlement settings for paid control access
type EntitlementConfig struct {
	LocalPath string `yaml:"local_path"` // Path to local entitlement file (air-gapped)
	CachePath string `yaml:"cache_path"` // Path to cache downloaded entitlements
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Name               string            `yaml:"name"` // Unique identifier for this database
	Type               string            `yaml:"type"` // oracle, postgres, supabase, mssql, sqlite
	Host               string            `yaml:"host"`
	Port               int               `yaml:"port"`
	Database           string            `yaml:"database"`     // For Postgres, MSSQL, SQLite file path
	ServiceName        string            `yaml:"service_name"` // For Oracle
	SID                string            `yaml:"sid"`          // For Oracle (alternative)
	Username           string            `yaml:"username"`
	Password           string            `yaml:"password"`
	SSLMode            string            `yaml:"ssl_mode"` // For Postgres
	ProjectRef         string            `yaml:"project_ref"`
	ManagementAPIToken string            `yaml:"management_api_token"`
	ManagementAPIURL   string            `yaml:"management_api_url"`
	EdgeSourcePath     string            `yaml:"edge_source_path"`
	ControlVariables   map[string]string `yaml:"control_variables"`
	AsSysDBA           bool              `yaml:"as_sysdba"` // For Oracle
	// AllowReadOnlyFallback explicitly acknowledges that this Oracle database
	// does not support session-level read-only mode (ORA-02248) and that the
	// connection will rely solely on query-guard enforcement. Defaults to
	// false: the agent fails closed and refuses to connect to such a
	// database until an operator sets this.
	AllowReadOnlyFallback bool              `yaml:"allow_read_only_fallback"`
	AuditLogPath          string            `yaml:"audit_log_path"`     // Optional: PostgreSQL csvlog path
	AuditLogMaxRows       int               `yaml:"audit_log_max_rows"` // Optional: max csv rows per run
	LogSources            []LogSourceConfig `yaml:"log_sources"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	Mode string     `yaml:"mode"` // file, http, siem_only
	File FileConfig `yaml:"file"`
	HTTP HTTPConfig `yaml:"http"`
	SIEM SIEMConfig `yaml:"siem"` // SIEM-only mode configuration
}

// SIEMConfig contains SIEM output settings for siem_only mode
type SIEMConfig struct {
	Destination   string                  `yaml:"destination"` // webhook, syslog
	Webhook       SIEMWebhookConfig       `yaml:"webhook"`
	Syslog        SIEMSyslogConfig        `yaml:"syslog"`
	Queue         SIEMQueueConfig         `yaml:"queue"`
	DeadLetter    SIEMDeadLetterConfig    `yaml:"dead_letter"`
	Deduplication SIEMDeduplicationConfig `yaml:"deduplication"`
}

// SIEMWebhookConfig contains webhook destination settings
type SIEMWebhookConfig struct {
	URL            string            `yaml:"url"`
	Headers        map[string]string `yaml:"headers"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
}

// SIEMSyslogConfig contains syslog destination settings
type SIEMSyslogConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Protocol       string `yaml:"protocol"` // tcp, udp
	Facility       string `yaml:"facility"` // local0-local7, user, daemon, etc.
	AppName        string `yaml:"app_name"`
	TimeoutSeconds int    `yaml:"timeout_seconds"` // Connection/write timeout (default: 30)
}

// SIEMQueueConfig contains delivery queue settings
type SIEMQueueConfig struct {
	MaxSize              int   `yaml:"max_size"`
	FlushIntervalSeconds int   `yaml:"flush_interval_seconds"`
	RetryMax             int   `yaml:"retry_max"`
	RetryBackoffSeconds  []int `yaml:"retry_backoff_seconds"`
	// Path is the durable queue persistence file. Give each agent instance
	// (or each database, if running multiple agents against one working
	// directory) its own path -- sharing a path across concurrent processes
	// risks corrupted or double-delivered state even with file locking.
	Path string `yaml:"path"`
}

// SIEMDeadLetterConfig contains dead-letter file settings
type SIEMDeadLetterConfig struct {
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"`
}

// SIEMDeduplicationConfig contains deduplication settings.
// Enabled defaults to true per AS-0020; use Disabled to explicitly turn off.
type SIEMDeduplicationConfig struct {
	Disabled    bool   `yaml:"disabled"`     // Explicitly disable deduplication (default: false = enabled)
	WindowHours int    `yaml:"window_hours"` // Deduplication window in hours (default: 24)
	PersistPath string `yaml:"persist_path"` // Dedup state file; give each agent instance its own path
}

// FileConfig contains file output settings
type FileConfig struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"` // json, csv
}

// HTTPConfig contains HTTP output settings
type HTTPConfig struct {
	URL     string `yaml:"url"`
	APIKey  string `yaml:"api_key"`
	Timeout int    `yaml:"timeout"` // timeout in seconds, default 30
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Output string `yaml:"output"` // stdout, file
	Path   string `yaml:"path"`   // File path when output=file
}

// LogMiningConfig contains agent-side log mining settings
type LogMiningConfig struct {
	Enabled         bool   `yaml:"enabled"`
	StatePath       string `yaml:"state_path"`
	MaxExcerptBytes int    `yaml:"max_excerpt_bytes"`
	MaxEntryBytes   int    `yaml:"max_entry_bytes"`
}

// LogSourceConfig contains a single log source definition for a database
type LogSourceConfig struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	Path          string `yaml:"path"`
	Enabled       bool   `yaml:"enabled"`
	MultilineMode string `yaml:"multiline_mode"`
	Timezone      string `yaml:"timezone"`
}

// ActiveValidationConfig contains runtime validation safety limits
type ActiveValidationConfig struct {
	Enabled           bool                       `yaml:"enabled"`
	MaxRequestsPerRun int                        `yaml:"max_requests_per_run"`
	MaxConcurrent     int                        `yaml:"max_concurrent"`
	TimeoutSeconds    int                        `yaml:"timeout_seconds"`
	MaxResponseBytes  int                        `yaml:"max_response_bytes"`
	AllowStateChange  bool                       `yaml:"allow_state_change"`
	Identities        []ActiveValidationIdentity `yaml:"identities"`
	Targets           []ActiveValidationTarget   `yaml:"targets"`
}

// ActiveValidationIdentity defines a named request identity/header set
type ActiveValidationIdentity struct {
	Name    string            `yaml:"name"`
	Headers map[string]string `yaml:"headers"`
}

// ActiveValidationTarget defines an allowlisted validation destination
type ActiveValidationTarget struct {
	Name         string            `yaml:"name"`
	BaseURL      string            `yaml:"base_url"`
	Headers      map[string]string `yaml:"headers"`
	AllowedPaths []string          `yaml:"allowed_paths"`
}

// AuditPoliciesConfig contains audit policy settings for compliance controls
type AuditPoliciesConfig struct {
	MinRetentionDays   int      `yaml:"min_retention_days"`  // Minimum audit retention in days (90 for PCI, 365 for SOX/HIPAA)
	SensitivePatterns  []string `yaml:"sensitive_patterns"`  // Table/schema patterns requiring audit (e.g., *CUSTOMER*, FINANCE.*)
	CriticalOperations []string `yaml:"critical_operations"` // Operations to flag in reports (e.g., DROP TABLE, GRANT DBA)
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	AllowHTTP bool `yaml:"allow_http"` // Allow insecure HTTP transport for backend/entitlement/webhook connections (default: false)
	// RequireSignatures is a pointer so an omitted key can be distinguished from
	// an explicit `false`: the effective default (via SignaturesRequired) is
	// secure-by-default (true) unless the operator explicitly opts out.
	RequireSignatures *bool  `yaml:"require_signatures"`
	PublicKey         string `yaml:"public_key"` // Base64-encoded RSA public key for control set verification
}

// SignaturesRequired returns whether control-set signatures are required.
// Defaults to true (fail closed) unless require_signatures is explicitly set
// to false in configuration.
func (s *SecurityConfig) SignaturesRequired() bool {
	return s.RequireSignatures == nil || *s.RequireSignatures
}

// GetMinRetentionDays returns the minimum retention days, defaulting to 365 if not set
func (a *AuditPoliciesConfig) GetMinRetentionDays() int {
	if a.MinRetentionDays == 0 {
		return 365 // Default to 1 year for SOX/HIPAA compliance
	}
	return a.MinRetentionDays
}

// GetSensitivePatterns returns the sensitive patterns with defaults if not set
func (a *AuditPoliciesConfig) GetSensitivePatterns() []string {
	if len(a.SensitivePatterns) == 0 {
		// Default sensitive patterns
		return []string{
			"*CUSTOMER*", "*PAYMENT*", "*CREDIT_CARD*", "*SSN*",
			"*PII*", "*HIPAA*", "FINANCE.*", "HR.*",
		}
	}
	return a.SensitivePatterns
}

// GetCriticalOperations returns the critical operations with defaults if not set
func (a *AuditPoliciesConfig) GetCriticalOperations() []string {
	if len(a.CriticalOperations) == 0 {
		// Default critical operations
		return []string{
			"DROP TABLE", "DROP DATABASE", "DROP USER", "TRUNCATE TABLE",
			"GRANT DBA", "GRANT SYSDBA", "GRANT sysadmin",
			"ALTER SYSTEM SET", "sp_addsrvrolemember",
		}
	}
	return a.CriticalOperations
}

// GetCachePath returns the entitlement cache path with a default
func (e *EntitlementConfig) GetCachePath() string {
	if strings.TrimSpace(e.CachePath) == "" {
		return ".cache/entitlement"
	}
	return strings.TrimSpace(e.CachePath)
}

// GetStatePath returns the cursor state path with a default
func (l *LogMiningConfig) GetStatePath() string {
	if strings.TrimSpace(l.StatePath) == "" {
		return ".cache/log-mining"
	}
	return strings.TrimSpace(l.StatePath)
}

// GetMaxExcerptBytes returns the max stored excerpt size with a default
func (l *LogMiningConfig) GetMaxExcerptBytes() int {
	if l.MaxExcerptBytes <= 0 {
		return 8 * 1024
	}
	return l.MaxExcerptBytes
}

// GetMaxEntryBytes returns the max buffered entry size with a default
func (l *LogMiningConfig) GetMaxEntryBytes() int {
	if l.MaxEntryBytes <= 0 {
		return 256 * 1024
	}
	return l.MaxEntryBytes
}

// GetPath returns the log file path with a default
func (l *LoggingConfig) GetPath() string {
	if strings.TrimSpace(l.Path) == "" {
		return "logs/agent.log"
	}
	return strings.TrimSpace(l.Path)
}

// GetMaxRequestsPerRun returns the max active validation requests per run
func (a *ActiveValidationConfig) GetMaxRequestsPerRun() int {
	if a.MaxRequestsPerRun <= 0 {
		return 10
	}
	return a.MaxRequestsPerRun
}

// GetMaxConcurrent returns the max active validation concurrency
func (a *ActiveValidationConfig) GetMaxConcurrent() int {
	if a.MaxConcurrent <= 0 {
		return 1
	}
	return a.MaxConcurrent
}

// GetTimeoutSeconds returns the per-request timeout for active validation
func (a *ActiveValidationConfig) GetTimeoutSeconds() int {
	if a.TimeoutSeconds <= 0 {
		return 10
	}
	return a.TimeoutSeconds
}

// GetMaxResponseBytes returns the max response body size for active validation
func (a *ActiveValidationConfig) GetMaxResponseBytes() int {
	if a.MaxResponseBytes <= 0 {
		return 64 * 1024
	}
	return a.MaxResponseBytes
}

// GetTimeoutSeconds returns the webhook timeout with default
func (w *SIEMWebhookConfig) GetTimeoutSeconds() int {
	if w.TimeoutSeconds <= 0 {
		return 30
	}
	return w.TimeoutSeconds
}

// GetPort returns the syslog port with default
func (s *SIEMSyslogConfig) GetPort() int {
	if s.Port <= 0 {
		return 514
	}
	return s.Port
}

// GetProtocol returns the syslog protocol with default
func (s *SIEMSyslogConfig) GetProtocol() string {
	if s.Protocol == "" {
		return "tcp"
	}
	return s.Protocol
}

// GetFacility returns the syslog facility with default
func (s *SIEMSyslogConfig) GetFacility() string {
	if s.Facility == "" {
		return "local0"
	}
	return s.Facility
}

// GetAppName returns the syslog app name with default
func (s *SIEMSyslogConfig) GetAppName() string {
	if s.AppName == "" {
		return "basecheck"
	}
	return s.AppName
}

// GetTimeoutSeconds returns the syslog timeout with default
func (s *SIEMSyslogConfig) GetTimeoutSeconds() int {
	if s.TimeoutSeconds <= 0 {
		return 30
	}
	return s.TimeoutSeconds
}

// GetMaxSize returns the queue max size with default
func (q *SIEMQueueConfig) GetMaxSize() int {
	if q.MaxSize <= 0 {
		return 1000
	}
	return q.MaxSize
}

// GetFlushIntervalSeconds returns the flush interval with default
func (q *SIEMQueueConfig) GetFlushIntervalSeconds() int {
	if q.FlushIntervalSeconds <= 0 {
		return 10
	}
	return q.FlushIntervalSeconds
}

// GetRetryMax returns the max retries with default
// GetRetryMax returns the max retry count with default.
// Returns 5 if unset or zero. Explicitly set values > 0 are used as-is.
// Note: "no retries" is not configurable via YAML (use queue.RetryMax: 0 in code).
func (q *SIEMQueueConfig) GetRetryMax() int {
	if q.RetryMax <= 0 {
		return 5
	}
	return q.RetryMax
}

// GetRetryBackoffSeconds returns the retry backoff sequence with default
func (q *SIEMQueueConfig) GetRetryBackoffSeconds() []int {
	if len(q.RetryBackoffSeconds) == 0 {
		return []int{1, 5, 30, 120, 300}
	}
	return q.RetryBackoffSeconds
}

// GetPath returns the queue persistence file path with default
func (q *SIEMQueueConfig) GetPath() string {
	if q.Path == "" {
		return ".cache/siem-queue.jsonl"
	}
	return q.Path
}

// GetPath returns the dead-letter file path with default
func (d *SIEMDeadLetterConfig) GetPath() string {
	if d.Path == "" {
		return ".cache/siem-dead-letter.jsonl"
	}
	return d.Path
}

// GetMaxSizeMB returns the dead-letter max size with default
func (d *SIEMDeadLetterConfig) GetMaxSizeMB() int {
	if d.MaxSizeMB <= 0 {
		return 100
	}
	return d.MaxSizeMB
}

// IsEnabled returns whether deduplication is enabled (default: true per AS-0020)
func (dd *SIEMDeduplicationConfig) IsEnabled() bool {
	return !dd.Disabled
}

// GetWindowHours returns the deduplication window with default
func (dd *SIEMDeduplicationConfig) GetWindowHours() int {
	if dd.WindowHours <= 0 {
		return 24
	}
	return dd.WindowHours
}

// GetPersistPath returns the deduplication state file path with default
func (dd *SIEMDeduplicationConfig) GetPersistPath() string {
	if dd.PersistPath == "" {
		return ".cache/siem-dedup.json"
	}
	return dd.PersistPath
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if len(c.Databases) == 0 && !strings.EqualFold(strings.TrimSpace(c.ControlSets.Source), "http") {
		return ErrNoDatabases
	}

	// Track database names to ensure uniqueness
	names := make(map[string]bool)

	for i, db := range c.Databases {
		// Validate name
		if db.Name == "" {
			return fmt.Errorf("database[%d]: missing name", i)
		}
		if names[db.Name] {
			return fmt.Errorf("database[%d]: duplicate name '%s'", i, db.Name)
		}
		names[db.Name] = true

		dbType := strings.ToLower(strings.TrimSpace(db.Type))

		// Validate database type
		if dbType != "oracle" && dbType != "postgres" && dbType != "supabase" && dbType != "mssql" && dbType != "sqlite" {
			return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrInvalidDatabaseType)
		}

		// SQLite uses local file path only.
		if dbType == "sqlite" {
			if strings.TrimSpace(db.Database) == "" {
				return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingSQLitePath)
			}
			continue
		}

		// Validate required fields for network databases
		if strings.TrimSpace(db.Host) == "" {
			return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingHost)
		}
		if db.Port == 0 {
			return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingPort)
		}
		if db.Port < 1 || db.Port > 65535 {
			return fmt.Errorf("database[%d] '%s': invalid port %d", i, db.Name, db.Port)
		}
		if strings.TrimSpace(db.Username) == "" {
			return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingUsername)
		}

		// Database-specific validation
		if dbType == "oracle" {
			if db.ServiceName == "" && db.SID == "" {
				return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingOracleService)
			}
			if strings.EqualFold(strings.TrimSpace(db.Username), "sys") {
				return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrOracleSysUserNotAllowed)
			}
			if db.AsSysDBA {
				return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrOracleSysDBANotAllowed)
			}
		}
		if dbType == "postgres" || dbType == "supabase" {
			if db.Database == "" {
				return fmt.Errorf("database[%d] '%s': %w", i, db.Name, ErrMissingPostgresDatabase)
			}
		}
		// MS SQL Server: Database field is optional (defaults to master)

		logSourceNames := make(map[string]bool)
		for j, source := range db.LogSources {
			if strings.TrimSpace(source.Name) == "" {
				return fmt.Errorf("database[%d] '%s': log_sources[%d]: %w", i, db.Name, j, ErrMissingLogSourceName)
			}
			if logSourceNames[source.Name] {
				return fmt.Errorf("database[%d] '%s': log_sources[%d]: duplicate name '%s'", i, db.Name, j, source.Name)
			}
			logSourceNames[source.Name] = true

			if strings.TrimSpace(source.Type) == "" {
				return fmt.Errorf("database[%d] '%s': log_sources[%d]: %w", i, db.Name, j, ErrMissingLogSourceType)
			}
			if strings.TrimSpace(source.Path) == "" &&
				!(dbType == "oracle" && strings.EqualFold(strings.TrimSpace(source.Type), "oracle_alert_log")) {
				return fmt.Errorf("database[%d] '%s': log_sources[%d]: %w", i, db.Name, j, ErrMissingLogSourcePath)
			}
		}
	}

	targetNames := make(map[string]bool)
	identityNames := make(map[string]bool)
	for i, identity := range c.ActiveValidation.Identities {
		if strings.TrimSpace(identity.Name) == "" {
			return fmt.Errorf("active_validation.identities[%d]: missing name", i)
		}
		if identityNames[identity.Name] {
			return fmt.Errorf("active_validation.identities[%d]: duplicate name '%s'", i, identity.Name)
		}
		identityNames[identity.Name] = true
	}
	for i, target := range c.ActiveValidation.Targets {
		if strings.TrimSpace(target.Name) == "" {
			return fmt.Errorf("active_validation.targets[%d]: missing name", i)
		}
		if targetNames[target.Name] {
			return fmt.Errorf("active_validation.targets[%d]: duplicate name '%s'", i, target.Name)
		}
		targetNames[target.Name] = true
		if strings.TrimSpace(target.BaseURL) == "" {
			return fmt.Errorf("active_validation.targets[%d] '%s': missing base_url", i, target.Name)
		}
		if err := security.ValidateHTTPS(target.BaseURL, c.Security.AllowHTTP); err != nil {
			return fmt.Errorf("active_validation.targets[%d] '%s': %w", i, target.Name, err)
		}
		if len(target.AllowedPaths) == 0 {
			return fmt.Errorf("active_validation.targets[%d] '%s': missing allowed_paths", i, target.Name)
		}
		for j, currentPath := range target.AllowedPaths {
			if !strings.HasPrefix(strings.TrimSpace(currentPath), "/") {
				return fmt.Errorf("active_validation.targets[%d] '%s' allowed_paths[%d]: must start with '/'", i, target.Name, j)
			}
		}
	}

	// Validate SIEM-only output mode
	if strings.EqualFold(strings.TrimSpace(c.Output.Mode), "siem_only") {
		if err := c.Output.SIEM.Validate(c.Security.AllowHTTP); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates SIEM configuration when siem_only mode is active
func (s *SIEMConfig) Validate(allowHTTP bool) error {
	dest := strings.ToLower(strings.TrimSpace(s.Destination))
	if dest == "" {
		return ErrSIEMMissingDestination
	}
	if dest != "webhook" && dest != "syslog" {
		return fmt.Errorf("output.siem.destination must be 'webhook' or 'syslog', got %q", s.Destination)
	}

	if dest == "webhook" {
		rawURL := strings.TrimSpace(s.Webhook.URL)
		if rawURL == "" {
			return ErrSIEMMissingWebhookURL
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("output.siem.webhook.url is invalid: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("output.siem.webhook.url must use http or https scheme, got %q", parsed.Scheme)
		}
		if parsed.Host == "" {
			return fmt.Errorf("output.siem.webhook.url missing host")
		}
		if !allowHTTP && parsed.Scheme == "http" {
			return ErrSIEMInsecureWebhook
		}
	}

	if dest == "syslog" {
		if strings.TrimSpace(s.Syslog.Host) == "" {
			return ErrSIEMMissingSyslogHost
		}
		// Port 0 means use default (514); negative or >65535 is invalid
		if s.Syslog.Port < 0 || s.Syslog.Port > 65535 {
			return fmt.Errorf("output.siem.syslog.port must be 0-65535, got %d", s.Syslog.Port)
		}
		proto := strings.ToLower(strings.TrimSpace(s.Syslog.Protocol))
		if proto != "" && proto != "tcp" && proto != "udp" {
			return fmt.Errorf("output.siem.syslog.protocol must be 'tcp' or 'udp', got %q", s.Syslog.Protocol)
		}
	}

	return nil
}
