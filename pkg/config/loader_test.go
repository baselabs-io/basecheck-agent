package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWithLogMiningAndLogSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
agent:
  name: "agent-1"
  token_file: ".agent_token"
  hostname: "localhost"
  version: "1.0.0"
control_sets:
  source: "local"
  local_path: "control-sets"
output:
  mode: "file"
  file:
    path: "output.json"
    format: "json"
logging:
  level: "info"
  output: "file"
  path: "logs/agent.log"
security:
  allow_http: false
  require_signatures: false
log_mining:
  enabled: true
  state_path: ".cache/log-mining"
  max_excerpt_bytes: 4096
  max_entry_bytes: 65536
active_validation:
  enabled: true
  max_requests_per_run: 6
  max_concurrent: 1
  timeout_seconds: 8
  max_response_bytes: 32768
  allow_state_change: false
  identities:
    - name: "anon"
      headers:
        apikey: "anon-key"
  targets:
    - name: "supabase-api"
      base_url: "https://example.supabase.co"
      allowed_paths:
        - "/storage/v1/"
        - "/rest/v1/rpc/"
databases:
  - name: "oracle-prod"
    type: "oracle"
    host: "localhost"
    port: 1521
    service_name: "ORCLPDB1"
    username: "basecheck_agent"
    password: "secret"
    log_sources:
      - name: "alert-log"
        type: "oracle_alert_log"
        path: "/var/log/oracle/alert.log"
        enabled: true
        multiline_mode: "timestamp"
        timezone: "UTC"
`

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if !cfg.LogMining.Enabled {
		t.Fatalf("expected log_mining.enabled to be true")
	}
	if cfg.LogMining.GetStatePath() != ".cache/log-mining" {
		t.Fatalf("unexpected state path: %s", cfg.LogMining.GetStatePath())
	}
	if cfg.Logging.GetPath() != "logs/agent.log" {
		t.Fatalf("unexpected log path: %s", cfg.Logging.GetPath())
	}
	if !cfg.ActiveValidation.Enabled {
		t.Fatalf("expected active_validation.enabled to be true")
	}
	if cfg.ActiveValidation.GetMaxRequestsPerRun() != 6 {
		t.Fatalf("unexpected active validation request budget: %d", cfg.ActiveValidation.GetMaxRequestsPerRun())
	}
	if len(cfg.ActiveValidation.Identities) != 1 {
		t.Fatalf("expected 1 active validation identity, got %d", len(cfg.ActiveValidation.Identities))
	}
	if len(cfg.Databases[0].LogSources) != 1 {
		t.Fatalf("expected 1 log source, got %d", len(cfg.Databases[0].LogSources))
	}
	if cfg.Databases[0].LogSources[0].Type != "oracle_alert_log" {
		t.Fatalf("unexpected log source type: %s", cfg.Databases[0].LogSources[0].Type)
	}
}

func TestValidateRejectsIncompleteLogSource(t *testing.T) {
	cfg := Config{
		Databases: []DatabaseConfig{
			{
				Name:     "postgres-prod",
				Type:     "postgres",
				Host:     "localhost",
				Port:     5432,
				Database: "postgres",
				Username: "basecheck_agent",
				LogSources: []LogSourceConfig{
					{
						Name: "csv-log",
						Type: "csvlog",
					},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing log source path")
	}
}

func TestValidateAllowsOracleAlertLogAutodiscovery(t *testing.T) {
	cfg := Config{
		Databases: []DatabaseConfig{
			{
				Name:        "oracle-prod",
				Type:        "oracle",
				Host:        "localhost",
				Port:        1521,
				ServiceName: "ORCLPDB1",
				Username:    "basecheck_agent",
				LogSources: []LogSourceConfig{
					{
						Name: "alert-log",
						Type: "oracle_alert_log",
					},
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected Oracle alert log autodiscovery config to validate, got %v", err)
	}
}

func TestValidateRejectsInvalidPortRange(t *testing.T) {
	cfg := Config{
		Databases: []DatabaseConfig{
			{
				Name:     "postgres-prod",
				Type:     "postgres",
				Host:     "localhost",
				Port:     70000,
				Database: "postgres",
				Username: "basecheck_agent",
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid port range")
	}
}

func TestValidateAllowsOnlineModeWithoutDatabases(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{
			Source: "http",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected online mode without databases to validate, got %v", err)
	}
}

func TestValidateRejectsActiveValidationTargetWithoutAllowedPaths(t *testing.T) {
	cfg := Config{
		Security: SecurityConfig{
			AllowHTTP: false,
		},
		ActiveValidation: ActiveValidationConfig{
			Enabled: true,
			Targets: []ActiveValidationTarget{
				{
					Name:    "supabase-api",
					BaseURL: "https://example.supabase.co",
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing active validation allowed_paths")
	}
}

func TestValidateRejectsInsecureActiveValidationTargetWhenHTTPDisabled(t *testing.T) {
	cfg := Config{
		Security: SecurityConfig{
			AllowHTTP: false,
		},
		ActiveValidation: ActiveValidationConfig{
			Enabled: true,
			Targets: []ActiveValidationTarget{
				{
					Name:         "supabase-api",
					BaseURL:      "http://example.supabase.co",
					AllowedPaths: []string{"/storage/v1/"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for insecure active validation base_url")
	}
}

func TestValidateRejectsDuplicateActiveValidationIdentity(t *testing.T) {
	cfg := Config{
		Security: SecurityConfig{
			AllowHTTP: false,
		},
		ActiveValidation: ActiveValidationConfig{
			Enabled: true,
			Identities: []ActiveValidationIdentity{
				{Name: "anon"},
				{Name: "anon"},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for duplicate active validation identity")
	}
}

func TestValidateSIEMOnlyModeRequiresDestination(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing siem destination")
	}
	if err != ErrSIEMMissingDestination {
		t.Fatalf("expected ErrSIEMMissingDestination, got %v", err)
	}
}

func TestValidateSIEMOnlyWebhookRequiresURL(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "webhook",
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing webhook URL")
	}
	if err != ErrSIEMMissingWebhookURL {
		t.Fatalf("expected ErrSIEMMissingWebhookURL, got %v", err)
	}
}

func TestValidateSIEMOnlyWebhookRejectsInsecureHTTP(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Security:    SecurityConfig{AllowHTTP: false},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "webhook",
				Webhook: SIEMWebhookConfig{
					URL: "http://insecure.example.com/events",
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for insecure webhook URL")
	}
	if err != ErrSIEMInsecureWebhook {
		t.Fatalf("expected ErrSIEMInsecureWebhook, got %v", err)
	}
}

func TestValidateSIEMOnlyWebhookAllowsHTTPSWhenInsecureDisabled(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Security:    SecurityConfig{AllowHTTP: false},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "webhook",
				Webhook: SIEMWebhookConfig{
					URL: "https://secure.example.com/events",
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected HTTPS webhook to validate, got %v", err)
	}
}

func TestValidateSIEMOnlyWebhookAllowsHTTPWhenEnabled(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Security:    SecurityConfig{AllowHTTP: true},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "webhook",
				Webhook: SIEMWebhookConfig{
					URL: "http://insecure.example.com/events",
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected HTTP webhook with allow_http to validate, got %v", err)
	}
}

func TestValidateSIEMOnlySyslogRequiresHost(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "syslog",
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for missing syslog host")
	}
	if err != ErrSIEMMissingSyslogHost {
		t.Fatalf("expected ErrSIEMMissingSyslogHost, got %v", err)
	}
}

func TestValidateSIEMOnlySyslogRejectsInvalidProtocol(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "syslog",
				Syslog: SIEMSyslogConfig{
					Host:     "syslog.example.com",
					Protocol: "http",
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for invalid syslog protocol")
	}
}

func TestValidateSIEMOnlySyslogAcceptsValidConfig(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "syslog",
				Syslog: SIEMSyslogConfig{
					Host:     "syslog.example.com",
					Port:     514,
					Protocol: "tcp",
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid syslog config to pass, got %v", err)
	}
}

func TestSIEMConfigDefaults(t *testing.T) {
	cfg := SIEMConfig{}

	// Webhook defaults
	if cfg.Webhook.GetTimeoutSeconds() != 30 {
		t.Errorf("expected default webhook timeout 30, got %d", cfg.Webhook.GetTimeoutSeconds())
	}

	// Syslog defaults
	if cfg.Syslog.GetPort() != 514 {
		t.Errorf("expected default syslog port 514, got %d", cfg.Syslog.GetPort())
	}
	if cfg.Syslog.GetProtocol() != "tcp" {
		t.Errorf("expected default syslog protocol tcp, got %s", cfg.Syslog.GetProtocol())
	}
	if cfg.Syslog.GetFacility() != "local0" {
		t.Errorf("expected default syslog facility local0, got %s", cfg.Syslog.GetFacility())
	}
	if cfg.Syslog.GetAppName() != "basecheck" {
		t.Errorf("expected default syslog app_name basecheck, got %s", cfg.Syslog.GetAppName())
	}

	// Queue defaults
	if cfg.Queue.GetMaxSize() != 1000 {
		t.Errorf("expected default queue max_size 1000, got %d", cfg.Queue.GetMaxSize())
	}
	if cfg.Queue.GetFlushIntervalSeconds() != 10 {
		t.Errorf("expected default flush interval 10, got %d", cfg.Queue.GetFlushIntervalSeconds())
	}
	if cfg.Queue.GetRetryMax() != 5 {
		t.Errorf("expected default retry max 5, got %d", cfg.Queue.GetRetryMax())
	}
	backoff := cfg.Queue.GetRetryBackoffSeconds()
	if len(backoff) != 5 || backoff[0] != 1 || backoff[4] != 300 {
		t.Errorf("unexpected default backoff: %v", backoff)
	}

	// Queue path defaults, and is instance-configurable (AS-0034)
	if cfg.Queue.GetPath() != ".cache/siem-queue.jsonl" {
		t.Errorf("expected default queue path, got %s", cfg.Queue.GetPath())
	}
	cfgQueuePath := SIEMConfig{Queue: SIEMQueueConfig{Path: ".cache/agent-2/siem-queue.jsonl"}}
	if cfgQueuePath.Queue.GetPath() != ".cache/agent-2/siem-queue.jsonl" {
		t.Errorf("expected configured queue path to be honored, got %s", cfgQueuePath.Queue.GetPath())
	}

	// Dead letter defaults
	if cfg.DeadLetter.GetPath() != ".cache/siem-dead-letter.jsonl" {
		t.Errorf("expected default dead letter path, got %s", cfg.DeadLetter.GetPath())
	}
	if cfg.DeadLetter.GetMaxSizeMB() != 100 {
		t.Errorf("expected default dead letter max size 100, got %d", cfg.DeadLetter.GetMaxSizeMB())
	}

	// Deduplication defaults - enabled by default per AS-0020
	if !cfg.Deduplication.IsEnabled() {
		t.Errorf("expected deduplication enabled by default")
	}
	if cfg.Deduplication.GetWindowHours() != 24 {
		t.Errorf("expected default dedup window 24, got %d", cfg.Deduplication.GetWindowHours())
	}

	// Deduplication persist path defaults, and is instance-configurable (AS-0034)
	if cfg.Deduplication.GetPersistPath() != ".cache/siem-dedup.json" {
		t.Errorf("expected default dedup persist path, got %s", cfg.Deduplication.GetPersistPath())
	}
	cfgDedupPath := SIEMConfig{Deduplication: SIEMDeduplicationConfig{PersistPath: ".cache/agent-2/siem-dedup.json"}}
	if cfgDedupPath.Deduplication.GetPersistPath() != ".cache/agent-2/siem-dedup.json" {
		t.Errorf("expected configured dedup persist path to be honored, got %s", cfgDedupPath.Deduplication.GetPersistPath())
	}

	// Explicitly disabled deduplication
	cfgDisabled := SIEMConfig{Deduplication: SIEMDeduplicationConfig{Disabled: true}}
	if cfgDisabled.Deduplication.IsEnabled() {
		t.Errorf("expected deduplication disabled when Disabled=true")
	}
}

func TestValidateSIEMOnlyWebhookRejectsInvalidURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"no scheme", "example.com/events"},
		{"ftp scheme", "ftp://example.com/events"},
		{"missing host", "https:///path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				ControlSets: ControlSetConfig{Source: "http"},
				Security:    SecurityConfig{AllowHTTP: true},
				Output: OutputConfig{
					Mode: "siem_only",
					SIEM: SIEMConfig{
						Destination: "webhook",
						Webhook:     SIEMWebhookConfig{URL: tt.url},
					},
				},
			}

			if err := cfg.Validate(); err == nil {
				t.Errorf("expected validation error for URL %q", tt.url)
			}
		})
	}
}

func TestValidateSIEMOnlySyslogRejectsInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"negative port", -1},
		{"port too high", 70000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				ControlSets: ControlSetConfig{Source: "http"},
				Output: OutputConfig{
					Mode: "siem_only",
					SIEM: SIEMConfig{
						Destination: "syslog",
						Syslog: SIEMSyslogConfig{
							Host: "syslog.example.com",
							Port: tt.port,
						},
					},
				},
			}

			if err := cfg.Validate(); err == nil {
				t.Errorf("expected validation error for port %d", tt.port)
			}
		})
	}
}

func TestValidateSIEMOnlySyslogAcceptsZeroPort(t *testing.T) {
	cfg := Config{
		ControlSets: ControlSetConfig{Source: "http"},
		Output: OutputConfig{
			Mode: "siem_only",
			SIEM: SIEMConfig{
				Destination: "syslog",
				Syslog: SIEMSyslogConfig{
					Host: "syslog.example.com",
					Port: 0, // means use default 514
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected port 0 (default) to validate, got %v", err)
	}
}

// TestSecuritySignaturesRequiredDefaultsToTrue guards against a control pack
// silently running unsigned when require_signatures is omitted from config.
// An omitted key must fail closed (signatures required), not fail open.
func TestSecuritySignaturesRequiredDefaultsToTrue(t *testing.T) {
	unset := SecurityConfig{}
	if !unset.SignaturesRequired() {
		t.Error("SignaturesRequired() with omitted require_signatures should default to true (fail closed)")
	}

	explicitFalse := false
	disabled := SecurityConfig{RequireSignatures: &explicitFalse}
	if disabled.SignaturesRequired() {
		t.Error("SignaturesRequired() should be false when require_signatures is explicitly set to false")
	}

	explicitTrue := true
	enabled := SecurityConfig{RequireSignatures: &explicitTrue}
	if !enabled.SignaturesRequired() {
		t.Error("SignaturesRequired() should be true when require_signatures is explicitly set to true")
	}
}

// TestLoadConfigOmittedRequireSignaturesDefaultsSecure confirms that loading a
// YAML config file with no require_signatures key at all results in signatures
// being required, not silently permissive.
func TestLoadConfigOmittedRequireSignaturesDefaultsSecure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
agent:
  name: "agent-1"
control_sets:
  source: "local"
  local_path: "control-sets"
databases:
  - name: "db-1"
    type: "sqlite"
    database: "test.db"
output:
  mode: "file"
  file:
    path: "output.json"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Security.SignaturesRequired() {
		t.Error("omitting require_signatures from config must still require signatures")
	}
}

func TestExpandEnvVarsSubstitutesSetVariable(t *testing.T) {
	t.Setenv("BASECHECK_TEST_DB_PASSWORD", "s3cret")

	input := []byte(`password: "${BASECHECK_TEST_DB_PASSWORD}"`)
	expanded, err := expandEnvVars(input)
	if err != nil {
		t.Fatalf("expandEnvVars() error: %v", err)
	}

	want := `password: "s3cret"`
	if string(expanded) != want {
		t.Errorf("expandEnvVars() = %q, want %q", expanded, want)
	}
}

func TestExpandEnvVarsFailsOnUndefinedVariable(t *testing.T) {
	os.Unsetenv("BASECHECK_TEST_UNDEFINED_VAR")

	input := []byte(`password: "${BASECHECK_TEST_UNDEFINED_VAR}"`)
	_, err := expandEnvVars(input)
	if err == nil {
		t.Fatal("expected error for undefined environment variable")
	}
	if !strings.Contains(err.Error(), "BASECHECK_TEST_UNDEFINED_VAR") {
		t.Errorf("expected error to name the missing variable, got: %v", err)
	}
}

func TestExpandEnvVarsFailsOnEmptyVariable(t *testing.T) {
	t.Setenv("BASECHECK_TEST_EMPTY_VAR", "")

	input := []byte(`password: "${BASECHECK_TEST_EMPTY_VAR}"`)
	_, err := expandEnvVars(input)
	if err == nil {
		t.Fatal("expected error for empty environment variable, not a silent blank substitution")
	}
}

func TestExpandEnvVarsNoOpWithoutSyntax(t *testing.T) {
	input := []byte("agent:\n  name: \"agent-1\"\n")
	expanded, err := expandEnvVars(input)
	if err != nil {
		t.Fatalf("expandEnvVars() error: %v", err)
	}
	if string(expanded) != string(input) {
		t.Errorf("expandEnvVars() changed content with no ${...} syntax: got %q, want %q", expanded, input)
	}
}

// TestLoadConfigExpandsEnvVars confirms the full LoadConfig path performs
// substitution, not just the lower-level helper.
func TestLoadConfigExpandsEnvVars(t *testing.T) {
	t.Setenv("BASECHECK_TEST_DB_PASSWORD", "s3cret")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
agent:
  name: "agent-1"
control_sets:
  source: "local"
  local_path: "control-sets"
databases:
  - name: "db-1"
    type: "sqlite"
    database: "test.db"
    password: "${BASECHECK_TEST_DB_PASSWORD}"
output:
  mode: "file"
  file:
    path: "output.json"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Databases[0].Password != "s3cret" {
		t.Errorf("Databases[0].Password = %q, want %q", cfg.Databases[0].Password, "s3cret")
	}
}

// TestLoadConfigFailsOnUndefinedEnvVar confirms LoadConfig fails closed
// (rather than loading a config with a blank/literal credential) when a
// referenced environment variable is not set.
func TestLoadConfigFailsOnUndefinedEnvVar(t *testing.T) {
	os.Unsetenv("BASECHECK_TEST_UNDEFINED_DB_PASSWORD")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
agent:
  name: "agent-1"
control_sets:
  source: "local"
  local_path: "control-sets"
databases:
  - name: "db-1"
    type: "sqlite"
    database: "test.db"
    password: "${BASECHECK_TEST_UNDEFINED_DB_PASSWORD}"
output:
  mode: "file"
  file:
    path: "output.json"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected LoadConfig to fail for undefined environment variable")
	}
}
