package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"basecheck-agent/pkg/agent"
	"basecheck-agent/pkg/config"
	"basecheck-agent/pkg/controlset"
	"basecheck-agent/pkg/database"
	"basecheck-agent/pkg/discovery"
	"basecheck-agent/pkg/entitlement"
	logmining "basecheck-agent/pkg/logs"
	oraclelogs "basecheck-agent/pkg/logs/oracle"
	pgcsvlog "basecheck-agent/pkg/logs/postgres"
	"basecheck-agent/pkg/output"
	"basecheck-agent/pkg/registration"
	"basecheck-agent/pkg/security"
	"basecheck-agent/pkg/siem"
)

// agentEntitlement holds the loaded entitlement for the current agent run.
// nil means free-only mode (no paid/enterprise packs allowed).
var agentEntitlement controlset.Entitlement

type backendAgentConfigResponse struct {
	Databases []backendDatabaseConfig `json:"databases"`
}

type backendDatabaseConfig struct {
	Name                  string `json:"name"`
	Type                  string `json:"type"`
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Database              string `json:"database"`
	ServiceName           string `json:"service_name"`
	SID                   string `json:"sid"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	SSLMode               string `json:"ssl_mode"`
	ProjectRef            string `json:"project_ref"`
	ManagementAPIToken    string `json:"management_api_token"`
	ManagementAPIURL      string `json:"management_api_url"`
	EdgeSourcePath        string `json:"edge_source_path"`
	AsSysDBA              bool   `json:"as_sysdba"`
	AllowReadOnlyFallback bool   `json:"allow_read_only_fallback"`
	AuditLogPath          string `json:"audit_log_path"`
	AuditLogMaxRows       int    `json:"audit_log_max_rows"`
}

// Version is set at build time via -ldflags
var Version = "1.0.0"

func main() {
	// Parse command-line flags
	testSIEM := flag.Bool("test-siem", false, "Send a test event to the configured SIEM destination and exit")
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	// Handle --version flag
	if *showVersion {
		fmt.Printf("BaseCheck Agent v%s\n", Version)
		os.Exit(0)
	}

	log.Println("BaseCheck Agent starting...")

	// Load config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Default agent.version to the running binary's build version when unset,
	// so SIEM export metadata always has a real agent_version rather than "".
	if strings.TrimSpace(cfg.Agent.Version) == "" {
		cfg.Agent.Version = Version
	}

	// Handle --test-siem flag
	if *testSIEM {
		runSIEMTest(cfg)
		return
	}

	if err := configureLogging(cfg); err != nil {
		log.Fatalf("Failed to configure logging: %v", err)
	}

	if strings.TrimSpace(cfg.Agent.Token) == "" && strings.TrimSpace(cfg.Agent.TokenFile) != "" {
		if token, err := registration.LoadToken(cfg.Agent.TokenFile); err == nil && strings.TrimSpace(token) != "" {
			cfg.Agent.Token = strings.TrimSpace(token)
		}
	}

	// Auto-detect actual hostname if not set or empty
	if strings.TrimSpace(cfg.Agent.Hostname) == "" {
		if actualHostname, err := os.Hostname(); err == nil && strings.TrimSpace(actualHostname) != "" {
			cfg.Agent.Hostname = strings.TrimSpace(actualHostname)
			log.Printf("Auto-detected hostname: %s", cfg.Agent.Hostname)
		} else {
			log.Printf("⚠️  Could not auto-detect hostname: %v", err)
			cfg.Agent.Hostname = "unknown"
		}
	} else {
		log.Printf("Using configured hostname: %s", cfg.Agent.Hostname)
	}

	log.Printf("Loaded configuration for %d database(s)", len(cfg.Databases))

	// Warn if insecure HTTP is allowed
	if cfg.Security.AllowHTTP {
		log.Println("⚠️  WARNING: Insecure HTTP connections allowed - this should only be used for development/testing")
	}

	// Detect agent mode (online vs offline)
	var agentMode *agent.Mode
	if cfg.ControlSets.Source == "http" {
		mode, err := detectMode(cfg)
		if err != nil {
			log.Fatalf("Failed to detect agent mode: %v", err)
		}
		agentMode = mode
		log.Printf("Agent mode: %s", strings.ToUpper(agentMode.Mode))

		// If offline mode detected, switch to local source
		if agentMode.IsOffline() {
			log.Println("Switching control_sets.source to 'local' for offline operation")
			cfg.ControlSets.Source = "local"
			// Ensure local_path is set (default to "control-sets" if empty)
			if cfg.ControlSets.LocalPath == "" {
				cfg.ControlSets.LocalPath = "control-sets"
			}
		}

		// If we just switched to online mode, upload pending results
		if agentMode.IsOnline() {
			if err := uploadPendingResults(cfg); err != nil {
				log.Printf("⚠ Failed to upload pending results: %v", err)
			}
		}
	} else {
		// Local mode - always offline
		agentMode = agent.NewOfflineMode("local_source")
		log.Println("Agent mode: OFFLINE (local source configured)")
	}

	// Ensure agent is registered (skip if in offline mode)
	if agentMode.IsOnline() {
		if strings.TrimSpace(cfg.Agent.Token) != "" {
			log.Printf("✓ Agent authenticated with configured token: %s", cfg.Agent.Name)
			if strings.TrimSpace(cfg.Agent.TokenFile) != "" {
				if err := registration.SaveToken(cfg.Agent.TokenFile, cfg.Agent.Token); err != nil {
					log.Printf("⚠ Failed to persist configured token to file: %v", err)
				}
			}
			// Resolve AgentID for entitlement binding (priority: config > persisted > name)
			if strings.TrimSpace(cfg.Agent.AgentID) == "" {
				if agentID, err := registration.LoadAgentID(cfg.Agent.TokenFile); err == nil && agentID != "" {
					cfg.Agent.AgentID = agentID
				} else {
					cfg.Agent.AgentID = cfg.Agent.Name
					log.Printf("  Using agent name as ID for entitlement binding (set agent.agent_id in config for paid packs)")
				}
			}
		} else {
			regResult, err := registration.EnsureRegistered(
				cfg.ControlSets.BackendURL,
				cfg.Agent.Name,
				cfg.Agent.Hostname,
				cfg.Agent.Version,
				cfg.Agent.TokenFile,
				cfg.Security.AllowHTTP,
			)
			if err != nil {
				log.Fatalf("Failed to register agent: %v", err)
			}
			cfg.Agent.Token = regResult.Token
			// Only set AgentID from registration if not configured
			if strings.TrimSpace(cfg.Agent.AgentID) == "" {
				cfg.Agent.AgentID = regResult.AgentID
			}
			log.Printf("✓ Agent registered/authenticated: %s (id=%s)", cfg.Agent.Name, cfg.Agent.AgentID)
		}
	} else {
		log.Println("Skipping registration (offline mode)")
		// Try to load token from file if it exists (for future online mode)
		if tokenData, err := os.ReadFile(cfg.Agent.TokenFile); err == nil {
			cfg.Agent.Token = strings.TrimSpace(string(tokenData))
		}
		// Resolve AgentID (priority: config > persisted > name)
		if strings.TrimSpace(cfg.Agent.AgentID) == "" {
			if agentID, err := registration.LoadAgentID(cfg.Agent.TokenFile); err == nil && agentID != "" {
				cfg.Agent.AgentID = agentID
			} else {
				cfg.Agent.AgentID = cfg.Agent.Name
			}
		}
	}

	// Load entitlement for paid/enterprise pack access
	if err := loadAgentEntitlement(cfg, agentMode); err != nil {
		// Fail if entitlement was explicitly configured (local_path set)
		// or if this is an online agent (expects server entitlement)
		if cfg.Entitlement.LocalPath != "" {
			log.Fatalf("Failed to load configured entitlement: %v", err)
		}
		// Log warning and continue in free-only mode
		log.Printf("⚠ Failed to load entitlement (running in free-only mode): %v", err)
	}

	// DISCOVERY PHASE: Discover new systems assigned to this agent
	// Skip discovery in offline mode (requires backend API access)
	if agentMode.IsOnline() {
		log.Println("\n=== DISCOVERY PHASE ===")
		if err := performDiscovery(cfg); err != nil {
			log.Printf("⚠ Discovery failed: %v", err)
			// Continue with regular audits even if discovery fails
		}
	} else {
		log.Println("\n=== DISCOVERY PHASE ===")
		log.Println("Skipping discovery (offline mode)")
	}

	if agentMode.IsOnline() {
		if err := syncOnlineDatabases(cfg); err != nil {
			log.Printf("⚠ Failed to sync online databases from backend: %v", err)
		}
		// Verify we have databases to audit in online mode
		if len(cfg.Databases) == 0 {
			log.Fatalf("No databases available for audit in online mode (backend sync may have failed)")
		}
	}

	os.Exit(runAuditPhase(cfg, agentMode))
}

// runOutcome aggregates per-database and SIEM-delivery results into an explicit
// run state so the process exit code reflects what actually happened instead of
// always reporting success.
type runOutcome struct {
	dbTotal         int
	dbFailed        int
	siemAttempted   bool
	siemDeliveryErr bool
	siemPending     int
	siemRejected    int
}

// Exit codes: 0 = success, 1 = failure (nothing usable produced or a required
// delivery guarantee was not met), 2 = degraded (partial failure).
const (
	exitSuccess  = 0
	exitFailure  = 1
	exitDegraded = 2
)

// code returns the process exit code for this outcome.
func (o runOutcome) code() int {
	if o.dbTotal > 0 && o.dbFailed == o.dbTotal {
		return exitFailure
	}
	if o.siemAttempted && o.siemDeliveryErr {
		return exitFailure
	}
	if o.dbFailed > 0 || o.siemPending > 0 || o.siemRejected > 0 {
		return exitDegraded
	}
	return exitSuccess
}

// summary returns the final human-readable log line for this outcome.
func (o runOutcome) summary() string {
	switch o.code() {
	case exitFailure:
		if o.dbTotal > 0 && o.dbFailed == o.dbTotal {
			return fmt.Sprintf("✗ Agent failed: all %d database(s) failed to process", o.dbTotal)
		}
		return "✗ Agent failed: SIEM delivery error"
	case exitDegraded:
		return fmt.Sprintf("⚠ Agent completed with degraded result: %d/%d database(s) failed, %d SIEM event(s) pending, %d SIEM event(s) rejected",
			o.dbFailed, o.dbTotal, o.siemPending, o.siemRejected)
	default:
		return "✓ Agent completed successfully"
	}
}

// runAuditPhase runs the audit phase and SIEM delivery for all configured
// databases and returns the process exit code reflecting the actual outcome.
//
// exitCode is a named return, and outcome is declared before the deferred
// SIEM Close(): Close's own final flush happens after every other step in
// this function (including the "return outcome.code()" at the bottom), so
// the only way its error can affect what the caller sees is to mutate the
// named return from inside the defer itself.
func runAuditPhase(cfg *config.Config, agentMode *agent.Mode) (exitCode int) {
	outcome := runOutcome{dbTotal: len(cfg.Databases)}

	// Initialize SIEM output if in siem_only mode
	var siemOutput *siem.Output
	if strings.EqualFold(strings.TrimSpace(cfg.Output.Mode), "siem_only") {
		log.Println("\n=== SIEM OUTPUT MODE ===")
		var err error
		siemOutput, err = siem.NewOutputFromConfig(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize SIEM output: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := siemOutput.Close(ctx); err != nil {
				log.Printf("⚠ SIEM output close error: %v", err)
				outcome.siemAttempted = true
				outcome.siemDeliveryErr = true
				exitCode = outcome.code()
			}
		}()
		log.Printf("✓ SIEM output initialized (destination: %s)", cfg.Output.SIEM.Destination)
	}

	// AUDIT PHASE: Collect data from all configured databases
	log.Println("\n=== AUDIT PHASE ===")
	allResults := make(map[string]interface{})
	var totalSIEMEvents int

	for _, dbCfg := range cfg.Databases {
		log.Printf("\n=== Processing database: %s ===", dbCfg.Name)

		result, err := processSingleDatabase(dbCfg, cfg, agentMode)
		if err != nil {
			log.Printf("✗ Failed to process database '%s': %v", dbCfg.Name, err)
			allResults[dbCfg.Name] = map[string]interface{}{
				"error":  err.Error(),
				"status": "failed",
			}
			outcome.dbFailed++
			continue
		}

		allResults[dbCfg.Name] = result
		log.Printf("✓ Successfully processed database '%s'", dbCfg.Name)

		// Emit findings to SIEM if in siem_only mode
		if siemOutput != nil {
			if controlResults, ok := result["control_results"].([]*controlset.ControlResult); ok {
				systemID := dbCfg.Name // Use database name as system ID
				systemName := dbCfg.Name
				if info, ok := result["instance_info"].(*database.InstanceInfo); ok && info != nil {
					if info.HostName != "" {
						systemName = info.HostName
					}
				}

				emitted, rejected, err := siemOutput.EmitFindings(controlResults, systemID, systemName, dbCfg.Type)
				outcome.siemRejected += rejected
				if err != nil {
					log.Printf("⚠ Failed to emit SIEM events for %s: %v", dbCfg.Name, err)
					outcome.siemDeliveryErr = true
				} else if emitted > 0 {
					log.Printf("→ Queued %d SIEM events for %s", emitted, dbCfg.Name)
					totalSIEMEvents += emitted
				}
			}
		}
	}

	// Flush SIEM events if in siem_only mode
	if siemOutput != nil {
		log.Println("\n=== SIEM DELIVERY ===")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		delivered, err := siemOutput.Flush(ctx)
		cancel()

		outcome.siemAttempted = true
		if err != nil {
			log.Printf("⚠ SIEM delivery error: %v", err)
			outcome.siemDeliveryErr = true
		}
		if delivered > 0 {
			log.Printf("✓ Delivered %d SIEM events", delivered)
		}

		pending := siemOutput.PendingCount()
		if pending > 0 {
			log.Printf("⚠ %d SIEM events still pending (will retry on next run)", pending)
		}
		outcome.siemPending = pending

		if siemOutput.PeriodicFlushErrorOccurred() {
			log.Println("⚠ a background periodic SIEM flush hit a delivery error during this run")
			outcome.siemDeliveryErr = true
		}

		log.Printf("✓ SIEM output complete (emitted: %d, delivered: %d, pending: %d)",
			totalSIEMEvents, delivered, pending)
	}

	// Output all results (skip for siem_only mode)
	if !strings.EqualFold(strings.TrimSpace(cfg.Output.Mode), "siem_only") {
		if err := outputAllResults(cfg, allResults, agentMode); err != nil {
			log.Fatalf("Failed to output results: %v", err)
		}
	}

	log.Println("\n" + outcome.summary())
	exitCode = outcome.code()
	return exitCode
}

func configureLogging(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.Logging.Output), "file") {
		return nil
	}

	logPath := cfg.Logging.GetPath()
	logDir := filepath.Dir(logPath)
	if strings.TrimSpace(logDir) != "" && logDir != "." {
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			return fmt.Errorf("failed to create log directory %s: %w", logDir, err)
		}
	}

	currentFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, currentFile))
	return nil
}

func processSingleDatabase(dbCfg config.DatabaseConfig, cfg *config.Config, agentMode *agent.Mode) (map[string]interface{}, error) {
	// Create database connection
	dbConfig := database.ConnectionConfig{
		Type:                  dbCfg.Type,
		Host:                  dbCfg.Host,
		Port:                  dbCfg.Port,
		Database:              dbCfg.Database,
		ServiceName:           dbCfg.ServiceName,
		SID:                   dbCfg.SID,
		Username:              dbCfg.Username,
		Password:              dbCfg.Password,
		SSLMode:               dbCfg.SSLMode,
		AsSysDBA:              dbCfg.AsSysDBA,
		AllowReadOnlyFallback: dbCfg.AllowReadOnlyFallback,
	}

	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}
	defer db.Close()

	// Connect
	log.Printf("Connecting to %s database at %s:%d...", dbCfg.Type, dbCfg.Host, dbCfg.Port)
	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	log.Println("✓ Connected successfully")

	// Get instance info
	info, err := db.GetInstanceInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance info: %w", err)
	}

	log.Printf("Instance: %s, Version: %s, Host: %s", info.InstanceName, info.Version, info.HostName)

	// Collect database objects
	log.Println("Collecting database objects...")
	collectCtx, collectCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer collectCancel()

	results, err := collectDatabaseObjects(collectCtx, db, dbCfg.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to collect objects: %w", err)
	}

	log.Printf("✓ Collected %d objects", len(results))

	// Execute all control sets (Security, Policy, Licensing)
	log.Println("Executing control sets...")
	allControlResults := []*controlset.ControlResult{}

	for _, controlSetType := range []string{"security", "policy", "licensing"} {
		log.Printf("→ Executing %s controls...", controlSetType)
		// Each control set gets its own 10-minute timeout
		controlSetCtx, controlSetCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		controlResults, err := executeControlSet(controlSetCtx, db, dbCfg, cfg, agentMode, controlSetType, info.Version)
		controlSetCancel() // Clean up immediately after execution
		if err != nil {
			if errors.Is(err, controlset.ErrControlSetNotFound) {
				log.Printf("→ No %s control pack configured; skipping", controlSetType)
				continue
			}
			log.Printf("⚠ %s control execution failed: %v", controlSetType, err)
		} else {
			log.Printf("✓ Executed %d %s controls", len(controlResults), controlSetType)
			allControlResults = append(allControlResults, controlResults...)
		}
	}

	controlResults := allControlResults
	log.Printf("✓ Total controls executed: %d", len(controlResults))

	result := map[string]interface{}{
		"instance_info": info,
		"connection_info": map[string]interface{}{
			"host":          dbCfg.Host,
			"port":          dbCfg.Port,
			"service_name":  dbCfg.ServiceName,
			"sid":           dbCfg.SID,
			"database_name": dbCfg.Database,
			"ssl_mode":      dbCfg.SSLMode,
			"project_ref":   dbCfg.ProjectRef,
			"type":          dbCfg.Type,
			"user_name":     dbCfg.Username,
		},
		"objects":         results,
		"control_results": controlResults,
		"collected_at":    time.Now(),
		"status":          "success",
	}

	if strings.EqualFold(dbCfg.Type, "postgres") && strings.TrimSpace(dbCfg.AuditLogPath) != "" {
		ingestionState, rawEvents, err := collectPostgresCSVLogs(dbCfg, cfg, agentMode)
		if err != nil {
			log.Printf("⚠ PostgreSQL csvlog collection failed for %s: %v", dbCfg.Name, err)
		} else {
			if ingestionState != nil {
				result["audit_log_ingestion_state"] = ingestionState
			}
			if len(rawEvents) > 0 {
				result["audit_log_raw_events"] = rawEvents
			}
		}
	}

	if cfg.LogMining.Enabled {
		ingestionState, rawEvents, err := collectConfiguredLogSources(dbCfg, cfg, agentMode, db, info)
		if err != nil {
			log.Printf("⚠ Log mining collection failed for %s: %v", dbCfg.Name, err)
		} else {
			if ingestionState != nil {
				result["audit_log_ingestion_state"] = ingestionState
			}
			if len(rawEvents) > 0 {
				result["audit_log_raw_events"] = rawEvents
			}
		}
	}

	return result, nil
}

func collectConfiguredLogSources(
	dbCfg config.DatabaseConfig,
	cfg *config.Config,
	agentMode *agent.Mode,
	db database.Database,
	info *database.InstanceInfo,
) (map[string]interface{}, []map[string]interface{}, error) {
	store := logmining.NewCursorStore(cfg.LogMining.GetStatePath())
	states, err := store.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load log mining state: %w", err)
	}

	logSources := dbCfg.LogSources
	if len(logSources) == 0 && strings.EqualFold(strings.TrimSpace(dbCfg.Type), "oracle") {
		logSources = []config.LogSourceConfig{
			{
				Name:    "alert-log",
				Type:    "oracle_alert_log",
				Enabled: true,
			},
		}
	}

	if len(logSources) == 0 {
		return nil, nil, nil
	}

	var ingestionState map[string]interface{}
	rawEvents := make([]map[string]interface{}, 0)

	for _, sourceCfg := range logSources {
		if !sourceCfg.Enabled {
			continue
		}

		sourcePath := strings.TrimSpace(sourceCfg.Path)
		if sourcePath == "" {
			sourcePath, err = resolveLogSourcePath(dbCfg, sourceCfg, db, info)
			if err != nil {
				return ingestionState, rawEvents, err
			}
		}

		source := logmining.Source{
			DatabaseName:  dbCfg.Name,
			DatabaseType:  strings.ToLower(strings.TrimSpace(dbCfg.Type)),
			Name:          sourceCfg.Name,
			Type:          sourceCfg.Type,
			Path:          sourcePath,
			Enabled:       sourceCfg.Enabled,
			MultilineMode: sourceCfg.MultilineMode,
			Timezone:      sourceCfg.Timezone,
		}

		stateKey := sourceKey(source)
		currentCursorState := states[stateKey]
		var currentLease *ingestionLeaseResponse
		if shouldUseBackendIngestionLease(cfg, agentMode) {
			currentLease, err = acquireIngestionLease(
				cfg,
				source.Type,
				source.Path,
				source.DatabaseType,
				source.DatabaseName,
				"history",
				"",
			)
			if err != nil {
				return ingestionState, rawEvents, err
			}
			if currentLease == nil {
				log.Printf("Skipping log source %s for %s because another agent holds the ingestion lease", source.Name, dbCfg.Name)
				continue
			}
			currentCursorState = logmining.CursorState{
				SourceKey:    stateKey,
				DatabaseName: source.DatabaseName,
				SourceName:   source.Name,
				Path:         source.Path,
				FileID:       currentLease.SourceFingerprint,
				Offset:       currentLease.LastOffset,
			}
			if strings.TrimSpace(currentLease.LastEventTimestamp) != "" {
				if parsedTime, parseErr := time.Parse(time.RFC3339, currentLease.LastEventTimestamp); parseErr == nil {
					currentCursorState.LastEventTime = parsedTime
				} else if parsedTime, parseErr := time.Parse("2006-01-02T15:04:05", currentLease.LastEventTimestamp); parseErr == nil {
					currentCursorState.LastEventTime = parsedTime
				}
			}
		}

		currentState, currentEvents, err := collectLogSource(source, cfg, currentCursorState)
		if err != nil {
			return ingestionState, rawEvents, err
		}
		if currentState == nil {
			continue
		}

		states[stateKey] = *currentState
		ingestionState = mapLogIngestionState(*currentState, source)
		if currentLease != nil {
			ingestionState["LeaseToken"] = currentLease.LeaseToken
			ingestionState["SourceKey"] = currentLease.SourceKey
			ingestionState["SourceMode"] = currentLease.SourceMode
		}
		rawEvents = append(rawEvents, mapRawLogEvents(currentEvents)...)
	}

	if err := store.Save(states); err != nil {
		return ingestionState, rawEvents, fmt.Errorf("failed to save log mining state: %w", err)
	}

	return ingestionState, rawEvents, nil
}

func resolveLogSourcePath(
	dbCfg config.DatabaseConfig,
	sourceCfg config.LogSourceConfig,
	db database.Database,
	info *database.InstanceInfo,
) (string, error) {
	if strings.TrimSpace(sourceCfg.Path) != "" {
		return strings.TrimSpace(sourceCfg.Path), nil
	}

	if !strings.EqualFold(strings.TrimSpace(dbCfg.Type), "oracle") ||
		!strings.EqualFold(strings.TrimSpace(sourceCfg.Type), "oracle_alert_log") {
		return "", fmt.Errorf("log source %s requires an explicit path", sourceCfg.Name)
	}

	if db == nil {
		return "", fmt.Errorf("Oracle alert log autodiscovery requires an active database connection")
	}

	currentInstanceName := ""
	if info != nil {
		currentInstanceName = info.InstanceName
	}
	if strings.TrimSpace(currentInstanceName) == "" {
		currentInstanceName = dbCfg.SID
	}

	resolver := oraclelogs.Resolver{}
	path, err := resolver.ResolveAlertLogPath(context.Background(), db, currentInstanceName)
	if err != nil {
		return "", err
	}
	return path, nil
}

func collectLogSource(
	source logmining.Source,
	cfg *config.Config,
	state logmining.CursorState,
) (*logmining.CursorState, []logmining.Event, error) {
	currentFile, err := os.Open(source.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open log source %s: %w", source.Path, err)
	}
	defer currentFile.Close()

	fileInfo, err := currentFile.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat open log source %s: %w", source.Path, err)
	}
	currentFingerprint := buildSourceFingerprint(fileInfo)

	if state.SourceKey == "" {
		state = logmining.CursorState{
			SourceKey:    sourceKey(source),
			DatabaseName: source.DatabaseName,
			SourceName:   source.Name,
			Path:         source.Path,
		}
	}

	if state.FileID != "" && state.FileID != currentFingerprint {
		state.Offset = 0
		state.LastEventTime = time.Time{}
	}

	if state.Offset > fileInfo.Size() {
		state.Offset = 0
	}

	if _, err := currentFile.Seek(state.Offset, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("failed to seek log source %s: %w", source.Path, err)
	}

	var events []logmining.Event
	switch source.Type {
	case "oracle_alert_log":
		parser := oraclelogs.Parser{MaxExcerptBytes: cfg.LogMining.GetMaxExcerptBytes()}
		events, err = parser.Parse(currentFile, source)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Oracle alert log %s: %w", source.Path, err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported log source type: %s", source.Type)
	}

	updatedState := &logmining.CursorState{
		SourceKey:    sourceKey(source),
		DatabaseName: source.DatabaseName,
		SourceName:   source.Name,
		Path:         source.Path,
		FileID:       currentFingerprint,
		Offset:       fileInfo.Size(),
		LastReadTime: time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if len(events) > 0 {
		lastEvent := events[len(events)-1]
		updatedState.LastEventTime = lastEvent.EventTime
	}

	return updatedState, events, nil
}

func sourceKey(source logmining.Source) string {
	return source.DatabaseName + "/" + source.Name
}

func buildSourceFingerprint(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	return fileFingerprint(info)
}

func shouldUseBackendIngestionLease(cfg *config.Config, agentMode *agent.Mode) bool {
	return agentMode != nil &&
		agentMode.IsOnline() &&
		strings.EqualFold(strings.TrimSpace(cfg.Output.Mode), "http") &&
		strings.TrimSpace(cfg.ControlSets.BackendURL) != "" &&
		strings.TrimSpace(cfg.Agent.Token) != ""
}

func acquireIngestionLease(
	cfg *config.Config,
	sourceType string,
	sourcePath string,
	databaseType string,
	databaseName string,
	sourceMode string,
	sourceKey string,
) (*ingestionLeaseResponse, error) {
	backendURL := strings.TrimRight(strings.TrimSpace(cfg.ControlSets.BackendURL), "/")
	if backendURL == "" {
		return nil, fmt.Errorf("control_sets.backend_url is required for ingestion lease")
	}
	if err := security.ValidateHTTPS(backendURL, cfg.Security.AllowHTTP); err != nil {
		return nil, err
	}

	requestBody := ingestionLeaseRequest{
		DatabaseType: databaseType,
		DatabaseName: databaseName,
		SourceType:   sourceType,
		SourcePath:   sourcePath,
		SourceMode:   sourceMode,
		SourceKey:    sourceKey,
	}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ingestion lease request: %w", err)
	}

	req, err := http.NewRequest("POST", backendURL+"/api/agent/ingestion-state/lease", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create ingestion lease request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", cfg.Agent.Token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("failed to acquire ingestion lease: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read ingestion lease response: %w", err)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ingestion lease request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var lease ingestionLeaseResponse
	if err := json.Unmarshal(body, &lease); err != nil {
		return nil, fmt.Errorf("failed to decode ingestion lease response: %w", err)
	}
	return &lease, nil
}

func mapLogIngestionState(state logmining.CursorState, source logmining.Source) map[string]interface{} {
	lastEventTime := ""
	if !state.LastEventTime.IsZero() {
		lastEventTime = state.LastEventTime.Format(time.RFC3339)
	}

	return map[string]interface{}{
		"DatabaseType":       source.DatabaseType,
		"DatabaseName":       source.DatabaseName,
		"SourceType":         source.Type,
		"SourcePath":         source.Path,
		"SourceFingerprint":  state.FileID,
		"LastOffset":         state.Offset,
		"LastLineNumber":     nil,
		"LastEventTimestamp": lastEventTime,
		"Status":             "Active",
	}
}

func mapRawLogEvents(events []logmining.Event) []map[string]interface{} {
	rawEvents := make([]map[string]interface{}, 0, len(events))
	for _, currentEvent := range events {
		eventTimestamp := ""
		if !currentEvent.EventTime.IsZero() {
			eventTimestamp = currentEvent.EventTime.Format(time.RFC3339)
		}

		rawEvents = append(rawEvents, map[string]interface{}{
			"EventHash":       currentEvent.Fingerprint,
			"EventTimestamp":  eventTimestamp,
			"DatabaseType":    currentEvent.DatabaseType,
			"DatabaseName":    currentEvent.DatabaseName,
			"SourceType":      currentEvent.SourceType,
			"SourcePath":      currentEvent.SourcePath,
			"Severity":        currentEvent.Severity,
			"Operation":       currentEvent.Category,
			"Statement":       currentEvent.Message,
			"RawRecord":       currentEvent.RawExcerpt,
			"IngestionStatus": "New",
			"ParsedRecord": map[string]interface{}{
				"code":                  currentEvent.Code,
				"category":              currentEvent.Category,
				"message":               currentEvent.Message,
				"line_count":            currentEvent.LineCount,
				"byte_count":            currentEvent.ByteCount,
				"raw_excerpt_truncated": currentEvent.RawExcerptTruncated,
			},
		})
	}
	return rawEvents
}

func collectDatabaseObjects(ctx context.Context, db database.Database, dbType string) ([]database.Row, error) {
	var query string

	switch strings.ToLower(dbType) {
	case "oracle":
		query = `
			SELECT
				owner,
				object_name,
				object_type,
				status,
				created,
				last_ddl_time
			FROM dba_objects
			WHERE owner NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'DBSNMP', 'APPQOSSYS',
								'GSMADMIN_INTERNAL', 'ORACLE_OCM', 'XDB', 'WMSYS',
								'CTXSYS', 'MDSYS', 'OLAPSYS', 'ORDDATA', 'ORDSYS')
			ORDER BY owner, object_type, object_name`

	case "postgres", "postgresql", "supabase":
		query = `
			SELECT
				schemaname as owner,
				tablename as object_name,
				'TABLE' as object_type
			FROM pg_tables
			WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
			ORDER BY schemaname, tablename`

	case "mssql", "sqlserver":
		query = `
			SELECT
				s.name AS owner,
				o.name AS object_name,
				o.type_desc AS object_type
			FROM sys.objects o
			INNER JOIN sys.schemas s ON s.schema_id = o.schema_id
			WHERE o.is_ms_shipped = 0
			  AND o.type IN ('U', 'V', 'P', 'FN', 'IF', 'TF', 'TR')
			ORDER BY s.name, o.type_desc, o.name`

	case "sqlite":
		query = `
			SELECT
				'' AS owner,
				name AS object_name,
				type AS object_type
			FROM sqlite_master
			WHERE type IN ('table', 'index', 'view', 'trigger')
			  AND name NOT LIKE 'sqlite_%'
			ORDER BY type, name`

	default:
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}

	return db.ExecuteQuery(ctx, query)
}

func outputAllResults(cfg *config.Config, allResults map[string]interface{}, agentMode *agent.Mode) error {
	outputCfg := output.Config{
		AgentName:   cfg.Agent.Name,
		AgentToken:  cfg.Agent.Token,
		AllowHTTP:   cfg.Security.AllowHTTP,
		OutputMode:  cfg.Output.Mode,
		FilePath:    cfg.Output.File.Path,
		HTTPURL:     cfg.Output.HTTP.URL,
		HTTPTimeout: cfg.Output.HTTP.Timeout,
	}

	offline := agentMode != nil && agentMode.IsOffline()
	return output.WriteResults(outputCfg, allResults, offline)
}

func executeControlSet(ctx context.Context, db database.Database, dbCfg config.DatabaseConfig, cfg *config.Config, agentMode *agent.Mode, controlSetType string, databaseVersion string) ([]*controlset.ControlResult, error) {
	// Create control set fetcher
	fetcher := controlset.NewFetcher(
		cfg.ControlSets.Source,
		cfg.ControlSets.LocalPath,
		cfg.ControlSets.BackendURL,
		cfg.ControlSets.CachePath,
		cfg.Agent.Token,
		cfg.Security.AllowHTTP,
		cfg.Security.SignaturesRequired(),
		cfg.Security.PublicKey,
	)

	// Set entitlement for paid/enterprise pack access
	if agentEntitlement != nil {
		fetcher.SetEntitlement(agentEntitlement)
	}

	// Fetch control set with specific type
	// Note: version parameter should be control-set version (e.g., "v1.0.0"), not database version
	// Passing empty string requests the latest active control set from backend
	log.Printf("Fetching %s control set from %s source...", controlSetType, cfg.ControlSets.Source)
	dbType := strings.ToLower(strings.TrimSpace(dbCfg.Type))
	if dbType == "postgresql" {
		dbType = "postgres"
	}
	dbTypeWithSuffix := dbType
	if controlSetType != "security" {
		dbTypeWithSuffix = dbType + "-" + controlSetType
	}
	set, err := fetcher.FetchControlSet(dbTypeWithSuffix, "") // Empty version = latest
	if err != nil {
		return nil, fmt.Errorf("failed to fetch control set: %w", err)
	}

	log.Printf("Loaded control set: %s (%d controls)", set.Metadata.ControlSetID, len(set.Controls))

	// Skip execution if the pack declares agent/database compatibility
	// requirements this run doesn't meet, instead of executing a pack that
	// may fail unpredictably or produce misleading results.
	if err := controlset.CheckCompatibility(set, Version, databaseVersion); err != nil {
		return nil, fmt.Errorf("control pack incompatible, skipping: %w", err)
	}

	// Execute all controls
	executor := controlset.NewExecutor(db)
	executor.ConfigureIngestionState(
		cfg.ControlSets.BackendURL,
		cfg.Agent.Token,
		dbCfg.Type,
		dbCfg.Name,
		cfg.Security.AllowHTTP,
		shouldUseBackendIngestionLease(cfg, agentMode),
	)
	executor.ConfigureManagementAPI(
		dbCfg.ProjectRef,
		dbCfg.ManagementAPIToken,
		dbCfg.ManagementAPIURL,
		cfg.Security.AllowHTTP,
	)
	executor.ConfigureSourceScan(dbCfg.EdgeSourcePath)
	executor.ConfigureControlVariables(dbCfg.ControlVariables)
	executor.ConfigureActiveValidation(cfg.ActiveValidation, cfg.Security.AllowHTTP)
	results := executor.ExecuteControlSet(ctx, set)

	// Log summary
	passCount := 0
	failCount := 0
	reviewCount := 0
	licenseCount := 0
	infoCount := 0
	errorCount := 0

	for _, result := range results {
		for _, procedureResult := range result.Procedures {
			switch procedureResult.Status {
			case "PASS":
				passCount++
			case "FAIL":
				failCount++
				log.Printf("  [FAIL] %s/%s: %d findings", result.ControlID, procedureResult.ProcedureID, len(procedureResult.Findings))
			case "REVIEW":
				reviewCount++
				log.Printf("  [REVIEW] %s/%s: %d findings", result.ControlID, procedureResult.ProcedureID, len(procedureResult.Findings))
			case "LICENSE":
				licenseCount++
				log.Printf("  [LICENSE] %s/%s: %d findings", result.ControlID, procedureResult.ProcedureID, len(procedureResult.Findings))
			case "INFO":
				infoCount++
				log.Printf("  [INFO] %s/%s: %d findings", result.ControlID, procedureResult.ProcedureID, len(procedureResult.Findings))
			case "ERROR":
				errorCount++
				log.Printf("  [ERROR] %s/%s: %v", result.ControlID, procedureResult.ProcedureID, procedureResult.Error)
			}
		}
		if result.Status == "ERROR" && result.Error != nil {
			log.Printf("  [ERROR] %s: %v", result.ControlID, result.Error)
		}
	}

	log.Printf("Control execution summary: %d pass, %d fail, %d review, %d license, %d info, %d error",
		passCount, failCount, reviewCount, licenseCount, infoCount, errorCount)

	return results, nil
}

// performDiscovery performs system discovery for systems assigned to this agent
func performDiscovery(cfg *config.Config) error {
	// Create discovery service
	discoveryService, err := discovery.NewDiscoveryService(
		cfg.ControlSets.BackendURL,
		cfg.Agent.Token,
		cfg.Security.AllowHTTP,
	)
	if err != nil {
		return fmt.Errorf("failed to create discovery service: %w", err)
	}

	// Fetch systems to discover from backend
	log.Println("Fetching systems to discover...")
	systemsToDiscover, err := discoveryService.FetchSystemsToDiscover()
	if err != nil {
		return fmt.Errorf("failed to fetch systems to discover: %w", err)
	}

	if len(systemsToDiscover) == 0 {
		log.Println("✓ No systems need discovery")
		return nil
	}

	log.Printf("Found %d system(s) to discover", len(systemsToDiscover))

	// Create control set fetcher
	fetcher := controlset.NewFetcher(
		cfg.ControlSets.Source,
		cfg.ControlSets.LocalPath,
		cfg.ControlSets.BackendURL,
		cfg.ControlSets.CachePath,
		cfg.Agent.Token,
		cfg.Security.AllowHTTP,
		cfg.Security.SignaturesRequired(),
		cfg.Security.PublicKey,
	)

	// Set entitlement for paid/enterprise pack access
	if agentEntitlement != nil {
		fetcher.SetEntitlement(agentEntitlement)
	}

	// Discover each system
	successCount := 0
	failCount := 0

	for _, system := range systemsToDiscover {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		err := discoveryService.DiscoverSystem(ctx, system, fetcher)
		cancel()

		if err != nil {
			log.Printf("✗ Failed to discover system %s: %v", system.Name, err)
			failCount++
		} else {
			successCount++
		}
	}

	log.Printf("\n✓ Discovery phase complete: %d succeeded, %d failed", successCount, failCount)
	return nil
}

// loadAgentEntitlement loads the entitlement from local file, cache, or server.
// Sets agentEntitlement global variable.
// Returns nil if no entitlement is available (free-only mode is valid).
func loadAgentEntitlement(cfg *config.Config, agentMode *agent.Mode) error {
	// Determine server URL for online mode
	serverURL := ""
	if agentMode != nil && agentMode.IsOnline() {
		serverURL = cfg.ControlSets.BackendURL
	}

	// Get agent ID for binding validation
	// Use backend-assigned AgentID (from registration) for entitlement binding
	agentID := cfg.Agent.AgentID
	if agentID == "" {
		// Fallback to agent name if AgentID not set (shouldn't happen after registration)
		agentID = cfg.Agent.Name
	}

	// AllowHTTP only relaxes transport; entitlement signatures are always required.
	loader := entitlement.NewLoader(
		cfg.Entitlement.LocalPath,
		cfg.Entitlement.GetCachePath(),
		serverURL,
		cfg.Agent.Token,
		agentID,
		cfg.Security.PublicKey,
		cfg.Security.AllowHTTP,
		false,
	)

	// Load entitlement
	ent, err := loader.Load()
	if err != nil {
		return err
	}

	if ent == nil {
		log.Println("No entitlement available - running in free-only mode")
		agentEntitlement = nil
		return nil
	}

	// Check if expired (warn but still set it - checkEntitlement will handle it)
	if ent.IsExpired() {
		log.Printf("⚠ Entitlement expired on %s - paid packs will be blocked", ent.NotAfter.Format(time.RFC3339))
	} else {
		log.Printf("✓ Entitlement loaded (tier=%s, expires=%s, packs=%d)",
			ent.Tier, ent.NotAfter.Format("2006-01-02"), len(ent.Packs))
	}

	agentEntitlement = ent
	return nil
}

type ingestionLeaseRequest struct {
	DatabaseType string `json:"database_type"`
	DatabaseName string `json:"database_name"`
	SourceType   string `json:"source_type"`
	SourcePath   string `json:"source_path"`
	SourceMode   string `json:"source_mode"`
	SourceKey    string `json:"source_key"`
}

type ingestionLeaseResponse struct {
	SourceKey          string `json:"source_key"`
	SourceMode         string `json:"source_mode"`
	LeaseToken         string `json:"lease_token"`
	LeaseExpiresAt     string `json:"lease_expires_at"`
	StateVersion       int64  `json:"state_version"`
	WatermarkJSON      string `json:"watermark_json"`
	LastOffset         int64  `json:"last_offset"`
	LastLineNumber     int64  `json:"last_line_number"`
	LastEventTimestamp string `json:"last_event_timestamp"`
	SourceFingerprint  string `json:"source_fingerprint"`
}

func syncOnlineDatabases(cfg *config.Config) error {
	response, err := fetchBackendAgentConfig(cfg)
	if err != nil {
		return err
	}

	syncedDatabases := make([]config.DatabaseConfig, 0, len(response.Databases))
	for _, db := range response.Databases {
		syncedDatabases = append(syncedDatabases, config.DatabaseConfig{
			Name:                  db.Name,
			Type:                  db.Type,
			Host:                  db.Host,
			Port:                  db.Port,
			Database:              db.Database,
			ServiceName:           db.ServiceName,
			SID:                   db.SID,
			Username:              db.Username,
			Password:              db.Password,
			SSLMode:               db.SSLMode,
			ProjectRef:            db.ProjectRef,
			ManagementAPIToken:    db.ManagementAPIToken,
			ManagementAPIURL:      db.ManagementAPIURL,
			EdgeSourcePath:        db.EdgeSourcePath,
			AsSysDBA:              db.AsSysDBA,
			AllowReadOnlyFallback: db.AllowReadOnlyFallback,
			AuditLogPath:          db.AuditLogPath,
			AuditLogMaxRows:       db.AuditLogMaxRows,
		})
	}

	cfg.Databases = syncedDatabases
	log.Printf("✓ Synced %d database(s) from backend for online mode", len(cfg.Databases))
	return nil
}

func fetchBackendAgentConfig(cfg *config.Config) (*backendAgentConfigResponse, error) {
	backendURL := strings.TrimRight(strings.TrimSpace(cfg.ControlSets.BackendURL), "/")
	if backendURL == "" {
		return nil, fmt.Errorf("control_sets.backend_url is required for online config sync")
	}

	if err := security.ValidateHTTPS(backendURL, cfg.Security.AllowHTTP); err != nil {
		return nil, err
	}

	requestURL := fmt.Sprintf("%s/api/agent/config?mode=online&hostname=%s",
		backendURL,
		neturl.QueryEscape(cfg.Agent.Hostname))

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create online config request: %w", err)
	}
	req.Header.Set("X-Agent-Token", cfg.Agent.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("failed to fetch online config: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read online config response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var response backendAgentConfigResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse online config response: %w", err)
	}

	return &response, nil
}

// detectMode detects whether agent should run in online or offline mode
func detectMode(cfg *config.Config) (*agent.Mode, error) {
	// Try to load cached mode
	cachedMode, err := agent.Load()
	if err == nil && !cachedMode.ShouldRetry() {
		log.Printf("Using cached offline mode (reason: %s, next retry: %v)", cachedMode.FallbackReason, cachedMode.NextRetry)
		return cachedMode, nil
	}

	// Perform connectivity check
	log.Println("Detecting agent mode (checking backend config endpoint)...")

	backendURL := strings.TrimRight(strings.TrimSpace(cfg.ControlSets.BackendURL), "/")
	if err := security.ValidateHTTPS(backendURL, cfg.Security.AllowHTTP); err != nil {
		log.Printf("⚠ Backend config endpoint refused: %v", err)
		return agent.NewOfflineMode("https_required"), nil
	}

	// Try backend config check
	if strings.TrimSpace(cfg.Agent.Token) == "" {
		checkPath := cfg.ControlSets.LocalPath
		if checkPath == "" {
			checkPath = "control-sets"
		}
		if _, err := os.Stat(checkPath); err == nil {
			log.Printf("⚠ No agent token available, using local control sets at %s → OFFLINE mode", checkPath)
			mode := agent.NewOfflineMode("missing_agent_token")
			mode.Save()
			return mode, nil
		}
		return nil, fmt.Errorf("agent token is required for backend connectivity check")
	}

	if _, err := fetchBackendAgentConfig(cfg); err == nil {
		log.Println("✓ Backend reachable → ONLINE mode")
		mode := agent.NewOnlineMode()
		mode.Save()
		return mode, nil
	} else {
		log.Printf("⚠ Backend config check failed: %v", err)
	}

	// Check if local control sets exist (use configured local_path)
	checkPath := cfg.ControlSets.LocalPath
	if checkPath == "" {
		checkPath = "control-sets" // Default fallback
	}

	if _, err := os.Stat(checkPath); err == nil {
		log.Printf("⚠ Found local control sets at %s → OFFLINE mode", checkPath)
		mode := agent.NewOfflineMode("backend_timeout")
		mode.Save()
		return mode, nil
	}

	return nil, fmt.Errorf("backend unreachable AND no local control sets found at %s - cannot proceed", checkPath)
}

func uploadPendingResults(cfg *config.Config) error {
	return output.UploadPending(cfg.Output.HTTP.URL, cfg.Agent.Token, cfg.Security.AllowHTTP)
}

func collectPostgresCSVLogs(dbCfg config.DatabaseConfig, cfg *config.Config, agentMode *agent.Mode) (map[string]interface{}, []map[string]interface{}, error) {
	logPath := strings.TrimSpace(dbCfg.AuditLogPath)
	if logPath == "" {
		return nil, nil, nil
	}

	// Acquire lease from backend if online
	var lease *pgcsvlog.LeaseInfo
	if shouldUseBackendIngestionLease(cfg, agentMode) {
		backendLease, err := acquireIngestionLease(cfg, "csvlog", logPath, "postgres", dbCfg.Name, "history", "")
		if err != nil {
			return nil, nil, err
		}
		if backendLease == nil {
			log.Printf("Skipping PostgreSQL csvlog ingestion for %s because another agent holds the ingestion lease", dbCfg.Name)
			return nil, nil, nil
		}
		lease = &pgcsvlog.LeaseInfo{
			LeaseToken:         backendLease.LeaseToken,
			SourceKey:          backendLease.SourceKey,
			SourceMode:         backendLease.SourceMode,
			LastOffset:         backendLease.LastOffset,
			LastLineNumber:     backendLease.LastLineNumber,
			LastEventTimestamp: backendLease.LastEventTimestamp,
			SourceFingerprint:  backendLease.SourceFingerprint,
		}
	}

	collectorCfg := pgcsvlog.CollectorConfig{
		DatabaseName: dbCfg.Name,
		DatabaseType: "postgres",
		LogPath:      logPath,
		MaxRows:      dbCfg.AuditLogMaxRows,
		DefaultDB:    dbCfg.Database,
	}

	return pgcsvlog.Collect(collectorCfg, lease)
}

// runSIEMTest sends a synthetic test event to the configured SIEM destination.
func runSIEMTest(cfg *config.Config) {
	log.Println("Running SIEM connectivity test...")

	// Validate SIEM configuration
	if cfg.Output.Mode != "siem_only" {
		log.Println("Note: output.mode is not 'siem_only', but testing SIEM destination anyway")
	}

	siemCfg := cfg.Output.SIEM

	// Normalize destination (case-insensitive, trim whitespace)
	destination := strings.ToLower(strings.TrimSpace(siemCfg.Destination))
	if destination == "" {
		log.Fatal("SIEM destination not configured (set output.siem.destination to 'webhook' or 'syslog')")
	}

	// Load persisted agent ID if not in config (matches production behavior)
	agentID := cfg.Agent.AgentID
	if strings.TrimSpace(agentID) == "" && strings.TrimSpace(cfg.Agent.TokenFile) != "" {
		if loadedID, err := registration.LoadAgentID(cfg.Agent.TokenFile); err == nil && loadedID != "" {
			agentID = loadedID
			log.Printf("Loaded persisted agent ID: %s", agentID)
		}
	}
	if strings.TrimSpace(agentID) == "" {
		agentID = cfg.Agent.Name
	}

	// Build test config from SIEM settings
	testCfg := siem.TestConfig{
		Destination: destination,
		AgentID:     agentID,
		AgentName:   cfg.Agent.Name,
	}

	switch destination {
	case "webhook":
		if siemCfg.Webhook.URL == "" {
			log.Fatal("Webhook URL not configured (set output.siem.webhook.url)")
		}
		if err := security.ValidateHTTPS(siemCfg.Webhook.URL, cfg.Security.AllowHTTP); err != nil {
			log.Fatalf("Webhook URL validation failed: %v", err)
		}
		testCfg.WebhookURL = siemCfg.Webhook.URL
		testCfg.WebhookHeaders = siemCfg.Webhook.Headers
		testCfg.WebhookTimeoutSeconds = siemCfg.Webhook.TimeoutSeconds
		testCfg.WebhookAgentVersion = cfg.Agent.Version
		testCfg.WebhookAllowInsecure = cfg.Security.AllowHTTP

	case "syslog":
		if strings.TrimSpace(siemCfg.Syslog.Host) == "" {
			log.Fatal("Syslog host not configured (set output.siem.syslog.host)")
		}
		testCfg.SyslogHost = siemCfg.Syslog.Host
		testCfg.SyslogPort = siemCfg.Syslog.Port
		testCfg.SyslogProtocol = siemCfg.Syslog.Protocol
		testCfg.SyslogFacility = siemCfg.Syslog.Facility
		testCfg.SyslogAppName = siemCfg.Syslog.AppName

	default:
		log.Fatalf("Unknown SIEM destination: %q (must be 'webhook' or 'syslog')", destination)
	}

	// Run test with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := siem.RunTest(ctx, testCfg)

	// Print result
	fmt.Println()
	fmt.Println(siem.FormatTestResult(result))

	if !result.Success {
		os.Exit(1)
	}

	log.Println("SIEM test completed successfully - verify event received in your SIEM")
}
