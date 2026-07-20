package controlset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"basecheck-agent/pkg/config"
	"basecheck-agent/pkg/database"
	"basecheck-agent/pkg/security"

	"gopkg.in/yaml.v3"
)

// Executor executes controls against a database
type Executor struct {
	db                 database.Database
	backendURL         string
	apiKey             string
	databaseType       string
	databaseName       string
	projectRef         string
	sourceScanPath     string
	controlVariables   map[string]string
	managementAPIToken string
	managementAPIURL   string
	allowHTTP          bool
	useIngestionState  bool
	activeValidation   config.ActiveValidationConfig
	activeIdentities   map[string]config.ActiveValidationIdentity
	activeTargets      map[string]config.ActiveValidationTarget
	activeSem          chan struct{}
	activeRequests     int
	activeMu           sync.Mutex
	evidenceLeaseByKey map[string]evidenceLease
	evidenceLeaseMu    sync.RWMutex
}

type httpProcedureSpec struct {
	Method  string `yaml:"method"`
	Path    string `yaml:"path"`
	RowPath string `yaml:"row_path"`
}

type activeValidationProcedureSpec struct {
	SeedSQL                    string                 `yaml:"seed_sql"`
	SeedExecutionMode          string                 `yaml:"seed_execution_mode"`
	SeedTests                  string                 `yaml:"seed_tests"`
	MaxTargets                 int                    `yaml:"max_targets"`
	Flow                       string                 `yaml:"flow"`
	Identity                   string                 `yaml:"identity"`
	Target                     string                 `yaml:"target"`
	Method                     string                 `yaml:"method"`
	Path                       string                 `yaml:"path"`
	RowPath                    string                 `yaml:"row_path"`
	ExpectedStatus             []int                  `yaml:"expected_status"`
	Headers                    map[string]string      `yaml:"headers"`
	Body                       map[string]interface{} `yaml:"body"`
	MintIdentity               string                 `yaml:"mint_identity"`
	MintTarget                 string                 `yaml:"mint_target"`
	MintMethod                 string                 `yaml:"mint_method"`
	MintPath                   string                 `yaml:"mint_path"`
	MintHeaders                map[string]string      `yaml:"mint_headers"`
	MintBody                   map[string]interface{} `yaml:"mint_body"`
	MintRowPath                string                 `yaml:"mint_row_path"`
	FetchExpectedStatus        []int                  `yaml:"fetch_expected_status"`
	ReplayPath                 string                 `yaml:"replay_path"`
	ReplayExpectedStatus       []int                  `yaml:"replay_expected_status"`
	ExpiryWaitSeconds          int                    `yaml:"expiry_wait_seconds"`
	ExpiryExpectedStatus       []int                  `yaml:"expiry_expected_status"`
	TriggerIdentity            string                 `yaml:"trigger_identity"`
	TriggerTarget              string                 `yaml:"trigger_target"`
	TriggerMethod              string                 `yaml:"trigger_method"`
	TriggerPath                string                 `yaml:"trigger_path"`
	TriggerHeaders             map[string]string      `yaml:"trigger_headers"`
	TriggerBody                map[string]interface{} `yaml:"trigger_body"`
	TriggerExpectedStatus      []int                  `yaml:"trigger_expected_status"`
	CallbackIdentity           string                 `yaml:"callback_identity"`
	CallbackTarget             string                 `yaml:"callback_target"`
	CallbackRegisterMethod     string                 `yaml:"callback_register_method"`
	CallbackRegisterPath       string                 `yaml:"callback_register_path"`
	CallbackRegisterHeaders    map[string]string      `yaml:"callback_register_headers"`
	CallbackRegisterBody       map[string]interface{} `yaml:"callback_register_body"`
	CallbackURLPath            string                 `yaml:"callback_url_path"`
	CallbackTokenPath          string                 `yaml:"callback_token_path"`
	CallbackPollMethod         string                 `yaml:"callback_poll_method"`
	CallbackPollPath           string                 `yaml:"callback_poll_path"`
	CallbackPollHeaders        map[string]string      `yaml:"callback_poll_headers"`
	CallbackPollRowPath        string                 `yaml:"callback_poll_row_path"`
	CallbackPollAttempts       int                    `yaml:"callback_poll_attempts"`
	CallbackPollWaitMillis     int                    `yaml:"callback_poll_wait_millis"`
	CallbackPollExpectedStatus []int                  `yaml:"callback_poll_expected_status"`
}

type sourceScanProcedureSpec struct {
	RootPath     string               `yaml:"root_path"`
	MetadataFile string               `yaml:"metadata_file"`
	Extensions   []string             `yaml:"extensions"`
	ExcludeDirs  []string             `yaml:"exclude_dirs"`
	Patterns     []sourceScanPattern  `yaml:"patterns"`
	FileRules    []sourceScanFileRule `yaml:"file_rules"`
	MaxMatches   int                  `yaml:"max_matches"`
}

type sourceScanPattern struct {
	Name          string `yaml:"name"`
	Regex         string `yaml:"regex"`
	CurrentValue  string `yaml:"current_value"`
	ExpectedValue string `yaml:"expected_value"`
	Reason        string `yaml:"reason"`
	Fix           string `yaml:"fix"`
}

type sourceScanFileRule struct {
	Name            string   `yaml:"name"`
	SinkRegex       string   `yaml:"sink_regex"`
	RequiredRegexes []string `yaml:"required_regexes"`
	CurrentValue    string   `yaml:"current_value"`
	ExpectedValue   string   `yaml:"expected_value"`
	Reason          string   `yaml:"reason"`
	Fix             string   `yaml:"fix"`
}

type sourceScanMetadataSpec struct {
	Functions map[string]map[string]interface{} `yaml:"functions"`
}

type evidenceLeaseRequest struct {
	DatabaseType string `json:"database_type"`
	DatabaseName string `json:"database_name"`
	SourceType   string `json:"source_type"`
	SourcePath   string `json:"source_path"`
	SourceMode   string `json:"source_mode"`
	SourceKey    string `json:"source_key"`
}

type evidenceLease struct {
	SourceKey          string `json:"source_key"`
	SourceMode         string `json:"source_mode"`
	LeaseToken         string `json:"lease_token"`
	WatermarkJSON      string `json:"watermark_json"`
	LastOffset         int64  `json:"last_offset"`
	LastLineNumber     int64  `json:"last_line_number"`
	LastEventTimestamp string `json:"last_event_timestamp"`
	SourceFingerprint  string `json:"source_fingerprint"`
}

var sqlWatermarkTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)

var sqlWatermarkHashPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

var controlVariableDefaultPattern = regexp.MustCompile(`\{\{([A-Za-z0-9_]+)\|([^}]*)\}\}`)

// NewExecutor creates a new control executor
func NewExecutor(db database.Database) *Executor {
	return &Executor{
		db:                 db,
		controlVariables:   map[string]string{},
		activeIdentities:   map[string]config.ActiveValidationIdentity{},
		activeTargets:      map[string]config.ActiveValidationTarget{},
		evidenceLeaseByKey: map[string]evidenceLease{},
	}
}

func (e *Executor) ConfigureIngestionState(backendURL, apiKey, databaseType, databaseName string, allowHTTP, enabled bool) {
	e.backendURL = strings.TrimRight(strings.TrimSpace(backendURL), "/")
	e.apiKey = strings.TrimSpace(apiKey)
	e.databaseType = strings.ToLower(strings.TrimSpace(databaseType))
	e.databaseName = strings.TrimSpace(databaseName)
	e.allowHTTP = allowHTTP
	e.useIngestionState = enabled && e.backendURL != "" && e.apiKey != "" && e.databaseType != "" && e.databaseName != ""
}

func (e *Executor) ConfigureManagementAPI(projectRef, token, apiURL string, allowHTTP bool) {
	e.projectRef = strings.TrimSpace(projectRef)
	e.managementAPIToken = strings.TrimSpace(token)
	e.managementAPIURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
	e.allowHTTP = allowHTTP
}

func (e *Executor) ConfigureSourceScan(rootPath string) {
	e.sourceScanPath = strings.TrimSpace(rootPath)
}

func (e *Executor) ConfigureControlVariables(current map[string]string) {
	e.controlVariables = map[string]string{}
	for key, value := range current {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		e.controlVariables[trimmedKey] = strings.TrimSpace(value)
	}
}

func (e *Executor) ConfigureActiveValidation(current config.ActiveValidationConfig, allowHTTP bool) {
	e.activeValidation = current
	e.allowHTTP = allowHTTP
	e.activeIdentities = make(map[string]config.ActiveValidationIdentity, len(current.Identities))
	for _, identity := range current.Identities {
		e.activeIdentities[strings.TrimSpace(identity.Name)] = identity
	}
	e.activeTargets = make(map[string]config.ActiveValidationTarget, len(current.Targets))
	for _, target := range current.Targets {
		e.activeTargets[strings.TrimSpace(target.Name)] = target
	}
	e.activeSem = make(chan struct{}, current.GetMaxConcurrent())
}

// ExecuteControl runs a single control and returns the result
func (e *Executor) ExecuteControl(ctx context.Context, control *Control) *ControlResult {
	result := &ControlResult{
		ControlID:       control.ControlID,
		ControlCode:     control.ControlCode,
		Category:        control.Category,
		Title:           control.Title,
		Status:          "PASS",
		Procedures:      []ProcedureResult{},
		EvidenceCapture: []EvidenceCaptureResult{},
		ExecutedAt:      time.Now(),
	}

	if len(control.Procedures) == 0 {
		result.Status = "ERROR"
		result.Error = fmt.Errorf("no procedures defined for control %s", control.ControlID)
		return result
	}

	for _, procedure := range control.Procedures {
		procedureResult := e.executeProcedure(ctx, control, procedure)
		result.Procedures = append(result.Procedures, procedureResult)
		if procedureResult.Status == "ERROR" {
			result.Status = "ERROR"
		} else if procedureResult.Status == "FAIL" && result.Status != "ERROR" {
			result.Status = "FAIL"
		} else if result.Status == "PASS" {
			result.Status = procedureResult.Status
		}
	}

	// Execute evidence capture queries
	for _, evidence := range control.EvidenceCapture {
		evidenceResult := e.executeEvidenceCapture(ctx, evidence)
		result.EvidenceCapture = append(result.EvidenceCapture, evidenceResult)
	}

	return result
}

// ExecuteControlSet runs all controls in a set
func (e *Executor) ExecuteControlSet(ctx context.Context, set *ControlSet) []*ControlResult {
	results := make([]*ControlResult, 0, len(set.Controls))

	for i := range set.Controls {
		result := e.ExecuteControl(ctx, &set.Controls[i])
		result.ControlPackName = set.Metadata.ControlSetID
		result.ControlPackVersion = set.Metadata.ControlSetVersion
		results = append(results, result)
	}

	return results
}

func (e *Executor) executeProcedure(ctx context.Context, control *Control, procedure ControlProcedure) ProcedureResult {
	result := ProcedureResult{
		ProcedureID: procedure.ProcedureID,
		Status:      "PASS",
		Findings:    []Finding{},
		ExecutedAt:  time.Now(),
	}

	executionMode := strings.ToLower(strings.TrimSpace(procedure.ExecutionMode))
	if executionMode == "" {
		executionMode = "sql"
	}

	var (
		rows []database.Row
		err  error
	)

	switch executionMode {
	case "http":
		rows, err = e.executeHTTPProcedure(ctx, procedure)
	case "active_validation":
		rows, err = e.executeActiveValidationProcedure(ctx, procedure)
	case "source_scan":
		rows, err = e.executeSourceScanProcedure(procedure)
	default:
		if strings.TrimSpace(procedure.Tests) == "" {
			result.Status = "ERROR"
			result.Error = fmt.Errorf("procedure %s: missing tests SQL", procedure.ProcedureID)
			return result
		}

		queryCtx, queryCancel := context.WithTimeout(ctx, 30*time.Second)
		defer queryCancel()
		rows, err = e.db.ExecuteQuery(queryCtx, e.interpolateControlVariables(procedure.Tests))
	}

	if err != nil {
		result.Status = "ERROR"
		result.Error = fmt.Errorf("procedure %s: query execution failed: %w", procedure.ProcedureID, err)
		return result
	}
	result.Rows = rows
	e.applyProcedureRows(control, procedure, rows, &result)
	return result
}

func (e *Executor) executeSourceScanProcedure(procedure ControlProcedure) ([]database.Row, error) {
	if strings.TrimSpace(procedure.Tests) == "" {
		return nil, fmt.Errorf("missing source scan procedure spec")
	}

	var spec sourceScanProcedureSpec
	if err := yaml.Unmarshal([]byte(procedure.Tests), &spec); err != nil {
		return nil, fmt.Errorf("invalid source scan procedure spec: %w", err)
	}

	rootPath := strings.TrimSpace(spec.RootPath)
	if rootPath == "" {
		rootPath = e.sourceScanPath
	}
	if rootPath == "" {
		return nil, nil
	}
	if len(spec.Patterns) == 0 && len(spec.FileRules) == 0 {
		return nil, fmt.Errorf("source scan requires at least one pattern or file rule")
	}
	metadataByFunction, err := loadSourceScanMetadata(rootPath, spec.MetadataFile)
	if err != nil {
		return nil, err
	}

	extensions := spec.Extensions
	if len(extensions) == 0 {
		extensions = []string{".ts", ".tsx", ".js", ".jsx"}
	}

	compiledPatterns := make([]*regexp.Regexp, 0, len(spec.Patterns))
	for _, pattern := range spec.Patterns {
		if strings.TrimSpace(pattern.Regex) == "" {
			return nil, fmt.Errorf("source scan pattern regex is required")
		}
		currentPattern, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid source scan regex %q: %w", pattern.Regex, err)
		}
		compiledPatterns = append(compiledPatterns, currentPattern)
	}

	compiledFileRules := make([]*regexp.Regexp, 0, len(spec.FileRules))
	requiredRegexesByRule := make([][]*regexp.Regexp, 0, len(spec.FileRules))
	for _, rule := range spec.FileRules {
		if strings.TrimSpace(rule.Name) == "" {
			return nil, fmt.Errorf("source scan file rule name is required")
		}
		if strings.TrimSpace(rule.SinkRegex) == "" {
			return nil, fmt.Errorf("source scan file rule sink_regex is required")
		}
		currentSink, err := regexp.Compile(rule.SinkRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid source scan sink regex %q: %w", rule.SinkRegex, err)
		}
		compiledFileRules = append(compiledFileRules, currentSink)
		currentRequiredRegexes := make([]*regexp.Regexp, 0, len(rule.RequiredRegexes))
		for _, requiredRegex := range rule.RequiredRegexes {
			compiledRequired, err := regexp.Compile(requiredRegex)
			if err != nil {
				return nil, fmt.Errorf("invalid source scan required regex %q: %w", requiredRegex, err)
			}
			currentRequiredRegexes = append(currentRequiredRegexes, compiledRequired)
		}
		requiredRegexesByRule = append(requiredRegexesByRule, currentRequiredRegexes)
	}

	maxMatches := spec.MaxMatches
	if maxMatches <= 0 {
		maxMatches = 100
	}

	rows := make([]database.Row, 0)
	err = filepath.Walk(rootPath, func(currentPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			for _, excludeDir := range spec.ExcludeDirs {
				if info.Name() == strings.TrimSpace(excludeDir) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !matchesSourceScanExtension(currentPath, extensions) {
			return nil
		}

		fileContent, err := os.ReadFile(currentPath)
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(rootPath, currentPath)
		if err != nil {
			relativePath = currentPath
		}
		relativePath = filepath.ToSlash(relativePath)
		functionName := deriveSourceScanFunctionName(relativePath)
		lines := strings.Split(string(fileContent), "\n")
		for lineIndex, line := range lines {
			for patternIndex, pattern := range spec.Patterns {
				match := compiledPatterns[patternIndex].FindString(line)
				if match == "" {
					continue
				}
				currentValue := strings.TrimSpace(pattern.CurrentValue)
				if currentValue == "" {
					currentValue = strings.TrimSpace(match)
				}
				row := database.Row{
					"function_name":   functionName,
					"file_path":       relativePath,
					"line_number":     lineIndex + 1,
					"matched_pattern": strings.TrimSpace(pattern.Name),
					"current_value":   currentValue,
					"expected_value":  strings.TrimSpace(pattern.ExpectedValue),
					"reason":          strings.TrimSpace(pattern.Reason),
					"fix":             strings.TrimSpace(pattern.Fix),
					"evidence_type":   "source_scan",
					"evidence_path":   relativePath,
					"line_text":       strings.TrimSpace(line),
				}
				mergeSourceScanMetadata(row, functionName, metadataByFunction)
				rows = append(rows, row)
				if len(rows) >= maxMatches {
					return filepath.SkipAll
				}
			}
		}
		for ruleIndex, rule := range spec.FileRules {
			sinkMatch := compiledFileRules[ruleIndex].FindString(string(fileContent))
			if sinkMatch == "" {
				continue
			}
			hasRequired := false
			for _, requiredRegex := range requiredRegexesByRule[ruleIndex] {
				if requiredRegex.FindString(string(fileContent)) != "" {
					hasRequired = true
					break
				}
			}
			if hasRequired {
				continue
			}
			currentValue := strings.TrimSpace(rule.CurrentValue)
			if currentValue == "" {
				currentValue = strings.TrimSpace(sinkMatch)
			}
			row := database.Row{
				"function_name":   functionName,
				"file_path":       relativePath,
				"line_number":     findSourceScanLineNumber(lines, compiledFileRules[ruleIndex]),
				"matched_pattern": strings.TrimSpace(rule.Name),
				"current_value":   currentValue,
				"expected_value":  strings.TrimSpace(rule.ExpectedValue),
				"reason":          strings.TrimSpace(rule.Reason),
				"fix":             strings.TrimSpace(rule.Fix),
				"evidence_type":   "source_scan",
				"evidence_path":   relativePath,
			}
			mergeSourceScanMetadata(row, functionName, metadataByFunction)
			rows = append(rows, row)
			if len(rows) >= maxMatches {
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll {
		return nil, err
	}
	return rows, nil
}

func loadSourceScanMetadata(rootPath string, metadataFile string) (map[string]database.Row, error) {
	currentMetadataFile := strings.TrimSpace(metadataFile)
	if currentMetadataFile == "" {
		return map[string]database.Row{}, nil
	}
	if !filepath.IsAbs(currentMetadataFile) {
		currentMetadataFile = filepath.Join(rootPath, currentMetadataFile)
	}
	fileContent, err := os.ReadFile(currentMetadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]database.Row{}, nil
		}
		return nil, fmt.Errorf("failed to read source scan metadata file: %w", err)
	}
	var spec sourceScanMetadataSpec
	if err := yaml.Unmarshal(fileContent, &spec); err != nil {
		return nil, fmt.Errorf("invalid source scan metadata file: %w", err)
	}
	rows := make(map[string]database.Row, len(spec.Functions))
	for functionName, metadata := range spec.Functions {
		currentFunctionName := strings.TrimSpace(functionName)
		if currentFunctionName == "" {
			continue
		}
		row := database.Row{}
		for key, value := range metadata {
			row[strings.TrimSpace(key)] = value
		}
		rows[currentFunctionName] = row
	}
	return rows, nil
}

func mergeSourceScanMetadata(row database.Row, functionName string, metadataByFunction map[string]database.Row) {
	currentFunctionName := strings.TrimSpace(functionName)
	if currentFunctionName == "" {
		return
	}
	defaultPath := "/" + currentFunctionName
	row["runtime_path"] = defaultPath
	row["runtime_method"] = "GET"
	row["cors_runtime_path"] = defaultPath
	row["cors_runtime_method"] = "OPTIONS"
	row["error_runtime_path"] = defaultPath
	row["error_runtime_method"] = "GET"
	row["auth_runtime_path"] = defaultPath
	row["auth_runtime_method"] = "GET"
	row["service_role_runtime_path"] = defaultPath
	row["service_role_runtime_method"] = "GET"
	row["privileged_runtime_path"] = defaultPath
	row["privileged_runtime_method"] = "GET"

	currentMetadata, exists := metadataByFunction[currentFunctionName]
	if !exists {
		return
	}
	for key, value := range currentMetadata {
		row[key] = value
	}
}

func matchesSourceScanExtension(currentPath string, extensions []string) bool {
	currentExt := strings.ToLower(filepath.Ext(currentPath))
	for _, extension := range extensions {
		if currentExt == strings.ToLower(strings.TrimSpace(extension)) {
			return true
		}
	}
	return false
}

func deriveSourceScanFunctionName(relativePath string) string {
	currentPath := strings.TrimSpace(filepath.ToSlash(relativePath))
	if currentPath == "" {
		return ""
	}
	parts := strings.Split(currentPath, "/")
	if len(parts) > 1 {
		return parts[0]
	}
	baseName := filepath.Base(currentPath)
	return strings.TrimSuffix(baseName, filepath.Ext(baseName))
}

func findSourceScanLineNumber(lines []string, pattern *regexp.Regexp) int {
	for lineIndex, line := range lines {
		if pattern.FindString(line) != "" {
			return lineIndex + 1
		}
	}
	return 0
}

func (e *Executor) executeActiveValidationProcedure(ctx context.Context, procedure ControlProcedure) ([]database.Row, error) {
	if !e.activeValidation.Enabled {
		return nil, fmt.Errorf("active validation is disabled")
	}
	if strings.TrimSpace(procedure.Tests) == "" {
		return nil, fmt.Errorf("missing active validation procedure spec")
	}

	var spec activeValidationProcedureSpec
	if err := yaml.Unmarshal([]byte(procedure.Tests), &spec); err != nil {
		return nil, fmt.Errorf("invalid active validation procedure spec: %w", err)
	}
	if strings.TrimSpace(spec.Target) == "" || strings.TrimSpace(spec.Method) == "" || strings.TrimSpace(spec.Path) == "" {
		currentFlow := strings.TrimSpace(spec.Flow)
		if currentFlow != "signed_url" && currentFlow != "callback_http" {
			return nil, fmt.Errorf("invalid active validation procedure spec: target, method, and path are required")
		}
	}
	if strings.EqualFold(strings.TrimSpace(spec.Flow), "signed_url") {
		return e.executeSignedURLValidationProcedure(ctx, spec)
	}
	if strings.EqualFold(strings.TrimSpace(spec.Flow), "callback_http") {
		return e.executeCallbackValidationProcedure(ctx, spec)
	}

	currentTarget, exists := e.activeTargets[strings.TrimSpace(spec.Target)]
	if !exists {
		return nil, fmt.Errorf("unknown active validation target: %s", spec.Target)
	}
	if err := security.ValidateHTTPS(currentTarget.BaseURL, e.allowHTTP); err != nil {
		return nil, err
	}

	method := strings.TrimSpace(spec.Method)
	if strings.TrimSpace(spec.SeedSQL) == "" && strings.TrimSpace(spec.SeedExecutionMode) == "" {
		if err := e.checkStateChangeMethodPolicy(method); err != nil {
			return nil, err
		}
	}
	var identity config.ActiveValidationIdentity
	if strings.TrimSpace(spec.Identity) != "" {
		currentIdentity, exists := e.activeIdentities[strings.TrimSpace(spec.Identity)]
		if !exists {
			return nil, fmt.Errorf("unknown active validation identity: %s", spec.Identity)
		}
		identity = currentIdentity
	}
	if strings.TrimSpace(spec.SeedSQL) == "" && strings.TrimSpace(spec.SeedExecutionMode) == "" {
		return e.executeActiveValidationRequest(ctx, currentTarget, identity, spec, method, nil)
	}

	seedRows, err := e.loadActiveValidationSeedRows(ctx, spec)
	if err != nil {
		return nil, err
	}
	maxTargets := spec.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 10
	}
	if maxTargets > len(seedRows) {
		maxTargets = len(seedRows)
	}
	rows := make([]database.Row, 0, maxTargets)
	for i := 0; i < maxTargets; i++ {
		interpolatedMethod := e.interpolateLiteral(method, seedRows[i])
		if err := e.checkStateChangeMethodPolicy(interpolatedMethod); err != nil {
			return nil, err
		}
		currentRows, err := e.executeActiveValidationRequest(ctx, currentTarget, identity, spec, method, seedRows[i])
		if err != nil {
			return nil, err
		}
		rows = append(rows, currentRows...)
	}
	return rows, nil
}

func (e *Executor) executeCallbackValidationProcedure(ctx context.Context, spec activeValidationProcedureSpec) ([]database.Row, error) {
	if strings.TrimSpace(spec.CallbackTarget) == "" || strings.TrimSpace(spec.TriggerTarget) == "" {
		return nil, fmt.Errorf("callback_http flow requires callback_target and trigger_target")
	}

	callbackTarget, exists := e.activeTargets[strings.TrimSpace(spec.CallbackTarget)]
	if !exists {
		return nil, fmt.Errorf("unknown active validation callback target: %s", spec.CallbackTarget)
	}
	triggerTarget, exists := e.activeTargets[strings.TrimSpace(spec.TriggerTarget)]
	if !exists {
		return nil, fmt.Errorf("unknown active validation trigger target: %s", spec.TriggerTarget)
	}

	var callbackIdentity config.ActiveValidationIdentity
	if strings.TrimSpace(spec.CallbackIdentity) != "" {
		currentIdentity, exists := e.activeIdentities[strings.TrimSpace(spec.CallbackIdentity)]
		if !exists {
			return nil, fmt.Errorf("unknown active validation callback identity: %s", spec.CallbackIdentity)
		}
		callbackIdentity = currentIdentity
	}

	var triggerIdentity config.ActiveValidationIdentity
	if strings.TrimSpace(spec.TriggerIdentity) != "" {
		currentIdentity, exists := e.activeIdentities[strings.TrimSpace(spec.TriggerIdentity)]
		if !exists {
			return nil, fmt.Errorf("unknown active validation trigger identity: %s", spec.TriggerIdentity)
		}
		triggerIdentity = currentIdentity
	}

	seedRows := []database.Row{{}}
	if strings.TrimSpace(spec.SeedSQL) != "" || strings.TrimSpace(spec.SeedExecutionMode) != "" {
		currentRows, err := e.loadActiveValidationSeedRows(ctx, spec)
		if err != nil {
			return nil, err
		}
		seedRows = currentRows
	}

	maxTargets := spec.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 5
	}
	if maxTargets > len(seedRows) {
		maxTargets = len(seedRows)
	}

	results := make([]database.Row, 0, maxTargets)
	for i := 0; i < maxTargets; i++ {
		currentRow, err := e.executeCallbackValidationForRow(ctx, callbackTarget, callbackIdentity, triggerTarget, triggerIdentity, spec, seedRows[i])
		if err != nil {
			return nil, err
		}
		results = append(results, currentRow)
	}

	return results, nil
}

func (e *Executor) executeCallbackValidationForRow(ctx context.Context, callbackTarget config.ActiveValidationTarget, callbackIdentity config.ActiveValidationIdentity, triggerTarget config.ActiveValidationTarget, triggerIdentity config.ActiveValidationIdentity, spec activeValidationProcedureSpec, seedRow database.Row) (database.Row, error) {
	registerPath, err := authorizeActiveValidationPath(callbackTarget, e.interpolateTemplate(spec.CallbackRegisterPath, seedRow))
	if err != nil {
		return nil, err
	}
	registerURL := strings.TrimRight(strings.TrimSpace(callbackTarget.BaseURL), "/") + registerPath
	registerHeaders := make(map[string]string)
	for key, value := range callbackIdentity.Headers {
		registerHeaders[key] = value
	}
	for key, value := range callbackTarget.Headers {
		registerHeaders[key] = value
	}
	for key, value := range spec.CallbackRegisterHeaders {
		registerHeaders[key] = value
	}

	if err := e.checkStateChangeMethodPolicy(spec.CallbackRegisterMethod); err != nil {
		return nil, err
	}
	registerStatus, _, registerBody, err := e.executeActiveValidationRaw(
		ctx,
		registerURL,
		registerPath,
		strings.ToUpper(strings.TrimSpace(spec.CallbackRegisterMethod)),
		registerHeaders,
		spec.CallbackRegisterBody,
		seedRow,
		[]int{200, 201},
	)
	if err != nil {
		return nil, err
	}

	var registerPayload interface{}
	if err := json.Unmarshal(registerBody, &registerPayload); err != nil {
		return nil, fmt.Errorf("failed to decode callback registration response: %w", err)
	}
	callbackURL := strings.TrimSpace(fmt.Sprintf("%v", extractHTTPRowData(registerPayload, spec.CallbackURLPath)))
	callbackToken := strings.TrimSpace(fmt.Sprintf("%v", extractHTTPRowData(registerPayload, spec.CallbackTokenPath)))
	if callbackURL == "" {
		return nil, fmt.Errorf("callback_http flow did not return callback URL")
	}

	triggerPath, err := authorizeActiveValidationPath(triggerTarget, e.interpolateTemplate(spec.TriggerPath, seedRow))
	if err != nil {
		return nil, err
	}
	triggerURL := strings.TrimRight(strings.TrimSpace(triggerTarget.BaseURL), "/") + triggerPath
	triggerHeaders := make(map[string]string)
	for key, value := range triggerIdentity.Headers {
		triggerHeaders[key] = value
	}
	for key, value := range triggerTarget.Headers {
		triggerHeaders[key] = value
	}
	for key, value := range spec.TriggerHeaders {
		triggerHeaders[key] = value
	}
	triggerSeed := make(database.Row)
	for key, value := range seedRow {
		triggerSeed[key] = value
	}
	triggerSeed["callback_url"] = callbackURL
	triggerSeed["callback_token"] = callbackToken
	if err := e.checkStateChangeMethodPolicy(spec.TriggerMethod); err != nil {
		return nil, err
	}
	triggerStatus, _, _, err := e.executeActiveValidationRaw(
		ctx,
		triggerURL,
		triggerPath,
		strings.ToUpper(strings.TrimSpace(spec.TriggerMethod)),
		triggerHeaders,
		spec.TriggerBody,
		triggerSeed,
		spec.TriggerExpectedStatus,
	)
	if err != nil {
		return nil, err
	}

	pollAttempts := spec.CallbackPollAttempts
	if pollAttempts <= 0 {
		pollAttempts = 5
	}
	waitMillis := spec.CallbackPollWaitMillis
	if waitMillis <= 0 {
		waitMillis = 500
	}
	if waitMillis > 5000 {
		waitMillis = 5000
	}

	pollSeed := make(database.Row)
	for key, value := range triggerSeed {
		pollSeed[key] = value
	}

	var currentPollRow database.Row
	for i := 0; i < pollAttempts; i++ {
		pollPath, err := authorizeActiveValidationPath(callbackTarget, e.interpolateTemplate(spec.CallbackPollPath, pollSeed))
		if err != nil {
			return nil, err
		}
		pollURL := strings.TrimRight(strings.TrimSpace(callbackTarget.BaseURL), "/") + pollPath
		pollHeaders := make(map[string]string)
		for key, value := range callbackIdentity.Headers {
			pollHeaders[key] = value
		}
		for key, value := range callbackTarget.Headers {
			pollHeaders[key] = value
		}
		for key, value := range spec.CallbackPollHeaders {
			pollHeaders[key] = value
		}
		if err := e.checkStateChangeMethodPolicy(spec.CallbackPollMethod); err != nil {
			return nil, err
		}
		pollStatus, _, pollBody, err := e.executeActiveValidationRaw(
			ctx,
			pollURL,
			pollPath,
			strings.ToUpper(strings.TrimSpace(spec.CallbackPollMethod)),
			pollHeaders,
			nil,
			pollSeed,
			spec.CallbackPollExpectedStatus,
		)
		if err != nil {
			return nil, err
		}
		var pollPayload interface{}
		if err := json.Unmarshal(pollBody, &pollPayload); err != nil {
			return nil, fmt.Errorf("failed to decode callback poll response: %w", err)
		}
		selected := extractHTTPRowData(pollPayload, spec.CallbackPollRowPath)
		currentPollRow = make(database.Row)
		for key, value := range seedRow {
			currentPollRow[key] = value
		}
		currentPollRow["callback_url"] = callbackURL
		currentPollRow["callback_token"] = callbackToken
		currentPollRow["register_status"] = registerStatus
		currentPollRow["trigger_status"] = triggerStatus
		currentPollRow["poll_status"] = pollStatus
		switch typed := selected.(type) {
		case map[string]interface{}:
			for key, value := range typed {
				currentPollRow[key] = value
			}
		default:
			currentPollRow["callback_result"] = typed
		}
		if isTruthyCallbackReceipt(selected) {
			return currentPollRow, nil
		}
		if i < pollAttempts-1 {
			time.Sleep(time.Duration(waitMillis) * time.Millisecond)
		}
	}

	if currentPollRow == nil {
		currentPollRow = make(database.Row)
	}
	currentPollRow["callback_received"] = false
	return currentPollRow, nil
}

func isTruthyCallbackReceipt(value interface{}) bool {
	switch current := value.(type) {
	case map[string]interface{}:
		for _, key := range []string{"received", "callback_received", "seen"} {
			if currentValue, ok := current[key]; ok {
				return fmt.Sprintf("%v", currentValue) == "true"
			}
		}
	case bool:
		return current
	}
	return false
}

func (e *Executor) executeSignedURLValidationProcedure(ctx context.Context, spec activeValidationProcedureSpec) ([]database.Row, error) {
	if strings.TrimSpace(spec.SeedSQL) == "" {
		return nil, fmt.Errorf("signed_url flow requires seed_sql")
	}
	if strings.TrimSpace(spec.MintTarget) == "" || strings.TrimSpace(spec.MintMethod) == "" || strings.TrimSpace(spec.MintPath) == "" {
		return nil, fmt.Errorf("signed_url flow requires mint_target, mint_method, and mint_path")
	}

	mintTarget, exists := e.activeTargets[strings.TrimSpace(spec.MintTarget)]
	if !exists {
		return nil, fmt.Errorf("unknown active validation mint target: %s", spec.MintTarget)
	}
	var mintIdentity config.ActiveValidationIdentity
	if strings.TrimSpace(spec.MintIdentity) != "" {
		currentIdentity, exists := e.activeIdentities[strings.TrimSpace(spec.MintIdentity)]
		if !exists {
			return nil, fmt.Errorf("unknown active validation mint identity: %s", spec.MintIdentity)
		}
		mintIdentity = currentIdentity
	}

	seedRows, err := e.loadActiveValidationSeedRows(ctx, spec)
	if err != nil {
		return nil, err
	}

	maxTargets := spec.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 5
	}
	if maxTargets > len(seedRows) {
		maxTargets = len(seedRows)
	}

	rows := make([]database.Row, 0, maxTargets)
	for i := 0; i < maxTargets; i++ {
		current, err := e.executeSignedURLValidationForRow(ctx, mintTarget, mintIdentity, spec, seedRows[i])
		if err != nil {
			return nil, err
		}
		rows = append(rows, current)
	}

	return rows, nil
}

func (e *Executor) loadActiveValidationSeedRows(ctx context.Context, spec activeValidationProcedureSpec) ([]database.Row, error) {
	if strings.TrimSpace(spec.SeedSQL) != "" {
		queryCtx, queryCancel := context.WithTimeout(ctx, 30*time.Second)
		defer queryCancel()
		seedRows, err := e.db.ExecuteQuery(queryCtx, spec.SeedSQL)
		if err != nil {
			return nil, fmt.Errorf("active validation seed query failed: %w", err)
		}
		return seedRows, nil
	}

	switch strings.ToLower(strings.TrimSpace(spec.SeedExecutionMode)) {
	case "":
		return nil, nil
	case "source_scan":
		seedProcedure := ControlProcedure{
			ProcedureID:   "active-validation-seed-source-scan",
			ExecutionMode: "source_scan",
			Tests:         spec.SeedTests,
		}
		seedRows, err := e.executeSourceScanProcedure(seedProcedure)
		if err != nil {
			return nil, fmt.Errorf("active validation source-scan seed failed: %w", err)
		}
		return seedRows, nil
	case "http":
		seedProcedure := ControlProcedure{
			ProcedureID:   "active-validation-seed-http",
			ExecutionMode: "http",
			Tests:         spec.SeedTests,
		}
		seedRows, err := e.executeHTTPProcedure(ctx, seedProcedure)
		if err != nil {
			return nil, fmt.Errorf("active validation HTTP seed failed: %w", err)
		}
		return seedRows, nil
	default:
		return nil, fmt.Errorf("unknown active validation seed_execution_mode: %s", spec.SeedExecutionMode)
	}
}

func (e *Executor) executeSignedURLValidationForRow(ctx context.Context, mintTarget config.ActiveValidationTarget, mintIdentity config.ActiveValidationIdentity, spec activeValidationProcedureSpec, seedRow database.Row) (database.Row, error) {
	mintSpec := activeValidationProcedureSpec{
		Target:         spec.MintTarget,
		Method:         spec.MintMethod,
		Path:           spec.MintPath,
		Headers:        spec.MintHeaders,
		Body:           spec.MintBody,
		ExpectedStatus: []int{200},
	}
	mintRows, err := e.executeActiveValidationRequest(ctx, mintTarget, mintIdentity, mintSpec, strings.ToUpper(strings.TrimSpace(spec.MintMethod)), seedRow)
	if err != nil {
		return nil, err
	}
	if len(mintRows) == 0 {
		return nil, fmt.Errorf("signed_url flow returned no mint response rows")
	}
	mintRow := mintRows[0]

	signedURL := extractSignedURLValue(mintRow, spec.MintRowPath)
	if strings.TrimSpace(signedURL) == "" {
		return nil, fmt.Errorf("signed_url flow did not return a signed URL")
	}

	result := make(database.Row)
	for key, value := range seedRow {
		result[key] = value
	}

	immediateStatus, requestPath, err := e.executeSignedURLFetch(ctx, mintTarget, signedURL, spec.FetchExpectedStatus)
	if err != nil {
		return nil, err
	}
	result["immediate_status"] = immediateStatus
	result["signed_url_path"] = requestPath

	if strings.TrimSpace(spec.ReplayPath) != "" {
		replayStatus, replayPath, err := e.executeSignedURLFetch(ctx, mintTarget, mutateSignedURLPath(signedURL, e.interpolateTemplate(spec.ReplayPath, seedRow)), spec.ReplayExpectedStatus)
		if err != nil {
			return nil, err
		}
		result["replay_status"] = replayStatus
		result["replay_path"] = replayPath
	}

	if spec.ExpiryWaitSeconds > 0 {
		waitSeconds := spec.ExpiryWaitSeconds
		if waitSeconds > 5 {
			waitSeconds = 5
		}
		time.Sleep(time.Duration(waitSeconds) * time.Second)
		expiryStatus, expiryPath, err := e.executeSignedURLFetch(ctx, mintTarget, signedURL, spec.ExpiryExpectedStatus)
		if err != nil {
			return nil, err
		}
		result["expiry_status"] = expiryStatus
		result["expiry_path"] = expiryPath
	}

	return result, nil
}

func (e *Executor) executeSignedURLFetch(ctx context.Context, currentTarget config.ActiveValidationTarget, signedURL string, expectedStatus []int) (int, string, error) {
	requestURL, requestPath, err := e.resolveSignedURL(currentTarget, signedURL)
	if err != nil {
		return 0, "", err
	}
	statusCode, _, _, err := e.executeActiveValidationRaw(ctx, requestURL, requestPath, "GET", nil, nil, nil, expectedStatus)
	if err != nil {
		return 0, "", err
	}
	return statusCode, requestPath, nil
}

func (e *Executor) resolveSignedURL(currentTarget config.ActiveValidationTarget, signedURL string) (string, string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(currentTarget.BaseURL), "/")
	parsedBase, err := neturl.Parse(baseURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid active validation base URL: %w", err)
	}

	if strings.HasPrefix(strings.TrimSpace(signedURL), "/") {
		return baseURL + strings.TrimSpace(signedURL), strings.TrimSpace(signedURL), nil
	}

	parsedSigned, err := neturl.Parse(strings.TrimSpace(signedURL))
	if err != nil {
		return "", "", fmt.Errorf("invalid signed URL: %w", err)
	}
	baseHost, err := normalizeSignedURLHost(parsedBase)
	if err != nil {
		return "", "", err
	}
	signedHost, err := normalizeSignedURLHost(parsedSigned)
	if err != nil {
		return "", "", err
	}
	if signedHost != baseHost {
		return "", "", fmt.Errorf("signed URL host is not allowlisted")
	}
	if !e.allowHTTP && parsedSigned.Scheme == "http" {
		return "", "", fmt.Errorf("insecure HTTP connection refused for signed URL")
	}
	return parsedSigned.String(), parsedSigned.RequestURI(), nil
}

func normalizeSignedURLHost(currentURL *neturl.URL) (string, error) {
	host := strings.TrimSpace(currentURL.Hostname())
	if host == "" {
		return "", fmt.Errorf("signed URL host is missing")
	}
	for _, currentRune := range host {
		if currentRune > 127 {
			return "", fmt.Errorf("signed URL host must be ASCII")
		}
	}
	port := strings.TrimSpace(currentURL.Port())
	if port == "" {
		return strings.ToLower(host), nil
	}
	return strings.ToLower(host) + ":" + port, nil
}

// canonicalizeActiveValidationPath resolves a request path to its canonical
// form -- decoding percent-escapes once and collapsing "." / ".." segments --
// so allowlist checks compare against what will actually be requested rather
// than a pre-traversal string that only superficially matches an allowed
// prefix (e.g. "/api/safe/../../admin" must not pass an "/api/safe" check).
func canonicalizeActiveValidationPath(rawPath string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", fmt.Errorf("active validation path is empty")
	}
	if strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("active validation path must be relative")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("active validation path must start with '/'")
	}

	// Parse so a query string (e.g. a signed URL's token parameter) is never
	// fed into path cleaning, and so percent-escapes are decoded exactly once
	// (url.Parse already decodes into parsed.Path; unescaping again here would
	// double-decode and corrupt legitimately-encoded characters).
	parsed, err := neturl.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("active validation path is not validly encoded: %w", err)
	}
	cleaned := path.Clean(parsed.Path)
	if !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("active validation path escapes root")
	}
	return cleaned, nil
}

// activeValidationPathAllowed reports whether candidate (already canonical)
// falls within one of allowedPaths, matching on "/"-delimited segment
// boundaries so an allowlisted "/api/safe" cannot match "/api/safe-admin/...".
func activeValidationPathAllowed(candidate string, allowedPaths []string) bool {
	for _, raw := range allowedPaths {
		allowed := strings.TrimSpace(raw)
		if allowed == "" {
			continue
		}
		allowed = path.Clean(allowed)
		if candidate == allowed {
			return true
		}
		prefix := allowed
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		if strings.HasPrefix(candidate, prefix) {
			return true
		}
	}
	return false
}

// authorizeActiveValidationPath enforces target.AllowedPaths against
// requestPath's canonical form (decoded and traversal-collapsed), but returns
// requestPath unchanged (trimmed only) so percent-encoded characters (e.g.
// "%20") remain intact on the wire -- only the authorization decision uses
// the canonical form, never the value actually requested. Every
// active-validation flow that sends a request against a statically
// allowlisted target (normal and callback register/trigger/poll) must call
// this immediately before dispatching the request, so no flow can bypass the
// boundary.
func authorizeActiveValidationPath(target config.ActiveValidationTarget, requestPath string) (string, error) {
	trimmed := strings.TrimSpace(requestPath)
	canonicalPath, err := canonicalizeActiveValidationPath(trimmed)
	if err != nil {
		return "", err
	}
	if !activeValidationPathAllowed(canonicalPath, target.AllowedPaths) {
		return "", fmt.Errorf("active validation path is not allowlisted: %s", canonicalPath)
	}
	return trimmed, nil
}

// checkStateChangeMethodPolicy rejects a state-changing HTTP method (anything
// other than GET/HEAD/OPTIONS) unless active validation is explicitly
// configured to allow state-changing requests. Every active-validation flow
// that dispatches a request (normal, callback register/trigger/poll) must
// call this before sending it -- the callback flow previously bypassed this
// check entirely, letting its register/trigger requests use POST/PUT/DELETE
// even when state-changing requests were supposed to be disabled.
func (e *Executor) checkStateChangeMethodPolicy(method string) error {
	currentMethod := strings.ToUpper(strings.TrimSpace(method))
	if currentMethod != "GET" && currentMethod != "HEAD" && currentMethod != "OPTIONS" && !e.activeValidation.AllowStateChange {
		return fmt.Errorf("state-changing active validation requests are disabled")
	}
	return nil
}

func (e *Executor) executeActiveValidationRaw(ctx context.Context, requestURL string, requestPath string, method string, headers map[string]string, body map[string]interface{}, seedRow database.Row, expectedStatus []int) (int, http.Header, []byte, error) {
	// Baseline canonicalization applied to every flow (normal, callback,
	// signed-URL) regardless of whether a flow-specific static allowlist also
	// applies: reject absolute URLs, require a rooted path, and collapse any
	// "." / ".." traversal segments so no flow can smuggle a malformed path
	// through the shared request executor.
	if _, err := canonicalizeActiveValidationPath(requestPath); err != nil {
		return 0, nil, nil, err
	}
	e.activeMu.Lock()
	if e.activeRequests >= e.activeValidation.GetMaxRequestsPerRun() {
		e.activeMu.Unlock()
		return 0, nil, nil, fmt.Errorf("active validation request budget exceeded")
	}
	e.activeRequests++
	e.activeMu.Unlock()

	if e.activeSem == nil {
		e.activeSem = make(chan struct{}, e.activeValidation.GetMaxConcurrent())
	}
	e.activeSem <- struct{}{}
	defer func() {
		<-e.activeSem
	}()

	var bodyReader io.Reader
	if len(body) > 0 {
		requestBody := make(map[string]interface{}, len(body))
		for key, value := range body {
			requestBody[key] = e.interpolateValue(value, seedRow)
		}
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to encode active validation body: %w", err)
		}
		if len(bodyBytes) > 16*1024 {
			return 0, nil, nil, fmt.Errorf("active validation body exceeds 16384 bytes")
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(e.activeValidation.GetTimeoutSeconds())*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, method, requestURL, bodyReader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create active validation request: %w", err)
	}
	for key, value := range headers {
		headerValue := e.interpolateLiteral(value, seedRow)
		if err := validateActiveValidationHeader(key, headerValue); err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set(key, headerValue)
	}
	if bodyReader != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Timeout: time.Duration(e.activeValidation.GetTimeoutSeconds()) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to execute active validation request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, int64(e.activeValidation.GetMaxResponseBytes()+1)))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to read active validation response: %w", err)
	}
	if len(responseBody) > e.activeValidation.GetMaxResponseBytes() {
		return 0, nil, nil, fmt.Errorf("active validation response exceeded %d bytes", e.activeValidation.GetMaxResponseBytes())
	}

	allowedStatus := len(expectedStatus) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300
	if !allowedStatus {
		for _, current := range expectedStatus {
			if resp.StatusCode == current {
				allowedStatus = true
				break
			}
		}
	}
	if !allowedStatus {
		return 0, nil, nil, fmt.Errorf("active validation returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	return resp.StatusCode, resp.Header.Clone(), responseBody, nil
}

func extractSignedURLValue(row database.Row, rowPath string) string {
	if strings.TrimSpace(rowPath) == "" {
		for _, key := range []string{"signedURL", "signed_url", "url"} {
			if value, ok := row[key]; ok {
				return formatDisplayValue(value)
			}
		}
		return ""
	}
	current := interface{}(map[string]interface{}(row))
	for _, part := range strings.Split(strings.TrimSpace(rowPath), ".") {
		if part == "" {
			continue
		}
		next, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		value, exists := next[part]
		if !exists {
			return ""
		}
		current = value
	}
	return formatDisplayValue(current)
}

func mutateSignedURLPath(signedURL string, replayPath string) string {
	if strings.TrimSpace(replayPath) == "" {
		return signedURL
	}
	parsed, err := neturl.Parse(strings.TrimSpace(signedURL))
	if err != nil {
		return signedURL
	}
	decodedPath, decodeErr := neturl.PathUnescape(strings.TrimSpace(replayPath))
	if decodeErr != nil {
		return signedURL
	}
	if !strings.HasPrefix(decodedPath, "/") {
		return signedURL
	}
	for _, currentPart := range strings.Split(decodedPath, "/") {
		if currentPart == ".." {
			return signedURL
		}
	}
	cleanPath := path.Clean(decodedPath)
	if !strings.HasPrefix(cleanPath, "/") {
		return signedURL
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	return parsed.String()
}

func (e *Executor) executeActiveValidationRequest(ctx context.Context, currentTarget config.ActiveValidationTarget, identity config.ActiveValidationIdentity, spec activeValidationProcedureSpec, method string, seedRow database.Row) ([]database.Row, error) {
	if seedRow != nil {
		method = strings.ToUpper(strings.TrimSpace(e.interpolateLiteral(method, seedRow)))
	}
	requestPath := e.interpolateTemplate(spec.Path, seedRow)
	requestPath = strings.ReplaceAll(requestPath, "{{PROJECT_REF}}", e.projectRef)
	requestPath, err := authorizeActiveValidationPath(currentTarget, requestPath)
	if err != nil {
		return nil, err
	}

	requestURL := strings.TrimRight(strings.TrimSpace(currentTarget.BaseURL), "/") + requestPath
	if _, err := neturl.Parse(requestURL); err != nil {
		return nil, fmt.Errorf("invalid active validation URL: %w", err)
	}
	headers := make(map[string]string)
	for key, value := range identity.Headers {
		headers[key] = value
	}
	for key, value := range currentTarget.Headers {
		headers[key] = value
	}
	for key, value := range spec.Headers {
		headers[key] = value
	}
	statusCode, responseHeaders, body, err := e.executeActiveValidationRaw(ctx, requestURL, requestPath, method, headers, spec.Body, seedRow, spec.ExpectedStatus)
	if err != nil {
		return nil, err
	}

	baseRow := make(database.Row)
	for key, value := range seedRow {
		baseRow[key] = value
	}
	baseRow["status_code"] = statusCode
	baseRow["request_path"] = requestPath
	baseRow["response_body"] = strings.TrimSpace(string(body))
	for key, values := range responseHeaders {
		if len(values) == 0 {
			continue
		}
		headerKey := "response_header_" + strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		baseRow[headerKey] = strings.TrimSpace(values[0])
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return []database.Row{baseRow}, nil
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		baseRow["body"] = strings.TrimSpace(string(body))
		return []database.Row{baseRow}, nil
	}

	selected := extractHTTPRowData(payload, spec.RowPath)
	switch typed := selected.(type) {
	case []interface{}:
		rows := make([]database.Row, 0, len(typed))
		for _, item := range typed {
			currentRow := make(database.Row)
			for key, value := range baseRow {
				currentRow[key] = value
			}
			switch current := item.(type) {
			case map[string]interface{}:
				for key, value := range current {
					currentRow[key] = value
				}
			default:
				currentRow["value"] = current
			}
			rows = append(rows, currentRow)
		}
		return rows, nil
	case map[string]interface{}:
		for key, value := range typed {
			baseRow[key] = value
		}
		return []database.Row{baseRow}, nil
	default:
		baseRow["value"] = typed
		return []database.Row{baseRow}, nil
	}
}

func (e *Executor) interpolateTemplate(template string, row database.Row) string {
	result := template
	result = strings.ReplaceAll(result, "{{PROJECT_REF}}", e.projectRef)
	result = e.interpolateControlVariables(result)
	for key, value := range row {
		placeholder := "{{" + key + "}}"
		currentValue := formatDisplayValue(value)
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), "_path") {
			result = strings.ReplaceAll(result, placeholder, currentValue)
		} else {
			result = strings.ReplaceAll(result, placeholder, neturl.PathEscape(currentValue))
		}
		placeholder = "{{" + strings.ToUpper(key) + "}}"
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), "_path") {
			result = strings.ReplaceAll(result, placeholder, currentValue)
		} else {
			result = strings.ReplaceAll(result, placeholder, neturl.PathEscape(currentValue))
		}
	}
	return result
}

func (e *Executor) interpolateLiteral(template string, row database.Row) string {
	result := template
	result = strings.ReplaceAll(result, "{{PROJECT_REF}}", e.projectRef)
	result = e.interpolateControlVariables(result)
	for key, value := range row {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, formatDisplayValue(value))
		placeholder = "{{" + strings.ToUpper(key) + "}}"
		result = strings.ReplaceAll(result, placeholder, formatDisplayValue(value))
	}
	return result
}

func (e *Executor) interpolateControlVariables(template string) string {
	result := template
	result = controlVariableDefaultPattern.ReplaceAllStringFunc(result, func(match string) string {
		parts := controlVariableDefaultPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		key := strings.TrimSpace(parts[1])
		if value, ok := e.controlVariables[key]; ok {
			return value
		}
		if value, ok := e.controlVariables[strings.ToUpper(key)]; ok {
			return value
		}
		return parts[2]
	})
	for key, value := range e.controlVariables {
		placeholder := "{{" + key + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
		placeholder = "{{" + strings.ToUpper(key) + "}}"
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

func (e *Executor) interpolateValue(value interface{}, row database.Row) interface{} {
	switch current := value.(type) {
	case string:
		return e.interpolateLiteral(current, row)
	case []interface{}:
		result := make([]interface{}, 0, len(current))
		for _, item := range current {
			result = append(result, e.interpolateValue(item, row))
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, len(current))
		for key, item := range current {
			result[key] = e.interpolateValue(item, row)
		}
		return result
	default:
		return value
	}
}

func (e *Executor) applyProcedureRows(control *Control, procedure ControlProcedure, rows []database.Row, result *ProcedureResult) {
	// If no criteria defined, treat as discovery mode - collect all rows as data
	if len(procedure.Criteria) == 0 {
		if len(rows) == 0 {
			return
		}

		finding := Finding{
			Severity:    "INFO",
			Title:       control.Title,
			Description: control.Description,
			Evidence: map[string]interface{}{
				"rows":      rows,
				"row_count": len(rows),
			},
		}
		result.Findings = append(result.Findings, finding)
		result.Status = "PASS"
		return
	}

	// Handle row_count conditions as pass criteria.
	// Example: row_count = 0 means PASS when no violating rows are returned.
	hasRowCountCriteria := false
	rowCountPass := true
	for _, criteria := range procedure.Criteria {
		if strings.Contains(criteria.Condition, "row_count") {
			hasRowCountCriteria = true
			if !e.evaluateRowCountCondition(criteria.Condition, len(rows)) {
				rowCountPass = false
				severity := strings.TrimSpace(criteria.Severity)
				if severity == "" {
					severity = "MEDIUM"
				}

				if len(rows) == 0 {
					title := strings.TrimSpace(criteria.FindingTitle)
					if title == "" {
						title = control.Title
					}

					finding := Finding{
						Severity:    severity,
						Title:       title,
						Description: control.Description,
						Evidence: map[string]interface{}{
							"rows":      rows,
							"row_count": len(rows),
							"condition": criteria.Condition,
						},
						Remediation: control.Remediation.Summary,
					}
					result.Findings = append(result.Findings, finding)
					continue
				}

				for _, row := range rows {
					title := strings.TrimSpace(criteria.FindingTitle)
					if title == "" {
						title = e.buildFallbackTitle(control.Title, row)
					} else {
						title = e.interpolateTitle(title, row)
					}

					finding := Finding{
						Severity:    severity,
						Title:       title,
						Description: control.Description,
						Evidence: map[string]interface{}{
							"row":       row,
							"row_count": len(rows),
							"condition": criteria.Condition,
						},
						Remediation: control.Remediation.Summary,
					}
					result.Findings = append(result.Findings, finding)
				}
			}
		}
	}
	if hasRowCountCriteria {
		if !rowCountPass {
			result.Status = "FAIL"
		}
		return
	}

	if len(rows) == 0 {
		return
	}

	// Handle regular security controls
	for _, row := range rows {
		for _, criteria := range procedure.Criteria {
			matched, err := e.evaluateCondition(criteria.Condition, row)
			if err != nil {
				// A condition that cannot be evaluated must never be treated as a
				// non-match: that would silently collapse into the procedure's
				// initial PASS status. Fail closed instead.
				result.Status = "ERROR"
				result.Error = fmt.Errorf("procedure %s: condition evaluation failed: %w", procedure.ProcedureID, err)
				return
			}
			if !matched {
				continue
			}

			title := strings.TrimSpace(criteria.FindingTitle)
			if title == "" {
				title = e.buildFallbackTitle(control.Title, row)
			}
			severity := strings.TrimSpace(criteria.Severity)
			if severity == "" {
				severity = "MEDIUM"
			}

			finding := Finding{
				Severity:    severity,
				Status:      findingStatus(criteria.Condition),
				Title:       e.interpolateTitle(title, row),
				Description: control.Description,
				Evidence:    row,
				Remediation: control.Remediation.Summary,
			}
			result.Findings = append(result.Findings, finding)
			result.Status = procedureStatus(criteria.Condition)
		}
	}
}

func procedureStatus(condition string) string {
	switch normalizedCondition(condition) {
	case "review_required":
		return "REVIEW"
	case "license_required":
		return "LICENSE"
	case "informational":
		return "INFO"
	default:
		return "FAIL"
	}
}

func findingStatus(condition string) string {
	switch normalizedCondition(condition) {
	case "review_required":
		return "Review Required"
	case "license_required":
		return "License Required"
	case "informational":
		return "Informational"
	default:
		return "New"
	}
}

func normalizedCondition(condition string) string {
	return strings.ToLower(strings.TrimSpace(condition))
}

func (e *Executor) buildFallbackTitle(currentTitle string, row database.Row) string {
	details := make([]string, 0, len(row))
	keys := make([]string, 0, len(row))
	priority := []string{
		"role_name",
		"schema_name",
		"table_name",
		"object_name",
		"function_name",
		"attribute_name",
		"current_value",
		"expected_value",
		"reason",
		"fix",
	}
	seen := map[string]bool{}

	for key := range row {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	appendKey := func(currentKey string) {
		if len(details) == 4 || seen[currentKey] {
			return
		}

		value := formatDisplayValue(row[currentKey])
		if value == "" || value == "<nil>" {
			return
		}

		if len(value) > 80 {
			value = value[:77] + "..."
		}

		details = append(details, fmt.Sprintf("%s=%s", strings.ToLower(currentKey), value))
		seen[currentKey] = true
	}

	for _, key := range priority {
		for _, currentKey := range keys {
			if strings.EqualFold(currentKey, key) {
				appendKey(currentKey)
				break
			}
		}
	}

	for _, key := range keys {
		if key == "" {
			continue
		}
		appendKey(key)
	}

	if len(details) == 0 {
		return currentTitle
	}

	return currentTitle + ": " + strings.Join(details, ", ")
}

// validateConditionSyntax checks that a control criterion condition is a
// recognized, well-formed syntax form, without evaluating it against any row.
// It mirrors evaluateCondition's dispatch so a malformed or unsupported
// condition is rejected at control-set load time -- before any customer
// database is queried -- instead of silently behaving as PASS at execution
// time. Keep this in sync with evaluateCondition's supported grammar.
func validateConditionSyntax(condition string) error {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return fmt.Errorf("empty condition")
	}

	normalized := normalizedCondition(condition)
	if normalized == "review_required" || normalized == "license_required" || normalized == "informational" {
		return nil
	}

	if strings.Contains(condition, " OR ") {
		for _, part := range strings.Split(condition, " OR ") {
			if err := validateConditionSyntax(strings.TrimSpace(part)); err != nil {
				return err
			}
		}
		return nil
	}

	if strings.Contains(condition, " AND ") {
		for _, part := range strings.Split(condition, " AND ") {
			if err := validateConditionSyntax(strings.TrimSpace(part)); err != nil {
				return err
			}
		}
		return nil
	}

	if strings.Contains(condition, "row_count") {
		return validateRowCountConditionSyntax(condition)
	}

	if strings.Contains(condition, " IN ") {
		parts := strings.Split(condition, " IN ")
		if len(parts) != 2 {
			return fmt.Errorf("malformed IN condition: %q", condition)
		}
		if strings.TrimSpace(parts[0]) == "" {
			return fmt.Errorf("IN condition is missing a column name: %q", condition)
		}
		valueList := strings.Trim(strings.TrimSpace(parts[1]), "()")
		if strings.TrimSpace(valueList) == "" {
			return fmt.Errorf("IN condition is missing a value list: %q", condition)
		}
		return nil
	}

	if strings.Contains(normalized, " contains ") {
		index := strings.Index(normalized, " contains ")
		if index <= 0 {
			return fmt.Errorf("malformed CONTAINS condition: %q", condition)
		}
		if strings.TrimSpace(condition[index+len(" contains "):]) == "" {
			return fmt.Errorf("CONTAINS condition is missing an expected value: %q", condition)
		}
		return nil
	}

	for _, op := range []string{"==", "!=", ">=", "<=", "=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.Split(condition, op)
			if len(parts) != 2 {
				return fmt.Errorf("malformed condition for operator %q: %q", op, condition)
			}
			if strings.TrimSpace(parts[0]) == "" {
				return fmt.Errorf("condition is missing a column name: %q", condition)
			}
			if strings.TrimSpace(parts[1]) == "" {
				return fmt.Errorf("condition is missing an expected value: %q", condition)
			}
			return nil
		}
	}

	return fmt.Errorf("unrecognized condition syntax: %q", condition)
}

// validateRowCountConditionSyntax checks the syntax of a "row_count" criterion
// (e.g. "row_count > 0") without evaluating it. See validateConditionSyntax.
func validateRowCountConditionSyntax(condition string) error {
	condition = strings.TrimSpace(condition)
	for _, op := range []string{">=", "<=", "==", "!=", "=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.Split(condition, op)
			if len(parts) != 2 {
				return fmt.Errorf("malformed row_count condition: %q", condition)
			}
			if strings.TrimSpace(parts[0]) != "row_count" {
				return fmt.Errorf("row_count condition must compare row_count, got: %q", condition)
			}
			if _, err := strconv.Atoi(strings.TrimSpace(parts[1])); err != nil {
				return fmt.Errorf("row_count condition expects an integer value: %q", condition)
			}
			return nil
		}
	}
	return fmt.Errorf("unrecognized row_count condition syntax: %q", condition)
}

// evaluateCondition evaluates a simple condition against a row.
// Supports: ==, !=, >, <, IN, CONTAINS, AND, OR
// Returns an error when the condition syntax is not recognized; callers must
// treat that as an execution error, never as a non-match (false).
func (e *Executor) evaluateCondition(condition string, row database.Row) (bool, error) {
	// Simple condition parser (basic implementation)
	// Format: "COLUMN_NAME == 'VALUE'" or "COLUMN_NAME > 5"

	condition = strings.TrimSpace(condition)
	normalized := normalizedCondition(condition)
	if normalized == "review_required" || normalized == "license_required" || normalized == "informational" {
		return true, nil
	}

	// Handle OR conditions
	if strings.Contains(condition, " OR ") {
		parts := strings.Split(condition, " OR ")
		for _, part := range parts {
			matched, err := e.evaluateCondition(strings.TrimSpace(part), row)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle AND conditions
	if strings.Contains(condition, " AND ") {
		parts := strings.Split(condition, " AND ")
		for _, part := range parts {
			matched, err := e.evaluateCondition(strings.TrimSpace(part), row)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle IN operator
	if strings.Contains(condition, " IN ") {
		return e.evaluateInCondition(condition, row)
	}

	// Handle CONTAINS operator
	if strings.Contains(normalized, " contains ") {
		return e.evaluateContainsCondition(condition, row)
	}

	// Handle simple operators
	for _, op := range []string{"==", "!=", ">=", "<=", "=", ">", "<"} {
		if strings.Contains(condition, op) {
			return e.evaluateSimpleCondition(condition, op, row)
		}
	}

	return false, fmt.Errorf("unrecognized condition syntax: %q", condition)
}

func (e *Executor) evaluateContainsCondition(condition string, row database.Row) (bool, error) {
	currentCondition := strings.TrimSpace(condition)
	lowerCondition := strings.ToLower(currentCondition)
	index := strings.Index(lowerCondition, " contains ")
	if index <= 0 {
		return false, fmt.Errorf("malformed CONTAINS condition: %q", condition)
	}

	columnName := strings.TrimSpace(currentCondition[:index])
	expectedValue := strings.Trim(strings.TrimSpace(currentCondition[index+len(" contains "):]), "'\"")

	actualValue, exists := row[columnName]
	if !exists {
		for key, value := range row {
			if strings.EqualFold(key, columnName) {
				actualValue = value
				exists = true
				break
			}
		}
	}
	if !exists {
		return false, nil
	}

	return strings.Contains(strings.ToLower(fmt.Sprintf("%v", actualValue)), strings.ToLower(expectedValue)), nil
}

func (e *Executor) executeHTTPProcedure(ctx context.Context, procedure ControlProcedure) ([]database.Row, error) {
	if strings.TrimSpace(procedure.Tests) == "" {
		return nil, fmt.Errorf("missing HTTP procedure spec")
	}
	if strings.TrimSpace(e.managementAPIToken) == "" {
		return nil, fmt.Errorf("missing Supabase Management API token")
	}
	if strings.TrimSpace(e.projectRef) == "" {
		return nil, fmt.Errorf("missing Supabase project ref")
	}
	if strings.TrimSpace(e.managementAPIURL) == "" {
		e.managementAPIURL = "https://api.supabase.com"
	}
	if err := security.ValidateHTTPS(e.managementAPIURL, e.allowHTTP); err != nil {
		return nil, err
	}

	var spec httpProcedureSpec
	if err := yaml.Unmarshal([]byte(procedure.Tests), &spec); err != nil {
		return nil, fmt.Errorf("invalid HTTP procedure spec: %w", err)
	}
	if strings.TrimSpace(spec.Method) == "" || strings.TrimSpace(spec.Path) == "" {
		return nil, fmt.Errorf("invalid HTTP procedure spec: method and path are required")
	}

	requestPath := strings.ReplaceAll(spec.Path, "{{PROJECT_REF}}", e.projectRef)
	if strings.Contains(requestPath, "://") {
		return nil, fmt.Errorf("invalid HTTP procedure spec: path must be relative")
	}
	if !strings.HasPrefix(requestPath, "/") {
		return nil, fmt.Errorf("invalid HTTP procedure spec: path must start with '/'")
	}
	requestURL := e.managementAPIURL + requestPath
	if _, err := neturl.Parse(requestURL); err != nil {
		return nil, fmt.Errorf("invalid Management API URL: %w", err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, strings.ToUpper(spec.Method), requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.managementAPIToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}
	if len(body) > 256*1024 {
		return nil, fmt.Errorf("management API response exceeded maximum size")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("management API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	trimmedBody := strings.TrimSpace(string(body))
	if trimmedBody == "" {
		return nil, fmt.Errorf("failed to decode HTTP response: empty body")
	}
	if !strings.HasPrefix(trimmedBody, "{") && !strings.HasPrefix(trimmedBody, "[") {
		return nil, fmt.Errorf("failed to decode HTTP response: expected JSON object or array")
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode HTTP response: %w", err)
	}

	selected := extractHTTPRowData(payload, spec.RowPath)
	switch typed := selected.(type) {
	case []interface{}:
		rows := make([]database.Row, 0, len(typed))
		for _, item := range typed {
			switch current := item.(type) {
			case map[string]interface{}:
				rows = append(rows, database.Row(current))
			default:
				rows = append(rows, database.Row{"value": current})
			}
		}
		return rows, nil
	case map[string]interface{}:
		return []database.Row{database.Row(typed)}, nil
	default:
		return []database.Row{{"value": typed}}, nil
	}
}

func extractHTTPRowData(payload interface{}, rowPath string) interface{} {
	current := payload
	for _, part := range strings.Split(strings.TrimSpace(rowPath), ".") {
		if part == "" {
			continue
		}
		next, ok := current.(map[string]interface{})
		if !ok {
			return payload
		}
		value, exists := next[part]
		if !exists {
			return payload
		}
		current = value
	}
	return current
}

// evaluateSimpleCondition handles basic comparisons
func (e *Executor) evaluateSimpleCondition(condition, operator string, row database.Row) (bool, error) {
	parts := strings.Split(condition, operator)
	if len(parts) != 2 {
		return false, fmt.Errorf("malformed condition for operator %q: %q", operator, condition)
	}

	columnName := strings.TrimSpace(parts[0])
	expectedValue := strings.Trim(strings.TrimSpace(parts[1]), "'\"")

	actualValue, exists := row[columnName]
	if !exists {
		for key, value := range row {
			if strings.EqualFold(key, columnName) {
				actualValue = value
				exists = true
				break
			}
		}
	}
	if !exists {
		return false, nil
	}

	actualStr := fmt.Sprintf("%v", actualValue)

	switch operator {
	case "==", "=":
		return actualStr == expectedValue, nil
	case "!=":
		return actualStr != expectedValue, nil
	case ">", "<", ">=", "<=":
		// Try numeric comparison first
		actualNum, actualErr := strconv.ParseFloat(actualStr, 64)
		expectedNum, expectedErr := strconv.ParseFloat(expectedValue, 64)

		if actualErr == nil && expectedErr == nil {
			// Both are numeric - use numeric comparison
			switch operator {
			case ">":
				return actualNum > expectedNum, nil
			case "<":
				return actualNum < expectedNum, nil
			case ">=":
				return actualNum >= expectedNum, nil
			case "<=":
				return actualNum <= expectedNum, nil
			}
		}

		// Fallback to string comparison if either is non-numeric
		switch operator {
		case ">":
			return actualStr > expectedValue, nil
		case "<":
			return actualStr < expectedValue, nil
		case ">=":
			return actualStr >= expectedValue, nil
		case "<=":
			return actualStr <= expectedValue, nil
		}
	}

	return false, fmt.Errorf("unrecognized operator %q", operator)
}

// evaluateInCondition handles IN operator
func (e *Executor) evaluateInCondition(condition string, row database.Row) (bool, error) {
	parts := strings.Split(condition, " IN ")
	if len(parts) != 2 {
		return false, fmt.Errorf("malformed IN condition: %q", condition)
	}

	columnName := strings.TrimSpace(parts[0])
	valueList := strings.Trim(strings.TrimSpace(parts[1]), "()")
	values := strings.Split(valueList, ",")

	actualValue, exists := row[columnName]
	if !exists {
		for key, value := range row {
			if strings.EqualFold(key, columnName) {
				actualValue = value
				exists = true
				break
			}
		}
	}
	if !exists {
		return false, nil
	}

	actualStr := fmt.Sprintf("%v", actualValue)

	for _, v := range values {
		v = strings.Trim(strings.TrimSpace(v), "'\"")
		if actualStr == v {
			return true, nil
		}
	}

	return false, nil
}

// interpolateTitle replaces {COLUMN_NAME} placeholders with actual values
func (e *Executor) interpolateTitle(title string, row database.Row) string {
	result := title
	for key, value := range row {
		placeholder := fmt.Sprintf("{%s}", key)
		result = strings.ReplaceAll(result, placeholder, formatDisplayValue(value))
	}
	return result
}

func formatDisplayValue(value interface{}) string {
	if currentValue, ok := value.([]byte); ok {
		return strings.TrimSpace(string(currentValue))
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

// evaluateRowCountCondition evaluates row_count conditions for discovery controls
// Format: "row_count > 0" or "row_count >= 5"
func (e *Executor) evaluateRowCountCondition(condition string, rowCount int) bool {
	condition = strings.TrimSpace(condition)

	// Handle simple operators
	for _, op := range []string{">=", "<=", "==", "!=", "=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.Split(condition, op)
			if len(parts) != 2 {
				return false
			}

			leftSide := strings.TrimSpace(parts[0])
			if leftSide != "row_count" {
				return false
			}

			var expectedValue int
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &expectedValue)

			switch op {
			case "==", "=":
				return rowCount == expectedValue
			case "!=":
				return rowCount != expectedValue
			case ">":
				return rowCount > expectedValue
			case "<":
				return rowCount < expectedValue
			case ">=":
				return rowCount >= expectedValue
			case "<=":
				return rowCount <= expectedValue
			}
		}
	}

	return false
}

// executeEvidenceCapture executes an evidence capture query
func (e *Executor) executeEvidenceCapture(ctx context.Context, evidence Evidence) EvidenceCaptureResult {
	sourceMode := evidence.SourceMode
	if strings.TrimSpace(sourceMode) == "" {
		sourceMode = classifyEvidenceSourceMode(e.databaseType, evidence.Type)
	}
	sourcePath := strings.TrimSpace(evidence.SourcePath)
	if sourcePath == "" {
		sourcePath = evidence.Type
	}
	sourceKey := buildEvidenceSourceKey(e.databaseType, e.databaseName, evidence.Type, sourcePath)
	result := EvidenceCaptureResult{
		Type:        evidence.Type,
		Description: evidence.Description,
		SourceMode:  sourceMode,
		SourcePath:  sourcePath,
		SourceKey:   sourceKey,
		Data:        []map[string]interface{}{},
	}

	if strings.TrimSpace(evidence.SQL) == "" {
		result.Error = fmt.Errorf("missing SQL for evidence capture")
		result.ErrorMessage = result.Error.Error()
		return result
	}

	sqlToExecute := evidence.SQL
	var lease *evidenceLease
	if e.useIngestionState && sourceMode != "activity" {
		currentLease, err := e.acquireEvidenceLease(evidence.Type, sourcePath, sourceMode, sourceKey)
		if err != nil {
			log.Printf("⚠ Evidence source %s lease unavailable for %s/%s, falling back to direct query: %v",
				evidence.Type, e.databaseType, e.databaseName, err)
			currentLease = nil
		}
		if currentLease == nil {
			if err == nil {
				result.Skipped = true
				result.SkipReason = "source is leased by another agent"
				log.Printf("Skipping evidence source %s for %s/%s because another agent holds the lease",
					evidence.Type, e.databaseType, e.databaseName)
				return result
			}
			sqlToExecute = applyDefaultEvidenceWindow(e.databaseType, evidence.Type, evidence.SQL)
		}
		if currentLease != nil {
			lease = currentLease
			result.LeaseToken = lease.LeaseToken
			result.SourceKey = lease.SourceKey
			if lease.SourceMode != "" {
				result.SourceMode = lease.SourceMode
			}
			log.Printf("Evidence source %s lease acquired for %s/%s (source_key=%s)",
				evidence.Type, e.databaseType, e.databaseName, result.SourceKey)
			sqlToExecute = buildIncrementalEvidenceSQL(e.databaseType, evidence.Type, evidence.SQL, lease.WatermarkJSON)
		}
	}

	// Create per-query timeout context (30 seconds max per evidence query)
	queryCtx, queryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer queryCancel()

	rows, err := e.db.ExecuteQuery(queryCtx, sqlToExecute)
	if err != nil {
		result.Error = fmt.Errorf("evidence capture query failed: %w", err)
		result.ErrorMessage = result.Error.Error()
		return result
	}

	// Convert []database.Row to []map[string]interface{}
	data := make([]map[string]interface{}, len(rows))
	for i, row := range rows {
		data[i] = map[string]interface{}(row)
	}
	result.Data = data
	if lease != nil {
		result.Watermark = calculateEvidenceWatermark(e.databaseType, evidence.Type, result.Data, lease.WatermarkJSON)
		log.Printf("Evidence source %s collected %d row(s) for %s/%s (source_key=%s)",
			evidence.Type, len(result.Data), e.databaseType, e.databaseName, result.SourceKey)
		if result.Watermark != "" && result.Watermark != lease.WatermarkJSON {
			log.Printf("Evidence source %s watermark advanced for %s/%s (source_key=%s)",
				evidence.Type, e.databaseType, e.databaseName, result.SourceKey)
		}
	}

	return result
}

func classifyEvidenceSourceMode(databaseType, evidenceType string) string {
	switch evidenceType {
	case "privilege_changes", "role_grants", "privilege_grants":
		return "snapshot"
	case "audit_operations_live":
		return "activity"
	case "audit_operations", "audit_operations_auth":
		return "history"
	case "audit_operations_traditional", "privilege_grant_history":
		return "history"
	default:
		return "history"
	}
}

func buildEvidenceSourceKey(databaseType, databaseName, sourceType, sourcePath string) string {
	rawKey := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(databaseType)),
		strings.TrimSpace(databaseName),
		strings.TrimSpace(sourceType),
		strings.TrimSpace(sourcePath),
	}, "|")
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

func (e *Executor) acquireEvidenceLease(sourceType, sourcePath, sourceMode, sourceKey string) (*evidenceLease, error) {
	if sourceMode == "activity" {
		return nil, nil
	}

	e.evidenceLeaseMu.RLock()
	cachedLease, ok := e.evidenceLeaseByKey[sourceKey]
	e.evidenceLeaseMu.RUnlock()
	if ok {
		return &cachedLease, nil
	}

	if err := security.ValidateHTTPS(e.backendURL, e.allowHTTP); err != nil {
		return nil, err
	}

	requestBody := evidenceLeaseRequest{
		DatabaseType: e.databaseType,
		DatabaseName: e.databaseName,
		SourceType:   sourceType,
		SourcePath:   sourcePath,
		SourceMode:   sourceMode,
		SourceKey:    sourceKey,
	}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence ingestion lease request: %w", err)
	}

	req, err := http.NewRequest("POST", e.backendURL+"/api/agent/ingestion-state/lease", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence ingestion lease request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", e.apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("failed to acquire evidence ingestion lease: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read evidence ingestion lease response: %w", err)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evidence ingestion lease request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var lease evidenceLease
	if err := json.Unmarshal(body, &lease); err != nil {
		return nil, fmt.Errorf("failed to decode evidence ingestion lease response: %w", err)
	}
	if strings.TrimSpace(lease.LeaseToken) == "" {
		return nil, fmt.Errorf("evidence ingestion lease response is missing lease token")
	}
	if strings.TrimSpace(lease.SourceKey) == "" {
		lease.SourceKey = sourceKey
	}
	if strings.TrimSpace(lease.SourceKey) != sourceKey {
		return nil, fmt.Errorf("evidence ingestion lease response source key mismatch")
	}
	e.evidenceLeaseMu.Lock()
	e.evidenceLeaseByKey[sourceKey] = lease
	e.evidenceLeaseMu.Unlock()
	return &lease, nil
}

func buildIncrementalEvidenceSQL(databaseType, evidenceType, sql, watermarkJSON string) string {
	if strings.TrimSpace(watermarkJSON) == "" {
		return applyDefaultEvidenceWindow(databaseType, evidenceType, sql)
	}

	var watermark map[string]interface{}
	if err := json.Unmarshal([]byte(watermarkJSON), &watermark); err != nil {
		log.Printf("⚠ Invalid evidence watermark for %s/%s, falling back to default window: %v", databaseType, evidenceType, err)
		return applyDefaultEvidenceWindow(databaseType, evidenceType, sql)
	}

	switch {
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "audit_operations":
		return strings.Replace(sql, "{{BASECHECK_ORACLE_UNIFIED_WATERMARK}}", buildOracleUnifiedWatermarkCondition(watermark), 1)
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "audit_operations_traditional":
		return strings.Replace(sql, "{{BASECHECK_ORACLE_TRADITIONAL_WATERMARK}}", buildOracleTraditionalWatermarkCondition(watermark), 1)
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "privilege_grant_history":
		return strings.Replace(sql, "{{BASECHECK_ORACLE_UNIFIED_WATERMARK}}", buildOracleUnifiedWatermarkCondition(watermark), 1)
	case strings.EqualFold(databaseType, "mssql") && evidenceType == "audit_operations":
		return strings.Replace(sql, "{{BASECHECK_MSSQL_TRACE_WATERMARK}}", buildMSSQLTraceWatermarkCondition(watermark), 1)
	case (strings.EqualFold(databaseType, "postgres") || strings.EqualFold(databaseType, "supabase")) && evidenceType == "audit_operations":
		return strings.Replace(sql, "{{BASECHECK_POSTGRES_STATEMENTS_WATERMARK}}", buildPostgresStatementsWatermarkCondition(watermark), 1)
	case strings.EqualFold(databaseType, "supabase") && evidenceType == "audit_operations_auth":
		return strings.Replace(sql, "{{BASECHECK_SUPABASE_AUTH_AUDIT_WATERMARK}}", buildSupabaseAuthAuditWatermarkCondition(watermark), 1)
	default:
		return sql
	}
}

func applyDefaultEvidenceWindow(databaseType, evidenceType, sql string) string {
	switch {
	case strings.EqualFold(databaseType, "oracle") && (evidenceType == "audit_operations" || evidenceType == "privilege_grant_history"):
		return strings.Replace(sql, "{{BASECHECK_ORACLE_UNIFIED_WATERMARK}}", "EVENT_TIMESTAMP > SYSTIMESTAMP - INTERVAL '30' DAY", 1)
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "audit_operations_traditional":
		return strings.Replace(sql, "{{BASECHECK_ORACLE_TRADITIONAL_WATERMARK}}", "EXTENDED_TIMESTAMP > SYSTIMESTAMP - INTERVAL '30' DAY", 1)
	case strings.EqualFold(databaseType, "mssql") && evidenceType == "audit_operations":
		return strings.Replace(sql, "{{BASECHECK_MSSQL_TRACE_WATERMARK}}", "te.StartTime > DATEADD(DAY, -30, GETDATE())", 1)
	case (strings.EqualFold(databaseType, "postgres") || strings.EqualFold(databaseType, "supabase")) && evidenceType == "audit_operations":
		return strings.Replace(sql, "{{BASECHECK_POSTGRES_STATEMENTS_WATERMARK}}", "COALESCE(pss.last_exec_time, NOW()) > NOW() - INTERVAL '30 days'", 1)
	case strings.EqualFold(databaseType, "supabase") && evidenceType == "audit_operations_auth":
		return strings.Replace(sql, "{{BASECHECK_SUPABASE_AUTH_AUDIT_WATERMARK}}", "created_at > NOW() - INTERVAL '30 days'", 1)
	default:
		return sql
	}
}

func buildOracleUnifiedWatermarkCondition(watermark map[string]interface{}) string {
	eventTimestamp := normalizeWatermarkTimestamp(watermark["event_timestamp"])
	entryID := toSQLInt(watermark["entry_id"])
	statementID := toSQLInt(watermark["statement_id"])
	if eventTimestamp == "" {
		return "EVENT_TIMESTAMP > SYSTIMESTAMP - INTERVAL '30' DAY"
	}
	return fmt.Sprintf(`(
    EVENT_TIMESTAMP > TO_TIMESTAMP('%s', 'YYYY-MM-DD"T"HH24:MI:SS')
    OR (EVENT_TIMESTAMP = TO_TIMESTAMP('%s', 'YYYY-MM-DD"T"HH24:MI:SS') AND (
        NVL(ENTRY_ID, -1) > %d
        OR (NVL(ENTRY_ID, -1) = %d AND NVL(STATEMENT_ID, -1) > %d)
    ))
)`, eventTimestamp, eventTimestamp, entryID, entryID, statementID)
}

func buildOracleTraditionalWatermarkCondition(watermark map[string]interface{}) string {
	eventTimestamp := normalizeWatermarkTimestamp(watermark["event_timestamp"])
	sessionID := toSQLInt(watermark["sessionid"])
	entryID := toSQLInt(watermark["entryid"])
	statementID := toSQLInt(watermark["statementid"])
	if eventTimestamp == "" {
		return "EXTENDED_TIMESTAMP > SYSTIMESTAMP - INTERVAL '30' DAY"
	}
	return fmt.Sprintf(`(
    EXTENDED_TIMESTAMP > TO_TIMESTAMP('%s', 'YYYY-MM-DD"T"HH24:MI:SS')
    OR (EXTENDED_TIMESTAMP = TO_TIMESTAMP('%s', 'YYYY-MM-DD"T"HH24:MI:SS') AND (
        NVL(SESSIONID, -1) > %d
        OR (NVL(SESSIONID, -1) = %d AND NVL(ENTRYID, -1) > %d)
        OR (NVL(SESSIONID, -1) = %d AND NVL(ENTRYID, -1) = %d AND NVL(STATEMENTID, -1) > %d)
    ))
)`, eventTimestamp, eventTimestamp, sessionID, sessionID, entryID, sessionID, entryID, statementID)
}

func buildMSSQLTraceWatermarkCondition(watermark map[string]interface{}) string {
	eventTimestamp := normalizeWatermarkTimestamp(watermark["event_timestamp"])
	eventClass := toSQLInt(watermark["event_class"])
	spid := toSQLInt(watermark["spid"])
	objectID := toSQLInt(watermark["object_id"])
	databaseID := toSQLInt(watermark["database_id"])
	if eventTimestamp == "" {
		return "te.StartTime > DATEADD(DAY, -30, GETDATE())"
	}
	return fmt.Sprintf(`(
    te.StartTime > CAST('%s' AS DATETIME)
    OR (te.StartTime = CAST('%s' AS DATETIME) AND (
        ISNULL(te.EventClass, -1) > %d
        OR (ISNULL(te.EventClass, -1) = %d AND ISNULL(te.SPID, -1) > %d)
        OR (ISNULL(te.EventClass, -1) = %d AND ISNULL(te.SPID, -1) = %d AND ISNULL(te.ObjectID, -1) > %d)
        OR (ISNULL(te.EventClass, -1) = %d AND ISNULL(te.SPID, -1) = %d AND ISNULL(te.ObjectID, -1) = %d AND ISNULL(te.DatabaseID, -1) > %d)
    ))
)`, eventTimestamp, eventTimestamp, eventClass, eventClass, spid, eventClass, spid, objectID, eventClass, spid, objectID, databaseID)
}

func buildPostgresStatementsWatermarkCondition(watermark map[string]interface{}) string {
	eventTimestamp := normalizeWatermarkTimestamp(watermark["event_timestamp"])
	queryID := toSQLInt(watermark["query_id"])
	userID := toSQLInt(watermark["user_id"])
	dbID := toSQLInt(watermark["dbid"])
	if eventTimestamp == "" {
		return "COALESCE(pss.last_exec_time, NOW()) > NOW() - INTERVAL '30 days'"
	}
	return fmt.Sprintf(`(
    COALESCE(pss.last_exec_time, NOW()) > TIMESTAMP '%s'
    OR (COALESCE(pss.last_exec_time, NOW()) = TIMESTAMP '%s' AND (
        COALESCE(pss.queryid, -1) > %d
        OR (COALESCE(pss.queryid, -1) = %d AND COALESCE(pss.userid, -1) > %d)
        OR (COALESCE(pss.queryid, -1) = %d AND COALESCE(pss.userid, -1) = %d AND COALESCE(pss.dbid, -1) > %d)
    ))
)`, eventTimestamp, eventTimestamp, queryID, queryID, userID, queryID, userID, dbID)
}

func buildSupabaseAuthAuditWatermarkCondition(watermark map[string]interface{}) string {
	eventTimestamp := normalizeWatermarkTimestamp(watermark["event_timestamp"])
	eventHash := normalizeWatermarkHash(watermark["event_hash"])
	if eventTimestamp == "" {
		return "created_at > NOW() - INTERVAL '30 days'"
	}
	if eventHash == "" {
		return fmt.Sprintf("created_at >= TIMESTAMP '%s'", eventTimestamp)
	}
	return fmt.Sprintf(`(
    created_at > TIMESTAMP '%s'
    OR (created_at = TIMESTAMP '%s' AND md5(COALESCE(payload::text, '')) > '%s')
)`, eventTimestamp, eventTimestamp, eventHash)
}

func calculateEvidenceWatermark(databaseType, evidenceType string, data []map[string]interface{}, currentWatermark string) string {
	if len(data) == 0 {
		return currentWatermark
	}
	lastRow := data[len(data)-1]
	watermark := map[string]interface{}{}
	switch {
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "audit_operations":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["entry_id"] = lastRow["ENTRY_ID"]
		watermark["statement_id"] = lastRow["STATEMENT_ID"]
		watermark["scn"] = lastRow["SCN"]
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "audit_operations_traditional":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["sessionid"] = lastRow["SESSIONID"]
		watermark["entryid"] = lastRow["ENTRYID"]
		watermark["statementid"] = lastRow["STATEMENTID"]
	case strings.EqualFold(databaseType, "oracle") && evidenceType == "privilege_grant_history":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["entry_id"] = lastRow["ENTRY_ID"]
		watermark["statement_id"] = lastRow["STATEMENT_ID"]
		watermark["scn"] = lastRow["SCN"]
	case strings.EqualFold(databaseType, "mssql") && evidenceType == "audit_operations":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["event_class"] = lastRow["EVENT_CLASS"]
		watermark["spid"] = lastRow["SPID"]
		watermark["object_id"] = lastRow["OBJECT_ID"]
		watermark["database_id"] = lastRow["DATABASE_ID"]
	case (strings.EqualFold(databaseType, "postgres") || strings.EqualFold(databaseType, "supabase")) && evidenceType == "audit_operations":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["query_id"] = lastRow["QUERY_ID"]
		watermark["user_id"] = lastRow["USER_ID"]
		watermark["dbid"] = lastRow["DBID"]
	case strings.EqualFold(databaseType, "supabase") && evidenceType == "audit_operations_auth":
		watermark["event_timestamp"] = toWatermarkTimestamp(lastRow["EVENT_TIMESTAMP"])
		watermark["event_hash"] = lastRow["EVENT_HASH"]
	default:
		return currentWatermark
	}

	dataBytes, err := json.Marshal(watermark)
	if err != nil {
		return currentWatermark
	}
	return string(dataBytes)
}

func toSQLString(value interface{}) string {
	if value == nil {
		return ""
	}
	stringValue := strings.TrimSpace(fmt.Sprintf("%v", value))
	stringValue = strings.TrimSuffix(stringValue, "Z")
	if strings.Contains(stringValue, ".") {
		stringValue = strings.SplitN(stringValue, ".", 2)[0]
	}
	if strings.Contains(stringValue, "+") {
		stringValue = strings.SplitN(stringValue, "+", 2)[0]
	}
	return stringValue
}

func normalizeWatermarkTimestamp(value interface{}) string {
	stringValue := toSQLString(value)
	if stringValue == "" {
		return ""
	}
	if matched := sqlWatermarkTimestampPattern.MatchString(stringValue); !matched {
		return ""
	}
	return stringValue
}

func normalizeWatermarkHash(value interface{}) string {
	stringValue := strings.TrimSpace(fmt.Sprintf("%v", value))
	if matched := sqlWatermarkHashPattern.MatchString(stringValue); !matched {
		return ""
	}
	return strings.ToLower(stringValue)
}

func validateActiveValidationHeader(key, value string) error {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return fmt.Errorf("active validation header name cannot be empty")
	}
	if strings.Contains(trimmedKey, ":") {
		return fmt.Errorf("active validation header name is invalid")
	}
	for _, currentRune := range trimmedKey {
		if currentRune <= 31 || currentRune == 127 {
			return fmt.Errorf("active validation header name is invalid")
		}
	}
	if strings.Contains(value, "\r") || strings.Contains(value, "\n") || strings.Contains(value, "\x00") {
		return fmt.Errorf("active validation header value is invalid")
	}
	return nil
}

func toSQLInt(value interface{}) int64 {
	if value == nil {
		return -1
	}
	switch currentValue := value.(type) {
	case int:
		return int64(currentValue)
	case int32:
		return int64(currentValue)
	case int64:
		return currentValue
	case float64:
		return int64(currentValue)
	case json.Number:
		parsedValue, _ := currentValue.Int64()
		return parsedValue
	default:
		parsedValue, err := strconv.ParseInt(fmt.Sprintf("%v", value), 10, 64)
		if err != nil {
			return -1
		}
		return parsedValue
	}
}

func toWatermarkTimestamp(value interface{}) string {
	return toSQLString(value)
}
