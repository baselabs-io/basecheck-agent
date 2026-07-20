package controlset

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"basecheck-agent/pkg/security"

	"gopkg.in/yaml.v3"
)

var ErrControlSetNotFound = errors.New("control set not found")

// backendControlSetResponse matches the JSON format returned by the backend API
type backendControlSetResponse struct {
	ControlSetID      string            `json:"control_set_id"`
	ControlSetVersion string            `json:"control_set_version"`
	DatabaseType      string            `json:"database_type"`
	ControlSetType    string            `json:"control_set_type"`
	Tier              string            `json:"tier,omitempty"`
	Signature         *backendSignature `json:"signature,omitempty"`
	Controls          []backendControl  `json:"controls"`
}

type backendSignature struct {
	Algorithm    string `json:"algorithm"`
	SignatureB64 string `json:"signature_b64"`
}

type backendControl struct {
	ControlID   string             `json:"control_id"`
	ControlCode string             `json:"control_code"`
	Category    string             `json:"category"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Remediation json.RawMessage    `json:"remediation,omitempty"`
	Procedures  []backendProcedure `json:"procedures"`
}

type backendProcedure struct {
	ProcedureID   string          `json:"procedure_id"`
	SystemType    string          `json:"system_type"`
	ExecutionMode string          `json:"execution_mode"`
	Tests         string          `json:"tests"`
	Criteria      json.RawMessage `json:"criteria"`
}

// Fetcher handles fetching control sets from various sources
type Fetcher struct {
	source            string // local or http
	localPath         string
	backendURL        string
	cachePath         string
	apiKey            string
	httpClient        *http.Client
	allowHTTP         bool // Allow insecure HTTP connections
	requireSignatures bool // Require valid signatures on control sets
	publicKey         string
	entitlement       Entitlement // Current entitlement for paid pack access (nil = free mode)
}

// Entitlement interface for checking pack access (avoids import cycle)
type Entitlement interface {
	IsExpired() bool
	AllowsTier(tier string) bool
	AllowsPack(packID string) bool
	CheckAccess(packID, packTier string) error
}

// NewFetcher creates a new control set fetcher
func NewFetcher(source, localPath, backendURL, cachePath, apiKey string, allowHTTP, requireSignatures bool, publicKey string) *Fetcher {
	return &Fetcher{
		source:            source,
		localPath:         localPath,
		backendURL:        backendURL,
		cachePath:         cachePath,
		apiKey:            apiKey,
		allowHTTP:         allowHTTP,
		requireSignatures: requireSignatures,
		publicKey:         publicKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetEntitlement sets the entitlement for paid pack access validation.
// Pass nil for free-only mode.
func (f *Fetcher) SetEntitlement(ent Entitlement) {
	f.entitlement = ent
}

// ErrEntitlementRequired is returned when a paid pack is requested without entitlement
var ErrEntitlementRequired = fmt.Errorf("entitlement required for paid control pack")

// ErrEntitlementExpired is returned when the entitlement has expired
var ErrEntitlementExpired = fmt.Errorf("entitlement expired")

// ErrPackNotEntitled is returned when the entitlement doesn't include the pack
var ErrPackNotEntitled = fmt.Errorf("control pack not in entitlement")

// ErrTierNotEntitled is returned when the entitlement tier is insufficient
var ErrTierNotEntitled = fmt.Errorf("entitlement tier insufficient for control pack")

// ErrUnknownTier is returned when a control pack has an unknown tier
var ErrUnknownPackTier = fmt.Errorf("control pack has unknown tier - refusing to execute")

// FetchControlSet fetches a control set for the specified database type
func (f *Fetcher) FetchControlSet(dbType, version string) (*ControlSet, error) {
	var set *ControlSet
	var err error

	switch f.source {
	case "local":
		set, err = f.fetchFromLocal(dbType)
	case "http":
		set, err = f.fetchFromHTTP(dbType, version)
	default:
		return nil, fmt.Errorf("unsupported control set source: %s", f.source)
	}

	if err != nil {
		return nil, err
	}

	// Check entitlement before allowing access to paid/enterprise packs
	if err := f.checkEntitlement(set); err != nil {
		return nil, err
	}

	// Enrich control set with evidence capture queries for all sources
	// Extract system type from dbType (remove -policy, -licensing, -discovery suffixes)
	systemType := dbType
	if len(dbType) > 10 && dbType[len(dbType)-10:] == "-discovery" {
		systemType = dbType[:len(dbType)-10]
	} else if len(dbType) > 7 && dbType[len(dbType)-7:] == "-policy" {
		systemType = dbType[:len(dbType)-7]
	} else if len(dbType) > 10 && dbType[len(dbType)-10:] == "-licensing" {
		systemType = dbType[:len(dbType)-10]
	}
	f.enrichWithEvidenceCapture(set, systemType)

	return set, nil
}

// checkEntitlement verifies the entitlement allows access to the control set.
// Enforcement rules:
//   - Free tier: always allowed, no entitlement needed
//   - Paid/Enterprise tier: requires valid, non-expired entitlement with matching pack and tier
//   - Unknown tier: fails closed (not executed)
func (f *Fetcher) checkEntitlement(set *ControlSet) error {
	// Check for unknown tier first - fail closed
	if !set.Metadata.IsValidTier() {
		return fmt.Errorf("%w: tier=%q, pack=%s",
			ErrUnknownPackTier, set.Metadata.Tier, set.Metadata.ControlSetID)
	}

	// Free tier packs are always allowed
	if set.Metadata.IsFree() {
		return nil
	}

	// Paid/Enterprise tier requires entitlement
	if f.entitlement == nil {
		return fmt.Errorf("%w: pack=%s requires tier=%s",
			ErrEntitlementRequired, set.Metadata.ControlSetID, set.Metadata.NormalizedTier())
	}

	// Check entitlement expiry
	if f.entitlement.IsExpired() {
		return fmt.Errorf("%w: pack=%s requires tier=%s",
			ErrEntitlementExpired, set.Metadata.ControlSetID, set.Metadata.NormalizedTier())
	}

	// Check tier level
	if !f.entitlement.AllowsTier(set.Metadata.NormalizedTier()) {
		return fmt.Errorf("%w: pack=%s requires tier=%s",
			ErrTierNotEntitled, set.Metadata.ControlSetID, set.Metadata.NormalizedTier())
	}

	// Check pack is in entitlement
	if !f.entitlement.AllowsPack(set.Metadata.ControlSetID) {
		return fmt.Errorf("%w: pack=%s not in entitlement",
			ErrPackNotEntitled, set.Metadata.ControlSetID)
	}

	return nil
}

// fetchFromLocal loads control set from local filesystem
func (f *Fetcher) fetchFromLocal(dbType string) (*ControlSet, error) {
	var pattern string

	// Check if this is a discovery control set (ends with "-discovery")
	if len(dbType) > 10 && dbType[len(dbType)-10:] == "-discovery" {
		// Discovery control set: oracle-discovery -> oracle-discovery-v*.yaml
		pattern = filepath.Join(f.localPath, fmt.Sprintf("%s-v*.yaml", dbType))
	} else {
		// Security control set: oracle -> oracle-controls-baseline-v*.yaml
		pattern = filepath.Join(f.localPath, fmt.Sprintf("%s-controls-baseline-v*.yaml", dbType))
	}

	// Find matching files
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search for control set files: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrControlSetNotFound, pattern)
	}

	// Use the first match (alphabetically sorted, so latest version if named consistently)
	setPath := matches[0]
	if len(matches) > 1 {
		fmt.Printf("⚠ Found %d control set files matching %s, using: %s\n", len(matches), pattern, filepath.Base(setPath))
	}

	// Load control set
	set, err := LoadControlSet(setPath)
	if err != nil {
		return nil, err
	}

	if set.Metadata.Signature.SignatureB64 != "" {
		if err := f.verifyControlSetSignature(set); err != nil {
			if f.requireSignatures {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
			fmt.Printf("⚠️  Warning: Local control set signature verification failed: %v\n", err)
		}
	} else if f.requireSignatures {
		return nil, fmt.Errorf("signature verification required but local control set has no signature - refusing to execute")
	}

	return set, nil
}

// fetchFromHTTP fetches control set from backend API
func (f *Fetcher) fetchFromHTTP(dbType, version string) (*ControlSet, error) {
	if err := security.ValidateHTTPS(f.backendURL, f.allowHTTP); err != nil {
		return nil, err
	}

	// Backend-first approach: Always try backend first to get latest control sets
	// Cache is only used as fallback when backend is unavailable

	// Extract system type and control set type from dbType parameter
	// Format: "oracle-discovery" -> systemType="oracle", controlSetType="discovery"
	// Format: "oracle-policy" -> systemType="oracle", controlSetType="policy"
	// Format: "oracle-licensing" -> systemType="oracle", controlSetType="licensing"
	// Format: "oracle" -> systemType="oracle", controlSetType="security"
	// Note: Keep original case for controlSetType (backend normalizes to lowercase in query)
	systemType := dbType
	controlSetType := "security"

	if len(dbType) > 10 && dbType[len(dbType)-10:] == "-discovery" {
		systemType = dbType[:len(dbType)-10]
		controlSetType = "discovery"
	} else if len(dbType) > 7 && dbType[len(dbType)-7:] == "-policy" {
		systemType = dbType[:len(dbType)-7]
		controlSetType = "policy"
	} else if len(dbType) > 10 && dbType[len(dbType)-10:] == "-licensing" {
		systemType = dbType[:len(dbType)-10]
		controlSetType = "licensing"
	}

	// Backend normalizes to lowercase in AgentGatewayController.java:165
	// so lowercase is correct here

	// Build API URL
	url := fmt.Sprintf("%s/api/agent/controlsets?systemType=%s&controlSetType=%s",
		f.backendURL, systemType, controlSetType)

	if version != "" {
		url += fmt.Sprintf("&version=%s", version)
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add agent token header
	if f.apiKey != "" {
		req.Header.Set("X-Agent-Token", f.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := f.httpClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		// Backend fetch failed - try to use cache even if expired (fallback for resilience)
		fmt.Printf("⚠ Backend fetch failed: %v\n", err)
		if cachedSet, err := f.loadFromCacheIgnoreExpiry(dbType, version); err == nil {
			fmt.Printf("✓ Using expired cache as fallback (backend unavailable)\n")
			return cachedSet, nil
		}
		return nil, fmt.Errorf("failed to fetch control set and no cache available: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		// Backend returned error - try to use cache even if expired
		fmt.Printf("⚠ Backend returned status %d: %s\n", resp.StatusCode, string(body))
		if cachedSet, err := f.loadFromCacheIgnoreExpiry(dbType, version); err == nil {
			fmt.Printf("✓ Using expired cache as fallback (backend error)\n")
			return cachedSet, nil
		}

		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse backend response
	var backendResp backendControlSetResponse
	if err := json.Unmarshal(body, &backendResp); err != nil {
		return nil, fmt.Errorf("failed to parse control set: %w", err)
	}

	// Convert backend response to ControlSet before verification so HTTP and cache use the same signed payload.
	set := f.convertBackendResponse(&backendResp)

	// Verify signature if present
	if backendResp.Signature != nil {
		canonicalPayload, err := f.createCanonicalPayload(set)
		if err != nil {
			return nil, err
		}
		if err := f.verifySignature(canonicalPayload, backendResp.Signature.SignatureB64); err != nil {
			if f.requireSignatures {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
			fmt.Printf("⚠️  Warning: Signature verification failed: %v\n", err)
		}
	} else if f.requireSignatures {
		return nil, fmt.Errorf("signature verification required but control set has no signature - refusing to execute")
	}

	// Cache the downloaded control set
	if err := f.saveToCache(set, dbType, version); err != nil {
		// Log warning but don't fail
		fmt.Printf("Warning: failed to cache control set: %v\n", err)
	}

	return set, nil
}

// loadFromCacheIgnoreExpiry loads cache without checking expiry (for fallback)
func (f *Fetcher) loadFromCacheIgnoreExpiry(dbType, version string) (*ControlSet, error) {
	if f.cachePath == "" {
		return nil, fmt.Errorf("cache path not configured")
	}

	// Use "latest" as cache key if no specific version requested
	cacheVersion := version
	if cacheVersion == "" {
		cacheVersion = "latest"
	}

	cacheFile := filepath.Join(f.cachePath, fmt.Sprintf("%s-%s.yaml", dbType, cacheVersion))

	// Check if cache file exists
	if _, err := os.Stat(cacheFile); err != nil {
		return nil, err
	}

	// Load control set from cache
	set, err := LoadControlSet(cacheFile)
	if err != nil {
		return nil, err
	}

	if set.Metadata.Signature.SignatureB64 != "" {
		if err := f.verifyControlSetSignature(set); err != nil {
			if f.requireSignatures {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
		}
	} else if f.requireSignatures {
		return nil, fmt.Errorf("signature verification required but cached control set has no signature - refusing to execute")
	}

	return set, nil
}

// loadFromCache attempts to load control set from cache
func (f *Fetcher) loadFromCache(dbType, version string) (*ControlSet, error) {
	if f.cachePath == "" {
		return nil, fmt.Errorf("cache path not configured")
	}

	// Use "latest" as cache key if no specific version requested
	cacheVersion := version
	if cacheVersion == "" {
		cacheVersion = "latest"
	}

	cacheFile := filepath.Join(f.cachePath, fmt.Sprintf("%s-%s.yaml", dbType, cacheVersion))

	// Check if cache file exists and is recent (< 7 days for safety)
	info, err := os.Stat(cacheFile)
	if err != nil {
		return nil, err
	}

	// If cache is older than 7 days, don't use it (production safety)
	if time.Since(info.ModTime()) > 7*24*time.Hour {
		return nil, fmt.Errorf("cache expired (> 7 days)")
	}

	// Load control set from cache
	set, err := LoadControlSet(cacheFile)
	if err != nil {
		return nil, err
	}

	if set.Metadata.Signature.SignatureB64 != "" {
		if err := f.verifyControlSetSignature(set); err != nil {
			if f.requireSignatures {
				return nil, fmt.Errorf("signature verification failed: %w", err)
			}
			fmt.Printf("⚠️  Warning: Cached control set signature verification failed: %v\n", err)
		}
	} else if f.requireSignatures {
		return nil, fmt.Errorf("signature verification required but cached control set has no signature - refusing to execute")
	}

	return set, nil
}

// saveToCache saves control set to cache
func (f *Fetcher) saveToCache(set *ControlSet, dbType, version string) error {
	if f.cachePath == "" {
		return nil
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(f.cachePath, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Use "latest" as cache key if no specific version requested
	cacheVersion := version
	if cacheVersion == "" {
		cacheVersion = "latest"
	}

	cacheFile := filepath.Join(f.cachePath, fmt.Sprintf("%s-%s.yaml", dbType, cacheVersion))

	// Marshal to YAML
	data, err := yaml.Marshal(set)
	if err != nil {
		return fmt.Errorf("failed to marshal control set: %w", err)
	}

	// Write to file (secure permissions)
	if err := os.WriteFile(cacheFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// createCanonicalPayload creates the signed representation of the control set.
func (f *Fetcher) createCanonicalPayload(set *ControlSet) ([]byte, error) {
	return marshalCanonical(f.canonicalControlSet(set))
}

// verifyControlSetSignature verifies the signature of a loaded ControlSet
func (f *Fetcher) verifyControlSetSignature(set *ControlSet) error {
	data, err := f.createCanonicalPayload(set)
	if err != nil {
		return fmt.Errorf("failed to marshal control set: %w", err)
	}

	return f.verifySignature(data, set.Metadata.Signature.SignatureB64)
}

type canonicalControlSet struct {
	ControlSetID      string `json:"control_set_id"`
	ControlSetVersion string `json:"control_set_version"`
	DatabaseType      string `json:"database_type"`
	ControlSetType    string `json:"control_set_type"`
	Tier              string `json:"tier,omitempty"`
	// DatabaseVersions and Compatibility are signed because CheckCompatibility
	// (compatibility.go) uses them to decide whether a pack executes at all.
	// Omitting them would let agent/database version constraints be tampered
	// with after signing without invalidating the signature.
	DatabaseVersions []string               `json:"database_versions,omitempty"`
	Compatibility    canonicalCompatibility `json:"compatibility,omitempty"`
	Controls         []canonicalControl     `json:"controls"`
}

// canonicalCompatibility is the signed representation of ControlSet.Compatibility.
type canonicalCompatibility struct {
	AgentMinVersion    string   `json:"agent_min_version,omitempty"`
	AgentMaxVersion    string   `json:"agent_max_version,omitempty"`
	RequiresPrivileges []string `json:"requires_privileges,omitempty"`
}

type canonicalControl struct {
	ControlID   string                `json:"control_id"`
	ControlCode string                `json:"control_code"`
	Category    string                `json:"category"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	Remediation *canonicalRemediation `json:"remediation,omitempty"`
	Procedures  []canonicalProcedure  `json:"procedures"`
	// EvidenceCapture is signed because ExecuteControl runs its SQL against the
	// customer database after control procedures (see executor.go). Omitting it
	// would let evidence-capture SQL be modified after signing without
	// invalidating the signature.
	EvidenceCapture []canonicalEvidence `json:"evidence_capture,omitempty"`
}

type canonicalRemediation struct {
	Summary        string   `json:"summary"`
	Steps          []string `json:"steps"`
	RemediationSQL string   `json:"remediation_sql"`
}

type canonicalProcedure struct {
	ProcedureID         string              `json:"procedure_id"`
	SystemType          string              `json:"system_type"`
	SystemApplicability string              `json:"system_applicability,omitempty"`
	ExecutionMode       string              `json:"execution_mode"`
	Tests               string              `json:"tests"`
	Criteria            []canonicalCriteria `json:"criteria"`
}

type canonicalCriteria struct {
	Condition           string `json:"condition"`
	Severity            string `json:"severity"`
	FindingTitle        string `json:"finding_title"`
	ComplianceFramework string `json:"compliance_framework"`
	AttributeMapping    bool   `json:"attribute_mapping"`
}

// canonicalEvidence is the signed representation of an executable evidence
// capture query (Control.EvidenceCapture). SQL is executable and must be
// covered by the signature exactly like procedure Tests.
type canonicalEvidence struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	SQL         string `json:"sql"`
	SourceMode  string `json:"source_mode"`
	SourcePath  string `json:"source_path"`
}

func (f *Fetcher) canonicalControlSet(set *ControlSet) canonicalControlSet {
	controls := append([]Control(nil), set.Controls...)
	sort.SliceStable(controls, func(i, j int) bool {
		left := strings.TrimSpace(controls[i].ControlCode)
		right := strings.TrimSpace(controls[j].ControlCode)
		if left == right {
			return strings.TrimSpace(controls[i].ControlID) < strings.TrimSpace(controls[j].ControlID)
		}
		return left < right
	})

	result := make([]canonicalControl, 0, len(controls))
	for _, control := range controls {
		controlID := strings.TrimSpace(control.ControlCode)
		if controlID == "" {
			controlID = strings.TrimSpace(control.ControlID)
		}

		item := canonicalControl{
			ControlID:       controlID,
			ControlCode:     controlID,
			Category:        strings.TrimSpace(control.Category),
			Title:           strings.TrimSpace(control.Title),
			Description:     strings.TrimSpace(control.Description),
			Procedures:      f.canonicalProcedures(control.Procedures),
			EvidenceCapture: f.canonicalEvidenceCapture(control.EvidenceCapture),
		}
		if !isZeroRemediation(control.Remediation) {
			item.Remediation = &canonicalRemediation{
				Summary:        strings.TrimSpace(control.Remediation.Summary),
				Steps:          control.Remediation.Steps,
				RemediationSQL: strings.TrimSpace(control.Remediation.RemediationSQL),
			}
		}
		result = append(result, item)
	}

	return canonicalControlSet{
		ControlSetID:      strings.TrimSpace(set.Metadata.ControlSetID),
		ControlSetVersion: strings.TrimSpace(set.Metadata.ControlSetVersion),
		DatabaseType:      strings.TrimSpace(set.Metadata.DatabaseType),
		ControlSetType:    defaultControlSetType(set.Metadata.ControlSetType),
		Tier:              strings.TrimSpace(set.Metadata.Tier),
		DatabaseVersions:  canonicalStringList(set.Metadata.DatabaseVersions),
		Compatibility: canonicalCompatibility{
			AgentMinVersion:    strings.TrimSpace(set.Compatibility.AgentMinVersion),
			AgentMaxVersion:    strings.TrimSpace(set.Compatibility.AgentMaxVersion),
			RequiresPrivileges: canonicalStringList(set.Compatibility.RequiresPrivileges),
		},
		Controls: result,
	}
}

// canonicalStringList trims each entry and sorts the result so that
// reordering a list without changing its content does not change the
// canonical payload, while returning nil (omitted from JSON) for an empty list.
func canonicalStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func (f *Fetcher) canonicalProcedures(procedures []ControlProcedure) []canonicalProcedure {
	current := append([]ControlProcedure(nil), procedures...)
	sort.SliceStable(current, func(i, j int) bool {
		return strings.TrimSpace(current[i].ProcedureID) < strings.TrimSpace(current[j].ProcedureID)
	})

	result := make([]canonicalProcedure, 0, len(current))
	for _, procedure := range current {
		result = append(result, canonicalProcedure{
			ProcedureID:         strings.TrimSpace(procedure.ProcedureID),
			SystemType:          strings.TrimSpace(procedure.SystemType),
			SystemApplicability: strings.TrimSpace(procedure.SystemApplicability),
			ExecutionMode:       defaultExecutionMode(procedure.ExecutionMode),
			Tests:               strings.TrimSpace(procedure.Tests),
			Criteria:            f.canonicalCriteria(procedure.Criteria),
		})
	}
	return result
}

func (f *Fetcher) canonicalCriteria(criteria []ControlCriteria) []canonicalCriteria {
	result := make([]canonicalCriteria, 0, len(criteria))
	for _, item := range criteria {
		result = append(result, canonicalCriteria{
			Condition:           strings.TrimSpace(item.Condition),
			Severity:            strings.TrimSpace(item.Severity),
			FindingTitle:        strings.TrimSpace(item.FindingTitle),
			ComplianceFramework: strings.TrimSpace(item.ComplianceFramework),
			AttributeMapping:    item.AttributeMapping,
		})
	}
	return result
}

func (f *Fetcher) canonicalEvidenceCapture(evidence []Evidence) []canonicalEvidence {
	if len(evidence) == 0 {
		return nil
	}

	result := make([]canonicalEvidence, 0, len(evidence))
	for _, item := range evidence {
		result = append(result, canonicalEvidence{
			Type:        strings.TrimSpace(item.Type),
			Description: strings.TrimSpace(item.Description),
			SQL:         strings.TrimSpace(item.SQL),
			SourceMode:  strings.TrimSpace(item.SourceMode),
			SourcePath:  strings.TrimSpace(item.SourcePath),
		})
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		if result[i].SourcePath != result[j].SourcePath {
			return result[i].SourcePath < result[j].SourcePath
		}
		return result[i].SQL < result[j].SQL
	})

	return result
}

func marshalCanonical(value interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("failed to marshal canonical payload: %w", err)
	}
	return bytes.TrimSpace(buffer.Bytes()), nil
}

func defaultExecutionMode(value string) string {
	current := strings.TrimSpace(value)
	if current == "" {
		return "sql"
	}
	return current
}

func defaultControlSetType(value string) string {
	current := strings.TrimSpace(value)
	if current == "" {
		return "Security"
	}
	return current
}

func isZeroRemediation(remediation Remediation) bool {
	return strings.TrimSpace(remediation.Summary) == "" &&
		len(remediation.Steps) == 0 &&
		strings.TrimSpace(remediation.RemediationSQL) == ""
}

// verifySignature verifies the RSA signature of the control set
func (f *Fetcher) verifySignature(data []byte, signatureB64 string) error {
	if strings.TrimSpace(f.publicKey) == "" {
		return fmt.Errorf("no public key configured")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(f.publicKey))
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Compute SHA256 hash of the data
	hash := sha256.Sum256(data)

	// Verify signature
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// convertBackendResponse converts backend JSON format to internal ControlSet format
func (f *Fetcher) convertBackendResponse(backendResp *backendControlSetResponse) *ControlSet {
	set := &ControlSet{
		Metadata: Metadata{
			ControlSetID:      backendResp.ControlSetID,
			ControlSetVersion: backendResp.ControlSetVersion,
			DatabaseType:      backendResp.DatabaseType,
			ControlSetType:    backendResp.ControlSetType,
			Tier:              backendResp.Tier,
		},
		Controls: make([]Control, len(backendResp.Controls)),
	}

	// Add signature to metadata if present
	if backendResp.Signature != nil {
		set.Metadata.Signature = Signature{
			Algorithm:    backendResp.Signature.Algorithm,
			SignatureB64: backendResp.Signature.SignatureB64,
		}
	}

	// Convert controls
	for i, backendCtrl := range backendResp.Controls {
		ctrl := Control{
			ControlID:   backendCtrl.ControlID,
			ControlCode: backendCtrl.ControlCode,
			Category:    backendCtrl.Category,
			Title:       backendCtrl.Title,
			Description: backendCtrl.Description,
			Procedures:  make([]ControlProcedure, len(backendCtrl.Procedures)),
		}

		// Parse remediation JSON if present.
		if len(backendCtrl.Remediation) > 0 {
			rawRemediation := bytes.TrimSpace(backendCtrl.Remediation)

			// Backend may return remediation as a JSON-encoded string containing JSON.
			if len(rawRemediation) > 0 && rawRemediation[0] == '"' {
				var remediationString string
				if err := json.Unmarshal(rawRemediation, &remediationString); err == nil {
					rawRemediation = []byte(remediationString)
				}
			}

			var remediation Remediation
			if err := json.Unmarshal(rawRemediation, &remediation); err == nil {
				ctrl.Remediation = remediation
			}
		}

		// Convert procedures
		for j, backendProc := range backendCtrl.Procedures {
			proc := ControlProcedure{
				ProcedureID:   backendProc.ProcedureID,
				SystemType:    backendProc.SystemType,
				ExecutionMode: backendProc.ExecutionMode,
				Tests:         backendProc.Tests,
			}

			// Parse criteria JSON if present
			if len(backendProc.Criteria) > 0 {
				rawCriteria := bytes.TrimSpace(backendProc.Criteria)

				// Backend may return criteria as a JSON-encoded string containing JSON.
				if len(rawCriteria) > 0 && rawCriteria[0] == '"' {
					var criteriaString string
					if err := json.Unmarshal(rawCriteria, &criteriaString); err == nil {
						rawCriteria = []byte(criteriaString)
					}
				}

				var criteria []ControlCriteria
				if err := json.Unmarshal(rawCriteria, &criteria); err == nil {
					proc.Criteria = criteria
				} else {
					// Support legacy single-object criteria payloads.
					var singleCriteria ControlCriteria
					if singleErr := json.Unmarshal(rawCriteria, &singleCriteria); singleErr == nil {
						proc.Criteria = []ControlCriteria{singleCriteria}
					}
				}
			}

			ctrl.Procedures[j] = proc
		}

		set.Controls[i] = ctrl
	}

	return set
}

// enrichWithEvidenceCapture adds evidence capture queries to controls
// This collects audit trail data (statements and privilege changes)
func (f *Fetcher) enrichWithEvidenceCapture(set *ControlSet, systemType string) {
	fmt.Printf("→ Enriching control set with evidence capture (systemType=%s, controls=%d)\n", systemType, len(set.Controls))

	// Support multiple database types
	switch systemType {
	case "oracle":
		f.enrichOracleAuditTrail(set)
	case "postgres", "postgresql":
		f.enrichPostgresAuditTrail(set)
	case "supabase":
		f.enrichSupabaseAuditTrail(set)
	case "mssql", "sqlserver":
		f.enrichMSSQLAuditTrail(set)
	default:
		fmt.Printf("  ⚠ Audit trail evidence capture not yet implemented for: %s\n", systemType)
		return
	}
}

// enrichOracleAuditTrail adds Oracle audit trail evidence capture
func (f *Fetcher) enrichOracleAuditTrail(set *ControlSet) {
	// Add evidence capture to Security control set
	// These queries collect audit trail data for display in UI
	enriched := 0
	for i := range set.Controls {
		control := &set.Controls[i]

		// Add audit operations, privilege changes, AND system attributes to ORA-SEC-004
		if control.ControlCode == "ORA-SEC-004" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (audit ops, privileges, attributes) to %s\n", control.ControlCode)

			// Primary: UNIFIED_AUDIT_TRAIL (Oracle 12c+)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations",
				Description: "Recent database operations from unified audit trail",
				SQL: `SELECT
    EVENT_TIMESTAMP,
    ENTRY_ID,
    STATEMENT_ID,
    SCN,
    DBUSERNAME,
    ACTION_NAME AS OPERATION,
    OBJECT_SCHEMA,
    OBJECT_NAME,
    OBJECT_TYPE,
    SQL_TEXT AS STATEMENT,
    TO_CHAR(RETURN_CODE) AS STATUS,
    USERHOST AS CLIENT_HOST,
    OS_PROGRAM AS CLIENT_PROGRAM,
    DBID || '_' || SYS_CONTEXT('USERENV', 'DB_NAME') AS DATABASE_NAME
FROM UNIFIED_AUDIT_TRAIL
WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}
  AND ACTION_NAME IN (
    -- DDL: Table Operations
    'CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'TRUNCATE TABLE',
    -- DDL: Index Operations
    'CREATE INDEX', 'DROP INDEX', 'ALTER INDEX',
    -- DDL: User/Role Management
    'CREATE USER', 'ALTER USER', 'DROP USER',
    'CREATE ROLE', 'ALTER ROLE', 'DROP ROLE',
    -- DDL: View Operations
    'CREATE VIEW', 'DROP VIEW',
    -- DDL: Procedure/Function Operations
    'CREATE PROCEDURE', 'DROP PROCEDURE', 'ALTER PROCEDURE',
    'CREATE FUNCTION', 'DROP FUNCTION', 'ALTER FUNCTION',
    'CREATE PACKAGE', 'DROP PACKAGE', 'ALTER PACKAGE',
    'CREATE TRIGGER', 'DROP TRIGGER', 'ALTER TRIGGER',
    -- DDL: Database Link Operations
    'CREATE DATABASE LINK', 'DROP DATABASE LINK',
    -- DDL: Tablespace Operations
    'CREATE TABLESPACE', 'DROP TABLESPACE', 'ALTER TABLESPACE',
    -- DDL: System/Database Operations
    'ALTER SYSTEM', 'ALTER DATABASE', 'ALTER SESSION',
    -- DCL: Grant/Revoke Operations
    'GRANT', 'REVOKE',
    -- DML: Data Modification (for context)
    'INSERT', 'UPDATE', 'DELETE', 'SELECT', 'MERGE'
  )
  AND DBUSERNAME <> 'AUDSYS'
  AND RETURN_CODE = 0
ORDER BY EVENT_TIMESTAMP ASC, ENTRY_ID ASC, STATEMENT_ID ASC
FETCH FIRST 1000 ROWS ONLY`,
			})

			// Fallback: DBA_AUDIT_TRAIL (Traditional auditing for Oracle < 12c)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations_traditional",
				Description: "Recent database operations from traditional audit trail (fallback)",
				SQL: `SELECT
    EXTENDED_TIMESTAMP AS EVENT_TIMESTAMP,
    SESSIONID,
    ENTRYID,
    STATEMENTID,
    USERNAME AS DBUSERNAME,
    ACTION_NAME AS OPERATION,
    OWNER AS OBJECT_SCHEMA,
    OBJ_NAME AS OBJECT_NAME,
    'DATABASE OBJECT' AS OBJECT_TYPE,
    SQL_TEXT AS STATEMENT,
    TO_CHAR(RETURNCODE) AS STATUS,
    USERHOST AS CLIENT_HOST,
    TERMINAL AS CLIENT_PROGRAM,
    SYS_CONTEXT('USERENV', 'DB_NAME') AS DATABASE_NAME
FROM DBA_AUDIT_TRAIL
WHERE {{BASECHECK_ORACLE_TRADITIONAL_WATERMARK}}
  AND ACTION_NAME IN (
    -- DDL: Table Operations
    'CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'TRUNCATE TABLE',
    -- DDL: Index Operations
    'CREATE INDEX', 'DROP INDEX', 'ALTER INDEX',
    -- DDL: User/Role Management
    'CREATE USER', 'ALTER USER', 'DROP USER',
    'CREATE ROLE', 'ALTER ROLE', 'DROP ROLE',
    -- DDL: View Operations
    'CREATE VIEW', 'DROP VIEW',
    -- DDL: Procedure/Function Operations
    'CREATE PROCEDURE', 'DROP PROCEDURE', 'ALTER PROCEDURE',
    'CREATE FUNCTION', 'DROP FUNCTION', 'ALTER FUNCTION',
    'CREATE PACKAGE', 'DROP PACKAGE', 'ALTER PACKAGE',
    'CREATE TRIGGER', 'DROP TRIGGER', 'ALTER TRIGGER',
    -- DDL: Database Link Operations
    'CREATE DATABASE LINK', 'DROP DATABASE LINK',
    -- DDL: Tablespace Operations
    'CREATE TABLESPACE', 'DROP TABLESPACE', 'ALTER TABLESPACE',
    -- DDL: System/Database Operations
    'ALTER SYSTEM', 'ALTER DATABASE', 'ALTER SESSION',
    -- DCL: Grant/Revoke Operations
    'GRANT', 'REVOKE',
    -- DML: Data Modification (for context)
    'INSERT', 'UPDATE', 'DELETE', 'SELECT', 'MERGE'
  )
  AND USERNAME <> 'AUDSYS'
  AND RETURNCODE = 0
ORDER BY EXTENDED_TIMESTAMP ASC, SESSIONID ASC, ENTRYID ASC, STATEMENTID ASC
FETCH FIRST 1000 ROWS ONLY`,
			})

			// Privilege Grant History from Unified Audit Trail
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "privilege_grant_history",
				Description: "Recent privilege grants from unified audit trail",
				SQL: `SELECT
    EVENT_TIMESTAMP,
    ENTRY_ID,
    STATEMENT_ID,
    SCN,
    DBUSERNAME AS GRANTOR,
    OBJECT_NAME AS GRANTEE,
    SQL_TEXT AS STATEMENT,
    OBJECT_SCHEMA,
    OBJECT_NAME AS NAME,
    'GRANT' AS ACTION,
    OBJECT_TYPE,
    TO_CHAR(RETURN_CODE) AS STATUS,
    USERHOST AS CLIENT_HOST,
    SYS_CONTEXT('USERENV', 'DB_NAME') AS DATABASE_NAME
FROM UNIFIED_AUDIT_TRAIL
WHERE {{BASECHECK_ORACLE_UNIFIED_WATERMARK}}
  AND ACTION_NAME = 'GRANT'
  AND (
    UPPER(SQL_TEXT) LIKE '%GRANT DBA%' OR
    UPPER(SQL_TEXT) LIKE '%GRANT SYSDBA%' OR
    UPPER(SQL_TEXT) LIKE '%GRANT SYSOPER%' OR
    UPPER(SQL_TEXT) LIKE '%CREATE ANY%' OR
    UPPER(SQL_TEXT) LIKE '%DROP ANY%' OR
    UPPER(SQL_TEXT) LIKE '%ALTER ANY%' OR
    UPPER(SQL_TEXT) LIKE '%DELETE ANY%' OR
    UPPER(SQL_TEXT) LIKE '%SELECT ANY%' OR
    UPPER(SQL_TEXT) LIKE '%UNLIMITED TABLESPACE%' OR
    UPPER(SQL_TEXT) LIKE '%BECOME USER%' OR
    UPPER(SQL_TEXT) LIKE '%EXEMPT ACCESS POLICY%'
  )
  AND DBUSERNAME <> 'AUDSYS'
  AND RETURN_CODE = 0
ORDER BY EVENT_TIMESTAMP ASC, ENTRY_ID ASC, STATEMENT_ID ASC
FETCH FIRST 500 ROWS ONLY`,
			})

			// Current System Privileges Snapshot
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "privilege_changes",
				Description: "Current system privileges granted to users",
				SQL: `SELECT
    SYSDATE AS EVENT_TIMESTAMP,
    GRANTEE,
    PRIVILEGE AS NAME,
    'GRANT' AS ACTION,
    'SYSTEM' AS GRANTOR,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    'SYSTEM PRIVILEGE' AS OBJECT_TYPE,
    'GRANT ' || PRIVILEGE || ' TO ' || GRANTEE AS STATEMENT,
    ADMIN_OPTION AS STATUS,
    SYS_CONTEXT('USERENV', 'DB_NAME') AS DATABASE_NAME
FROM DBA_SYS_PRIVS
WHERE GRANTEE NOT IN ('SYS', 'SYSTEM', 'PUBLIC', 'DBA', 'RESOURCE', 'CONNECT')
ORDER BY GRANTEE, PRIVILEGE
FETCH FIRST 1000 ROWS ONLY`,
			})

			// Current Role Grants (including DBA role)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "role_grants",
				Description: "Current role grants to users (including DBA)",
				SQL: `SELECT
    SYSDATE AS EVENT_TIMESTAMP,
    GRANTEE,
    GRANTED_ROLE AS NAME,
    'GRANT' AS ACTION,
    'SYSTEM' AS GRANTOR,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    'ROLE' AS OBJECT_TYPE,
    'GRANT ' || GRANTED_ROLE || ' TO ' || GRANTEE AS STATEMENT,
    ADMIN_OPTION AS STATUS,
    SYS_CONTEXT('USERENV', 'DB_NAME') AS DATABASE_NAME
FROM DBA_ROLE_PRIVS
WHERE GRANTEE NOT IN ('SYS', 'SYSTEM', 'PUBLIC')
  AND GRANTED_ROLE IN ('DBA', 'SYSDBA', 'SYSOPER', 'RESOURCE', 'SELECT_CATALOG_ROLE',
                        'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE')
ORDER BY GRANTEE, GRANTED_ROLE
FETCH FIRST 500 ROWS ONLY`,
			})

			// Add database configuration parameters (not object counts)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "system_attributes",
				Description: "Database configuration parameters and settings",
				SQL: `SELECT UPPER(NAME) AS ATTRIBUTE_NAME, VALUE AS ATTRIBUTE_VALUE,
       CASE WHEN ISDEFAULT = 'TRUE' THEN 'text (default)' ELSE 'text (modified)' END AS ATTRIBUTE_TYPE,
       'Database Parameters' AS CATEGORY
FROM V$PARAMETER
WHERE NAME IN (
    'db_name', 'db_unique_name', 'db_domain', 'instance_name', 'service_names',
    'memory_target', 'memory_max_target', 'sga_target', 'sga_max_size', 'pga_aggregate_target',
    'processes', 'sessions', 'db_block_size', 'db_cache_size',
    'log_archive_dest_1', 'log_archive_format', 'log_buffer',
    'undo_management', 'undo_tablespace', 'undo_retention',
    'audit_trail', 'audit_sys_operations', 'audit_file_dest',
    'remote_login_passwordfile', 'sec_case_sensitive_logon', 'sec_max_failed_login_attempts',
    'password_life_time', 'password_reuse_time', 'password_lock_time',
    'control_files', 'db_recovery_file_dest', 'db_recovery_file_dest_size',
    'compatible', 'nls_language', 'nls_territory', 'nls_characterset',
    'open_cursors', 'cursor_sharing', 'optimizer_mode',
    'db_create_file_dest', 'db_create_online_log_dest_1'
)
ORDER BY NAME`,
			})
			fmt.Printf("    → Added %d system attributes to evidence capture\n", 33)
		}

		// Add RMAN backup history to ORA-POL-006 (Recent Backup Exists)
		if control.ControlCode == "ORA-POL-006" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (RMAN backup history) to %s\n", control.ControlCode)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "backup_history",
				Description: "Recent RMAN backup history",
				SQL: `SELECT
    TO_CHAR(START_TIME, 'YYYY-MM-DD HH24:MI:SS') AS BACKUP_START_TIME,
    TO_CHAR(END_TIME, 'YYYY-MM-DD HH24:MI:SS') AS BACKUP_END_TIME,
    INPUT_TYPE AS BACKUP_TYPE,
    STATUS AS BACKUP_STATUS,
    ROUND(INPUT_BYTES/1024/1024/1024, 2) AS SIZE_GB,
    ROUND(OUTPUT_BYTES/1024/1024/1024, 2) AS OUTPUT_SIZE_GB,
    TIME_TAKEN_DISPLAY AS DURATION,
    INPUT_BYTES_DISPLAY AS INPUT_SIZE,
    OUTPUT_BYTES_DISPLAY AS OUTPUT_SIZE
FROM V$RMAN_BACKUP_JOB_DETAILS
WHERE START_TIME > SYSDATE - 30
ORDER BY START_TIME DESC
FETCH FIRST 100 ROWS ONLY`,
			})
		}

		// Add tablespace usage to ORA-POL-018 (Tablespace Usage Under Threshold)
		if control.ControlCode == "ORA-POL-018" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (tablespace usage) to %s\n", control.ControlCode)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "tablespace_usage",
				Description: "Tablespace usage statistics",
				SQL: `SELECT
    TABLESPACE_NAME,
    ROUND(USED_SPACE * 8192 / 1024 / 1024 / 1024, 2) AS USED_GB,
    ROUND(TABLESPACE_SIZE * 8192 / 1024 / 1024 / 1024, 2) AS TOTAL_GB,
    ROUND(USED_PERCENT, 2) AS USED_PERCENT,
    ROUND((TABLESPACE_SIZE - USED_SPACE) * 8192 / 1024 / 1024 / 1024, 2) AS FREE_GB,
    CASE
        WHEN USED_PERCENT > 90 THEN 'CRITICAL'
        WHEN USED_PERCENT > 80 THEN 'WARNING'
        ELSE 'OK'
    END AS STATUS
FROM DBA_TABLESPACE_USAGE_METRICS
ORDER BY USED_PERCENT DESC`,
			})
		}

		// Add patch history to ORA-POL-009 (Recent Patch Set Update Applied)
		if control.ControlCode == "ORA-POL-009" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (patch history) to %s\n", control.ControlCode)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "patch_history",
				Description: "Installed Oracle patches and bug fixes",
				SQL: `SELECT
    PATCH_ID,
    PATCH_UID,
    PATCH_TYPE,
    ACTION,
    STATUS,
    DESCRIPTION,
    TO_CHAR(ACTION_TIME, 'YYYY-MM-DD HH24:MI:SS') AS INSTALLED_DATE,
    BUNDLE_SERIES AS PATCH_BUNDLE
FROM DBA_REGISTRY_SQLPATCH
ORDER BY ACTION_TIME DESC
FETCH FIRST 50 ROWS ONLY`,
			})
		}

		// Add feature usage to ORA-LIC-001 (Partitioning Option Usage)
		if control.ControlCode == "ORA-LIC-001" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (feature usage stats) to %s\n", control.ControlCode)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "feature_usage",
				Description: "Oracle feature and option usage statistics",
				SQL: `SELECT
    NAME AS FEATURE_NAME,
    VERSION AS ORACLE_VERSION,
    DETECTED_USAGES AS USAGE_COUNT,
    CURRENTLY_USED AS IS_CURRENTLY_USED,
    TO_CHAR(FIRST_USAGE_DATE, 'YYYY-MM-DD HH24:MI:SS') AS FIRST_USED,
    TO_CHAR(LAST_USAGE_DATE, 'YYYY-MM-DD HH24:MI:SS') AS LAST_USED,
    LAST_SAMPLE_DATE,
    SAMPLE_INTERVAL AS SAMPLE_DAYS,
    DESCRIPTION AS FEATURE_DESCRIPTION
FROM DBA_FEATURE_USAGE_STATISTICS
WHERE DETECTED_USAGES > 0
ORDER BY LAST_USAGE_DATE DESC, DETECTED_USAGES DESC
FETCH FIRST 100 ROWS ONLY`,
			})
		}

		// Add session statistics to ORA-POL-019 (Active Sessions Within Limits)
		if control.ControlCode == "ORA-POL-019" {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (session statistics) to %s\n", control.ControlCode)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "session_statistics",
				Description: "Current database session statistics",
				SQL: `SELECT
    STATUS AS SESSION_STATUS,
    COUNT(*) AS SESSION_COUNT,
    ROUND(AVG(LAST_CALL_ET), 2) AS AVG_IDLE_TIME_SECONDS,
    MAX(LAST_CALL_ET) AS MAX_IDLE_TIME_SECONDS
FROM V$SESSION
WHERE USERNAME IS NOT NULL
GROUP BY STATUS
UNION ALL
SELECT
    'TOTAL' AS SESSION_STATUS,
    COUNT(*) AS SESSION_COUNT,
    NULL AS AVG_IDLE_TIME_SECONDS,
    NULL AS MAX_IDLE_TIME_SECONDS
FROM V$SESSION
ORDER BY SESSION_STATUS`,
			})
		}
	}

	fmt.Printf("  → Enriched %d controls with evidence capture\n", enriched)
}

// enrichPostgresAuditTrail adds PostgreSQL audit trail evidence capture
func (f *Fetcher) enrichPostgresAuditTrail(set *ControlSet) {
	enriched := 0

	// Find a security control to attach evidence capture
	// Using PG-SEC-001 or first security control if it doesn't exist
	for i := range set.Controls {
		control := &set.Controls[i]

		if control.ControlCode == "PG-SEC-001" || (enriched == 0 && control.Category == "Security") {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (audit ops, privileges) to %s\n", control.ControlCode)

			// PostgreSQL DDL Audit Trail (using pgaudit or pg_stat_statements)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations",
				Description: "Recent database operations from pg_stat_statements",
				SourceMode:  "activity",
				SourcePath:  "pg_stat_statements",
				SQL: `SELECT
    COALESCE(pss.last_exec_time, NOW()) AS EVENT_TIMESTAMP,
    pss.queryid AS QUERY_ID,
    pss.dbid AS DBID,
    pss.userid AS USER_ID,
    usename AS DBUSERNAME,
    CASE
        WHEN query ~* '^CREATE TABLE' THEN 'CREATE TABLE'
        WHEN query ~* '^DROP TABLE' THEN 'DROP TABLE'
        WHEN query ~* '^ALTER TABLE' THEN 'ALTER TABLE'
        WHEN query ~* '^TRUNCATE' THEN 'TRUNCATE TABLE'
        WHEN query ~* '^CREATE INDEX' THEN 'CREATE INDEX'
        WHEN query ~* '^DROP INDEX' THEN 'DROP INDEX'
        WHEN query ~* '^CREATE USER|^CREATE ROLE' THEN 'CREATE USER'
        WHEN query ~* '^DROP USER|^DROP ROLE' THEN 'DROP USER'
        WHEN query ~* '^ALTER USER|^ALTER ROLE' THEN 'ALTER USER'
        WHEN query ~* '^CREATE VIEW' THEN 'CREATE VIEW'
        WHEN query ~* '^DROP VIEW' THEN 'DROP VIEW'
        WHEN query ~* '^CREATE FUNCTION' THEN 'CREATE FUNCTION'
        WHEN query ~* '^DROP FUNCTION' THEN 'DROP FUNCTION'
        WHEN query ~* '^CREATE PROCEDURE' THEN 'CREATE PROCEDURE'
        WHEN query ~* '^DROP PROCEDURE' THEN 'DROP PROCEDURE'
        WHEN query ~* '^CREATE SCHEMA' THEN 'CREATE SCHEMA'
        WHEN query ~* '^DROP SCHEMA' THEN 'DROP SCHEMA'
        WHEN query ~* '^CREATE DATABASE' THEN 'CREATE DATABASE'
        WHEN query ~* '^DROP DATABASE' THEN 'DROP DATABASE'
        WHEN query ~* '^CREATE EXTENSION' THEN 'CREATE EXTENSION'
        WHEN query ~* '^DROP EXTENSION' THEN 'DROP EXTENSION'
        WHEN query ~* '^GRANT' THEN 'GRANT'
        WHEN query ~* '^REVOKE' THEN 'REVOKE'
        WHEN query ~* '^INSERT' THEN 'INSERT'
        WHEN query ~* '^UPDATE' THEN 'UPDATE'
        WHEN query ~* '^DELETE' THEN 'DELETE'
        WHEN query ~* '^SELECT' THEN 'SELECT'
        ELSE 'OTHER'
    END AS OPERATION,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    'DATABASE OBJECT' AS OBJECT_TYPE,
    query AS STATEMENT,
    '0' AS STATUS,
    NULL AS CLIENT_HOST,
    NULL AS CLIENT_PROGRAM,
    current_database() AS DATABASE_NAME
FROM pg_stat_statements pss
JOIN pg_user pu ON pss.userid = pu.usesysid
WHERE {{BASECHECK_POSTGRES_STATEMENTS_WATERMARK}}
  AND pss.query ~* '(CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|INSERT|UPDATE|DELETE|SELECT)'
  AND pu.usename NOT IN ('postgres', 'rdsadmin')
  AND pss.calls > 0
ORDER BY pss.last_exec_time ASC NULLS LAST, pss.queryid ASC
LIMIT 1000`,
			})

			// PostgreSQL live operation visibility (fallback, does not require pg_stat_statements)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations_live",
				Description: "Current non-idle client operations from pg_stat_activity",
				SourceMode:  "activity",
				SourcePath:  "pg_stat_activity",
				SQL: `SELECT
    NOW() AS EVENT_TIMESTAMP,
    pid AS PID,
    backend_start AS BACKEND_START,
    query_start AS QUERY_START,
    state_change AS STATE_CHANGE,
    usename AS DBUSERNAME,
    CASE
        WHEN query ~* '^CREATE ' THEN 'CREATE'
        WHEN query ~* '^ALTER ' THEN 'ALTER'
        WHEN query ~* '^DROP ' THEN 'DROP'
        WHEN query ~* '^TRUNCATE ' THEN 'TRUNCATE'
        WHEN query ~* '^GRANT ' THEN 'GRANT'
        WHEN query ~* '^REVOKE ' THEN 'REVOKE'
        WHEN query ~* '^INSERT ' THEN 'INSERT'
        WHEN query ~* '^UPDATE ' THEN 'UPDATE'
        WHEN query ~* '^DELETE ' THEN 'DELETE'
        ELSE 'OTHER'
    END AS OPERATION,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    backend_type AS OBJECT_TYPE,
    query AS STATEMENT,
    COALESCE(wait_event_type, 'RUNNING') AS STATUS,
    client_addr::text AS CLIENT_HOST,
    application_name AS CLIENT_PROGRAM,
    datname AS DATABASE_NAME
FROM pg_stat_activity
WHERE backend_type = 'client backend'
  AND state <> 'idle'
  AND usename NOT IN ('postgres', 'rdsadmin')
ORDER BY query_start DESC NULLS LAST
LIMIT 1000`,
			})

			// PostgreSQL Current Privileges
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "privilege_changes",
				Description: "Current database privileges granted to users",
				SQL: `SELECT
    NOW() AS EVENT_TIMESTAMP,
    grantee AS GRANTEE,
    privilege_type AS NAME,
    'GRANT' AS ACTION,
    grantor AS GRANTOR,
    table_schema AS OBJECT_SCHEMA,
    table_name AS OBJECT_NAME,
    'TABLE' AS OBJECT_TYPE,
    'GRANT ' || privilege_type || ' ON ' || table_schema || '.' || table_name || ' TO ' || grantee AS STATEMENT,
    is_grantable AS STATUS,
    current_database() AS DATABASE_NAME
FROM information_schema.table_privileges
WHERE grantee NOT IN ('postgres', 'rdsadmin', 'PUBLIC')
  AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
ORDER BY grantee, table_schema, table_name
LIMIT 1000`,
			})

			// PostgreSQL Role Grants
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "role_grants",
				Description: "Current role memberships (including superuser)",
				SQL: `SELECT
    NOW() AS EVENT_TIMESTAMP,
    r.rolname AS GRANTEE,
    m.rolname AS NAME,
    'GRANT' AS ACTION,
    'SYSTEM' AS GRANTOR,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    CASE WHEN m.rolsuper THEN 'SUPERUSER ROLE' ELSE 'ROLE' END AS OBJECT_TYPE,
    'GRANT ' || m.rolname || ' TO ' || r.rolname AS STATEMENT,
    CASE WHEN a.admin_option THEN 'WITH ADMIN OPTION' ELSE 'NO' END AS STATUS,
    current_database() AS DATABASE_NAME
FROM pg_roles r
JOIN pg_auth_members a ON r.oid = a.member
JOIN pg_roles m ON a.roleid = m.oid
WHERE r.rolname NOT IN ('postgres', 'rdsadmin')
  AND (m.rolsuper OR m.rolcreaterole OR m.rolcreatedb)
ORDER BY r.rolname, m.rolname
LIMIT 500`,
			})

			break
		}
	}

	fmt.Printf("  → Enriched %d controls with evidence capture\n", enriched)
}

// enrichSupabaseAuditTrail adds Supabase-oriented evidence capture.
func (f *Fetcher) enrichSupabaseAuditTrail(set *ControlSet) {
	enriched := 0

	for i := range set.Controls {
		control := &set.Controls[i]

		if control.ControlCode == "SB-SEC-001" || control.ControlCode == "SB-OPS-014" || control.ControlCode == "SB-VAL-001" || (enriched == 0 && (control.Category == "RLS" || control.Category == "Audit and Monitoring" || control.Category == "Storage Validation")) {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (RLS posture, policy inventory, grants, auth audit) to %s\n", control.ControlCode)

			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "rls_status",
				Description: "RLS status for exposed Supabase schemas",
				SQL: `SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS force_rls
FROM pg_class c
JOIN pg_namespace n
  ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND n.nspname IN ('public', 'storage')
ORDER BY n.nspname, c.relname`,
			})

			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "policy_definitions",
				Description: "Current policy definitions for exposed schemas",
				SQL: `SELECT
    schemaname AS schema_name,
    tablename AS table_name,
    policyname,
    cmd,
    array_to_string(roles, ',') AS roles,
    qual,
    with_check
FROM pg_policies
WHERE schemaname IN ('public', 'storage')
ORDER BY schemaname, tablename, policyname`,
			})

			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "privilege_changes",
				Description: "Current grants for anon/authenticated/service_role roles",
				SourceMode:  "snapshot",
				SourcePath:  "information_schema.role_table_grants",
				SQL: `SELECT
    NOW() AS EVENT_TIMESTAMP,
    grantee,
    privilege_type AS NAME,
    'GRANT' AS ACTION,
    grantor AS GRANTOR,
    table_schema AS OBJECT_SCHEMA,
    table_name AS OBJECT_NAME,
    'TABLE' AS OBJECT_TYPE,
    current_database() AS DATABASE_NAME
FROM information_schema.role_table_grants
WHERE grantee IN ('anon', 'authenticated', 'service_role')
  AND table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY grantee, table_schema, table_name, privilege_type`,
			})

			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations_auth",
				Description: "Recent authentication audit events from auth.audit_log_entries",
				SourceMode:  "history",
				SourcePath:  "auth.audit_log_entries",
				SQL: `SELECT
    created_at AS EVENT_TIMESTAMP,
    md5(COALESCE(payload::text, '')) AS EVENT_HASH,
    COALESCE(
      NULLIF(payload->>'actor_id', ''),
      NULLIF(payload->>'user_id', ''),
      NULLIF(payload->'actor'->>'id', ''),
      NULLIF(payload->'user'->>'id', ''),
      NULLIF(payload->>'actor', ''),
      'auth'
    ) AS DBUSERNAME,
    UPPER(REPLACE(COALESCE(
      NULLIF(payload->>'type', ''),
      NULLIF(payload->>'action', ''),
      NULLIF(payload->>'event_type', ''),
      'auth_event'
    ), '_', ' ')) AS ACTION_NAME,
    'auth' AS OBJECT_SCHEMA,
    COALESCE(
      NULLIF(payload->>'type', ''),
      NULLIF(payload->>'action', ''),
      NULLIF(payload->>'event_type', ''),
      'auth_event'
    ) AS OBJECT_NAME,
    'AUTH_EVENT' AS OBJECT_TYPE,
    payload::text AS STATEMENT,
    COALESCE(
      NULLIF(payload->>'ip_address', ''),
      NULLIF(payload->>'ip', ''),
      NULLIF(payload->'actor'->>'ip_address', '')
    ) AS CLIENT_HOST,
    COALESCE(
      NULLIF(payload->>'provider', ''),
      NULLIF(payload->'actor'->>'provider', ''),
      'supabase-auth'
    ) AS CLIENT_PROGRAM,
    current_database() AS DATABASE_NAME
FROM auth.audit_log_entries
WHERE {{BASECHECK_SUPABASE_AUTH_AUDIT_WATERMARK}}
ORDER BY created_at ASC, md5(COALESCE(payload::text, '')) ASC
LIMIT 1000`,
			})
		}
	}

	fmt.Printf("  → Enriched %d controls with evidence capture\n", enriched)
}

// enrichMSSQLAuditTrail adds MS SQL Server audit trail evidence capture
func (f *Fetcher) enrichMSSQLAuditTrail(set *ControlSet) {
	enriched := 0

	// Find a security control to attach evidence capture
	// Using MS-SEC-001 or first security control if it doesn't exist
	for i := range set.Controls {
		control := &set.Controls[i]

		if control.ControlCode == "MS-SEC-001" || (enriched == 0 && control.Category == "Security") {
			enriched++
			fmt.Printf("  ✓ Adding evidence capture (audit ops, privileges) to %s\n", control.ControlCode)

			// SQL Server Audit Trail (DDL/DCL operations)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "audit_operations",
				Description: "Recent database operations from default trace",
				SQL: `SELECT TOP 1000
    te.StartTime AS EVENT_TIMESTAMP,
    te.EventClass AS EVENT_CLASS,
    te.ObjectID AS OBJECT_ID,
    te.SPID AS SPID,
    te.DatabaseID AS DATABASE_ID,
    l.name AS DBUSERNAME,
    CASE te.EventClass
        WHEN 46 THEN 'CREATE TABLE'
        WHEN 47 THEN 'DROP TABLE'
        WHEN 164 THEN 'ALTER TABLE'
        WHEN 116 THEN 'TRUNCATE TABLE'
        WHEN 64 THEN 'CREATE INDEX'
        WHEN 65 THEN 'DROP INDEX'
        WHEN 103 THEN 'CREATE USER'
        WHEN 104 THEN 'DROP USER'
        WHEN 152 THEN 'ALTER USER'
        WHEN 131 THEN 'CREATE ROLE'
        WHEN 132 THEN 'DROP ROLE'
        WHEN 135 THEN 'GRANT'
        WHEN 136 THEN 'REVOKE'
        WHEN 162 THEN 'CREATE PROCEDURE'
        WHEN 163 THEN 'DROP PROCEDURE'
        WHEN 164 THEN 'ALTER PROCEDURE'
        WHEN 166 THEN 'CREATE FUNCTION'
        WHEN 167 THEN 'DROP FUNCTION'
        WHEN 21 THEN 'CREATE DATABASE'
        WHEN 22 THEN 'DROP DATABASE'
        WHEN 53 THEN 'CREATE SCHEMA'
        WHEN 54 THEN 'DROP SCHEMA'
        ELSE 'OTHER'
    END AS OPERATION,
    te.ObjectName AS OBJECT_SCHEMA,
    te.ObjectName AS OBJECT_NAME,
    te.ObjectType AS OBJECT_TYPE,
    te.TextData AS STATEMENT,
    CAST(te.Success AS VARCHAR(10)) AS STATUS,
    te.HostName AS CLIENT_HOST,
    te.ApplicationName AS CLIENT_PROGRAM,
    DB_NAME(te.DatabaseID) AS DATABASE_NAME
FROM sys.fn_trace_gettable(
    (SELECT TOP 1 path FROM sys.traces WHERE is_default = 1),
    DEFAULT
) te
LEFT JOIN sys.server_principals l ON te.LoginSid = l.sid
WHERE {{BASECHECK_MSSQL_TRACE_WATERMARK}}
  AND te.EventClass IN (46, 47, 164, 116, 64, 65, 103, 104, 152, 131, 132, 135, 136,
                        162, 163, 164, 166, 167, 21, 22, 53, 54)
  AND l.name NOT IN ('sa', 'NT AUTHORITY\SYSTEM')
ORDER BY te.StartTime ASC, te.EventClass ASC, te.SPID ASC, te.ObjectID ASC`,
			})

			// SQL Server Current Server-Level Permissions
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "privilege_changes",
				Description: "Current server-level permissions",
				SQL: `SELECT TOP 1000
    GETDATE() AS EVENT_TIMESTAMP,
    pr.name AS GRANTEE,
    pe.permission_name AS NAME,
    pe.state_desc AS ACTION,
    'SERVER' AS GRANTOR,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    'SERVER PERMISSION' AS OBJECT_TYPE,
    pe.state_desc + ' ' + pe.permission_name + ' TO [' + pr.name + ']' AS STATEMENT,
    pe.state_desc AS STATUS,
    DB_NAME() AS DATABASE_NAME
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pr.name NOT IN ('sa', 'public', 'NT AUTHORITY\SYSTEM')
  AND pe.permission_name IN ('CONTROL SERVER', 'ALTER ANY DATABASE', 'CREATE ANY DATABASE',
                              'ALTER ANY LOGIN', 'CREATE LOGIN', 'VIEW ANY DEFINITION')
ORDER BY pr.name, pe.permission_name`,
			})

			// SQL Server Role Memberships (sysadmin, etc.)
			control.EvidenceCapture = append(control.EvidenceCapture, Evidence{
				Type:        "role_grants",
				Description: "Current server role memberships (sysadmin, etc.)",
				SQL: `SELECT TOP 500
    GETDATE() AS EVENT_TIMESTAMP,
    member.name AS GRANTEE,
    role.name AS NAME,
    'GRANT' AS ACTION,
    'SYSTEM' AS GRANTOR,
    NULL AS OBJECT_SCHEMA,
    NULL AS OBJECT_NAME,
    'SERVER ROLE' AS OBJECT_TYPE,
    'ALTER SERVER ROLE [' + role.name + '] ADD MEMBER [' + member.name + ']' AS STATEMENT,
    'MEMBER' AS STATUS,
    DB_NAME() AS DATABASE_NAME
FROM sys.server_role_members rm
JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
JOIN sys.server_principals member ON rm.member_principal_id = member.principal_id
WHERE role.name IN ('sysadmin', 'serveradmin', 'securityadmin', 'processadmin',
                     'setupadmin', 'bulkadmin', 'diskadmin', 'dbcreator')
  AND member.name NOT IN ('sa', 'NT AUTHORITY\SYSTEM')
ORDER BY member.name, role.name`,
			})

			break
		}
	}

	fmt.Printf("  → Enriched %d controls with evidence capture\n", enriched)
}
