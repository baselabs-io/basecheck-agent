package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"basecheck-agent/pkg/controlset"
	"basecheck-agent/pkg/database"
	"basecheck-agent/pkg/security"
)

// SystemToDiscover represents a system that needs discovery
type SystemToDiscover struct {
	SystemID    string                   `json:"system_id"`
	Name        string                   `json:"name"`
	Type        string                   `json:"type"`
	Credentials []map[string]interface{} `json:"credentials"`
}

// AgentConfig represents the agent configuration from backend
type AgentConfig struct {
	AgentID           string             `json:"agent_id"`
	Name              string             `json:"name"`
	SystemsToDiscover []SystemToDiscover `json:"systems_to_discover"`
}

// DiscoveryService handles system discovery
type DiscoveryService struct {
	backendURL string
	agentToken string
	httpClient *http.Client
}

// NewDiscoveryService creates a new discovery service
func NewDiscoveryService(backendURL, agentToken string, allowHTTP bool) (*DiscoveryService, error) {
	if err := security.ValidateHTTPS(backendURL, allowHTTP); err != nil {
		return nil, err
	}

	return &DiscoveryService{
		backendURL: backendURL,
		agentToken: agentToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// FetchSystemsToDiscover fetches systems that need discovery from the backend
func (d *DiscoveryService) FetchSystemsToDiscover() ([]SystemToDiscover, error) {
	// Call the new /api/systems?status=New endpoint
	url := fmt.Sprintf("%s/api/systems?status=New", d.backendURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Agent-Token", d.agentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("failed to fetch systems: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - backend returns an array of System objects
	var systems []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&systems); err != nil {
		return nil, fmt.Errorf("failed to parse systems: %w", err)
	}

	// Convert to SystemToDiscover format
	var result []SystemToDiscover
	for _, sys := range systems {
		systemToDiscover := SystemToDiscover{
			SystemID: getString(sys, "id"),
			Name:     getString(sys, "name"),
			Type:     strings.ToLower(getString(sys, "type")),
		}

		// Extract credentials from the system object
		if credsArray, ok := sys["credentials"].([]interface{}); ok && len(credsArray) > 0 {
			for _, currentCredential := range credsArray {
				if credMap, ok := currentCredential.(map[string]interface{}); ok {
					systemToDiscover.Credentials = append(systemToDiscover.Credentials, credMap)
				}
			}
		}

		// Only add systems that have credentials
		if len(systemToDiscover.Credentials) > 0 {
			result = append(result, systemToDiscover)
		}
	}

	return result, nil
}

// DiscoverSystem performs discovery on a single system
func (d *DiscoveryService) DiscoverSystem(ctx context.Context, system SystemToDiscover, fetcher *controlset.Fetcher) error {
	log.Printf("\n=== Discovering system: %s (%s) ===", system.Name, system.Type)

	var lastErr error
	for _, currentCredential := range system.Credentials {
		dbConfig, err := d.buildDatabaseConfig(system.Type, currentCredential)
		if err != nil {
			lastErr = fmt.Errorf("failed to build database config: %w", err)
			continue
		}

		db, err := database.NewDatabase(dbConfig)
		if err != nil {
			lastErr = fmt.Errorf("failed to create database: %w", err)
			continue
		}

		log.Printf("Connecting to %s database...", system.Type)
		if err := db.Connect(); err != nil {
			db.Close()
			lastErr = fmt.Errorf("failed to connect: %w", err)
			continue
		}
		log.Println("✓ Connected successfully")

		info, err := db.GetInstanceInfo()
		if err != nil {
			db.Close()
			lastErr = fmt.Errorf("failed to get instance info: %w", err)
			continue
		}

		log.Printf("Fetching discovery control set for %s...", system.Type)
		controlSet, err := fetcher.FetchControlSet(system.Type+"-discovery", info.Version)
		if err != nil {
			db.Close()
			lastErr = fmt.Errorf("failed to fetch discovery control set: %w", err)
			continue
		}

		log.Printf("Loaded discovery control set: %s (%d controls)", controlSet.Metadata.ControlSetID, len(controlSet.Controls))
		log.Println("Executing discovery procedures...")
		executor := controlset.NewExecutor(db)
		results := executor.ExecuteControlSet(ctx, controlSet)
		db.Close()

		attributes := d.extractAttributes(results)
		log.Printf("✓ Collected %d system attributes", len(attributes))

		if err := d.sendDiscoveryResults(system.SystemID, getInt64(currentCredential, "id"), attributes); err != nil {
			return fmt.Errorf("failed to send discovery results: %w", err)
		}

		log.Printf("✓ Discovery completed for system: %s", system.Name)
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("failed to discover system")
}

// buildDatabaseConfig builds database connection config from system credentials
func (d *DiscoveryService) buildDatabaseConfig(systemType string, creds map[string]interface{}) (database.ConnectionConfig, error) {
	systemType = strings.ToLower(systemType)

	config := database.ConnectionConfig{
		Type:     systemType,
		Host:     getString(creds, "host"),
		Port:     getInt(creds, "port"),
		Username: getString(creds, "userName"), // Backend returns camelCase
		Password: getString(creds, "password"),
	}

	// Oracle-specific fields
	if systemType == "oracle" {
		config.ServiceName = getString(creds, "serviceName") // Backend returns camelCase
		config.SID = getString(creds, "sid")
		if strings.EqualFold(strings.TrimSpace(config.Username), "sys") {
			return database.ConnectionConfig{}, fmt.Errorf("oracle discovery requires dedicated read-only user, SYS is not allowed")
		}
		if strings.EqualFold(strings.TrimSpace(getString(creds, "authType")), "SYSDBA") {
			return database.ConnectionConfig{}, fmt.Errorf("oracle discovery does not allow SYSDBA authentication")
		}
		config.AsSysDBA = false
	}

	// Postgres-specific fields
	if systemType == "postgres" || systemType == "postgresql" || systemType == "supabase" {
		config.Database = getString(creds, "databaseName") // Backend returns camelCase
		config.SSLMode = getString(creds, "sslMode")       // Backend returns camelCase
		if config.SSLMode == "" {
			if systemType == "supabase" {
				config.SSLMode = "require"
			} else {
				config.SSLMode = "prefer"
			}
		}
	}

	// SQLite-specific fields
	if systemType == "sqlite" {
		config.Database = getString(creds, "databaseName")
		if config.Database == "" {
			config.Database = getString(creds, "host")
		}
		if err := validateSQLitePath(config.Database); err != nil {
			return database.ConnectionConfig{}, fmt.Errorf("invalid SQLite path: %w", err)
		}
	}

	return config, nil
}

// validateSQLitePath validates the SQLite database file path for security
func validateSQLitePath(dbPath string) error {
	// Reject empty paths
	if strings.TrimSpace(dbPath) == "" {
		return fmt.Errorf("SQLite database path cannot be empty")
	}

	// Reject directory traversal patterns
	if strings.Contains(dbPath, "..") {
		return fmt.Errorf("directory traversal not allowed in database path")
	}

	// Require absolute path
	if !filepath.IsAbs(dbPath) {
		return fmt.Errorf("database path must be absolute, got: %s", dbPath)
	}

	// Verify file exists and is regular file (not directory/device)
	linkInfo, err := os.Lstat(dbPath)
	if err != nil {
		return fmt.Errorf("database file not accessible: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path must not be a symlink")
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("database file not accessible: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database path must be a regular file")
	}

	return nil
}

// extractAttributes extracts system attributes from discovery control results
func (d *DiscoveryService) extractAttributes(results []*controlset.ControlResult) []map[string]interface{} {
	var attributes []map[string]interface{}

	for _, result := range results {
		for _, procedureResult := range result.Procedures {
			if procedureResult.Status == "PASS" || procedureResult.Status == "FAIL" {
				for _, rowMap := range procedureResult.Rows {
					attribute := map[string]interface{}{
						"name":     getString(rowMap, "ATTRIBUTE_NAME"),
						"value":    getValue(rowMap, "ATTRIBUTE_VALUE"),
						"type":     getString(rowMap, "ATTRIBUTE_TYPE"),
						"category": getString(rowMap, "CATEGORY"),
					}

					if attribute["name"] != "" && attribute["value"] != nil {
						attributes = append(attributes, attribute)
					}
				}
			}
		}
	}

	return attributes
}

// sendDiscoveryResults sends discovery results to the backend
func (d *DiscoveryService) sendDiscoveryResults(systemID string, credentialID int64, attributes []map[string]interface{}) error {
	url := fmt.Sprintf("%s/api/systems/discovery", d.backendURL)

	payload := map[string]interface{}{
		"system_id":     systemID,
		"credential_id": credentialID,
		"attributes":    attributes,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Agent-Token", d.agentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Println("✓ Discovery results sent to backend")
	return nil
}

// Helper functions to safely extract values from maps
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
		return fmt.Sprintf("%v", val)
	}
	for currentKey, currentValue := range m {
		if strings.EqualFold(currentKey, key) {
			if str, ok := currentValue.(string); ok {
				return str
			}
			return fmt.Sprintf("%v", currentValue)
		}
	}
	return ""
}

func getValue(m map[string]interface{}, key string) interface{} {
	if val, ok := m[key]; ok {
		return val
	}
	for currentKey, currentValue := range m {
		if strings.EqualFold(currentKey, key) {
			return currentValue
		}
	}
	return nil
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			// Try to parse string as int
			var i int
			fmt.Sscanf(v, "%d", &i)
			return i
		}
	}
	return 0
}

func getInt64(m map[string]interface{}, key string) int64 {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		case string:
			var i int64
			fmt.Sscanf(v, "%d", &i)
			return i
		}
	}
	return 0
}

// CanDiscover checks if this agent can discover the given system
// by comparing the agent's hostname with the system's credential host
func (d *DiscoveryService) CanDiscover(system SystemToDiscover, agentHostname string) bool {
	if strings.EqualFold(system.Type, "supabase") {
		return true
	}

	// Normalize both hostnames for comparison
	normalizedAgentHost := normalizeHostname(agentHostname)
	for _, currentCredential := range system.Credentials {
		credHost := getString(currentCredential, "host")
		if credHost == "" {
			continue
		}

		normalizedCredHost := normalizeHostname(credHost)
		if normalizedAgentHost == normalizedCredHost {
			return true
		}

		localhostVariations := []string{"localhost", "127.0.0.1", "::1"}
		agentIsLocalhost := false
		credIsLocalhost := false

		for _, variation := range localhostVariations {
			if normalizedAgentHost == variation {
				agentIsLocalhost = true
			}
			if normalizedCredHost == variation {
				credIsLocalhost = true
			}
		}

		if agentIsLocalhost && credIsLocalhost {
			return true
		}
	}

	log.Printf("⚠ System %s has no matching credential host for agent host '%s', skipping",
		system.Name, agentHostname)
	return false
}

// normalizeHostname normalizes a hostname for comparison
func normalizeHostname(hostname string) string {
	if hostname == "" {
		return ""
	}
	// Remove protocol, port, and convert to lowercase
	normalized := strings.ToLower(hostname)
	normalized = strings.TrimPrefix(normalized, "http://")
	normalized = strings.TrimPrefix(normalized, "https://")

	// Remove port if present
	if idx := strings.Index(normalized, ":"); idx != -1 {
		normalized = normalized[:idx]
	}

	return strings.TrimSpace(normalized)
}
