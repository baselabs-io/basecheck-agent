package entitlement

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"basecheck-agent/pkg/security"

	"gopkg.in/yaml.v3"
)

// Loader handles loading and caching entitlements.
type Loader struct {
	// LocalPath is the path to a local entitlement file (for air-gapped mode)
	LocalPath string

	// CachePath is the directory to cache downloaded entitlements
	CachePath string

	// ServerURL is the backend URL to fetch entitlements from
	ServerURL string

	// AgentToken is the token for authenticating with the server
	AgentToken string

	// AgentID is this agent's ID for binding validation
	AgentID string

	// PublicKey is the base64-encoded public key for signature verification (required)
	PublicKey string

	// AllowInsecureTransport permits plain HTTP when fetching the entitlement from
	// the server (dev/test only). This is independent of AllowInsecureSignature and
	// must never, by itself, weaken signature verification.
	AllowInsecureTransport bool

	// AllowInsecureSignature disables entitlement signature verification (dev/test
	// only). This must be set explicitly and is never implied by transport settings.
	AllowInsecureSignature bool

	// HTTPClient is the HTTP client to use for server requests
	HTTPClient *http.Client
}

// NewLoader creates a new entitlement loader with security enabled.
// publicKey is required unless allowInsecureSignature is true. allowInsecureTransport
// and allowInsecureSignature are independent controls: relaxing HTTP transport must
// never disable signature verification.
func NewLoader(localPath, cachePath, serverURL, agentToken, agentID, publicKey string, allowInsecureTransport, allowInsecureSignature bool) *Loader {
	return &Loader{
		LocalPath:              localPath,
		CachePath:              cachePath,
		ServerURL:              serverURL,
		AgentToken:             agentToken,
		AgentID:                agentID,
		PublicKey:              publicKey,
		AllowInsecureTransport: allowInsecureTransport,
		AllowInsecureSignature: allowInsecureSignature,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Load attempts to load an entitlement from available sources.
// Order: local file -> cache (non-expired only) -> server
// Returns nil, nil if no entitlement is available (free mode).
// Returns error if entitlement exists but is invalid/unsigned.
func (l *Loader) Load() (*Entitlement, error) {
	// Fail closed: require public key unless explicitly in insecure signature mode
	if !l.AllowInsecureSignature && strings.TrimSpace(l.PublicKey) == "" {
		return nil, ErrSignatureRequired
	}

	// Try local file first (for air-gapped deployments)
	if l.LocalPath != "" {
		ent, err := l.LoadFromFile(l.LocalPath)
		if err == nil {
			return ent, nil
		}
		// Local path was explicitly configured - any error is a configuration failure
		// For air-gapped mode, a missing file should fail clearly, not silently degrade
		if err == ErrNotFound {
			return nil, fmt.Errorf("%w: %s", ErrLocalPathNotFound, l.LocalPath)
		}
		// Local file exists but is invalid - fail, don't fall through
		return nil, err
	}

	// Try cache (non-expired only - expired cache is not a fallback)
	if l.CachePath != "" {
		ent, err := l.LoadFromCache()
		if err == nil {
			if !ent.IsExpired() {
				return ent, nil
			}
			fmt.Printf("  Cached entitlement expired, will try server\n")
		}
	}

	// Try server
	if l.ServerURL != "" && l.AgentToken != "" {
		ent, err := l.LoadFromServer()
		if err == nil {
			// Cache the downloaded entitlement
			if l.CachePath != "" {
				if cacheErr := l.SaveToCache(ent); cacheErr != nil {
					fmt.Printf("  Warning: failed to cache entitlement: %v\n", cacheErr)
				}
			}
			return ent, nil
		}
		if err != ErrNotFound {
			fmt.Printf("  Failed to fetch entitlement from server: %v\n", err)
		}
		// Do NOT fall back to expired cache - that would violate "expired = free mode"
		// If server fails, agent runs in free mode
	}

	// No valid entitlement available - agent runs in free mode
	return nil, nil
}

// LoadFromFile loads an entitlement from a YAML or JSON file.
func (l *Loader) LoadFromFile(path string) (*Entitlement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrLoadFailed, err)
	}

	return l.parseAndVerify(data, path)
}

// LoadFromCache loads the cached entitlement.
func (l *Loader) LoadFromCache() (*Entitlement, error) {
	if l.CachePath == "" {
		return nil, ErrNotFound
	}

	cachePath := filepath.Join(l.CachePath, "entitlement.yaml")
	return l.LoadFromFile(cachePath)
}

// LoadFromServer fetches the entitlement from the backend server.
func (l *Loader) LoadFromServer() (*Entitlement, error) {
	if l.ServerURL == "" {
		return nil, fmt.Errorf("%w: no server URL configured", ErrLoadFailed)
	}
	if l.AgentToken == "" {
		return nil, fmt.Errorf("%w: no agent token configured", ErrLoadFailed)
	}

	if err := security.ValidateHTTPS(l.ServerURL, l.AllowInsecureTransport); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInsecureHTTP, err)
	}

	url := strings.TrimSuffix(l.ServerURL, "/") + "/api/agent/entitlement"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrLoadFailed, err)
	}

	req.Header.Set("X-Agent-Token", l.AgentToken)
	req.Header.Set("Accept", "application/json")

	resp, err := l.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrLoadFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No entitlement for this agent - free mode
		return nil, ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: server returned %d: %s", ErrLoadFailed, resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrLoadFailed, err)
	}

	return l.parseAndVerify(body, url)
}

// SaveToCache saves an entitlement to the cache directory.
func (l *Loader) SaveToCache(ent *Entitlement) error {
	if l.CachePath == "" {
		return nil
	}

	// Create cache directory if needed
	if err := os.MkdirAll(l.CachePath, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath := filepath.Join(l.CachePath, "entitlement.yaml")

	data, err := yaml.Marshal(ent)
	if err != nil {
		return fmt.Errorf("failed to marshal entitlement: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// parseAndVerify parses entitlement from YAML or JSON data, validates, and verifies signature.
func (l *Loader) parseAndVerify(data []byte, source string) (*Entitlement, error) {
	var ent Entitlement

	// Try JSON first (server response)
	if err := json.Unmarshal(data, &ent); err != nil {
		// Try YAML (local file)
		if yamlErr := yaml.Unmarshal(data, &ent); yamlErr != nil {
			return nil, fmt.Errorf("%w: invalid format: %v", ErrParseFailed, yamlErr)
		}
	}

	// Validate fields
	if err := ent.Validate(); err != nil {
		return nil, fmt.Errorf("entitlement from %s: %w", source, err)
	}

	// Verify agent binding
	if l.AgentID != "" && !ent.IsBoundToAgent(l.AgentID) {
		return nil, fmt.Errorf("entitlement from %s: %w (expected %s, got %s)",
			source, ErrAgentMismatch, l.AgentID, ent.AgentID)
	}

	// Verify signature (required unless insecure signature mode)
	if l.AllowInsecureSignature {
		if ent.SignatureB64 != "" && l.PublicKey != "" {
			// If signature is present, still verify it even in insecure mode
			if err := ent.Verify(l.PublicKey); err != nil {
				fmt.Printf("  Warning: entitlement signature verification failed: %v\n", err)
			}
		}
	} else {
		// Fail closed: signature required
		if err := ent.Verify(l.PublicKey); err != nil {
			return nil, fmt.Errorf("entitlement from %s: %w", source, err)
		}
	}

	return &ent, nil
}
