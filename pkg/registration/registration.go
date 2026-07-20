package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"basecheck-agent/pkg/security"
)

// RegisterRequest represents the agent registration request
type RegisterRequest struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

// RegisterResponse represents the agent registration response
type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
	Status  string `json:"status"`
}

// Register registers the agent with the backend and returns the registration response.
// The response contains AgentID (backend-assigned), Token (for auth), and Status.
func Register(backendURL, name, hostname, version string, allowHTTP bool) (*RegisterResponse, error) {
	if err := security.ValidateHTTPS(backendURL, allowHTTP); err != nil {
		return nil, err
	}
	// Build registration request
	reqBody := RegisterRequest{
		Name:     name,
		Hostname: hostname,
		Version:  version,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	url := backendURL + "/api/agents"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var regResp RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	return &regResp, nil
}

// SaveToken saves the agent token to a file
func SaveToken(tokenFile, token string) error {
	return os.WriteFile(tokenFile, []byte(token), 0600)
}

// LoadToken loads the agent token from a file
func LoadToken(tokenFile string) (string, error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // Token file doesn't exist
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}
	return string(bytes.TrimSpace(data)), nil
}

// agentIDFile returns the path to the agent ID file based on the token file path.
// The agent ID file is stored alongside the token file with ".id" suffix.
func agentIDFile(tokenFile string) string {
	return tokenFile + ".id"
}

// SaveAgentID saves the backend-assigned agent ID to a file
func SaveAgentID(tokenFile, agentID string) error {
	return os.WriteFile(agentIDFile(tokenFile), []byte(agentID), 0600)
}

// LoadAgentID loads the backend-assigned agent ID from a file
func LoadAgentID(tokenFile string) (string, error) {
	data, err := os.ReadFile(agentIDFile(tokenFile))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // Agent ID file doesn't exist
		}
		return "", fmt.Errorf("failed to read agent ID file: %w", err)
	}
	return string(bytes.TrimSpace(data)), nil
}

// RegistrationResult contains the token and agent ID from registration
type RegistrationResult struct {
	Token   string
	AgentID string
}

// EnsureRegistered ensures the agent is registered and returns the token and agent ID.
// The AgentID is the backend-assigned identifier used for entitlement binding.
func EnsureRegistered(backendURL, name, hostname, version, tokenFile string, allowHTTP bool) (*RegistrationResult, error) {
	// Try to load existing token and agent ID
	token, err := LoadToken(tokenFile)
	if err != nil {
		return nil, err
	}

	agentID, err := LoadAgentID(tokenFile)
	if err != nil {
		return nil, err
	}

	if token != "" {
		// If we have a token but no agent ID, use agent name as fallback
		// (for backward compatibility with pre-existing registrations)
		if agentID == "" {
			agentID = name
		}
		return &RegistrationResult{Token: token, AgentID: agentID}, nil
	}

	// No token found, register agent
	regResp, err := Register(backendURL, name, hostname, version, allowHTTP)
	if err != nil {
		return nil, err
	}

	// Save token
	if err := SaveToken(tokenFile, regResp.Token); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	// Save agent ID
	if err := SaveAgentID(tokenFile, regResp.AgentID); err != nil {
		return nil, fmt.Errorf("failed to save agent ID: %w", err)
	}

	return &RegistrationResult{Token: regResp.Token, AgentID: regResp.AgentID}, nil
}
