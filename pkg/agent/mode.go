// Package agent provides agent runtime state management.
package agent

import (
	"encoding/json"
	"os"
	"time"
)

// ModeFile is the default path for persisted mode state.
const ModeFile = ".agent_mode"

// Mode represents the agent's connectivity mode (online/offline).
type Mode struct {
	Mode           string    `json:"mode"`            // "online" or "offline"
	LastCheck      time.Time `json:"last_check"`      // Last connectivity check
	NextRetry      time.Time `json:"next_retry"`      // Next retry time (for offline mode)
	FallbackReason string    `json:"fallback_reason"` // Why we're in this mode
}

// NewOnlineMode creates a new online mode state.
func NewOnlineMode() *Mode {
	return &Mode{
		Mode:      "online",
		LastCheck: time.Now(),
	}
}

// NewOfflineMode creates a new offline mode state with retry after 24h.
func NewOfflineMode(reason string) *Mode {
	return &Mode{
		Mode:           "offline",
		LastCheck:      time.Now(),
		NextRetry:      time.Now().Add(24 * time.Hour),
		FallbackReason: reason,
	}
}

// IsOnline returns true if agent is in online mode.
func (m *Mode) IsOnline() bool {
	return m != nil && m.Mode == "online"
}

// IsOffline returns true if agent is in offline mode.
func (m *Mode) IsOffline() bool {
	return m != nil && m.Mode == "offline"
}

// ShouldRetry returns true if offline mode should attempt backend reconnection.
func (m *Mode) ShouldRetry() bool {
	return m.IsOffline() && time.Now().After(m.NextRetry)
}

// Load loads the saved mode from the mode file.
func Load() (*Mode, error) {
	return LoadFrom(ModeFile)
}

// LoadFrom loads mode from a specific file path.
func LoadFrom(path string) (*Mode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mode Mode
	if err := json.Unmarshal(data, &mode); err != nil {
		return nil, err
	}

	return &mode, nil
}

// Save persists mode to the mode file.
func (m *Mode) Save() error {
	return m.SaveTo(ModeFile)
}

// SaveTo persists mode to a specific file path.
func (m *Mode) SaveTo(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
