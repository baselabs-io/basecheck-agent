package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewOnlineMode(t *testing.T) {
	mode := NewOnlineMode()

	if mode.Mode != "online" {
		t.Errorf("Expected mode 'online', got %q", mode.Mode)
	}

	if mode.IsOffline() {
		t.Error("NewOnlineMode() should not be offline")
	}

	if !mode.IsOnline() {
		t.Error("NewOnlineMode() should be online")
	}

	if mode.LastCheck.IsZero() {
		t.Error("LastCheck should be set")
	}
}

func TestNewOfflineMode(t *testing.T) {
	reason := "test_reason"
	mode := NewOfflineMode(reason)

	if mode.Mode != "offline" {
		t.Errorf("Expected mode 'offline', got %q", mode.Mode)
	}

	if mode.FallbackReason != reason {
		t.Errorf("Expected reason %q, got %q", reason, mode.FallbackReason)
	}

	if !mode.IsOffline() {
		t.Error("NewOfflineMode() should be offline")
	}

	if mode.IsOnline() {
		t.Error("NewOfflineMode() should not be online")
	}

	if mode.LastCheck.IsZero() {
		t.Error("LastCheck should be set")
	}

	if mode.NextRetry.IsZero() {
		t.Error("NextRetry should be set")
	}

	// NextRetry should be ~24h in the future
	expectedRetry := time.Now().Add(24 * time.Hour)
	diff := mode.NextRetry.Sub(expectedRetry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("NextRetry should be ~24h from now, got diff of %v", diff)
	}
}

func TestIsOnlineOffline(t *testing.T) {
	tests := []struct {
		name      string
		mode      *Mode
		isOnline  bool
		isOffline bool
	}{
		{
			name:      "online mode",
			mode:      NewOnlineMode(),
			isOnline:  true,
			isOffline: false,
		},
		{
			name:      "offline mode",
			mode:      NewOfflineMode("test"),
			isOnline:  false,
			isOffline: true,
		},
		{
			name:      "nil mode",
			mode:      nil,
			isOnline:  false,
			isOffline: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.IsOnline(); got != tt.isOnline {
				t.Errorf("IsOnline() = %v, want %v", got, tt.isOnline)
			}
			if got := tt.mode.IsOffline(); got != tt.isOffline {
				t.Errorf("IsOffline() = %v, want %v", got, tt.isOffline)
			}
		})
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		name        string
		mode        *Mode
		shouldRetry bool
	}{
		{
			name:        "online mode never retries",
			mode:        NewOnlineMode(),
			shouldRetry: false,
		},
		{
			name: "offline mode with future retry",
			mode: &Mode{
				Mode:      "offline",
				NextRetry: time.Now().Add(1 * time.Hour),
			},
			shouldRetry: false,
		},
		{
			name: "offline mode with past retry",
			mode: &Mode{
				Mode:      "offline",
				NextRetry: time.Now().Add(-1 * time.Hour),
			},
			shouldRetry: true,
		},
		{
			name:        "nil mode",
			mode:        nil,
			shouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.ShouldRetry(); got != tt.shouldRetry {
				t.Errorf("ShouldRetry() = %v, want %v", got, tt.shouldRetry)
			}
		})
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_mode.json")

	// Create and save a mode
	original := NewOfflineMode("network_error")

	if err := original.SaveTo(testFile); err != nil {
		t.Fatalf("SaveTo() failed: %v", err)
	}

	// Load it back
	loaded, err := LoadFrom(testFile)
	if err != nil {
		t.Fatalf("LoadFrom() failed: %v", err)
	}

	// Compare
	if loaded.Mode != original.Mode {
		t.Errorf("Mode: got %q, want %q", loaded.Mode, original.Mode)
	}
	if loaded.FallbackReason != original.FallbackReason {
		t.Errorf("FallbackReason: got %q, want %q", loaded.FallbackReason, original.FallbackReason)
	}

	// Timestamps should be close (within 1 second due to JSON marshaling)
	if diff := loaded.LastCheck.Sub(original.LastCheck); diff > time.Second || diff < -time.Second {
		t.Errorf("LastCheck diff too large: %v", diff)
	}
}

func TestLoadFromNonExistent(t *testing.T) {
	_, err := LoadFrom("/nonexistent/path/mode.json")
	if err == nil {
		t.Error("LoadFrom() should fail for nonexistent file")
	}
}

func TestLoadFromInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(testFile, []byte("invalid json{"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err := LoadFrom(testFile)
	if err == nil {
		t.Error("LoadFrom() should fail for invalid JSON")
	}
}

func TestDefaultModeFile(t *testing.T) {
	// Test that Load() and Save() use the default file
	tmpDir := t.TempDir()

	// Change to temp directory for this test
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	defer os.Chdir(oldDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Save using default path
	mode := NewOnlineMode()
	if err := mode.Save(); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(ModeFile); err != nil {
		t.Errorf("Default mode file not created: %v", err)
	}

	// Load using default path
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if loaded.Mode != mode.Mode {
		t.Errorf("Loaded mode %q doesn't match saved mode %q", loaded.Mode, mode.Mode)
	}
}
