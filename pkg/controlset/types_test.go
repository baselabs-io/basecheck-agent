package controlset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTierNormalization(t *testing.T) {
	tests := []struct {
		name           string
		tier           string
		wantNormalized string
		wantValid      bool
		wantLevel      int
	}{
		{"empty tier is invalid (fails closed)", "", "", false, -1},
		{"free lowercase", "free", "free", true, 0},
		{"free uppercase", "FREE", "free", true, 0},
		{"free mixed case", "Free", "free", true, 0},
		{"free with spaces", "  free  ", "free", true, 0},
		{"paid lowercase", "paid", "paid", true, 1},
		{"paid uppercase", "PAID", "paid", true, 1},
		{"paid with spaces", " paid ", "paid", true, 1},
		{"enterprise lowercase", "enterprise", "enterprise", true, 2},
		{"enterprise uppercase", "ENTERPRISE", "enterprise", true, 2},
		{"enterprise mixed case", "Enterprise", "enterprise", true, 2},
		{"unknown tier", "premium", "premium", false, -1},
		{"unknown tier with spaces", " custom ", "custom", false, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Metadata{Tier: tt.tier}

			if got := m.NormalizedTier(); got != tt.wantNormalized {
				t.Errorf("NormalizedTier() = %q, want %q", got, tt.wantNormalized)
			}

			if got := m.IsValidTier(); got != tt.wantValid {
				t.Errorf("IsValidTier() = %v, want %v", got, tt.wantValid)
			}

			if got := TierLevel(tt.tier); got != tt.wantLevel {
				t.Errorf("TierLevel(%q) = %d, want %d", tt.tier, got, tt.wantLevel)
			}
		})
	}
}

func TestMetadataTierHelpers(t *testing.T) {
	tests := []struct {
		name             string
		tier             string
		wantIsFree       bool
		wantIsPaid       bool
		wantIsEnterprise bool
		wantNeedsEntl    bool
	}{
		{"empty tier is not free (fails closed)", "", false, false, false, false},
		{"free tier", "free", true, false, false, false},
		{"FREE tier", "FREE", true, false, false, false},
		{"paid tier", "paid", false, true, false, true},
		{"PAID tier", "PAID", false, true, false, true},
		{"enterprise tier", "enterprise", false, false, true, true},
		{"ENTERPRISE tier", "ENTERPRISE", false, false, true, true},
		{"unknown tier defaults to free checks", "custom", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Metadata{Tier: tt.tier}

			if got := m.IsFree(); got != tt.wantIsFree {
				t.Errorf("IsFree() = %v, want %v", got, tt.wantIsFree)
			}
			if got := m.IsPaid(); got != tt.wantIsPaid {
				t.Errorf("IsPaid() = %v, want %v", got, tt.wantIsPaid)
			}
			if got := m.IsEnterprise(); got != tt.wantIsEnterprise {
				t.Errorf("IsEnterprise() = %v, want %v", got, tt.wantIsEnterprise)
			}
			if got := m.NeedsEntitlement(); got != tt.wantNeedsEntl {
				t.Errorf("NeedsEntitlement() = %v, want %v", got, tt.wantNeedsEntl)
			}
		})
	}
}

func TestTierLevelComparison(t *testing.T) {
	// Verify tier level ordering for entitlement checks
	if TierLevel("free") >= TierLevel("paid") {
		t.Error("free should be less than paid")
	}
	if TierLevel("paid") >= TierLevel("enterprise") {
		t.Error("paid should be less than enterprise")
	}

	// Unknown tier should fail closed (return -1)
	if TierLevel("unknown") >= TierLevel("free") {
		t.Error("unknown tier should fail closed with level -1")
	}
}

// TestBundledControlPacksHaveExplicitTier validates that all bundled control packs
// in control-sets/*.yaml have explicit metadata.tier set to a valid value.
// This prevents production leakage where missing tier defaults to free.
func TestBundledControlPacksHaveExplicitTier(t *testing.T) {
	// Find the control-sets directory relative to this test file
	// The test runs from pkg/controlset, so control-sets is ../../control-sets
	controlSetsDir := "../../control-sets"

	// Check if directory exists
	if _, err := os.Stat(controlSetsDir); os.IsNotExist(err) {
		t.Skip("control-sets directory not found (running from different directory)")
	}

	// Find all YAML files
	entries, err := os.ReadDir(controlSetsDir)
	if err != nil {
		t.Fatalf("failed to read control-sets directory: %v", err)
	}

	var yamlFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			// Skip backup files
			if strings.HasSuffix(entry.Name(), ".bak") {
				continue
			}
			yamlFiles = append(yamlFiles, entry.Name())
		}
	}

	if len(yamlFiles) == 0 {
		t.Fatal("no YAML files found in control-sets directory")
	}

	// Validate each control pack
	for _, filename := range yamlFiles {
		t.Run(filename, func(t *testing.T) {
			path := filepath.Join(controlSetsDir, filename)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", filename, err)
			}

			// Parse just the metadata section
			var pack struct {
				Metadata struct {
					ControlSetID string `yaml:"control_set_id"`
					Tier         string `yaml:"tier"`
				} `yaml:"metadata"`
			}

			if err := yaml.Unmarshal(data, &pack); err != nil {
				t.Fatalf("failed to parse %s: %v", filename, err)
			}

			// Check that tier is explicitly set (not empty)
			if pack.Metadata.Tier == "" {
				t.Errorf("control pack %s is missing explicit metadata.tier (defaults to free = leakage risk)", filename)
			}

			// Check that tier is a valid value
			if pack.Metadata.Tier != "" {
				m := &Metadata{Tier: pack.Metadata.Tier}
				if !m.IsValidTier() {
					t.Errorf("control pack %s has unknown tier %q (must be free, paid, or enterprise)", filename, pack.Metadata.Tier)
				}
			}
		})
	}
}

// TestFreePacksNoLeakyEvidenceColumns validates that free-tier control packs
// do not return columns that expose paid-tier evidence (exact identities,
// timestamps, audit events, SQL text, etc.).
func TestFreePacksNoLeakyEvidenceColumns(t *testing.T) {
	// Columns that indicate paid-tier evidence leakage in free packs
	// These reveal WHO, WHEN, or detailed audit/log content
	leakyColumnPatterns := []string{
		// Exact identity columns (WHO) - these expose specific principals
		"principal_name",
		"login_name",
		"grantee",
		"grantor",
		"member_name",
		// Timestamp columns (WHEN) - these expose timeline/history
		"create_date",
		"modify_date",
		"grant_date",
		"password_last_set",
		// Audit/log content - these expose raw audit data
		"event_time",
		"statement",
		"sql_text",
		"command_text",
		"audit_file",
		"log_record",
		// Grant details - these expose permission provenance
		"granted_by",
	}

	controlSetsDir := "../../control-sets"
	if _, err := os.Stat(controlSetsDir); os.IsNotExist(err) {
		t.Skip("control-sets directory not found")
	}

	entries, err := os.ReadDir(controlSetsDir)
	if err != nil {
		t.Fatalf("failed to read control-sets directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".bak") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filename := entry.Name()
		t.Run(filename, func(t *testing.T) {
			path := filepath.Join(controlSetsDir, filename)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", filename, err)
			}

			// Parse metadata and controls
			var pack struct {
				Metadata struct {
					Tier string `yaml:"tier"`
				} `yaml:"metadata"`
				Controls []struct {
					ControlCode string `yaml:"control_code"`
					Procedures  []struct {
						Tests string `yaml:"tests"`
					} `yaml:"procedures"`
				} `yaml:"controls"`
			}

			if err := yaml.Unmarshal(data, &pack); err != nil {
				t.Fatalf("failed to parse %s: %v", filename, err)
			}

			// Only check free-tier packs
			m := &Metadata{Tier: pack.Metadata.Tier}
			if !m.IsFree() {
				t.Skip("not a free-tier pack")
			}

			// Check each control's SQL for leaky columns
			for _, control := range pack.Controls {
				for _, proc := range control.Procedures {
					sqlLower := strings.ToLower(proc.Tests)
					for _, pattern := range leakyColumnPatterns {
						// Check for column as SELECT alias (AS pattern)
						if strings.Contains(sqlLower, " as "+pattern) {
							t.Errorf("control %s has leaky column alias %q (free tier should not expose exact identities/timestamps)",
								control.ControlCode, pattern)
						}
					}
				}
			}
		})
	}
}
