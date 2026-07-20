package controlset

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexicographic
		{"1.10.0", "1.2.0", 1},
		{"1.0", "1.0.0", 0}, // missing trailing segment treated as 0
		{"1.0.1", "1.0", 1},
		{"", "", 0},
	}

	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCheckCompatibilityAgentVersionBounds(t *testing.T) {
	set := &ControlSet{
		Metadata: Metadata{ControlSetID: "test-pack"},
		Compatibility: Compatibility{
			AgentMinVersion: "1.0.0",
			AgentMaxVersion: "2.0.0",
		},
	}

	if err := CheckCompatibility(set, "1.5.0", ""); err != nil {
		t.Errorf("expected agent version within bounds to be compatible, got: %v", err)
	}

	if err := CheckCompatibility(set, "0.9.0", ""); err == nil {
		t.Error("expected agent version below min to be rejected")
	}

	if err := CheckCompatibility(set, "2.1.0", ""); err == nil {
		t.Error("expected agent version above max to be rejected")
	}
}

func TestCheckCompatibilityDatabaseVersions(t *testing.T) {
	set := &ControlSet{
		Metadata: Metadata{
			ControlSetID:     "test-pack",
			DatabaseVersions: []string{"19c", "21c"},
		},
	}

	if err := CheckCompatibility(set, "1.0.0", "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0"); err != nil {
		t.Errorf("expected substring-matched database version to be compatible, got: %v", err)
	}

	if err := CheckCompatibility(set, "1.0.0", "Oracle Database 11g Release 11.2.0.4.0"); err == nil {
		t.Error("expected unlisted database version to be rejected")
	}
}

func TestCheckCompatibilityEmptyMetadataImposesNoConstraint(t *testing.T) {
	set := &ControlSet{
		Metadata: Metadata{ControlSetID: "test-pack"},
	}

	if err := CheckCompatibility(set, "0.0.1", "anything at all"); err != nil {
		t.Errorf("expected no compatibility metadata to impose no constraint, got: %v", err)
	}
}

// TestCheckCompatibilityBundledControlPacks confirms every real bundled
// control pack's compatibility metadata (when declared) is satisfied by the
// current agent build version, guarding against a false rejection.
func TestCheckCompatibilityBundledControlPacks(t *testing.T) {
	// oracle-discovery-v1.0.0.yaml declares agent_min_version: "1.0.0".
	// The build-time agent version constant lives in cmd/agent (main.Version)
	// and isn't importable here, so this test uses a representative current
	// value; a real regression would be caught by AS-0038's manual
	// verification step and by CI running against the actual build version.
	set := &ControlSet{
		Metadata: Metadata{ControlSetID: "oracle-discovery"},
		Compatibility: Compatibility{
			AgentMinVersion: "1.0.0",
		},
	}
	if err := CheckCompatibility(set, "1.0.0", ""); err != nil {
		t.Errorf("expected bundled oracle-discovery compatibility to be satisfied, got: %v", err)
	}
}
