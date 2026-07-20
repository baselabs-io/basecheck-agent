package controlset

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckCompatibility validates a control set's declared compatibility
// (agent version bounds and supported database versions) against the
// running agent and the connected database. Returns a descriptive error
// when incompatible; the caller must not execute the control set in that
// case. Empty/unset fields impose no constraint.
//
// requires_privileges is intentionally not checked here: verifying it would
// require engine-specific privilege-introspection queries (Oracle grants,
// Postgres roles, MSSQL permissions each have a different model), which is
// a materially larger effort. It remains declarative/documentation-only.
func CheckCompatibility(set *ControlSet, agentVersion, databaseVersion string) error {
	compat := set.Compatibility

	if minVersion := strings.TrimSpace(compat.AgentMinVersion); minVersion != "" {
		if compareVersions(agentVersion, minVersion) < 0 {
			return fmt.Errorf("control pack %s requires agent >= %s, running %s",
				set.Metadata.ControlSetID, minVersion, agentVersion)
		}
	}

	if maxVersion := strings.TrimSpace(compat.AgentMaxVersion); maxVersion != "" {
		if compareVersions(agentVersion, maxVersion) > 0 {
			return fmt.Errorf("control pack %s requires agent <= %s, running %s",
				set.Metadata.ControlSetID, maxVersion, agentVersion)
		}
	}

	if len(set.Metadata.DatabaseVersions) > 0 && strings.TrimSpace(databaseVersion) != "" {
		normalizedActual := strings.ToLower(databaseVersion)
		matched := false
		for _, declared := range set.Metadata.DatabaseVersions {
			trimmed := strings.TrimSpace(declared)
			if trimmed == "" {
				continue
			}
			if strings.Contains(normalizedActual, strings.ToLower(trimmed)) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("control pack %s declares supported database versions %v, connected database reports %q",
				set.Metadata.ControlSetID, set.Metadata.DatabaseVersions, databaseVersion)
		}
	}

	return nil
}

// compareVersions compares two dot-separated numeric version strings
// (e.g. "1.2.0" vs "1.10.0"), returning -1, 0, or 1 as a < b, a == b, a > b.
// Non-numeric segments compare as 0 so a malformed version fails closed
// toward "not clearly compatible" rather than panicking.
func compareVersions(a, b string) int {
	aParts := strings.Split(strings.TrimSpace(a), ".")
	bParts := strings.Split(strings.TrimSpace(b), ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		aNum := versionSegment(aParts, i)
		bNum := versionSegment(bParts, i)
		if aNum != bNum {
			if aNum < bNum {
				return -1
			}
			return 1
		}
	}
	return 0
}

func versionSegment(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
	if err != nil {
		return 0
	}
	return n
}
