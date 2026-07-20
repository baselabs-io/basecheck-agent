package controlset

import (
	"strings"
	"time"

	"basecheck-agent/pkg/database"
)

// ControlSet represents a complete signed control set
type ControlSet struct {
	Metadata       Metadata       `yaml:"metadata"`
	Compatibility  Compatibility  `yaml:"compatibility"`
	Controls       []Control      `yaml:"controls"`
	Correlations   []Correlation  `yaml:"correlations"`
	UpdateStrategy UpdateStrategy `yaml:"update_strategy"`
	Verification   Verification   `yaml:"verification"`
}

// Metadata contains control set identification and versioning
type Metadata struct {
	ControlSetID      string     `yaml:"control_set_id"`
	ControlSetVersion string     `yaml:"control_set_version"`
	DatabaseType      string     `yaml:"database_type"`
	ControlSetType    string     `yaml:"control_set_type"`
	DatabaseVersions  []string   `yaml:"database_versions"`
	CreatedDate       time.Time  `yaml:"created_date"`
	UpdatedDate       time.Time  `yaml:"updated_date"`
	Author            string     `yaml:"author"`
	License           string     `yaml:"license"`
	Tier string `yaml:"tier" json:"tier"` // free, paid, enterprise (entitlement derived from this)
	Signature         Signature  `yaml:"signature"`
	Encryption        Encryption `yaml:"encryption"`
}

// Tier constants for control set entitlement
const (
	TierFree       = "free"
	TierPaid       = "paid"
	TierEnterprise = "enterprise"
)

// normalizeTier normalizes a tier string to lowercase and trimmed.
// Returns the normalized tier and whether it's a known valid tier.
// An empty tier is never valid: every control pack must declare its tier
// explicitly so a missing/incomplete tier fails closed instead of silently
// running as free.
func normalizeTier(tier string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	switch normalized {
	case TierFree:
		return TierFree, true
	case TierPaid:
		return TierPaid, true
	case TierEnterprise:
		return TierEnterprise, true
	default:
		return normalized, false
	}
}

// NormalizedTier returns the normalized tier value (lowercase, trimmed).
func (m *Metadata) NormalizedTier() string {
	normalized, _ := normalizeTier(m.Tier)
	return normalized
}

// IsFree returns true if the control set explicitly declares the free tier.
func (m *Metadata) IsFree() bool {
	normalized, _ := normalizeTier(m.Tier)
	return normalized == TierFree
}

// IsPaid returns true if the control set requires paid tier
func (m *Metadata) IsPaid() bool {
	normalized, _ := normalizeTier(m.Tier)
	return normalized == TierPaid
}

// IsEnterprise returns true if the control set requires enterprise tier
func (m *Metadata) IsEnterprise() bool {
	normalized, _ := normalizeTier(m.Tier)
	return normalized == TierEnterprise
}

// IsValidTier returns true if the tier is an explicit known valid tier (free, paid, enterprise)
func (m *Metadata) IsValidTier() bool {
	_, valid := normalizeTier(m.Tier)
	return valid
}

// NeedsEntitlement returns true if the control set requires entitlement validation.
// Entitlement is derived solely from the signed Tier field (not RequiresEntitlement).
func (m *Metadata) NeedsEntitlement() bool {
	normalized, _ := normalizeTier(m.Tier)
	return normalized == TierPaid || normalized == TierEnterprise
}

// TierLevel returns numeric tier level for comparison (free=0, paid=1, enterprise=2).
// Unknown tiers return -1 to fail closed in comparisons.
func TierLevel(tier string) int {
	normalized, valid := normalizeTier(tier)
	if !valid {
		return -1 // unknown tier fails closed
	}
	switch normalized {
	case TierPaid:
		return 1
	case TierEnterprise:
		return 2
	default:
		return 0
	}
}

// Signature contains cryptographic signature information
type Signature struct {
	Algorithm    string `yaml:"algorithm"`
	PublicKeyID  string `yaml:"public_key_id"`
	SignatureB64 string `yaml:"signature_b64"`
}

// Encryption contains encryption metadata
type Encryption struct {
	Algorithm string `yaml:"algorithm"`
	Encrypted bool   `yaml:"encrypted"`
}

// Compatibility defines agent and privilege requirements
type Compatibility struct {
	AgentMinVersion    string   `yaml:"agent_min_version"`
	AgentMaxVersion    string   `yaml:"agent_max_version"`
	RequiresPrivileges []string `yaml:"requires_privileges"`
}

// Control represents a single security check
type Control struct {
	ControlID       string             `yaml:"control_id"`
	ControlCode     string             `yaml:"control_code"`
	Category        string             `yaml:"category"`
	Title           string             `yaml:"title"`
	Description     string             `yaml:"description"`
	Procedures      []ControlProcedure `yaml:"procedures"`
	Remediation     Remediation        `yaml:"remediation"`
	EvidenceCapture []Evidence         `yaml:"evidence_capture"`
	References      []Reference        `yaml:"references"`
	RiskMetadata    RiskMetadata       `yaml:"risk_metadata"`
}

// ControlProcedure represents an executable test with criteria
type ControlProcedure struct {
	ProcedureID         string            `yaml:"procedure_id"`
	SystemType          string            `yaml:"system_type"`
	SystemApplicability string            `yaml:"system_applicability"`
	ExecutionMode       string            `yaml:"execution_mode"`
	Tests               string            `yaml:"tests"`
	Criteria            []ControlCriteria `yaml:"criteria"`
}

// ControlCriteria defines condition-based severity assignment
type ControlCriteria struct {
	Condition           string `yaml:"condition" json:"condition"`
	Severity            string `yaml:"severity" json:"severity"`
	FindingTitle        string `yaml:"finding_title" json:"finding_title,omitempty"`
	ComplianceFramework string `yaml:"compliance_framework" json:"compliance_framework,omitempty"`
	AttributeMapping    bool   `yaml:"attribute_mapping" json:"attribute_mapping,omitempty"`
}

// Remediation contains fix guidance
type Remediation struct {
	Summary        string   `yaml:"summary" json:"summary"`
	Steps          []string `yaml:"steps" json:"steps"`
	RemediationSQL string   `yaml:"remediation_sql" json:"remediation_sql"`
}

// Evidence defines what to capture for audit trail
type Evidence struct {
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	SQL         string `yaml:"sql"`
	SourceMode  string `yaml:"source_mode"`
	SourcePath  string `yaml:"source_path"`
}

// Reference links to compliance frameworks
type Reference struct {
	Framework string `yaml:"framework"`
	ControlID string `yaml:"control_id"`
	URL       string `yaml:"url"`
}

// RiskMetadata contains risk scoring information
type RiskMetadata struct {
	BaseScore      float64 `yaml:"base_score"`
	Exploitability string  `yaml:"exploitability"`
	Impact         string  `yaml:"impact"`
	Prevalence     float64 `yaml:"prevalence"`
}

// Correlation defines cross-rule relationships
type Correlation struct {
	CorrelationID      string   `yaml:"correlation_id"`
	Name               string   `yaml:"name"`
	Description        string   `yaml:"description"`
	ControlIDs         []string `yaml:"control_ids"`
	SeverityMultiplier float64  `yaml:"severity_multiplier"`
	CombinedSeverity   string   `yaml:"combined_severity"`
}

// UpdateStrategy defines update behavior
type UpdateStrategy struct {
	Frequency         string `yaml:"frequency"`
	AutoUpdateEnabled bool   `yaml:"auto_update_enabled"`
	UpdateChannel     string `yaml:"update_channel"`
}

// Verification contains signature verification data
type Verification struct {
	PublicKeyPEM           string `yaml:"public_key_pem"`
	VerifyBeforeExecution  bool   `yaml:"verify_before_execution"`
	FailOnInvalidSignature bool   `yaml:"fail_on_invalid_signature"`
}

// ControlResult represents the outcome of executing a control
type ControlResult struct {
	ControlID       string
	ControlCode     string
	Category        string
	Title           string
	Status          string // PASS, FAIL, ERROR
	Procedures      []ProcedureResult
	EvidenceCapture []EvidenceCaptureResult
	Error           error
	ExecutedAt      time.Time
	// ControlPackName and ControlPackVersion identify the control set this
	// result came from (set from ControlSet.Metadata by ExecuteControlSet), so
	// downstream consumers (e.g. SIEM export) can attribute a finding to its
	// exact originating pack instead of leaving it blank.
	ControlPackName    string
	ControlPackVersion string
}

// EvidenceCaptureResult represents captured audit evidence
type EvidenceCaptureResult struct {
	Type         string
	Description  string
	SourceMode   string
	SourcePath   string
	SourceKey    string
	LeaseToken   string
	Watermark    string
	Skipped      bool
	SkipReason   string
	ErrorMessage string
	Data         []map[string]interface{}
	Error        error
}

// ProcedureResult represents the outcome of executing a procedure
type ProcedureResult struct {
	ProcedureID string
	Status      string         // PASS, FAIL, REVIEW, LICENSE, INFO, ERROR
	Rows        []database.Row `json:"rows"`
	Findings    []Finding
	Error       error
	ExecutedAt  time.Time
}

// Finding represents a single security issue found
type Finding struct {
	Severity    string
	Status      string
	Title       string
	Description string
	Evidence    map[string]interface{}
	Remediation string
}
