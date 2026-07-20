// Package entitlement provides control set entitlement validation.
// Entitlements control which control packs an agent can execute based on
// organization licensing and tier.
package entitlement

import (
	"strings"
	"time"

	"basecheck-agent/pkg/controlset"
)

// Entitlement represents a signed entitlement manifest that controls
// which control packs an agent is allowed to execute.
type Entitlement struct {
	// OrganizationID is the organization this entitlement belongs to
	OrganizationID string `yaml:"organization_id" json:"organization_id"`

	// AgentID binds this entitlement to a specific agent (prevents copying)
	AgentID string `yaml:"agent_id" json:"agent_id"`

	// LicenseID is the license key this entitlement was issued from
	LicenseID string `yaml:"license_id" json:"license_id"`

	// IssuedAt is when this entitlement was created
	IssuedAt time.Time `yaml:"issued_at" json:"issued_at"`

	// NotAfter is the expiration time - entitlement is invalid after this
	NotAfter time.Time `yaml:"not_after" json:"not_after"`

	// Tier is the maximum tier level allowed (free, paid, enterprise)
	Tier string `yaml:"tier" json:"tier"`

	// Packs is the list of control pack IDs this entitlement allows
	Packs []string `yaml:"packs" json:"packs"`

	// Features is the list of enabled features (e.g., siem_export, remediation_workflows)
	Features []string `yaml:"features" json:"features"`

	// SignatureB64 is the base64-encoded signature of the canonical entitlement
	SignatureB64 string `yaml:"signature" json:"signature"`
}

// ClockSkewTolerance is the tolerance for clock differences when checking expiry
const ClockSkewTolerance = 5 * time.Minute

// IsExpired returns true if the entitlement has expired.
// Includes clock skew tolerance of 5 minutes.
func (e *Entitlement) IsExpired() bool {
	return time.Now().After(e.NotAfter.Add(ClockSkewTolerance))
}

// IsExpiredAt returns true if the entitlement is expired at the given time.
func (e *Entitlement) IsExpiredAt(t time.Time) bool {
	return t.After(e.NotAfter.Add(ClockSkewTolerance))
}

// TimeUntilExpiry returns the duration until the entitlement expires.
// Returns 0 if already expired.
func (e *Entitlement) TimeUntilExpiry() time.Duration {
	remaining := time.Until(e.NotAfter)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// AllowsTier returns true if this entitlement allows the given tier.
// Tier hierarchy: free < paid < enterprise
// An entitlement with tier "enterprise" allows all tiers.
// An entitlement with tier "paid" allows "free" and "paid".
// An entitlement with tier "free" allows only "free".
func (e *Entitlement) AllowsTier(requestedTier string) bool {
	entitlementLevel := controlset.TierLevel(e.Tier)
	requestedLevel := controlset.TierLevel(requestedTier)

	// If either tier is invalid (level -1), fail closed
	if entitlementLevel < 0 || requestedLevel < 0 {
		return false
	}

	return entitlementLevel >= requestedLevel
}

// AllowsPack returns true if this entitlement allows the given pack ID.
// Pack matching is case-insensitive.
func (e *Entitlement) AllowsPack(packID string) bool {
	normalizedPackID := strings.ToLower(strings.TrimSpace(packID))
	for _, allowed := range e.Packs {
		if strings.ToLower(strings.TrimSpace(allowed)) == normalizedPackID {
			return true
		}
	}
	return false
}

// HasFeature returns true if this entitlement has the given feature enabled.
// Feature matching is case-insensitive.
func (e *Entitlement) HasFeature(feature string) bool {
	normalizedFeature := strings.ToLower(strings.TrimSpace(feature))
	for _, f := range e.Features {
		if strings.ToLower(strings.TrimSpace(f)) == normalizedFeature {
			return true
		}
	}
	return false
}

// Validate performs basic validation of the entitlement fields.
// Does not verify signature - use Verify() for that.
// Does not check agent binding - use ValidateForAgent() for that.
func (e *Entitlement) Validate() error {
	if strings.TrimSpace(e.OrganizationID) == "" {
		return ErrMissingOrgID
	}
	if strings.TrimSpace(e.AgentID) == "" {
		return ErrMissingAgentID
	}
	if e.IssuedAt.IsZero() {
		return ErrMissingIssuedAt
	}
	if e.NotAfter.IsZero() {
		return ErrMissingNotAfter
	}
	if e.NotAfter.Before(e.IssuedAt) {
		return ErrInvalidDateRange
	}
	if strings.TrimSpace(e.Tier) == "" {
		return ErrMissingTier
	}
	// Validate tier is known
	if controlset.TierLevel(e.Tier) < 0 {
		return ErrUnknownTier
	}
	return nil
}

// ValidateForAgent validates the entitlement and checks it is bound to the given agent.
func (e *Entitlement) ValidateForAgent(agentID string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if !e.IsBoundToAgent(agentID) {
		return ErrAgentMismatch
	}
	return nil
}

// IsBoundToAgent returns true if this entitlement is bound to the given agent ID.
// Comparison is case-insensitive.
func (e *Entitlement) IsBoundToAgent(agentID string) bool {
	return strings.EqualFold(strings.TrimSpace(e.AgentID), strings.TrimSpace(agentID))
}

// CheckAccess checks if this entitlement allows access to a control pack
// with the given ID and tier. Returns nil if allowed, error otherwise.
func (e *Entitlement) CheckAccess(packID, packTier string) error {
	if e.IsExpired() {
		return ErrExpired
	}
	if !e.AllowsTier(packTier) {
		return ErrInsufficientTier
	}
	if !e.AllowsPack(packID) {
		return ErrPackNotAllowed
	}
	return nil
}
