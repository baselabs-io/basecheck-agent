package entitlement

import "errors"

// Validation errors
var (
	ErrMissingOrgID      = errors.New("entitlement: missing organization_id")
	ErrMissingAgentID    = errors.New("entitlement: missing agent_id")
	ErrMissingIssuedAt   = errors.New("entitlement: missing issued_at")
	ErrMissingNotAfter   = errors.New("entitlement: missing not_after")
	ErrInvalidDateRange  = errors.New("entitlement: not_after is before issued_at")
	ErrMissingTier       = errors.New("entitlement: missing tier")
	ErrUnknownTier       = errors.New("entitlement: unknown tier value")
	ErrMissingSignature  = errors.New("entitlement: missing signature")
	ErrInvalidSignature  = errors.New("entitlement: invalid signature")
	ErrNoPublicKey       = errors.New("entitlement: no public key configured")
	ErrInvalidPublicKey  = errors.New("entitlement: invalid public key")
	ErrAgentMismatch     = errors.New("entitlement: agent_id does not match this agent")
)

// Access check errors
var (
	ErrExpired          = errors.New("entitlement: expired")
	ErrInsufficientTier = errors.New("entitlement: insufficient tier")
	ErrPackNotAllowed   = errors.New("entitlement: pack not in allowed list")
	ErrFeatureDisabled  = errors.New("entitlement: feature not enabled")
)

// Loading errors
var (
	ErrNotFound             = errors.New("entitlement: not found")
	ErrLoadFailed           = errors.New("entitlement: failed to load")
	ErrParseFailed          = errors.New("entitlement: failed to parse")
	ErrInsecureHTTP         = errors.New("entitlement: insecure HTTP connection refused")
	ErrSignatureRequired    = errors.New("entitlement: signature verification required but no public key configured")
	ErrLocalPathNotFound    = errors.New("entitlement: configured local_path file not found")
)
