package entitlement

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// canonicalEntitlement is the signed representation of an entitlement.
// Fields are ordered and normalized for deterministic signature verification.
// All string fields are trimmed and lowercased for consistency.
type canonicalEntitlement struct {
	OrganizationID string   `json:"organization_id"`
	AgentID        string   `json:"agent_id"`
	LicenseID      string   `json:"license_id,omitempty"`
	IssuedAt       string   `json:"issued_at"` // RFC3339 format
	NotAfter       string   `json:"not_after"` // RFC3339 format
	Tier           string   `json:"tier"`
	Packs          []string `json:"packs"`
	Features       []string `json:"features"`
}

// Verify verifies the entitlement signature using the provided public key.
// The public key should be base64-encoded DER (PKIX) format.
// Returns nil if signature is valid, error otherwise.
func (e *Entitlement) Verify(publicKeyB64 string) error {
	if strings.TrimSpace(publicKeyB64) == "" {
		return ErrNoPublicKey
	}

	if strings.TrimSpace(e.SignatureB64) == "" {
		return ErrMissingSignature
	}

	// Decode public key
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return fmt.Errorf("%w: failed to decode: %v", ErrInvalidPublicKey, err)
	}

	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse: %v", ErrInvalidPublicKey, err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: not an RSA public key", ErrInvalidPublicKey)
	}

	// Create canonical payload
	canonical, err := e.canonicalPayload()
	if err != nil {
		return fmt.Errorf("%w: failed to create canonical payload: %v", ErrInvalidSignature, err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(e.SignatureB64)
	if err != nil {
		return fmt.Errorf("%w: failed to decode signature: %v", ErrInvalidSignature, err)
	}

	// Compute hash and verify
	hash := sha256.Sum256(canonical)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature); err != nil {
		return fmt.Errorf("%w: verification failed: %v", ErrInvalidSignature, err)
	}

	return nil
}

// canonicalPayload creates the deterministic JSON representation for signing.
// All string values are normalized (trimmed, lowercased) for consistency
// with case-insensitive access checks.
func (e *Entitlement) canonicalPayload() ([]byte, error) {
	// Normalize and sort packs (lowercase for case-insensitive matching)
	packs := make([]string, len(e.Packs))
	for i, p := range e.Packs {
		packs[i] = strings.ToLower(strings.TrimSpace(p))
	}
	sort.Strings(packs)

	// Normalize and sort features (lowercase for case-insensitive matching)
	features := make([]string, len(e.Features))
	for i, f := range e.Features {
		features[i] = strings.ToLower(strings.TrimSpace(f))
	}
	sort.Strings(features)

	canonical := canonicalEntitlement{
		OrganizationID: strings.ToLower(strings.TrimSpace(e.OrganizationID)),
		AgentID:        strings.ToLower(strings.TrimSpace(e.AgentID)),
		LicenseID:      strings.ToLower(strings.TrimSpace(e.LicenseID)),
		IssuedAt:       e.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       e.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Tier:           strings.ToLower(strings.TrimSpace(e.Tier)),
		Packs:          packs,
		Features:       features,
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(canonical); err != nil {
		return nil, err
	}

	return bytes.TrimSpace(buf.Bytes()), nil
}

// VerifyAndValidate performs both signature verification and field validation.
// Recommended entry point for entitlement verification.
func (e *Entitlement) VerifyAndValidate(publicKeyB64 string) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := e.Verify(publicKeyB64); err != nil {
		return err
	}
	return nil
}
