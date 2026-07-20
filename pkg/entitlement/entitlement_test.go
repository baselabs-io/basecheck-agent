package entitlement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEntitlementIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		notAfter time.Time
		wantExp  bool
	}{
		{"future date not expired", time.Now().Add(24 * time.Hour), false},
		{"past date expired", time.Now().Add(-24 * time.Hour), true},
		{"within clock skew tolerance not expired", time.Now().Add(-3 * time.Minute), false},
		{"beyond clock skew tolerance expired", time.Now().Add(-10 * time.Minute), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Entitlement{NotAfter: tt.notAfter}
			if got := e.IsExpired(); got != tt.wantExp {
				t.Errorf("IsExpired() = %v, want %v", got, tt.wantExp)
			}
		})
	}
}

func TestEntitlementAllowsTier(t *testing.T) {
	tests := []struct {
		name          string
		entTier       string
		requestedTier string
		want          bool
	}{
		{"enterprise allows enterprise", "enterprise", "enterprise", true},
		{"enterprise allows paid", "enterprise", "paid", true},
		{"enterprise allows free", "enterprise", "free", true},
		{"paid allows paid", "paid", "paid", true},
		{"paid allows free", "paid", "free", true},
		{"paid denies enterprise", "paid", "enterprise", false},
		{"free allows free", "free", "free", true},
		{"free denies paid", "free", "paid", false},
		{"free denies enterprise", "free", "enterprise", false},
		{"unknown entitlement tier fails closed", "custom", "free", false},
		{"unknown requested tier fails closed", "paid", "custom", false},
		{"case insensitive", "PAID", "paid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Entitlement{Tier: tt.entTier}
			if got := e.AllowsTier(tt.requestedTier); got != tt.want {
				t.Errorf("AllowsTier(%q) = %v, want %v", tt.requestedTier, got, tt.want)
			}
		})
	}
}

func TestEntitlementAllowsPack(t *testing.T) {
	e := &Entitlement{
		Packs: []string{"oracle-cis-benchmark", "postgres-security", "MySQL-Baseline"},
	}

	tests := []struct {
		packID string
		want   bool
	}{
		{"oracle-cis-benchmark", true},
		{"postgres-security", true},
		{"MySQL-Baseline", true},
		{"mysql-baseline", true}, // case insensitive
		{"ORACLE-CIS-BENCHMARK", true},
		{"  oracle-cis-benchmark  ", true}, // whitespace trimmed
		{"mssql-security", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.packID, func(t *testing.T) {
			if got := e.AllowsPack(tt.packID); got != tt.want {
				t.Errorf("AllowsPack(%q) = %v, want %v", tt.packID, got, tt.want)
			}
		})
	}
}

func TestEntitlementHasFeature(t *testing.T) {
	e := &Entitlement{
		Features: []string{"siem_export", "Remediation_Workflows"},
	}

	tests := []struct {
		feature string
		want    bool
	}{
		{"siem_export", true},
		{"SIEM_EXPORT", true},
		{"remediation_workflows", true},
		{"active_validation", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.feature, func(t *testing.T) {
			if got := e.HasFeature(tt.feature); got != tt.want {
				t.Errorf("HasFeature(%q) = %v, want %v", tt.feature, got, tt.want)
			}
		})
	}
}

func TestEntitlementValidate(t *testing.T) {
	validEnt := func() *Entitlement {
		return &Entitlement{
			OrganizationID: "org-123",
			AgentID:        "agent-456",
			IssuedAt:       time.Now().Add(-time.Hour),
			NotAfter:       time.Now().Add(24 * time.Hour),
			Tier:           "paid",
		}
	}

	tests := []struct {
		name    string
		modify  func(*Entitlement)
		wantErr error
	}{
		{"valid entitlement", func(e *Entitlement) {}, nil},
		{"missing org id", func(e *Entitlement) { e.OrganizationID = "" }, ErrMissingOrgID},
		{"missing agent id", func(e *Entitlement) { e.AgentID = "" }, ErrMissingAgentID},
		{"missing issued_at", func(e *Entitlement) { e.IssuedAt = time.Time{} }, ErrMissingIssuedAt},
		{"missing not_after", func(e *Entitlement) { e.NotAfter = time.Time{} }, ErrMissingNotAfter},
		{"not_after before issued_at", func(e *Entitlement) {
			e.IssuedAt = time.Now()
			e.NotAfter = time.Now().Add(-time.Hour)
		}, ErrInvalidDateRange},
		{"missing tier", func(e *Entitlement) { e.Tier = "" }, ErrMissingTier},
		{"unknown tier", func(e *Entitlement) { e.Tier = "premium" }, ErrUnknownTier},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEnt()
			tt.modify(e)
			err := e.Validate()
			if tt.wantErr == nil && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestEntitlementAgentBinding(t *testing.T) {
	e := &Entitlement{
		OrganizationID: "org-123",
		AgentID:        "agent-456",
		IssuedAt:       time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		Tier:           "paid",
	}

	tests := []struct {
		name    string
		agentID string
		want    bool
	}{
		{"exact match", "agent-456", true},
		{"case insensitive", "AGENT-456", true},
		{"with whitespace", "  agent-456  ", true},
		{"wrong agent", "agent-789", false},
		{"empty agent", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.IsBoundToAgent(tt.agentID); got != tt.want {
				t.Errorf("IsBoundToAgent(%q) = %v, want %v", tt.agentID, got, tt.want)
			}
		})
	}
}

func TestEntitlementValidateForAgent(t *testing.T) {
	e := &Entitlement{
		OrganizationID: "org-123",
		AgentID:        "agent-456",
		IssuedAt:       time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		Tier:           "paid",
	}

	t.Run("correct agent", func(t *testing.T) {
		if err := e.ValidateForAgent("agent-456"); err != nil {
			t.Errorf("ValidateForAgent() unexpected error: %v", err)
		}
	})

	t.Run("wrong agent", func(t *testing.T) {
		if err := e.ValidateForAgent("agent-789"); err != ErrAgentMismatch {
			t.Errorf("ValidateForAgent() error = %v, want %v", err, ErrAgentMismatch)
		}
	})
}

func TestEntitlementCheckAccess(t *testing.T) {
	e := &Entitlement{
		OrganizationID: "org-123",
		AgentID:        "agent-456",
		IssuedAt:       time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		Tier:           "paid",
		Packs:          []string{"oracle-security", "postgres-security"},
	}

	tests := []struct {
		name     string
		packID   string
		packTier string
		wantErr  error
	}{
		{"allowed pack and tier", "oracle-security", "paid", nil},
		{"allowed pack lower tier", "oracle-security", "free", nil},
		{"pack not allowed", "mssql-security", "paid", ErrPackNotAllowed},
		{"tier too high", "oracle-security", "enterprise", ErrInsufficientTier},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.CheckAccess(tt.packID, tt.packTier)
			if tt.wantErr == nil && err != nil {
				t.Errorf("CheckAccess() unexpected error: %v", err)
			}
			if tt.wantErr != nil && err != tt.wantErr {
				t.Errorf("CheckAccess() error = %v, want %v", err, tt.wantErr)
			}
		})
	}

	// Test expired entitlement
	t.Run("expired entitlement", func(t *testing.T) {
		expired := *e
		expired.NotAfter = time.Now().Add(-time.Hour)
		if err := expired.CheckAccess("oracle-security", "paid"); err != ErrExpired {
			t.Errorf("CheckAccess() with expired entitlement: got %v, want %v", err, ErrExpired)
		}
	})
}

// Helper to generate test keys and sign an entitlement
func signEntitlement(t *testing.T, ent *Entitlement) (publicKeyB64 string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyB64 = base64.StdEncoding.EncodeToString(publicKeyBytes)

	payload, err := ent.canonicalPayload()
	if err != nil {
		t.Fatalf("Failed to create canonical payload: %v", err)
	}

	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	ent.SignatureB64 = base64.StdEncoding.EncodeToString(signature)

	return publicKeyB64
}

func TestEntitlementVerify(t *testing.T) {
	ent := &Entitlement{
		OrganizationID: "org-123",
		AgentID:        "agent-456",
		LicenseID:      "lic-789",
		IssuedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:       time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Tier:           "paid",
		Packs:          []string{"oracle-security", "postgres-security"},
		Features:       []string{"siem_export"},
	}

	publicKeyB64 := signEntitlement(t, ent)

	t.Run("valid signature", func(t *testing.T) {
		if err := ent.Verify(publicKeyB64); err != nil {
			t.Errorf("Verify() with valid signature: %v", err)
		}
	})

	t.Run("tampered data", func(t *testing.T) {
		tampered := *ent
		tampered.Tier = "enterprise"
		if err := tampered.Verify(publicKeyB64); err == nil {
			t.Error("Verify() should fail with tampered data")
		}
	})

	t.Run("tampered agent_id", func(t *testing.T) {
		tampered := *ent
		tampered.AgentID = "different-agent"
		if err := tampered.Verify(publicKeyB64); err == nil {
			t.Error("Verify() should fail with tampered agent_id")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		noSig := *ent
		noSig.SignatureB64 = ""
		if err := noSig.Verify(publicKeyB64); err != ErrMissingSignature {
			t.Errorf("Verify() with missing signature: got %v, want %v", err, ErrMissingSignature)
		}
	})

	t.Run("no public key", func(t *testing.T) {
		if err := ent.Verify(""); err != ErrNoPublicKey {
			t.Errorf("Verify() with no public key: got %v, want %v", err, ErrNoPublicKey)
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		err := ent.Verify("not-valid-base64!!!")
		if err == nil {
			t.Error("Verify() should fail with invalid public key")
		}
	})
}

func TestLoaderRequiresPublicKey(t *testing.T) {
	loader := NewLoader("", "", "", "", "agent-123", "", false, false)

	_, err := loader.Load()
	if err != ErrSignatureRequired {
		t.Errorf("Load() without public key: got %v, want %v", err, ErrSignatureRequired)
	}
}

// TestLoaderInsecureTransportDoesNotWeakenSignature guards against the coupling bug
// where enabling plain HTTP transport (e.g. via security.allow_http) implicitly
// disabled entitlement signature verification. The two must be independent.
func TestLoaderInsecureTransportDoesNotWeakenSignature(t *testing.T) {
	loader := NewLoader("", "", "", "", "agent-123", "", true, false)

	_, err := loader.Load()
	if err != ErrSignatureRequired {
		t.Errorf("Load() with insecure transport but secure signature: got %v, want %v", err, ErrSignatureRequired)
	}
}

func TestLoaderAllowsInsecureMode(t *testing.T) {
	tmpDir := t.TempDir()
	entPath := filepath.Join(tmpDir, "entitlement.yaml")

	// Create valid entitlement without signature
	entData := `
organization_id: org-123
agent_id: agent-456
issued_at: 2026-01-01T00:00:00Z
not_after: 2027-01-01T00:00:00Z
tier: paid
packs:
  - oracle-security
`
	if err := os.WriteFile(entPath, []byte(entData), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// With insecure mode, should load without signature
	loader := NewLoader(entPath, "", "", "", "agent-456", "", true, true)
	ent, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() in insecure mode: %v", err)
	}
	if ent == nil {
		t.Fatal("Load() returned nil entitlement")
	}
	if ent.OrganizationID != "org-123" {
		t.Errorf("OrganizationID = %q, want %q", ent.OrganizationID, "org-123")
	}
}

func TestLoaderEnforcesHTTPS(t *testing.T) {
	loader := NewLoader("", "", "http://insecure.example.com", "token", "agent-123", "fake-key", false, false)

	_, err := loader.LoadFromServer()
	if err == nil {
		t.Error("LoadFromServer() should fail with HTTP URL")
	}
	if err != nil && err.Error() != "entitlement: insecure HTTP connection refused: use https:// or set AllowInsecure for testing" {
		// Check it's the right error type
		if !strings.Contains(err.Error(), "insecure HTTP") {
			t.Errorf("LoadFromServer() error = %v, want insecure HTTP error", err)
		}
	}
}

func TestLoaderEnforcesAgentBinding(t *testing.T) {
	tmpDir := t.TempDir()
	entPath := filepath.Join(tmpDir, "entitlement.yaml")

	entData := `
organization_id: org-123
agent_id: agent-456
issued_at: 2026-01-01T00:00:00Z
not_after: 2027-01-01T00:00:00Z
tier: paid
packs:
  - oracle-security
`
	if err := os.WriteFile(entPath, []byte(entData), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	t.Run("correct agent", func(t *testing.T) {
		loader := NewLoader(entPath, "", "", "", "agent-456", "", true, true)
		ent, err := loader.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if ent == nil {
			t.Fatal("Load() returned nil")
		}
	})

	t.Run("wrong agent", func(t *testing.T) {
		loader := NewLoader(entPath, "", "", "", "different-agent", "", true, true)
		_, err := loader.Load()
		if err == nil {
			t.Error("Load() should fail with wrong agent")
		}
	})
}

func TestLoaderLoadFromFile(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create valid entitlement file
	entPath := filepath.Join(tmpDir, "entitlement.yaml")
	entData := `
organization_id: org-123
agent_id: agent-456
issued_at: 2026-01-01T00:00:00Z
not_after: 2027-01-01T00:00:00Z
tier: paid
packs:
  - oracle-security
features:
  - siem_export
`
	if err := os.WriteFile(entPath, []byte(entData), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	loader := NewLoader("", "", "", "", "agent-456", "", true, true)

	t.Run("load valid file", func(t *testing.T) {
		ent, err := loader.LoadFromFile(entPath)
		if err != nil {
			t.Fatalf("LoadFromFile() error: %v", err)
		}
		if ent.OrganizationID != "org-123" {
			t.Errorf("OrganizationID = %q, want %q", ent.OrganizationID, "org-123")
		}
		if ent.AgentID != "agent-456" {
			t.Errorf("AgentID = %q, want %q", ent.AgentID, "agent-456")
		}
		if ent.Tier != "paid" {
			t.Errorf("Tier = %q, want %q", ent.Tier, "paid")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := loader.LoadFromFile(filepath.Join(tmpDir, "nonexistent.yaml"))
		if err != ErrNotFound {
			t.Errorf("LoadFromFile() for nonexistent file: got %v, want %v", err, ErrNotFound)
		}
	})
}

func TestLoaderLoadFromServer(t *testing.T) {
	// Create test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/entitlement" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Agent-Token") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ent := map[string]interface{}{
			"organization_id": "org-456",
			"agent_id":        "agent-789",
			"issued_at":       "2026-01-01T00:00:00Z",
			"not_after":       "2027-01-01T00:00:00Z",
			"tier":            "enterprise",
			"packs":           []string{"oracle-security"},
			"features":        []string{},
		}
		json.NewEncoder(w).Encode(ent)
	}))
	defer server.Close()

	// Use the test server's client which trusts its cert
	loader := NewLoader("", "", server.URL, "test-token", "agent-789", "", true, true)
	loader.HTTPClient = server.Client()

	t.Run("load from server", func(t *testing.T) {
		ent, err := loader.LoadFromServer()
		if err != nil {
			t.Fatalf("LoadFromServer() error: %v", err)
		}
		if ent.OrganizationID != "org-456" {
			t.Errorf("OrganizationID = %q, want %q", ent.OrganizationID, "org-456")
		}
		if ent.Tier != "enterprise" {
			t.Errorf("Tier = %q, want %q", ent.Tier, "enterprise")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		badLoader := NewLoader("", "", server.URL, "bad-token", "agent-789", "", true, true)
		badLoader.HTTPClient = server.Client()
		_, err := badLoader.LoadFromServer()
		if err == nil {
			t.Error("LoadFromServer() should fail with invalid token")
		}
	})
}

func TestLoaderSaveToCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache")

	loader := NewLoader("", cachePath, "", "", "agent-789", "", true, true)

	ent := &Entitlement{
		OrganizationID: "org-789",
		AgentID:        "agent-789",
		IssuedAt:       time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		Tier:           "paid",
		Packs:          []string{"test-pack"},
	}

	if err := loader.SaveToCache(ent); err != nil {
		t.Fatalf("SaveToCache() error: %v", err)
	}

	// Verify file was created
	cachedPath := filepath.Join(cachePath, "entitlement.yaml")
	if _, err := os.Stat(cachedPath); os.IsNotExist(err) {
		t.Error("Cache file was not created")
	}

	// Verify we can load it back
	loaded, err := loader.LoadFromCache()
	if err != nil {
		t.Fatalf("LoadFromCache() error: %v", err)
	}
	if loaded.OrganizationID != ent.OrganizationID {
		t.Errorf("Loaded OrganizationID = %q, want %q", loaded.OrganizationID, ent.OrganizationID)
	}
}

func TestLoaderExpiredCacheNotUsedAsFallback(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache")

	// Create expired entitlement in cache
	loader := NewLoader("", cachePath, "", "", "agent-123", "", true, true)

	expiredEnt := &Entitlement{
		OrganizationID: "org-123",
		AgentID:        "agent-123",
		IssuedAt:       time.Now().Add(-48 * time.Hour),
		NotAfter:       time.Now().Add(-24 * time.Hour), // expired
		Tier:           "paid",
		Packs:          []string{"test-pack"},
	}

	if err := loader.SaveToCache(expiredEnt); err != nil {
		t.Fatalf("SaveToCache() error: %v", err)
	}

	// Load should return nil (free mode), not expired cache
	ent, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if ent != nil {
		t.Error("Load() should return nil for expired cache, not the expired entitlement")
	}
}

func TestLoaderConfiguredLocalPathMissingFails(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist.yaml")

	// When local_path is configured but file doesn't exist,
	// should fail clearly rather than silently degrading to free mode
	loader := NewLoader(nonExistentPath, "", "", "", "agent-123", "", true, true)

	_, err := loader.Load()
	if err == nil {
		t.Error("Load() should fail when configured local_path doesn't exist")
	}
	if !strings.Contains(err.Error(), "local_path file not found") {
		t.Errorf("Load() error should mention local_path not found, got: %v", err)
	}
}
