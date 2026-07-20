package controlset

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFetchControlSetRequireSignaturesWithoutSignatureFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "oracle-controls-baseline",
			"control_set_version": "1.0.0",
			"database_type":       "oracle",
			"control_set_type":    "security",
			"controls":            []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, true, "")
	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatalf("expected signature-required fetch to fail when signature is missing")
	}
}

func TestFetchControlSetRequireSignaturesWithSignatureFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "oracle-controls-baseline",
			"control_set_version": "1.0.0",
			"database_type":       "oracle",
			"control_set_type":    "security",
			"signature": map[string]interface{}{
				"algorithm":     "SHA256withRSA",
				"signature_b64": "invalid-signature",
			},
			"controls": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, true, "")
	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatalf("expected signature-required fetch to fail closed")
	}
}

func TestFetchControlSetRequireSignaturesWithValidSignatureSucceeds(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	publicKeyB64 := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey))
	pubPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	publicKeyB64 = base64.StdEncoding.EncodeToString(pubPKIX)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := canonicalControlSet{
			ControlSetID:      "oracle-controls-baseline",
			ControlSetVersion: "1.0.0",
			DatabaseType:      "oracle",
			ControlSetType:    "security",
			Tier:              "free",
			Controls:          []canonicalControl{},
		}
		data, err := marshalCanonical(payload)
		if err != nil {
			t.Fatalf("failed to marshal canonical payload: %v", err)
		}
		hash := sha256.Sum256(data)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatalf("failed to sign payload: %v", err)
		}

		resp := map[string]interface{}{
			"control_set_id":      "oracle-controls-baseline",
			"control_set_version": "1.0.0",
			"database_type":       "oracle",
			"control_set_type":    "security",
			"tier":                "free",
			"signature": map[string]interface{}{
				"algorithm":     "SHA256withRSA",
				"signature_b64": base64.StdEncoding.EncodeToString(signature),
			},
			"controls": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, true, publicKeyB64)
	if _, err := fetcher.FetchControlSet("oracle", ""); err != nil {
		t.Fatalf("expected signature-required fetch to succeed: %v", err)
	}
}

// TestFetchLocalControlSetSignatureCoversEvidenceCaptureSQL guards against the
// canonical signed payload omitting EvidenceCapture, which ExecuteControl
// executes against the customer database (see executor.go). If the signed
// payload doesn't cover it, evidence-capture SQL in a local control-pack file
// could be tampered with after signing without invalidating the signature.
func TestFetchLocalControlSetSignatureCoversEvidenceCaptureSQL(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubPKIX)

	buildSet := func(sql string) *ControlSet {
		return &ControlSet{
			Metadata: Metadata{
				ControlSetID:      "oracle-controls-baseline",
				ControlSetVersion: "1.0.0",
				DatabaseType:      "oracle",
				ControlSetType:    "security",
				Tier:              "free",
			},
			Controls: []Control{{
				ControlID:   "ORA-SEC-004",
				ControlCode: "ORA-SEC-004",
				Procedures: []ControlProcedure{{
					ProcedureID: "ora-sec-004-check",
					SystemType:  "oracle",
					Tests:       "SELECT 1 FROM dual",
				}},
				EvidenceCapture: []Evidence{{
					Type: "audit_operations",
					SQL:  sql,
				}},
			}},
		}
	}

	// Sign a control set whose evidence-capture SQL is a read-only SELECT.
	signer := NewFetcher("local", "", "", "", "", true, true, publicKeyB64)
	signedEvidenceSQL := "SELECT * FROM audit_trail"
	signedSet := buildSet(signedEvidenceSQL)
	payload, err := signer.createCanonicalPayload(signedSet)
	if err != nil {
		t.Fatalf("failed to build canonical payload: %v", err)
	}
	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	writeControlSet := func(t *testing.T, set *ControlSet) string {
		t.Helper()
		dir := t.TempDir()
		data, err := yaml.Marshal(set)
		if err != nil {
			t.Fatalf("failed to marshal control set: %v", err)
		}
		path := filepath.Join(dir, "oracle-controls-baseline-v1.0.0.yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("failed to write control set file: %v", err)
		}
		return dir
	}

	t.Run("matching evidence_capture verifies", func(t *testing.T) {
		set := buildSet(signedEvidenceSQL)
		set.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, set)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err != nil {
			t.Fatalf("expected fetch to succeed when evidence_capture matches signed payload: %v", err)
		}
	})

	t.Run("tampered evidence_capture SQL fails signature verification", func(t *testing.T) {
		// Same signature, but the evidence-capture SQL was changed after signing.
		tampered := buildSet("DROP TABLE audit_trail")
		tampered.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, tampered)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err == nil {
			t.Fatal("expected tampered evidence_capture SQL to fail signature verification")
		}
	})
}

// TestFetchLocalControlSetSignatureCoversCompatibilityMetadata guards
// against the canonical signed payload omitting Compatibility/DatabaseVersions
// and ControlProcedure.SystemApplicability, which CheckCompatibility
// (compatibility.go) uses to decide whether a pack executes at all. If the
// signed payload doesn't cover them, an attacker (or corruption) could tamper
// with these execution-gating fields after signing without invalidating the
// signature.
func TestFetchLocalControlSetSignatureCoversCompatibilityMetadata(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubPKIX)

	buildSet := func(agentMinVersion string) *ControlSet {
		return &ControlSet{
			Metadata: Metadata{
				ControlSetID:      "oracle-controls-baseline",
				ControlSetVersion: "1.0.0",
				DatabaseType:      "oracle",
				ControlSetType:    "security",
				Tier:              "free",
				DatabaseVersions:  []string{"19c"},
			},
			Compatibility: Compatibility{
				AgentMinVersion: agentMinVersion,
			},
			Controls: []Control{{
				ControlID:   "ORA-SEC-001",
				ControlCode: "ORA-SEC-001",
				Procedures: []ControlProcedure{{
					ProcedureID:         "ora-sec-001-check",
					SystemType:          "oracle",
					SystemApplicability: "on-premise",
					Tests:               "SELECT 1 FROM dual",
				}},
			}},
		}
	}

	signer := NewFetcher("local", "", "", "", "", true, true, publicKeyB64)
	signedSet := buildSet("1.0.0")
	payload, err := signer.createCanonicalPayload(signedSet)
	if err != nil {
		t.Fatalf("failed to build canonical payload: %v", err)
	}
	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	writeControlSet := func(t *testing.T, set *ControlSet) string {
		t.Helper()
		dir := t.TempDir()
		data, err := yaml.Marshal(set)
		if err != nil {
			t.Fatalf("failed to marshal control set: %v", err)
		}
		path := filepath.Join(dir, "oracle-controls-baseline-v1.0.0.yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("failed to write control set file: %v", err)
		}
		return dir
	}

	t.Run("matching compatibility metadata verifies", func(t *testing.T) {
		set := buildSet("1.0.0")
		set.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, set)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err != nil {
			t.Fatalf("expected fetch to succeed when compatibility metadata matches signed payload: %v", err)
		}
	})

	t.Run("tampered agent_min_version fails signature verification", func(t *testing.T) {
		// Same signature, but agent_min_version was lowered after signing --
		// e.g. to force a pack to run against an agent it wasn't vetted for.
		tampered := buildSet("0.0.1")
		tampered.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, tampered)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err == nil {
			t.Fatal("expected tampered agent_min_version to fail signature verification")
		}
	})

	t.Run("tampered database_versions fails signature verification", func(t *testing.T) {
		tampered := buildSet("1.0.0")
		tampered.Metadata.DatabaseVersions = []string{"11.2"}
		tampered.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, tampered)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err == nil {
			t.Fatal("expected tampered database_versions to fail signature verification")
		}
	})

	t.Run("tampered system_applicability fails signature verification", func(t *testing.T) {
		tampered := buildSet("1.0.0")
		tampered.Controls[0].Procedures[0].SystemApplicability = "cloud"
		tampered.Metadata.Signature = Signature{Algorithm: "SHA256withRSA", SignatureB64: signatureB64}
		dir := writeControlSet(t, tampered)

		fetcher := NewFetcher("local", dir, "", "", "", true, true, publicKeyB64)
		if _, err := fetcher.FetchControlSet("oracle", ""); err == nil {
			t.Fatal("expected tampered system_applicability to fail signature verification")
		}
	})
}

func TestFetchControlSetOptionalSignaturesSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "oracle-controls-baseline",
			"control_set_version": "1.0.0",
			"database_type":       "oracle",
			"control_set_type":    "security",
			"tier":                "free",
			"signature": map[string]interface{}{
				"algorithm":     "SHA256withRSA",
				"signature_b64": "invalid-signature",
			},
			"controls": []map[string]interface{}{
				{
					"control_id":   "ORA-SEC-001",
					"control_code": "ORA-SEC-001",
					"category":     "security",
					"title":        "Sample",
					"description":  "Sample control",
					"procedures": []map[string]interface{}{
						{
							"procedure_id": "p1",
							"system_type":  "oracle",
							"tests":        "SELECT 1 FROM dual",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("expected fetch to succeed when signatures are optional: %v", err)
	}

	if set.Metadata.ControlSetVersion != "1.0.0" {
		t.Fatalf("unexpected control set version: %s", set.Metadata.ControlSetVersion)
	}
}

func TestFetchControlSetParsesCriteriaFromJSONString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "sqlite-controls-baseline-v1.0.0",
			"control_set_version": "1.0.0",
			"database_type":       "sqlite",
			"control_set_type":    "security",
			"tier":                "free",
			"controls": []map[string]interface{}{
				{
					"control_id":   "SQLITE-SEC-001",
					"control_code": "SQLITE-SEC-001",
					"category":     "Configuration",
					"title":        "Foreign keys",
					"description":  "Foreign keys enabled",
					"procedures": []map[string]interface{}{
						{
							"procedure_id": "SQLITE-SEC-001-P1",
							"system_type":  "sqlite",
							"tests":        "SELECT foreign_keys AS FK_ENABLED FROM pragma_foreign_keys",
							"criteria":     "[{\"condition\":\"FK_ENABLED == 0\",\"severity\":\"HIGH\",\"finding_title\":\"Foreign keys disabled\"}]",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	set, err := fetcher.FetchControlSet("sqlite", "")
	if err != nil {
		t.Fatalf("expected fetch to succeed: %v", err)
	}

	if len(set.Controls) != 1 || len(set.Controls[0].Procedures) != 1 {
		t.Fatalf("unexpected controls/procedures layout")
	}

	procedure := set.Controls[0].Procedures[0]
	if len(procedure.Criteria) != 1 {
		t.Fatalf("expected criteria to be parsed from JSON string, got %d", len(procedure.Criteria))
	}

	if procedure.Criteria[0].Condition != "FK_ENABLED == 0" {
		t.Fatalf("unexpected criteria condition: %s", procedure.Criteria[0].Condition)
	}
}

func TestFetchControlSetParsesExecutionMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "supabase-control-plane-security-v1.0.0",
			"control_set_version": "1.0.0",
			"database_type":       "supabase",
			"control_set_type":    "security",
			"tier":                "free",
			"controls": []map[string]interface{}{
				{
					"control_id":   "SB-PLAT-001",
					"control_code": "SB-PLAT-001",
					"category":     "Control Plane",
					"title":        "Management API Coverage Review",
					"description":  "Tests Management API coverage",
					"procedures": []map[string]interface{}{
						{
							"procedure_id":   "sb-plat-001-check",
							"system_type":    "supabase",
							"execution_mode": "http",
							"tests":          "method: GET\npath: /v1/projects/{{PROJECT_REF}}\n",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	set, err := fetcher.FetchControlSet("supabase", "")
	if err != nil {
		t.Fatalf("expected fetch to succeed: %v", err)
	}

	if set.Controls[0].Procedures[0].ExecutionMode != "http" {
		t.Fatalf("expected execution_mode to round-trip, got %q", set.Controls[0].Procedures[0].ExecutionMode)
	}
}

func TestFetchControlSetParsesRemediationFromJSONString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "supabase-controls-baseline-v1.0.0",
			"control_set_version": "1.0.0",
			"database_type":       "supabase",
			"control_set_type":    "security",
			"tier":                "free",
			"controls": []map[string]interface{}{
				{
					"control_id":   "SB-SEC-001",
					"control_code": "SB-SEC-001",
					"category":     "RLS",
					"title":        "Row Level Security Enabled on Exposed Tables",
					"description":  "Detects tables in public or storage schemas with RLS disabled",
					"remediation":  "{\"summary\":\"Enable RLS\",\"steps\":[\"Enable RLS on exposed tables\"],\"remediation_sql\":\"ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\"}",
					"procedures": []map[string]interface{}{
						{
							"procedure_id": "sb-sec-001-check",
							"system_type":  "supabase",
							"tests":        "SELECT 1",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	set, err := fetcher.FetchControlSet("supabase", "")
	if err != nil {
		t.Fatalf("expected fetch to succeed: %v", err)
	}

	if len(set.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(set.Controls))
	}

	if set.Controls[0].Remediation.Summary != "Enable RLS" {
		t.Fatalf("unexpected remediation summary: %s", set.Controls[0].Remediation.Summary)
	}

	if len(set.Controls[0].Remediation.Steps) != 1 {
		t.Fatalf("expected remediation steps to be parsed")
	}

	if set.Controls[0].Remediation.RemediationSQL == "" {
		t.Fatalf("expected remediation SQL to be parsed")
	}
}

func TestFetchControlSetParsesRemediationFromJSONObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "supabase-controls-baseline-v1.0.0",
			"control_set_version": "1.0.0",
			"database_type":       "supabase",
			"control_set_type":    "security",
			"tier":                "free",
			"controls": []map[string]interface{}{
				{
					"control_id":   "SB-SEC-002",
					"control_code": "SB-SEC-002",
					"category":     "RLS",
					"title":        "Anonymous Access",
					"description":  "Detects anonymous access to sensitive tables",
					"remediation": map[string]interface{}{
						"summary":         "Restrict anonymous access",
						"steps":           []string{"Review grants", "Revoke unnecessary access"},
						"remediation_sql": "REVOKE SELECT ON public.users FROM anon;",
					},
					"procedures": []map[string]interface{}{
						{
							"procedure_id": "sb-sec-002-check",
							"system_type":  "supabase",
							"tests":        "SELECT 1",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	set, err := fetcher.FetchControlSet("supabase", "")
	if err != nil {
		t.Fatalf("expected fetch to succeed: %v", err)
	}

	if len(set.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(set.Controls))
	}

	if set.Controls[0].Remediation.Summary != "Restrict anonymous access" {
		t.Fatalf("unexpected remediation summary: %s", set.Controls[0].Remediation.Summary)
	}

	if len(set.Controls[0].Remediation.Steps) != 2 {
		t.Fatalf("expected remediation steps to be parsed")
	}

	if set.Controls[0].Remediation.RemediationSQL == "" {
		t.Fatalf("expected remediation SQL to be parsed")
	}
}

func TestEnrichOracleAuditTrailKeepsSysOperationsVisible(t *testing.T) {
	fetcher := NewFetcher("local", "", "", "", "", true, false, "")
	set := &ControlSet{
		Controls: []Control{
			{
				ControlID:   "ORA-SEC-004",
				ControlCode: "ORA-SEC-004",
				Title:       "Audit Trail",
				Procedures: []ControlProcedure{
					{
						ProcedureID: "P-1",
						SystemType:  "oracle",
						Tests:       "SELECT 1 FROM dual",
					},
				},
			},
		},
	}

	fetcher.enrichOracleAuditTrail(set)

	if len(set.Controls[0].EvidenceCapture) < 3 {
		t.Fatalf("expected oracle audit trail evidence capture to be added")
	}

	auditOperationsSQL := set.Controls[0].EvidenceCapture[0].SQL
	if strings.Contains(auditOperationsSQL, "DBUSERNAME NOT IN ('SYS', 'SYSTEM', 'AUDSYS')") {
		t.Fatalf("expected SYS and SYSTEM operations to remain visible")
	}
	if !strings.Contains(auditOperationsSQL, "DBUSERNAME <> 'AUDSYS'") {
		t.Fatalf("expected AUDSYS exclusion to remain in audit operations query")
	}

	traditionalSQL := set.Controls[0].EvidenceCapture[1].SQL
	if strings.Contains(traditionalSQL, "USERNAME NOT IN ('SYS', 'SYSTEM', 'AUDSYS')") {
		t.Fatalf("expected SYS and SYSTEM traditional audit rows to remain visible")
	}
	if !strings.Contains(traditionalSQL, "USERNAME <> 'AUDSYS'") {
		t.Fatalf("expected AUDSYS exclusion to remain in traditional audit query")
	}

	privilegeHistorySQL := set.Controls[0].EvidenceCapture[2].SQL
	if strings.Contains(privilegeHistorySQL, "DBUSERNAME NOT IN ('SYS', 'SYSTEM')") {
		t.Fatalf("expected SYS and SYSTEM privilege history to remain visible")
	}
	if !strings.Contains(privilegeHistorySQL, "DBUSERNAME <> 'AUDSYS'") {
		t.Fatalf("expected AUDSYS exclusion to remain in privilege history query")
	}

	if !strings.Contains(auditOperationsSQL, "ENTRY_ID") || !strings.Contains(auditOperationsSQL, "STATEMENT_ID") || !strings.Contains(auditOperationsSQL, "SCN") {
		t.Fatalf("expected unified audit query to include source identity fields for deduplication")
	}

	if !strings.Contains(traditionalSQL, "EXTENDED_TIMESTAMP AS EVENT_TIMESTAMP") ||
		!strings.Contains(traditionalSQL, "SESSIONID") ||
		!strings.Contains(traditionalSQL, "ENTRYID") ||
		!strings.Contains(traditionalSQL, "STATEMENTID") {
		t.Fatalf("expected traditional audit query to include source identity fields for deduplication")
	}

	if !strings.Contains(privilegeHistorySQL, "ENTRY_ID") || !strings.Contains(privilegeHistorySQL, "STATEMENT_ID") || !strings.Contains(privilegeHistorySQL, "SCN") {
		t.Fatalf("expected privilege history query to include source identity fields for deduplication")
	}
}

func TestEnrichPostgresAuditTrailIncludesIdentityFields(t *testing.T) {
	fetcher := NewFetcher("local", "", "", "", "", true, false, "")
	set := &ControlSet{
		Controls: []Control{
			{
				ControlID:   "PG-SEC-001",
				ControlCode: "PG-SEC-001",
				Category:    "Security",
				Procedures: []ControlProcedure{
					{
						ProcedureID: "P-1",
						SystemType:  "postgres",
						Tests:       "SELECT 1",
					},
				},
			},
		},
	}

	fetcher.enrichPostgresAuditTrail(set)

	if len(set.Controls[0].EvidenceCapture) < 4 {
		t.Fatalf("expected postgres audit trail evidence capture to be added")
	}

	auditOperationsSQL := set.Controls[0].EvidenceCapture[0].SQL
	if set.Controls[0].EvidenceCapture[0].SourceMode != "activity" {
		t.Fatalf("expected postgres pg_stat_statements evidence to remain activity, got %s", set.Controls[0].EvidenceCapture[0].SourceMode)
	}
	if set.Controls[0].EvidenceCapture[0].SourcePath != "pg_stat_statements" {
		t.Fatalf("expected postgres pg_stat_statements source path, got %s", set.Controls[0].EvidenceCapture[0].SourcePath)
	}
	if !strings.Contains(auditOperationsSQL, "pss.queryid AS QUERY_ID") ||
		!strings.Contains(auditOperationsSQL, "pss.dbid AS DBID") ||
		!strings.Contains(auditOperationsSQL, "pss.userid AS USER_ID") {
		t.Fatalf("expected postgres history query to include source identity fields")
	}

	liveSQL := set.Controls[0].EvidenceCapture[1].SQL
	if set.Controls[0].EvidenceCapture[1].SourceMode != "activity" {
		t.Fatalf("expected postgres live evidence to remain activity, got %s", set.Controls[0].EvidenceCapture[1].SourceMode)
	}
	if set.Controls[0].EvidenceCapture[1].SourcePath != "pg_stat_activity" {
		t.Fatalf("expected postgres live source path, got %s", set.Controls[0].EvidenceCapture[1].SourcePath)
	}
	if !strings.Contains(liveSQL, "pid AS PID") ||
		!strings.Contains(liveSQL, "backend_start AS BACKEND_START") ||
		!strings.Contains(liveSQL, "query_start AS QUERY_START") ||
		!strings.Contains(liveSQL, "state_change AS STATE_CHANGE") {
		t.Fatalf("expected postgres live query to include activity identity fields")
	}
}

func TestEnrichMSSQLAuditTrailIncludesIdentityFields(t *testing.T) {
	fetcher := NewFetcher("local", "", "", "", "", true, false, "")
	set := &ControlSet{
		Controls: []Control{
			{
				ControlID:   "MS-SEC-001",
				ControlCode: "MS-SEC-001",
				Category:    "Security",
				Procedures: []ControlProcedure{
					{
						ProcedureID: "P-1",
						SystemType:  "mssql",
						Tests:       "SELECT 1",
					},
				},
			},
		},
	}

	fetcher.enrichMSSQLAuditTrail(set)

	if len(set.Controls[0].EvidenceCapture) < 3 {
		t.Fatalf("expected mssql audit trail evidence capture to be added")
	}

	auditOperationsSQL := set.Controls[0].EvidenceCapture[0].SQL
	if !strings.Contains(auditOperationsSQL, "te.EventClass AS EVENT_CLASS") ||
		!strings.Contains(auditOperationsSQL, "te.ObjectID AS OBJECT_ID") ||
		!strings.Contains(auditOperationsSQL, "te.SPID AS SPID") ||
		!strings.Contains(auditOperationsSQL, "te.DatabaseID AS DATABASE_ID") {
		t.Fatalf("expected mssql audit query to include source identity fields")
	}
}

// mockEntitlement implements the Entitlement interface for testing
type mockEntitlement struct {
	expired     bool
	tier        string
	allowedTier string
	packs       []string
}

func (m *mockEntitlement) IsExpired() bool {
	return m.expired
}

func (m *mockEntitlement) AllowsTier(tier string) bool {
	// Tier hierarchy: enterprise > paid > free
	tierLevel := func(t string) int {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "enterprise":
			return 2
		case "paid":
			return 1
		default:
			return 0
		}
	}
	return tierLevel(m.tier) >= tierLevel(tier)
}

func (m *mockEntitlement) AllowsPack(packID string) bool {
	for _, p := range m.packs {
		if strings.EqualFold(p, packID) {
			return true
		}
	}
	return false
}

func (m *mockEntitlement) CheckAccess(packID, packTier string) error {
	if m.expired {
		return ErrEntitlementExpired
	}
	if !m.AllowsTier(packTier) {
		return ErrTierNotEntitled
	}
	if !m.AllowsPack(packID) {
		return ErrPackNotEntitled
	}
	return nil
}

// Helper to create a test server returning a control set with specified tier
func newTieredControlSetServer(t *testing.T, tier string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"control_set_id":      "oracle-controls-baseline",
			"control_set_version": "1.0.0",
			"database_type":       "oracle",
			"control_set_type":    "security",
			"tier":                tier,
			"controls": []map[string]interface{}{
				{
					"control_id":   "TEST-001",
					"control_code": "TEST-001",
					"category":     "Test",
					"title":        "Test Control",
					"description":  "Test control for tier testing",
					"procedures": []map[string]interface{}{
						{
							"procedure_id": "test-001-p1",
							"system_type":  "oracle",
							"tests":        "SELECT 1 FROM DUAL",
						},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestFetchControlSetFreePackRunsWithNoEntitlement(t *testing.T) {
	server := newTieredControlSetServer(t, "free")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	// No entitlement set

	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("free pack should succeed without entitlement: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}
}

func TestFetchControlSetEmptyTierFailsClosed(t *testing.T) {
	server := newTieredControlSetServer(t, "") // missing tier must not silently run as free
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	// No entitlement set

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("expected control pack with missing tier to be rejected, not treated as free")
	}
	if !strings.Contains(err.Error(), "unknown tier") {
		t.Fatalf("expected unknown-tier rejection, got: %v", err)
	}
}

func TestFetchControlSetPaidPackBlockedWithNoEntitlement(t *testing.T) {
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	// No entitlement set

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("paid pack should fail without entitlement")
	}
	if !strings.Contains(err.Error(), "entitlement required") {
		t.Fatalf("expected entitlement required error, got: %v", err)
	}
}

func TestFetchControlSetPaidPackAllowedWithMatchingEntitlement(t *testing.T) {
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("paid pack with valid entitlement should succeed: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}
}

func TestFetchControlSetPaidPackBlockedWhenEntitlementLacksPack(t *testing.T) {
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"postgres-controls-baseline"}, // different pack
	})

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("paid pack should fail when pack not in entitlement")
	}
	if !strings.Contains(err.Error(), "not in entitlement") {
		t.Fatalf("expected pack not in entitlement error, got: %v", err)
	}
}

func TestFetchControlSetEnterprisePackBlockedByPaidEntitlement(t *testing.T) {
	server := newTieredControlSetServer(t, "enterprise")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid", // paid entitlement cannot access enterprise pack
		packs:   []string{"oracle-controls-baseline"},
	})

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("enterprise pack should fail with paid entitlement")
	}
	if !strings.Contains(err.Error(), "tier insufficient") {
		t.Fatalf("expected tier insufficient error, got: %v", err)
	}
}

func TestFetchControlSetEnterprisePackAllowedByEnterpriseEntitlement(t *testing.T) {
	server := newTieredControlSetServer(t, "enterprise")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "enterprise",
		packs:   []string{"oracle-controls-baseline"},
	})

	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("enterprise pack with enterprise entitlement should succeed: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}
}

func TestFetchControlSetUnknownTierFailsClosed(t *testing.T) {
	server := newTieredControlSetServer(t, "premium") // unknown tier
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "enterprise", // highest tier
		packs:   []string{"oracle-controls-baseline"},
	})

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("unknown tier should fail closed")
	}
	if !strings.Contains(err.Error(), "unknown tier") {
		t.Fatalf("expected unknown tier error, got: %v", err)
	}
}

func TestFetchControlSetExpiredEntitlementFallsBackToFreeOnly(t *testing.T) {
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: true, // expired
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("paid pack with expired entitlement should fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}

	// Free pack should still work with expired entitlement
	freeServer := newTieredControlSetServer(t, "free")
	defer freeServer.Close()

	freeFetcher := NewFetcher("http", "", freeServer.URL, "", "agent-token", true, false, "")
	freeFetcher.SetEntitlement(&mockEntitlement{
		expired: true,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	set, err := freeFetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("free pack should succeed even with expired entitlement: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}
}

func TestFetchControlSetPaidPackBlockedAfterEntitlementExpiry(t *testing.T) {
	// This test verifies that a paid pack cannot be fetched after entitlement expires,
	// even if it was previously fetched successfully.
	// The entitlement check happens on every fetch.

	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")

	// First fetch with valid entitlement
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("first fetch should succeed: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}

	// Now simulate entitlement expiry
	fetcher.SetEntitlement(&mockEntitlement{
		expired: true, // now expired
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Second fetch should fail because entitlement is checked every time
	_, err = fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("fetch after entitlement expiry should fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}
}

func TestFetchControlSetCachedPaidPackBlockedAfterEntitlementExpiry(t *testing.T) {
	// This test verifies that cached paid packs are blocked after entitlement expires.
	// Uses local file source to simulate cache/local pack scenario.

	tmpDir := t.TempDir()

	// Create a paid control set file directly (simulating cached/local pack)
	controlSetYAML := `
metadata:
  control_set_id: oracle-controls-baseline
  control_set_version: "1.0.0"
  database_type: oracle
  control_set_type: security
  tier: paid
controls:
  - control_id: ORA-SEC-001
    control_code: ORA-SEC-001
    category: Security
    title: Test Control
    description: Test control for entitlement testing
    procedures:
      - procedure_id: ora-sec-001-check
        system_type: oracle
        tests: SELECT 1 FROM DUAL
`
	controlSetFile := filepath.Join(tmpDir, "oracle-controls-baseline-v1.0.0.yaml")
	if err := os.WriteFile(controlSetFile, []byte(controlSetYAML), 0600); err != nil {
		t.Fatalf("failed to create test control set file: %v", err)
	}

	// First: load local pack with valid entitlement
	fetcher1 := NewFetcher("local", tmpDir, "", "", "", true, false, "")
	fetcher1.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	set, err := fetcher1.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("first fetch should succeed: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}
	if set.Metadata.Tier != "paid" {
		t.Fatalf("expected tier=paid, got %s", set.Metadata.Tier)
	}

	// Second: same local pack with expired entitlement
	fetcher2 := NewFetcher("local", tmpDir, "", "", "", true, false, "")
	fetcher2.SetEntitlement(&mockEntitlement{
		expired: true, // now expired
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Fetch should fail because entitlement is expired
	_, err = fetcher2.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("fetch with expired entitlement should fail even for local pack")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}

	// Third: verify free pack still works with expired entitlement
	freeControlSetYAML := `
metadata:
  control_set_id: postgres-controls-baseline
  control_set_version: "1.0.0"
  database_type: postgres
  control_set_type: security
  tier: free
controls:
  - control_id: PG-SEC-001
    control_code: PG-SEC-001
    category: Security
    title: Test Control
    description: Test control for entitlement testing
    procedures:
      - procedure_id: pg-sec-001-check
        system_type: postgres
        tests: SELECT 1
`
	freeControlSetFile := filepath.Join(tmpDir, "postgres-controls-baseline-v1.0.0.yaml")
	if err := os.WriteFile(freeControlSetFile, []byte(freeControlSetYAML), 0600); err != nil {
		t.Fatalf("failed to create free control set file: %v", err)
	}

	fetcher3 := NewFetcher("local", tmpDir, "", "", "", true, false, "")
	fetcher3.SetEntitlement(&mockEntitlement{
		expired: true, // expired entitlement
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Free pack should still work
	freeSet, err := fetcher3.FetchControlSet("postgres", "")
	if err != nil {
		t.Fatalf("free pack should succeed with expired entitlement: %v", err)
	}
	if freeSet == nil {
		t.Fatal("expected free control set to be returned")
	}
}

func TestFetchControlSetSetEntitlementNil(t *testing.T) {
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, "", "agent-token", true, false, "")

	// Set entitlement
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Clear entitlement
	fetcher.SetEntitlement(nil)

	// Now paid pack should fail
	_, err := fetcher.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("paid pack should fail after entitlement cleared")
	}
}

func TestFetchControlSetHTTPCacheFallbackBlockedWithExpiredEntitlement(t *testing.T) {
	// This test verifies Slice 4: Cache expiry enforcement
	// When backend is down and we fall back to cached control set,
	// paid packs should still be blocked if entitlement is expired.

	tmpDir := t.TempDir()

	// First, create a server and cache a paid control set
	server := newTieredControlSetServer(t, "paid")
	defer server.Close()

	fetcher := NewFetcher("http", "", server.URL, tmpDir, "agent-token", true, false, "")
	fetcher.SetEntitlement(&mockEntitlement{
		expired: false,
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Fetch and cache the control set
	set, err := fetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("initial fetch should succeed: %v", err)
	}
	if set == nil {
		t.Fatal("expected control set to be returned")
	}

	// Verify cache file exists and is readable
	cacheFile := filepath.Join(tmpDir, "oracle-latest.yaml")
	cacheData, err := os.ReadFile(cacheFile)
	if err != nil {
		entries, _ := os.ReadDir(tmpDir)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("cache file should exist after successful fetch, err=%v, dir contents: %v", err, names)
	}

	// Verify cache file can be loaded
	cachedSet, err := LoadControlSet(cacheFile)
	if err != nil {
		t.Fatalf("cache file should be loadable: %v, contents:\n%s", err, string(cacheData))
	}
	if cachedSet.Metadata.Tier != "paid" {
		t.Fatalf("cached set should have tier=paid, got %s", cachedSet.Metadata.Tier)
	}

	// Now simulate: backend down + expired entitlement
	// Create a server that returns 503 to simulate backend unavailable
	downServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Backend unavailable"))
	}))
	defer downServer.Close()

	fetcher2 := NewFetcher("http", "", downServer.URL, tmpDir, "agent-token", true, false, "")
	fetcher2.SetEntitlement(&mockEntitlement{
		expired: true, // entitlement expired
		tier:    "paid",
		packs:   []string{"oracle-controls-baseline"},
	})

	// Fetch should fail because entitlement is expired
	// Even though the control set is in cache and backend returns error
	_, err = fetcher2.FetchControlSet("oracle", "")
	if err == nil {
		t.Fatal("cached paid pack should be blocked when entitlement expires")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}

	// Verify free pack from cache still works with expired entitlement
	// First, cache a free control set
	freeServer := newTieredControlSetServer(t, "free")
	defer freeServer.Close()

	freeFetcher := NewFetcher("http", "", freeServer.URL, tmpDir, "agent-token", true, false, "")
	freeFetcher.SetEntitlement(&mockEntitlement{expired: false, tier: "free", packs: []string{}})

	_, err = freeFetcher.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("caching free pack should succeed: %v", err)
	}

	// Now fetch free pack from cache with expired entitlement
	freeFetcher2 := NewFetcher("http", "", downServer.URL, tmpDir, "agent-token", true, false, "")
	freeFetcher2.SetEntitlement(&mockEntitlement{
		expired: true, // expired
		tier:    "paid",
		packs:   []string{},
	})

	freeSet, err := freeFetcher2.FetchControlSet("oracle", "")
	if err != nil {
		t.Fatalf("free pack from cache should succeed with expired entitlement: %v", err)
	}
	if freeSet == nil {
		t.Fatal("expected free control set from cache")
	}
}

// TestLocalFetcherFindsFreeBaselines validates that the local fetcher can discover
// control packs using the standard naming convention (*-controls-baseline-v*.yaml).
// This ensures mssql, postgres, and supabase free packs are actually discoverable.
func TestLocalFetcherFindsFreeBaselines(t *testing.T) {
	// control-sets is at ../../control-sets relative to this test file
	controlSetsDir := "../../control-sets"
	if _, err := os.Stat(controlSetsDir); os.IsNotExist(err) {
		t.Skip("control-sets directory not found (running from different directory)")
	}

	tests := []struct {
		dbType         string
		expectedTier   string
		expectedIDPart string
	}{
		{"mssql", "free", "mssql-controls-baseline"},
		{"postgres", "free", "postgres-controls-baseline"},
		{"supabase", "free", "supabase-controls-baseline"},
		{"oracle", "free", "oracle-controls-baseline"},
		{"sqlite", "free", "sqlite-controls-baseline"},
		// mysql excluded: runtime support not implemented yet
	}

	for _, tt := range tests {
		t.Run(tt.dbType, func(t *testing.T) {
			fetcher := NewFetcher("local", controlSetsDir, "", "", "", true, false, "")
			// No entitlement needed for free packs

			set, err := fetcher.FetchControlSet(tt.dbType, "")
			if err != nil {
				t.Fatalf("local fetch for %s should succeed: %v", tt.dbType, err)
			}
			if set == nil {
				t.Fatalf("expected control set for %s", tt.dbType)
			}

			// Verify it's the expected pack
			if !strings.Contains(set.Metadata.ControlSetID, tt.expectedIDPart) {
				t.Errorf("expected control_set_id to contain %q, got %q",
					tt.expectedIDPart, set.Metadata.ControlSetID)
			}

			// Verify tier
			if set.Metadata.NormalizedTier() != tt.expectedTier {
				t.Errorf("expected tier=%s, got %s", tt.expectedTier, set.Metadata.NormalizedTier())
			}
		})
	}
}

func TestLocalFetcherReportsMissingControlSet(t *testing.T) {
	fetcher := NewFetcher("local", t.TempDir(), "", "", "", true, false, "")

	_, err := fetcher.FetchControlSet("postgres-policy", "")
	if !errors.Is(err, ErrControlSetNotFound) {
		t.Fatalf("expected ErrControlSetNotFound, got %v", err)
	}
}
