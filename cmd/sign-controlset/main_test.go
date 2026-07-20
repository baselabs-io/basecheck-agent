package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"basecheck-agent/pkg/controlset"
)

const sampleControlSet = `metadata:
  control_set_id: sample-controls-baseline-v1.0.0
  control_set_version: 1.0.0
  database_type: sqlite
  control_set_type: Security
  tier: free
  description: sample
  author: system
  license: Proprietary
  # a trailing comment

controls:
  - control_id: SAMPLE-001
    control_code: SAMPLE-001
    category: Data Protection
    title: Sample
    description: Sample control
    procedures:
      - procedure_id: SAMPLE-001-P1
        system_type: sqlite
        tests: |
          SELECT 1
        criteria:
          - condition: "1 == 1"
            severity: HIGH
            finding_title: "Sample finding"
`

func TestPatchSignatureBlockInsertsAndIsIdempotentOnReSign(t *testing.T) {
	patched, err := patchSignatureBlock([]byte(sampleControlSet), "RSA-SHA256", "", "AAAA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	patchedStr := string(patched)
	if !strings.Contains(patchedStr, "  signature:") {
		t.Fatalf("expected signature block to be inserted, got:\n%s", patchedStr)
	}
	if !strings.Contains(patchedStr, `signature_b64: "AAAA"`) {
		t.Fatalf("expected signature_b64 AAAA, got:\n%s", patchedStr)
	}
	// Comment and structure must survive untouched.
	if !strings.Contains(patchedStr, "# a trailing comment") {
		t.Fatalf("expected comment to be preserved, got:\n%s", patchedStr)
	}

	// Re-signing must replace, not duplicate, the signature block.
	reSigned, err := patchSignatureBlock(patched, "RSA-SHA256", "key-1", "BBBB")
	if err != nil {
		t.Fatalf("unexpected error on re-sign: %v", err)
	}
	reSignedStr := string(reSigned)
	if strings.Count(reSignedStr, "  signature:") != 1 {
		t.Fatalf("expected exactly one signature block after re-signing, got:\n%s", reSignedStr)
	}
	if strings.Contains(reSignedStr, "AAAA") {
		t.Fatalf("expected old signature to be replaced, got:\n%s", reSignedStr)
	}
	if !strings.Contains(reSignedStr, `signature_b64: "BBBB"`) || !strings.Contains(reSignedStr, "public_key_id: key-1") {
		t.Fatalf("expected new signature and key id, got:\n%s", reSignedStr)
	}
}

// TestSignedControlSetRoundTripsAndVerifies proves the full pipeline: sign a
// real control-set YAML, load it back through controlset.LoadControlSet, and
// confirm the embedded signature verifies against the canonical payload --
// the exact check the agent's fetcher performs at startup.
func TestSignedControlSetRoundTripsAndVerifies(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	dir := t.TempDir()
	inPath := filepath.Join(dir, "sample-controls-baseline-v1.0.0.yaml")
	if err := os.WriteFile(inPath, []byte(sampleControlSet), 0o644); err != nil {
		t.Fatalf("failed to write sample file: %v", err)
	}

	if err := run(writeTempKey(t, privateKey), inPath, "", "test-key"); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	set, err := controlset.LoadControlSet(inPath)
	if err != nil {
		t.Fatalf("failed to load signed control set: %v", err)
	}
	if set.Metadata.Signature.SignatureB64 == "" {
		t.Fatal("expected signature_b64 to be populated after signing")
	}

	payload, err := controlset.CreateCanonicalPayload(set)
	if err != nil {
		t.Fatalf("failed to build canonical payload: %v", err)
	}

	pubKeyB64, err := controlset.EncodePublicKeyPKIX(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	if err := controlset.VerifySignedControlSet(set, pubKeyB64); err != nil {
		t.Fatalf("signature failed to verify: %v", err)
	}
	_ = payload
}

func writeTempKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return path
}
