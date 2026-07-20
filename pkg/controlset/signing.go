package controlset

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// CreateCanonicalPayload returns the exact canonical, deterministic byte
// representation of a control set that gets hashed and signed/verified.
// Exported so an offline signing tool (cmd/sign-controlset) can produce
// signatures that verifyControlSetSignature will accept without needing to
// construct a Fetcher: the canonical-payload builder methods don't read or
// mutate any Fetcher state, they're plain data transforms.
func CreateCanonicalPayload(set *ControlSet) ([]byte, error) {
	var f Fetcher
	return f.createCanonicalPayload(set)
}

// SignCanonicalPayload signs a canonical control-set payload with an RSA
// private key using the same PKCS1v15/SHA256 scheme verifySignature expects,
// returning the base64-encoded signature to store in
// metadata.signature.signature_b64.
func SignCanonicalPayload(payload []byte, privateKey *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// EncodePublicKeyPKIX base64-encodes an RSA public key in PKIX/DER form, the
// format the agent's security.public_key config field expects.
func EncodePublicKeyPKIX(publicKey *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// VerifySignedControlSet verifies a control set's embedded signature against
// the given base64-encoded PKIX RSA public key, performing the same check
// the agent's fetcher does when loading a local or cached control set.
// Exported for tooling (cmd/sign-controlset) to confirm a freshly signed
// pack actually verifies before shipping it.
func VerifySignedControlSet(set *ControlSet, publicKeyB64 string) error {
	f := Fetcher{publicKey: publicKeyB64}
	return f.verifyControlSetSignature(set)
}
