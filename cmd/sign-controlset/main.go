// sign-controlset signs a bundled control-set YAML file with an RSA private
// key so the agent's read-only query guard's signature-verification layer
// (security.require_signatures, default true) can accept it. It computes the
// same canonical payload the agent verifies against
// (controlset.CreateCanonicalPayload), signs it, and writes the resulting
// metadata.signature block back into the YAML file in place.
//
// Usage:
//
//	go run ./cmd/sign-controlset -key .signing/dev-private-key.pem -in control-sets/sqlite-controls-baseline-v1.0.0.yaml
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"basecheck-agent/pkg/controlset"
)

func main() {
	keyPath := flag.String("key", "", "path to RSA private key (PEM, PKCS1 or PKCS8)")
	inPath := flag.String("in", "", "path to the control-set YAML file to sign")
	outPath := flag.String("out", "", "output path (default: overwrite -in)")
	keyID := flag.String("key-id", "", "optional public_key_id to record in the signature block")
	flag.Parse()

	if strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*inPath) == "" {
		fmt.Fprintln(os.Stderr, "usage: sign-controlset -key <private_key.pem> -in <control-set.yaml> [-out <path>] [-key-id <id>]")
		os.Exit(2)
	}

	if err := run(*keyPath, *inPath, *outPath, *keyID); err != nil {
		fmt.Fprintf(os.Stderr, "sign-controlset: %v\n", err)
		os.Exit(1)
	}
}

func run(keyPath, inPath, outPath, keyID string) error {
	privateKey, err := loadRSAPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	set, err := controlset.LoadControlSet(inPath)
	if err != nil {
		return fmt.Errorf("failed to load control set: %w", err)
	}

	payload, err := controlset.CreateCanonicalPayload(set)
	if err != nil {
		return fmt.Errorf("failed to build canonical payload: %w", err)
	}

	signatureB64, err := controlset.SignCanonicalPayload(payload, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	content, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", inPath, err)
	}

	patched, err := patchSignatureBlock(content, "RSA-SHA256", keyID, signatureB64)
	if err != nil {
		return fmt.Errorf("failed to patch signature block: %w", err)
	}

	target := outPath
	if strings.TrimSpace(target) == "" {
		target = inPath
	}

	info, err := os.Stat(inPath)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode()
	}

	if err := os.WriteFile(target, patched, mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", target, err)
	}

	fmt.Printf("signed %s (control_set_id=%s)\n", target, set.Metadata.ControlSetID)
	return nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	generic, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unsupported private key format (expected PKCS1 or PKCS8 RSA key): %w", err)
	}

	rsaKey, ok := generic.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}
	return rsaKey, nil
}

// patchSignatureBlock inserts or replaces the "  signature:" block nested
// under the YAML file's top-level "metadata:" section, leaving the rest of
// the file (including comments and formatting) untouched. A full
// yaml.Marshal round-trip would strip the hand-written comments that
// document each control, so this patches the raw text directly instead.
func patchSignatureBlock(content []byte, algorithm, keyID, signatureB64 string) ([]byte, error) {
	original := string(content)
	trailingNewline := strings.HasSuffix(original, "\n")
	lines := strings.Split(strings.TrimSuffix(original, "\n"), "\n")

	metadataIdx := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "metadata:" {
			metadataIdx = i
			break
		}
	}
	if metadataIdx == -1 {
		return nil, fmt.Errorf("no top-level 'metadata:' section found")
	}

	// End of the metadata block: the first subsequent non-empty line with no
	// leading whitespace (i.e. the next top-level YAML key), or EOF.
	endIdx := len(lines)
	for i := metadataIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			endIdx = i
			break
		}
	}

	// Strip any pre-existing "  signature:" block so re-signing is idempotent.
	sigStart, sigEnd := findIndentedBlock(lines, metadataIdx+1, endIdx, "signature:", 2)
	if sigStart != -1 {
		lines = append(lines[:sigStart], lines[sigEnd:]...)
		endIdx -= sigEnd - sigStart
	}

	// Insert right after the last non-blank metadata line, before any
	// trailing blank line(s) that separate metadata from the next section.
	insertPos := endIdx
	for insertPos > metadataIdx+1 && strings.TrimSpace(lines[insertPos-1]) == "" {
		insertPos--
	}

	block := []string{"  signature:", "    algorithm: " + algorithm}
	if strings.TrimSpace(keyID) != "" {
		block = append(block, "    public_key_id: "+keyID)
	}
	block = append(block, fmt.Sprintf("    signature_b64: %q", signatureB64))

	newLines := make([]string, 0, len(lines)+len(block))
	newLines = append(newLines, lines[:insertPos]...)
	newLines = append(newLines, block...)
	newLines = append(newLines, lines[insertPos:]...)

	result := strings.Join(newLines, "\n")
	if trailingNewline {
		result += "\n"
	}
	return []byte(result), nil
}

// findIndentedBlock finds a "<key>" line at the given indent within
// [start, end) and returns its span, including any deeper-indented lines
// that belong to it. Returns (-1, -1) if not found.
func findIndentedBlock(lines []string, start, end int, key string, indent int) (int, int) {
	prefix := strings.Repeat(" ", indent)
	for i := start; i < end; i++ {
		trimmed := strings.TrimLeft(lines[i], " \t")
		lineIndent := len(lines[i]) - len(trimmed)
		if lineIndent == indent && strings.HasPrefix(lines[i], prefix) && trimmed == key {
			blockEnd := i + 1
			for blockEnd < end {
				next := lines[blockEnd]
				if next == "" {
					break
				}
				nextTrimmed := strings.TrimLeft(next, " \t")
				nextIndent := len(next) - len(nextTrimmed)
				if nextIndent <= indent {
					break
				}
				blockEnd++
			}
			return i, blockEnd
		}
	}
	return -1, -1
}
