package siem

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDeadLetterUsesRestrictivePermissions guards against dead-letter state
// (failed events, evidence, failure context) being readable by other local
// users via a permissive file/directory mode.
func TestDeadLetterUsesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state", "siem-dead-letter.jsonl")

	dl, err := NewDeadLetter(DeadLetterConfig{Path: path})
	if err != nil {
		t.Fatalf("NewDeadLetter() error: %v", err)
	}
	defer dl.Close()

	if err := dl.Write(testEvent(), errors.New("delivery failed")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat dead-letter file: %v", err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("dead-letter file mode = %o, want %o", mode, 0o600)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dead-letter directory: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("dead-letter directory mode = %o, want %o", mode, 0o700)
	}
}
