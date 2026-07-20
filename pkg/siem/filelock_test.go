package siem

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLockAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	lock, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("acquireFileLock() error: %v", err)
	}

	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("expected lock file to exist: %v", err)
	}

	if err := lock.release(); err != nil {
		t.Fatalf("release() error: %v", err)
	}

	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("expected lock file to be removed after release, stat err: %v", err)
	}
}

// TestFileLockBlocksConcurrentHolder guards against two processes (simulated
// here as two independent acquireFileLock calls on the same path) both
// believing they hold exclusive access at once.
func TestFileLockBlocksConcurrentHolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	first, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquireFileLock() error: %v", err)
	}
	defer first.release()

	done := make(chan error, 1)
	go func() {
		_, err := acquireFileLock(path)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected second acquireFileLock() to fail or block while first lock is held")
		}
	case <-time.After(lockAcquireTimeout + 2*time.Second):
		t.Fatal("second acquireFileLock() neither returned nor timed out as expected")
	}
}

// TestFileLockReclaimsStaleLock guards against a lock file abandoned by a
// crashed process permanently blocking future runs: a lock file older than
// staleLockAfter must be reclaimed rather than honored forever.
func TestFileLockReclaimsStaleLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	lockPath := path + ".lock"

	if err := os.WriteFile(lockPath, []byte("pid=99999999\n"), 0o600); err != nil {
		t.Fatalf("failed to seed lock file: %v", err)
	}
	staleTime := time.Now().Add(-(staleLockAfter + time.Minute))
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to backdate lock file: %v", err)
	}

	lock, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("expected stale lock to be reclaimed, got error: %v", err)
	}
	defer lock.release()
}
