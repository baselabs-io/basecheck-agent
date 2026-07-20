package siem

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// staleLockAfter is how long an unattended lock file is treated as abandoned
// (e.g. left behind by a process that crashed mid-operation) and reclaimed.
// The lock is only ever held for the duration of a single persist/flush
// operation (never for a whole agent run), so this only needs to comfortably
// exceed the worst-case single operation -- a Flush with full retry backoff
// -- not an entire audit run.
const staleLockAfter = 30 * time.Minute

// lockAcquireTimeout bounds how long a process waits for another live
// process's lock before giving up and leaving events pending for the next
// scheduled run, so a slow-but-alive holder cannot block this one forever.
const lockAcquireTimeout = 10 * time.Second

// fileLock is an advisory, cross-process lock based on exclusive file
// creation (O_CREATE|O_EXCL), used to serialize access to a persisted
// queue/dedup file across overlapping agent processes (e.g. overlapping cron
// runs) for the duration of a single load/persist/flush operation. It is not
// a kernel-level flock -- there is a narrow race between the staleness check
// and the exclusive create -- but it closes the practical gap where multiple
// processes silently corrupt or double-deliver shared state with no
// coordination at all.
type fileLock struct {
	path string
	held bool
}

// acquireFileLock creates a lock file at path+".lock", waiting up to
// lockAcquireTimeout for a concurrently-held lock to be released. A lock file
// older than staleLockAfter is treated as abandoned and reclaimed.
func acquireFileLock(path string) (*fileLock, error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}

	deadline := time.Now().Add(lockAcquireTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "pid=%d acquired=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			f.Close()
			return &fileLock{path: lockPath, held: true}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create lock file %s: %w", lockPath, err)
		}

		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > staleLockAfter {
			fmt.Fprintf(os.Stderr, "warning: reclaiming abandoned lock file %s (older than %s)\n", lockPath, staleLockAfter)
			if rmErr := os.Remove(lockPath); rmErr != nil && !os.IsNotExist(rmErr) {
				return nil, fmt.Errorf("remove stale lock file %s: %w", lockPath, rmErr)
			}
			continue
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for lock %s (held by another process)", lockPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// release removes the lock file. Safe to call at most once; a second call is
// a no-op.
func (l *fileLock) release() error {
	if l == nil || !l.held {
		return nil
	}
	l.held = false
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove lock file %s: %w", l.path, err)
	}
	return nil
}
