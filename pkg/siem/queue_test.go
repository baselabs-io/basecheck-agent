package siem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockDestination is a test destination that can be configured to fail.
type mockDestination struct {
	sendFunc  func(ctx context.Context, events []*Event) error
	sendCount int32
	closed    bool
}

func (m *mockDestination) Send(ctx context.Context, events []*Event) error {
	atomic.AddInt32(&m.sendCount, 1)
	if m.sendFunc != nil {
		return m.sendFunc(ctx, events)
	}
	return nil
}

func (m *mockDestination) Close() error {
	m.closed = true
	return nil
}

func (m *mockDestination) SendCount() int {
	return int(atomic.LoadInt32(&m.sendCount))
}

func testEvent() *Event {
	now := time.Now().UTC()
	return &Event{
		Version:        EventVersion,
		EventType:      EventTypeCreated,
		EventTime:      now,
		AgentID:        "agent-1",
		SystemID:       "sys-1",
		SystemName:     "test-db",
		DatabaseEngine: "postgres",
		FindingID:      "find-123",
		Fingerprint:    "fp-123",
		ControlCode:    "PG-001",
		ControlName:    "Test Control",
		FindingTitle:   "Test Finding",
		Severity:       SeverityHigh,
		FindingStatus:  FindingStatusOpen,
		FirstSeen:      now,
		LastSeen:       now,
		Source:         "control_audit",
		Export: &EventExport{
			ControlPackName:    "postgres-security",
			ControlPackVersion: "1.0.0",
			AgentVersion:       "1.0.0",
			Mode:               "siem_only",
			Destination:        "webhook",
		},
	}
}

// TestQueuePersistUsesRestrictivePermissions guards against queue state
// (queued findings, evidence) being readable by other local users via a
// permissive file/directory mode. Prior to this fix, the temp file was
// created with os.Create (0666 minus umask) instead of an explicit 0600.
func TestQueuePersistUsesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	persistPath := filepath.Join(dir, "state", "siem-queue.jsonl")

	q, err := NewQueue(&mockDestination{}, nil, QueueConfig{PersistPath: persistPath})
	if err != nil {
		t.Fatalf("NewQueue() error: %v", err)
	}

	if _, _, err := q.Enqueue([]*Event{testEvent()}); err != nil {
		t.Fatalf("Enqueue() error: %v", err)
	}

	fileInfo, err := os.Stat(persistPath)
	if err != nil {
		t.Fatalf("stat persist file: %v", err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("queue persist file mode = %o, want %o", mode, 0o600)
	}

	dirInfo, err := os.Stat(filepath.Dir(persistPath))
	if err != nil {
		t.Fatalf("stat persist directory: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("queue persist directory mode = %o, want %o", mode, 0o700)
	}
}

func TestNewQueue(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		dest := &mockDestination{}
		q, err := NewQueue(dest, nil, QueueConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if q == nil {
			t.Fatal("expected non-nil queue")
		}
	})

	t.Run("nil destination", func(t *testing.T) {
		_, err := NewQueue(nil, nil, QueueConfig{})
		if err == nil {
			t.Fatal("expected error for nil destination")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{RetryMax: -1}) // -1 means use default
		if q.config.MaxSize != 1000 {
			t.Errorf("MaxSize = %d, want 1000", q.config.MaxSize)
		}
		if q.config.RetryMax != 5 {
			t.Errorf("RetryMax = %d, want 5", q.config.RetryMax)
		}
	})

	t.Run("retry max zero means no retries", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{RetryMax: 0})
		if q.config.RetryMax != 0 {
			t.Errorf("RetryMax = %d, want 0", q.config.RetryMax)
		}
	})
}

func TestQueueEnqueue(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "queue.jsonl")

	t.Run("enqueue events", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{PersistPath: persistPath})

		events := []*Event{testEvent(), testEvent()}
		if _, _, err := q.Enqueue(events); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}

		if q.Len() != 2 {
			t.Errorf("Len() = %d, want 2", q.Len())
		}

		// Verify persistence
		if _, err := os.Stat(persistPath); os.IsNotExist(err) {
			t.Error("persist file should exist")
		}
	})

	t.Run("queue full", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			MaxSize:     2,
			PersistPath: filepath.Join(dir, "full.jsonl"),
		})

		q.Enqueue([]*Event{testEvent(), testEvent()})
		_, _, err := q.Enqueue([]*Event{testEvent()})
		if err == nil {
			t.Fatal("expected error for full queue")
		}
	})

	t.Run("closed queue", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			PersistPath: filepath.Join(dir, "closed.jsonl"),
		})
		q.Close(context.Background())

		_, _, err := q.Enqueue([]*Event{testEvent()})
		if err == nil {
			t.Fatal("expected error for closed queue")
		}
	})

	// TestQueueEnqueue/all_events_invalid_reports_rejected_count guards
	// against a caller mistaking "enqueued=0, err=nil" for "nothing to
	// enqueue" when it actually means every event failed the event contract
	// and was dead-lettered -- the rejected count is what distinguishes the
	// two, and must never be silently dropped.
	t.Run("all events invalid reports rejected count, not silent success", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			PersistPath: filepath.Join(dir, "invalid.jsonl"),
		})

		invalid := testEvent()
		invalid.FindingTitle = "" // fails Validate(): finding_title is required

		enqueued, rejected, err := q.Enqueue([]*Event{invalid})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if enqueued != 0 {
			t.Errorf("enqueued = %d, want 0", enqueued)
		}
		if rejected != 1 {
			t.Errorf("rejected = %d, want 1", rejected)
		}
	})

	t.Run("mix of valid and invalid events reports both counts", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			PersistPath: filepath.Join(dir, "mixed.jsonl"),
		})

		invalid := testEvent()
		invalid.FindingTitle = ""

		enqueued, rejected, err := q.Enqueue([]*Event{testEvent(), invalid})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if enqueued != 1 {
			t.Errorf("enqueued = %d, want 1", enqueued)
		}
		if rejected != 1 {
			t.Errorf("rejected = %d, want 1", rejected)
		}
	})
}

func TestQueueFlush(t *testing.T) {
	dir := t.TempDir()

	t.Run("successful flush", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			PersistPath: filepath.Join(dir, "flush.jsonl"),
		})

		q.Enqueue([]*Event{testEvent(), testEvent()})
		result := q.Flush(context.Background())

		if result.Err != nil {
			t.Fatalf("Flush failed: %v", result.Err)
		}
		if result.DeliveredCount != 2 {
			t.Errorf("DeliveredCount = %d, want 2", result.DeliveredCount)
		}
		if len(result.Delivered) != 2 {
			t.Errorf("len(Delivered) = %d, want 2", len(result.Delivered))
		}
		if q.Len() != 0 {
			t.Errorf("Len() = %d, want 0 after flush", q.Len())
		}
		if dest.SendCount() != 1 {
			t.Errorf("SendCount = %d, want 1", dest.SendCount())
		}
	})

	t.Run("empty queue", func(t *testing.T) {
		dest := &mockDestination{}
		q, _ := NewQueue(dest, nil, QueueConfig{
			PersistPath: filepath.Join(dir, "empty.jsonl"),
		})

		result := q.Flush(context.Background())
		if result.Err != nil {
			t.Fatalf("Flush failed: %v", result.Err)
		}
		if result.DeliveredCount != 0 {
			t.Errorf("DeliveredCount = %d, want 0", result.DeliveredCount)
		}
	})

	t.Run("retryable error with backoff", func(t *testing.T) {
		attempts := 0
		dest := &mockDestination{
			sendFunc: func(ctx context.Context, events []*Event) error {
				attempts++
				if attempts < 3 {
					return NewRetryableError(errors.New("temporary failure"))
				}
				return nil
			},
		}

		q, _ := NewQueue(dest, nil, QueueConfig{
			RetryMax:            5,
			RetryBackoffSeconds: []int{0, 0, 0, 0, 0}, // No delay for test
			PersistPath:         filepath.Join(dir, "retry.jsonl"),
		})

		q.Enqueue([]*Event{testEvent()})
		result := q.Flush(context.Background())

		if result.Err != nil {
			t.Fatalf("Flush failed: %v", result.Err)
		}
		if result.DeliveredCount != 1 {
			t.Errorf("DeliveredCount = %d, want 1", result.DeliveredCount)
		}
		if attempts != 3 {
			t.Errorf("attempts = %d, want 3", attempts)
		}
	})

	t.Run("permanent error to dead-letter", func(t *testing.T) {
		dest := &mockDestination{
			sendFunc: func(ctx context.Context, events []*Event) error {
				return errors.New("permanent failure")
			},
		}

		dlPath := filepath.Join(dir, "deadletter.jsonl")
		dl, _ := NewDeadLetter(DeadLetterConfig{Path: dlPath})
		defer dl.Close()

		q, _ := NewQueue(dest, dl, QueueConfig{
			PersistPath: filepath.Join(dir, "perm.jsonl"),
		})

		q.Enqueue([]*Event{testEvent()})
		result := q.Flush(context.Background())

		if result.Err == nil {
			t.Fatal("expected error for permanent failure")
		}
		if q.Len() != 0 {
			t.Errorf("Len() = %d, want 0 (sent to dead-letter)", q.Len())
		}

		// Verify dead-letter has the event
		count, _ := dl.Count()
		if count != 1 {
			t.Errorf("dead-letter count = %d, want 1", count)
		}
	})

	t.Run("max retries exceeded to dead-letter", func(t *testing.T) {
		dest := &mockDestination{
			sendFunc: func(ctx context.Context, events []*Event) error {
				return NewRetryableError(errors.New("always fails"))
			},
		}

		dlPath := filepath.Join(dir, "dl-maxretry.jsonl")
		dl, _ := NewDeadLetter(DeadLetterConfig{Path: dlPath})
		defer dl.Close()

		q, _ := NewQueue(dest, dl, QueueConfig{
			RetryMax:            2,
			RetryBackoffSeconds: []int{0, 0},
			PersistPath:         filepath.Join(dir, "maxretry.jsonl"),
		})

		q.Enqueue([]*Event{testEvent()})
		result := q.Flush(context.Background())

		if result.Err == nil {
			t.Fatal("expected error for max retries")
		}

		// 1 initial + 2 retries = 3 attempts
		if dest.SendCount() != 3 {
			t.Errorf("SendCount = %d, want 3", dest.SendCount())
		}

		count, _ := dl.Count()
		if count != 1 {
			t.Errorf("dead-letter count = %d, want 1", count)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		dest := &mockDestination{
			sendFunc: func(ctx context.Context, events []*Event) error {
				return NewRetryableError(errors.New("retryable"))
			},
		}

		q, _ := NewQueue(dest, nil, QueueConfig{
			RetryMax:            10,
			RetryBackoffSeconds: []int{1}, // 1 second backoff
			PersistPath:         filepath.Join(dir, "cancel.jsonl"),
		})

		q.Enqueue([]*Event{testEvent()})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		result := q.Flush(ctx)
		if result.Err == nil {
			t.Fatal("expected error for context cancellation")
		}

		// Events should remain in queue for later retry
		if q.Len() != 1 {
			t.Errorf("Len() = %d, want 1 (preserved for retry)", q.Len())
		}
	})

	t.Run("deadline exceeded keeps events pending", func(t *testing.T) {
		// Destination returns DeadlineExceeded directly (not wrapped in retryable)
		dest := &mockDestination{
			sendFunc: func(ctx context.Context, events []*Event) error {
				return context.DeadlineExceeded
			},
		}

		q, _ := NewQueue(dest, nil, QueueConfig{
			RetryMax:    0, // No retries
			PersistPath: filepath.Join(dir, "deadline.jsonl"),
		})

		q.Enqueue([]*Event{testEvent()})

		result := q.Flush(context.Background())
		if result.Err == nil {
			t.Fatal("expected error for deadline exceeded")
		}

		// Events should remain in queue (not dead-lettered)
		if q.Len() != 1 {
			t.Errorf("Len() = %d, want 1 (preserved, not dead-lettered)", q.Len())
		}
	})
}

func TestQueuePersistence(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "persist.jsonl")

	// Create queue and enqueue events (no flush, simulating crash)
	dest := &mockDestination{}
	q1, _ := NewQueue(dest, nil, QueueConfig{
		PersistPath: persistPath,
	})

	q1.Enqueue([]*Event{testEvent(), testEvent()})

	// Simulate crash - don't flush, just abandon queue
	// Events should be persisted to disk

	// Create new queue with same persist path
	dest2 := &mockDestination{}
	q2, _ := NewQueue(dest2, nil, QueueConfig{PersistPath: persistPath})

	// Should have loaded persisted events
	if q2.Len() != 2 {
		t.Errorf("Len() = %d, want 2 (loaded from persist)", q2.Len())
	}

	// Flush should deliver the recovered events
	result := q2.Flush(context.Background())
	if result.Err != nil {
		t.Fatalf("Flush failed: %v", result.Err)
	}
	if result.DeliveredCount != 2 {
		t.Errorf("DeliveredCount = %d, want 2", result.DeliveredCount)
	}
}

// TestQueueConcurrentEnqueueAcrossIndependentInstancesDoesNotLoseEvents
// guards against a lost-update bug where two independent Queue instances
// sharing one persist path (e.g. two agent processes, or two Queue objects
// in the same process) each enqueue while working from their own stale
// in-memory snapshot: the file lock prevents them from writing at the exact
// same instant, but without reloading current on-disk state before merging,
// whichever instance writes last silently overwrites the other's event.
func TestQueueConcurrentEnqueueAcrossIndependentInstancesDoesNotLoseEvents(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "shared.jsonl")
	cfg := QueueConfig{PersistPath: persistPath, MaxSize: 100}

	q1, err := NewQueue(&mockDestination{}, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q1: %v", err)
	}
	q2, err := NewQueue(&mockDestination{}, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q2: %v", err)
	}

	if _, _, err := q1.Enqueue([]*Event{testEvent()}); err != nil {
		t.Fatalf("q1 enqueue failed: %v", err)
	}
	if _, _, err := q2.Enqueue([]*Event{testEvent()}); err != nil {
		t.Fatalf("q2 enqueue failed: %v", err)
	}

	q3, err := NewQueue(&mockDestination{}, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q3: %v", err)
	}
	if q3.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (events from both independent queue instances must survive)", q3.Len())
	}
}

// TestQueueFlushAcrossIndependentInstancesReloadsBeforeFinalWrite guards
// against Flush computing "what's newly enqueued since the snapshot" from
// its own in-memory q.pending: that comparison must be against a fresh
// reload of the persist file, since another Queue instance sharing the same
// path may have enqueued (or even flushed) while this instance's delivery
// was in flight.
func TestQueueFlushAcrossIndependentInstancesReloadsBeforeFinalWrite(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "shared-flush.jsonl")
	cfg := QueueConfig{PersistPath: persistPath, MaxSize: 100}

	sendStarted := make(chan struct{})
	sendContinue := make(chan struct{})
	dest1 := &mockDestination{
		sendFunc: func(ctx context.Context, events []*Event) error {
			close(sendStarted)
			<-sendContinue
			return nil
		},
	}

	q1, err := NewQueue(dest1, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q1: %v", err)
	}
	if _, _, err := q1.Enqueue([]*Event{testEvent()}); err != nil {
		t.Fatalf("q1 enqueue failed: %v", err)
	}

	flushDone := make(chan struct{})
	go func() {
		q1.Flush(context.Background())
		close(flushDone)
	}()
	<-sendStarted

	// A second, independent queue instance enqueues while q1's delivery is
	// in flight -- simulating a second agent process sharing this path.
	q2, err := NewQueue(&mockDestination{}, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q2: %v", err)
	}
	if _, _, err := q2.Enqueue([]*Event{testEvent()}); err != nil {
		t.Fatalf("q2 enqueue failed: %v", err)
	}

	close(sendContinue)
	<-flushDone

	q3, err := NewQueue(&mockDestination{}, nil, cfg)
	if err != nil {
		t.Fatalf("failed to create q3: %v", err)
	}
	if q3.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 (q2's event enqueued during q1's flush must survive)", q3.Len())
	}
}

func TestQueueClose(t *testing.T) {
	dir := t.TempDir()

	dest := &mockDestination{}
	q, _ := NewQueue(dest, nil, QueueConfig{
		PersistPath: filepath.Join(dir, "close.jsonl"),
	})

	q.Enqueue([]*Event{testEvent()})
	err := q.Close(context.Background())

	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Should have flushed on close
	if dest.SendCount() != 1 {
		t.Errorf("SendCount = %d, want 1 (flushed on close)", dest.SendCount())
	}

	// Double close should be safe
	err = q.Close(context.Background())
	if err != nil {
		t.Fatalf("Double close failed: %v", err)
	}
}

func TestQueueConcurrentEnqueueDuringFlush(t *testing.T) {
	dir := t.TempDir()

	// Destination that blocks during send
	sendStarted := make(chan struct{})
	sendContinue := make(chan struct{})
	dest := &mockDestination{
		sendFunc: func(ctx context.Context, events []*Event) error {
			close(sendStarted)
			<-sendContinue
			return nil
		},
	}

	q, _ := NewQueue(dest, nil, QueueConfig{
		PersistPath: filepath.Join(dir, "concurrent.jsonl"),
	})

	// Enqueue initial event
	q.Enqueue([]*Event{testEvent()})

	// Start flush in background
	flushDone := make(chan struct{})
	go func() {
		q.Flush(context.Background())
		close(flushDone)
	}()

	// Wait for send to start
	<-sendStarted

	// Enqueue more events while flush is in progress
	q.Enqueue([]*Event{testEvent(), testEvent()})

	// Let send complete
	close(sendContinue)
	<-flushDone

	// The newly enqueued events should still be in the queue
	if q.Len() != 2 {
		t.Errorf("Len() = %d, want 2 (events enqueued during flush)", q.Len())
	}
}

// TestQueueConcurrentFlushDoesNotDoubleDeliver guards against two concurrent
// Flush calls (e.g. one triggered by overlapping cron runs, or two goroutines
// in the same process) both snapshotting the same pending batch and
// delivering it twice. The dedicated flush lock must fully serialize them.
func TestQueueConcurrentFlushDoesNotDoubleDeliver(t *testing.T) {
	dir := t.TempDir()

	sendStarted := make(chan struct{})
	sendContinue := make(chan struct{})
	var sendStartedOnce sync.Once
	dest := &mockDestination{
		sendFunc: func(ctx context.Context, events []*Event) error {
			sendStartedOnce.Do(func() { close(sendStarted) })
			<-sendContinue
			return nil
		},
	}

	q, _ := NewQueue(dest, nil, QueueConfig{
		PersistPath: filepath.Join(dir, "concurrent-flush.jsonl"),
	})

	q.Enqueue([]*Event{testEvent(), testEvent()})

	var wg sync.WaitGroup
	results := make([]FlushResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = q.Flush(context.Background())
		}(i)
	}

	// Let the first Send call block, then release both.
	<-sendStarted
	close(sendContinue)
	wg.Wait()

	if got := dest.SendCount(); got != 1 {
		t.Errorf("SendCount() = %d, want 1 (second Flush must not re-deliver the same batch)", got)
	}

	totalDelivered := results[0].DeliveredCount + results[1].DeliveredCount
	if totalDelivered != 2 {
		t.Errorf("total DeliveredCount across both Flush calls = %d, want 2 (no double-delivery, no lost delivery)", totalDelivered)
	}
}

func TestQueueDeadLetterWriteFailurePreservesEvents(t *testing.T) {
	dir := t.TempDir()

	dest := &mockDestination{
		sendFunc: func(ctx context.Context, events []*Event) error {
			return errors.New("permanent failure")
		},
	}

	// Create a dead-letter that will fail to write
	dlPath := filepath.Join(dir, "readonly", "deadletter.jsonl")
	// Don't create the directory - writes will fail

	dl := &DeadLetter{
		path:      dlPath,
		maxSizeMB: 100,
	}

	q, _ := NewQueue(dest, dl, QueueConfig{
		PersistPath: filepath.Join(dir, "preserve.jsonl"),
	})

	q.Enqueue([]*Event{testEvent()})
	result := q.Flush(context.Background())

	if result.Err == nil {
		t.Fatal("expected error")
	}

	// Events should be preserved since dead-letter write failed
	if q.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (preserved due to dead-letter failure)", q.Len())
	}
}

func TestQueueLoadFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "corrupt.jsonl")

	// Write corrupt data
	os.WriteFile(persistPath, []byte("not valid json\n"), 0o644)

	dest := &mockDestination{}
	_, err := NewQueue(dest, nil, QueueConfig{PersistPath: persistPath})

	if err == nil {
		t.Fatal("expected error for corrupt persist file")
	}

	// Corrupt file should be moved aside with timestamp
	matches, _ := filepath.Glob(persistPath + ".corrupt.*")
	if len(matches) == 0 {
		t.Error("corrupt file should be moved to .corrupt.<timestamp>")
	}
}

func TestQueueNoDeadLetterKeepsEventsPending(t *testing.T) {
	dir := t.TempDir()

	dest := &mockDestination{
		sendFunc: func(ctx context.Context, events []*Event) error {
			return errors.New("permanent failure")
		},
	}

	// No dead-letter configured
	q, _ := NewQueue(dest, nil, QueueConfig{
		PersistPath: filepath.Join(dir, "nodl.jsonl"),
	})

	q.Enqueue([]*Event{testEvent()})
	result := q.Flush(context.Background())

	if result.Err == nil {
		t.Fatal("expected error for permanent failure")
	}

	// Events should be kept pending since no dead-letter is available
	if q.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (kept pending without dead-letter)", q.Len())
	}
}

func TestQueueEnqueueRollbackOnPersistFailure(t *testing.T) {
	dir := t.TempDir()

	// Create a file where we need a directory - persist will fail
	blockingFile := filepath.Join(dir, "blocking")
	os.WriteFile(blockingFile, []byte("block"), 0o644)
	persistPath := filepath.Join(blockingFile, "queue.jsonl")

	dest := &mockDestination{}
	q := &Queue{
		dest:        dest,
		config:      QueueConfig{MaxSize: 1000},
		pending:     make([]*Event, 0),
		persistPath: persistPath,
	}

	// First enqueue should fail (can't create dir where file exists)
	_, _, err := q.Enqueue([]*Event{testEvent()})
	if err == nil {
		t.Fatal("expected error for persist failure")
	}

	// Queue should be empty (rolled back)
	if q.Len() != 0 {
		t.Errorf("Len() = %d, want 0 (rolled back)", q.Len())
	}
}
