package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Queue manages durable event delivery with retry and dead-letter handling.
type Queue struct {
	mu          sync.Mutex
	dest        Destination
	deadLetter  *DeadLetter
	config      QueueConfig
	pending     []*Event
	persistPath string
	closed      bool
}

// QueueConfig contains queue settings.
type QueueConfig struct {
	// MaxSize is the maximum number of events to buffer before blocking.
	MaxSize int

	// FlushIntervalSeconds is how often to attempt delivery.
	FlushIntervalSeconds int

	// RetryMax is the maximum delivery attempts before dead-letter.
	RetryMax int

	// RetryBackoffSeconds is the backoff sequence for retries.
	RetryBackoffSeconds []int

	// PersistPath is the file path for durable queue storage.
	PersistPath string
}

// NewQueue creates a new delivery queue.
// deadLetter is required for durable delivery - permanent failures and max retries
// will be written there. Pass nil only for testing.
func NewQueue(dest Destination, deadLetter *DeadLetter, cfg QueueConfig) (*Queue, error) {
	if dest == nil {
		return nil, fmt.Errorf("destination is required")
	}

	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1000
	}
	if cfg.FlushIntervalSeconds <= 0 {
		cfg.FlushIntervalSeconds = 10
	}
	// RetryMax < 0 means use default; 0 means no retries (immediate dead-letter)
	if cfg.RetryMax < 0 {
		cfg.RetryMax = 5
	}
	if len(cfg.RetryBackoffSeconds) == 0 {
		cfg.RetryBackoffSeconds = []int{1, 5, 30, 120, 300}
	}
	if cfg.PersistPath == "" {
		cfg.PersistPath = ".cache/siem-queue.jsonl"
	}

	q := &Queue{
		dest:        dest,
		deadLetter:  deadLetter,
		config:      cfg,
		pending:     make([]*Event, 0, cfg.MaxSize),
		persistPath: cfg.PersistPath,
	}

	// Load any persisted events from previous run. Locked so a concurrent
	// process cannot be mid-write to the same persist file while we read it.
	lock, err := acquireFileLock(cfg.PersistPath)
	if err != nil {
		return nil, fmt.Errorf("acquire queue lock: %w", err)
	}
	loadErr := q.loadPersisted()
	lock.release()

	if loadErr != nil {
		// Move corrupt file aside with timestamp to preserve evidence
		timestamp := time.Now().UTC().Format("20060102-150405")
		corruptPath := fmt.Sprintf("%s.corrupt.%s", cfg.PersistPath, timestamp)
		if renameErr := os.Rename(cfg.PersistPath, corruptPath); renameErr != nil {
			// Can't even move the file - this is a critical failure
			return nil, fmt.Errorf("failed to load persisted queue and cannot move corrupt file: load error: %v, rename error: %w", loadErr, renameErr)
		}
		return nil, fmt.Errorf("failed to load persisted queue (corrupt file moved to %s): %w", corruptPath, loadErr)
	}

	return q, nil
}

// Enqueue adds events to the queue for delivery.
// Assigns a delivery ID to each event (stable across retries of the same
// queued item) and validates it against the event contract before queueing;
// events that fail validation are routed to dead-letter instead of being
// silently queued for delivery. Returns the number of events actually
// enqueued (post-validation), the number rejected (failed validation, so
// dead-lettered or dropped), and an error if the queue is full or closed.
// A caller must check rejected, not just err: a batch that is entirely
// invalid enqueues zero events with a nil error, which looks identical to
// "nothing to enqueue" unless rejected is inspected too.
func (q *Queue) Enqueue(events []*Event) (enqueued int, rejected int, err error) {
	q.mu.Lock()
	closed := q.closed
	q.mu.Unlock()

	if closed {
		return 0, 0, fmt.Errorf("queue is closed")
	}

	valid := make([]*Event, 0, len(events))
	for _, e := range events {
		if e.Export != nil && e.Export.DeliveryID == "" {
			e.Export.DeliveryID = uuid.NewString()
		}

		if err := e.Validate(); err != nil {
			rejected++
			if q.deadLetter != nil {
				if dlErr := q.deadLetter.Write(e, fmt.Errorf("event validation failed: %w", err)); dlErr != nil {
					fmt.Fprintf(os.Stderr, "failed to write invalid event to dead-letter: %v\n", dlErr)
				}
			} else {
				fmt.Fprintf(os.Stderr, "warning: invalid SIEM event dropped (no dead-letter configured): %v\n", err)
			}
			continue
		}

		valid = append(valid, e)
	}

	// Locked so a concurrent process cannot write the same persist file at
	// the same time. Reloading current on-disk state here (rather than
	// merging into this instance's own in-memory q.pending) is required for
	// correctness when multiple independent Queue instances share a persist
	// path (e.g. two agent processes, or two Queue objects in tests): each
	// instance's in-memory q.pending only reflects what *it* has loaded or
	// written, not what a concurrent instance already wrote. Merging into a
	// stale in-memory snapshot would silently drop the other instance's
	// events even though the lock prevents them from writing at the exact
	// same moment -- the lock alone doesn't make each writer aware of the
	// other's data.
	//
	// Lock order: this file lock is acquired BEFORE q.mu (below), never
	// while holding it. Flush's finalization step acquires the same two
	// locks in the same order (persist file lock, then q.mu); acquiring them
	// in reverse order here would let a concurrent Enqueue and Flush
	// ABBA-deadlock (each blocked waiting for the lock the other already
	// holds) until the file lock's acquire timeout breaks the stall.
	lock, err := acquireFileLock(q.persistPath)
	if err != nil {
		return 0, rejected, fmt.Errorf("acquire queue lock: %w", err)
	}
	defer lock.release()

	current, err := loadPersistedEvents(q.persistPath)
	if err != nil {
		return 0, rejected, fmt.Errorf("reload persisted queue: %w", err)
	}

	if len(current)+len(valid) > q.config.MaxSize {
		return 0, rejected, fmt.Errorf("queue full: %d pending, %d new, max %d",
			len(current), len(valid), q.config.MaxSize)
	}

	merged := make([]*Event, len(current), len(current)+len(valid))
	copy(merged, current)
	merged = append(merged, valid...)

	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return 0, rejected, fmt.Errorf("queue is closed")
	}
	oldPending := q.pending
	q.pending = merged
	persistErr := q.persist()
	if persistErr != nil {
		q.pending = oldPending // Rollback on failure
	}
	q.mu.Unlock()

	if persistErr != nil {
		return 0, rejected, fmt.Errorf("persist queue: %w", persistErr)
	}

	return len(valid), rejected, nil
}

// FlushResult contains the outcome of a Flush operation.
type FlushResult struct {
	DeliveredCount int
	Delivered      []*Event // Events successfully delivered to SIEM
	// Abandoned holds events that failed delivery and were permanently
	// written to dead-letter storage, so the queue will not retry them.
	// A caller tracking dedup reservations for these events (see
	// Deduplicator.Filter) must release them, or they stay wrongly
	// suppressed for the rest of the dedup window even though nothing was
	// ever delivered. Events kept pending for a future retry (including ones
	// that failed to write to dead-letter) are NOT included here -- they are
	// still in flight and their reservation should stay active.
	Abandoned []*Event
	Err       error
}

// Flush attempts to deliver all pending events.
// Returns FlushResult with delivered events for dedup recording.
//
// A dedicated flush lock (distinct from the persist-file lock used by
// Enqueue) is held for the full snapshot-through-delivery-through-persisted-
// state-update window, so a concurrent Flush -- same process or another --
// cannot interleave with this one and double-deliver the same batch. It is a
// separate lock specifically so Enqueue can still take the persist-file lock
// and add new events while a Flush's delivery is in progress (see the
// "newly enqueued" handling below), which is desired and already covered by
// TestQueueConcurrentEnqueueDuringFlush.
//
// Both the initial batch and the final "what's newly arrived" comparison are
// computed from a fresh read of the persist file taken under the persist
// lock, never from this instance's in-memory q.pending: q.pending only
// reflects what *this* Queue instance has loaded or written, which can be
// stale relative to another process (or another Queue instance in the same
// process) sharing the same persist path. Diffing against a stale in-memory
// snapshot is exactly what silently dropped concurrently-enqueued events
// before this fix.
func (q *Queue) Flush(ctx context.Context) FlushResult {
	flushLock, err := acquireFileLock(q.persistPath + ".flush")
	if err != nil {
		return FlushResult{Err: fmt.Errorf("acquire flush lock: %w", err)}
	}
	defer flushLock.release()

	persistLock, err := acquireFileLock(q.persistPath)
	if err != nil {
		return FlushResult{Err: fmt.Errorf("acquire queue lock: %w", err)}
	}
	batch, err := loadPersistedEvents(q.persistPath)
	persistLock.release()
	if err != nil {
		return FlushResult{Err: fmt.Errorf("reload persisted queue: %w", err)}
	}

	q.mu.Lock()
	q.pending = batch
	q.mu.Unlock()

	if len(batch) == 0 {
		return FlushResult{}
	}

	deliveredEvents, remaining, abandoned, err := q.deliverWithRetry(ctx, batch)

	// Reload again right before the final write: events may have been
	// enqueued (by this process or another) while delivery was in flight.
	// Diff by delivery ID against the batch just attempted -- every event
	// that reaches here has a non-empty Export.DeliveryID (Validate
	// requires it) -- so only events genuinely new since the snapshot are
	// kept, instead of ones already accounted for in `remaining`.
	//
	// Lock order: this file lock is held across the q.mu acquisition below
	// (persist file lock, then q.mu) -- the same order Enqueue uses. Keep
	// these consistent; reversing either one reintroduces an ABBA lock-order
	// hazard between concurrent Enqueue and Flush calls.
	persistLock, lockErr := acquireFileLock(q.persistPath)
	if lockErr != nil {
		return FlushResult{
			DeliveredCount: len(deliveredEvents),
			Delivered:      deliveredEvents,
			Abandoned:      abandoned,
			Err:            fmt.Errorf("acquire queue lock: %w", lockErr),
		}
	}
	defer persistLock.release()

	onDisk, reloadErr := loadPersistedEvents(q.persistPath)
	if reloadErr != nil {
		return FlushResult{
			DeliveredCount: len(deliveredEvents),
			Delivered:      deliveredEvents,
			Abandoned:      abandoned,
			Err:            fmt.Errorf("reload persisted queue before final write: %w", reloadErr),
		}
	}

	newlyEnqueued := eventsNotInDeliveryIDs(onDisk, batch)

	q.mu.Lock()
	q.pending = append(append([]*Event(nil), remaining...), newlyEnqueued...)
	persistErr := q.persist()
	q.mu.Unlock()

	if persistErr != nil {
		return FlushResult{
			DeliveredCount: len(deliveredEvents),
			Delivered:      deliveredEvents,
			Abandoned:      abandoned,
			Err:            fmt.Errorf("persist after flush: %w", persistErr),
		}
	}

	return FlushResult{
		DeliveredCount: len(deliveredEvents),
		Delivered:      deliveredEvents,
		Abandoned:      abandoned,
		Err:            err,
	}
}

// eventsNotInDeliveryIDs returns the events in candidates whose
// Export.DeliveryID does not appear in excluded.
func eventsNotInDeliveryIDs(candidates, excluded []*Event) []*Event {
	excludedIDs := make(map[string]struct{}, len(excluded))
	for _, e := range excluded {
		if e.Export != nil {
			excludedIDs[e.Export.DeliveryID] = struct{}{}
		}
	}

	result := make([]*Event, 0, len(candidates))
	for _, e := range candidates {
		if e.Export == nil {
			result = append(result, e)
			continue
		}
		if _, found := excludedIDs[e.Export.DeliveryID]; !found {
			result = append(result, e)
		}
	}
	return result
}

// deliverWithRetry attempts delivery with backoff retries.
// Returns delivered events, remaining (still-pending, will be retried)
// events, abandoned (permanently dead-lettered, will NOT be retried) events,
// and any final error.
func (q *Queue) deliverWithRetry(ctx context.Context, events []*Event) (delivered, remaining, abandoned []*Event, err error) {
	if len(events) == 0 {
		return nil, nil, nil, nil
	}

	var lastErr error
	backoffs := q.config.RetryBackoffSeconds

	for attempt := 0; attempt <= q.config.RetryMax; attempt++ {
		select {
		case <-ctx.Done():
			// Context canceled - return events for later retry
			return nil, events, nil, ctx.Err()
		default:
		}

		sendErr := q.dest.Send(ctx, events)
		if sendErr == nil {
			// Success - return delivered events
			return events, nil, nil, nil
		}

		lastErr = sendErr

		// Context cancellation/timeout means shutdown - keep events pending for next restart
		if errors.Is(sendErr, context.Canceled) || errors.Is(sendErr, context.DeadlineExceeded) {
			return nil, events, nil, sendErr
		}

		if !IsRetryable(sendErr) {
			// Permanent failure - send to dead-letter
			pending, dead := q.sendToDeadLetter(events, sendErr)
			return nil, pending, dead, sendErr
		}

		// Retryable error - backoff and retry
		if attempt < q.config.RetryMax {
			backoffIdx := attempt
			if backoffIdx >= len(backoffs) {
				backoffIdx = len(backoffs) - 1
			}
			backoff := time.Duration(backoffs[backoffIdx]) * time.Second

			select {
			case <-ctx.Done():
				return nil, events, nil, ctx.Err()
			case <-time.After(backoff):
				// Continue to next attempt
			}
		}
	}

	// Max retries exceeded - send to dead-letter
	pending, dead := q.sendToDeadLetter(events, lastErr)
	if len(pending) > 0 {
		// Some events couldn't be written to dead-letter, keep them pending
		return nil, pending, dead, fmt.Errorf("max retries exceeded, %d events kept pending (dead-letter write failed): %w", len(pending), lastErr)
	}
	return nil, nil, dead, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// sendToDeadLetter writes failed events to dead-letter storage. Returns the
// events that could not be written (kept pending, to retry later) and the
// events that WERE written (abandoned -- the queue will not retry them, so
// a caller tracking dedup reservations for them must release those too).
// If no dead-letter is configured, all events are kept pending (none
// abandoned) to avoid silent loss.
func (q *Queue) sendToDeadLetter(events []*Event, err error) (pending, abandoned []*Event) {
	if q.deadLetter == nil {
		fmt.Fprintf(os.Stderr, "warning: no dead-letter configured, %d events kept pending\n", len(events))
		return events, nil
	}

	for _, event := range events {
		if writeErr := q.deadLetter.Write(event, err); writeErr != nil {
			fmt.Fprintf(os.Stderr, "failed to write to dead-letter: %v\n", writeErr)
			pending = append(pending, event)
			continue
		}
		abandoned = append(abandoned, event)
	}
	return pending, abandoned
}

// Len returns the number of pending events.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// Close flushes remaining events and closes the queue.
func (q *Queue) Close(ctx context.Context) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	q.closed = true
	q.mu.Unlock()

	// Final flush attempt
	result := q.Flush(ctx)
	return result.Err
}

// persist writes pending events to disk for durability.
func (q *Queue) persist() error {
	// Ensure directory exists
	dir := filepath.Dir(q.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create queue directory: %w", err)
	}

	// Write to temp file then rename for atomicity
	tmpPath := q.persistPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	encoder := json.NewEncoder(f)
	for _, event := range q.pending {
		if err := encoder.Encode(event); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("encode event: %w", err)
		}
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, q.persistPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// loadPersisted loads events from the persist file into q.pending.
func (q *Queue) loadPersisted() error {
	events, err := loadPersistedEvents(q.persistPath)
	if err != nil {
		return err
	}
	q.pending = append(q.pending, events...)
	return nil
}

// loadPersistedEvents reads the events currently persisted at path. It is a
// free function (not a *Queue method) so Enqueue and Flush can use it to
// reload authoritative on-disk state under the file lock without going
// through -- or mutating -- any particular Queue instance's in-memory
// q.pending first.
func loadPersistedEvents(path string) ([]*Event, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No persisted data
		}
		return nil, fmt.Errorf("open persist file: %w", err)
	}
	defer f.Close()

	var events []*Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("unmarshal event: %w", err)
		}
		events = append(events, &event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan persist file: %w", err)
	}

	return events, nil
}
