package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Deduplicator suppresses duplicate SIEM events within a time window.
// Events are deduplicated by fingerprint. Status changes are never suppressed.
//
// Filter() atomically checks and reserves each fingerprint it lets through
// (see Filter's doc comment). Call RecordDelivered() after successful SIEM
// delivery to confirm the reservation, or Release() if the event will never
// actually be delivered, so its fingerprint isn't wrongly suppressed for the
// rest of the window.
type Deduplicator struct {
	mu          sync.Mutex
	cache       map[string]*dedupEntry
	windowHours int
	persistPath string
}

// dedupEntry tracks the last delivered state for a fingerprint.
type dedupEntry struct {
	Fingerprint   string    `json:"fingerprint"`
	SystemID      string    `json:"system_id"`
	LastStatus    string    `json:"last_status"`
	LastEventType string    `json:"last_event_type"`
	LastDelivered time.Time `json:"last_delivered"`
	// ControlCode and ControlName for remediation event generation
	ControlCode string `json:"control_code,omitempty"`
	ControlName string `json:"control_name,omitempty"`
	// ControlPackName and ControlPackVersion carry forward the originating
	// pack identity so remediation events (synthesized from cache state, not
	// a fresh finding) can still populate export metadata.
	ControlPackName    string `json:"control_pack_name,omitempty"`
	ControlPackVersion string `json:"control_pack_version,omitempty"`
}

// DeduplicatorConfig contains deduplication settings.
type DeduplicatorConfig struct {
	WindowHours int
	PersistPath string
}

// NewDeduplicator creates a new deduplicator.
func NewDeduplicator(cfg DeduplicatorConfig) (*Deduplicator, error) {
	if cfg.WindowHours <= 0 {
		cfg.WindowHours = 24
	}
	if cfg.PersistPath == "" {
		cfg.PersistPath = ".cache/siem-dedup.json"
	}

	d := &Deduplicator{
		cache:       make(map[string]*dedupEntry),
		windowHours: cfg.WindowHours,
		persistPath: cfg.PersistPath,
	}

	// Load persisted state. Locked so a concurrent process cannot be mid-write
	// to the same persist file while we read it.
	lock, lockErr := acquireFileLock(cfg.PersistPath)
	if lockErr != nil {
		return nil, fmt.Errorf("acquire dedup lock: %w", lockErr)
	}
	loadErr := d.load()
	lock.release()

	if loadErr != nil {
		// Move corrupt file aside with timestamp
		timestamp := time.Now().UTC().Format("20060102-150405")
		corruptPath := fmt.Sprintf("%s.corrupt.%s", cfg.PersistPath, timestamp)
		if renameErr := os.Rename(cfg.PersistPath, corruptPath); renameErr != nil && !os.IsNotExist(renameErr) {
			return nil, fmt.Errorf("failed to load dedup state and cannot move corrupt file: load error: %v, rename error: %w", loadErr, renameErr)
		}
		return nil, fmt.Errorf("failed to load dedup state (corrupt file moved to %s): %w", corruptPath, loadErr)
	}

	return d, nil
}

// Filter returns events that should be emitted (not suppressed), and
// immediately reserves each returned event's fingerprint in the persisted
// dedup state.
//
// The check (has this fingerprint already been emitted recently?) and the
// reserve (mark it emitted now) happen as a single atomic sequence under the
// persist file lock -- reload authoritative on-disk state, decide, write the
// reservation back -- so a concurrent process (or another Deduplicator
// instance in this process) sharing the same persist path cannot interleave
// between the decision and the write and independently authorize the same
// fingerprint. Checking only this instance's in-memory cache (as this used
// to do, deferring any state update to RecordDelivered after delivery) left
// a window wide enough for two overlapping agent runs to both decide "emit"
// for the same fingerprint before either had recorded anything.
//
// If delivery is not going to happen after all (e.g. the queue rejects the
// event, or delivery is permanently dead-lettered and will not be retried),
// call Release with the same events to give back the reservation; otherwise
// the fingerprint stays wrongly suppressed for the rest of the dedup window
// even though nothing was ever delivered.
//
// On a dedup lock or persist failure, this fails closed: it suppresses the
// whole batch (returns nil) rather than risk two processes both deciding to
// emit without either successfully recording it.
func (d *Deduplicator) Filter(events []*Event) []*Event {
	d.mu.Lock()
	defer d.mu.Unlock()

	fileLock, err := acquireFileLock(d.persistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: dedup lock unavailable, suppressing %d event(s) for this batch: %v\n", len(events), err)
		return nil
	}
	defer fileLock.release()

	if err := d.reloadAndMergeLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: dedup reload failed, suppressing %d event(s) for this batch: %v\n", len(events), err)
		return nil
	}

	// Snapshot so a write failure below can roll back the reservations made
	// in this call without discarding the merge just performed.
	preReserve := d.cache

	now := time.Now().UTC()
	windowDuration := time.Duration(d.windowHours) * time.Hour
	d.cache = make(map[string]*dedupEntry, len(preReserve))
	for fp, entry := range preReserve {
		d.cache[fp] = entry
	}

	var result []*Event
	for _, event := range events {
		if d.shouldEmit(event, now, windowDuration) {
			d.updateCache(event, now)
			result = append(result, event)
		}
	}

	d.pruneExpired(now, windowDuration)

	if err := d.writeLocked(); err != nil {
		d.cache = preReserve // nothing was persisted; discard the in-memory reservations too
		fmt.Fprintf(os.Stderr, "warning: failed to persist dedup reservation, suppressing %d event(s) for this batch: %v\n", len(events), err)
		return nil
	}

	return result
}

// Release removes the dedup reservation for each given event's fingerprint,
// so a fingerprint that Filter reserved but that will never actually be
// delivered does not stay wrongly suppressed for the rest of the dedup
// window. Best-effort: it deletes unconditionally rather than checking who
// last wrote the entry, so it can in rare cases erase a legitimate delivery
// recorded by another process in the brief window between this process's
// reservation and its release -- an acceptable trade-off given the
// alternative (a silently and permanently suppressed finding) is worse.
func (d *Deduplicator) Release(events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	fileLock, err := acquireFileLock(d.persistPath)
	if err != nil {
		return fmt.Errorf("acquire dedup lock: %w", err)
	}
	defer fileLock.release()

	if err := d.reloadAndMergeLocked(); err != nil {
		return err
	}

	for _, event := range events {
		delete(d.cache, event.Fingerprint)
	}

	now := time.Now().UTC()
	d.pruneExpired(now, time.Duration(d.windowHours)*time.Hour)

	return d.writeLocked()
}

// RecordDelivered updates dedup state after successful SIEM delivery.
// Call this only after events have been confirmed delivered to the SIEM.
// Persists state to disk to survive restarts.
func (d *Deduplicator) RecordDelivered(events []*Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UTC()
	windowDuration := time.Duration(d.windowHours) * time.Hour

	for _, event := range events {
		d.updateCache(event, now)
	}

	// Prune expired entries
	d.pruneExpired(now, windowDuration)

	// Persist immediately after recording delivered events
	return d.persistLocked()
}

// shouldEmit determines if an event should be emitted or suppressed.
func (d *Deduplicator) shouldEmit(event *Event, now time.Time, window time.Duration) bool {
	entry, exists := d.cache[event.Fingerprint]
	if !exists {
		// First occurrence - always emit
		return true
	}

	// Check if within window (based on last successful delivery)
	if now.Sub(entry.LastDelivered) > window {
		// Outside window - emit as new occurrence
		return true
	}

	// Within window - check for status change
	if event.FindingStatus != entry.LastStatus {
		// Status changed (e.g., open -> remediated) - always emit
		return true
	}

	// Within window, same status - check event type for lifecycle changes
	// created -> recurring is expected suppression
	// but remediated -> regressed should emit
	if isSignificantEventTypeChange(entry.LastEventType, event.EventType) {
		return true
	}

	// Duplicate within window - suppress
	return false
}

// isSignificantEventTypeChange checks if the event type transition is significant.
func isSignificantEventTypeChange(lastType, newType string) bool {
	// Significant transitions that should always emit:
	// - Any -> remediated (finding fixed)
	// - Any -> regressed (finding returned)
	// - Any -> updated (finding details changed)
	switch newType {
	case EventTypeRemediated, EventTypeRegressed, EventTypeUpdated:
		return true
	}
	return false
}

// updateCache records the event in the cache.
func (d *Deduplicator) updateCache(event *Event, now time.Time) {
	entry := &dedupEntry{
		Fingerprint:   event.Fingerprint,
		SystemID:      event.SystemID,
		LastStatus:    event.FindingStatus,
		LastEventType: event.EventType,
		LastDelivered: now,
		ControlCode:   event.ControlCode,
		ControlName:   event.ControlName,
	}
	if event.Export != nil {
		entry.ControlPackName = event.Export.ControlPackName
		entry.ControlPackVersion = event.Export.ControlPackVersion
	}
	d.cache[event.Fingerprint] = entry
}

// pruneExpired removes entries older than the window.
func (d *Deduplicator) pruneExpired(now time.Time, window time.Duration) {
	for fp, entry := range d.cache {
		if now.Sub(entry.LastDelivered) > window {
			delete(d.cache, fp)
		}
	}
}

// Persist saves the deduplication state to disk.
func (d *Deduplicator) Persist() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.persistLocked()
}

// persistLocked writes dedup state to disk. The caller must already hold
// d.mu; this additionally acquires the cross-process file lock for the
// duration of the write so a concurrent process cannot corrupt the same
// persist file.
//
// Before writing, it reloads and merges current on-disk state (see
// reloadAndMergeLocked) so a concurrent process's writes since this
// instance's last load are not silently discarded.
func (d *Deduplicator) persistLocked() error {
	fileLock, err := acquireFileLock(d.persistPath)
	if err != nil {
		return fmt.Errorf("acquire dedup lock: %w", err)
	}
	defer fileLock.release()

	if err := d.reloadAndMergeLocked(); err != nil {
		return err
	}

	now := time.Now().UTC()
	d.pruneExpired(now, time.Duration(d.windowHours)*time.Hour)

	return d.writeLocked()
}

// reloadAndMergeLocked reloads the current on-disk dedup state and merges it
// with this instance's in-memory cache (newest LastDelivered per fingerprint
// wins), adopting the merged result as the new d.cache. The caller must hold
// d.mu and the persist file lock.
//
// Each Deduplicator loads on-disk state only once, at construction; without
// this reload-and-merge step, writing d.cache directly would silently
// discard any updates a concurrent process persisted after that initial
// load -- the file lock only prevents two writes from corrupting each
// other, it does not by itself prevent one from clobbering the other's data.
func (d *Deduplicator) reloadAndMergeLocked() error {
	onDisk, err := loadDedupEntries(d.persistPath)
	if err != nil {
		return fmt.Errorf("reload dedup state: %w", err)
	}
	merged := make(map[string]*dedupEntry, len(onDisk)+len(d.cache))
	for _, entry := range onDisk {
		merged[entry.Fingerprint] = entry
	}
	for fp, entry := range d.cache {
		existing, ok := merged[fp]
		if !ok || !entry.LastDelivered.Before(existing.LastDelivered) {
			merged[fp] = entry
		}
	}
	d.cache = merged
	return nil
}

// writeLocked writes d.cache to disk. The caller must hold d.mu and the
// persist file lock.
func (d *Deduplicator) writeLocked() error {
	dir := filepath.Dir(d.persistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dedup directory: %w", err)
	}

	// Convert map to slice for JSON
	entries := make([]*dedupEntry, 0, len(d.cache))
	for _, entry := range d.cache {
		entries = append(entries, entry)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal dedup state: %w", err)
	}

	tmpPath := d.persistPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write dedup state: %w", err)
	}

	if err := os.Rename(tmpPath, d.persistPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename dedup state: %w", err)
	}

	return nil
}

// load restores deduplication state from disk.
func (d *Deduplicator) load() error {
	entries, err := loadDedupEntries(d.persistPath)
	if err != nil {
		return err
	}

	// Rebuild cache
	now := time.Now().UTC()
	window := time.Duration(d.windowHours) * time.Hour
	for _, entry := range entries {
		// Only load non-expired entries
		if now.Sub(entry.LastDelivered) <= window {
			d.cache[entry.Fingerprint] = entry
		}
	}

	return nil
}

// loadDedupEntries reads the dedup entries currently persisted at path. It
// is a free function (not a *Deduplicator method) so persistLocked can
// reload authoritative on-disk state under the file lock without going
// through -- or mutating -- any particular Deduplicator instance's in-memory
// cache first.
func loadDedupEntries(path string) ([]*dedupEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No persisted state
		}
		return nil, fmt.Errorf("read dedup state: %w", err)
	}

	var entries []*dedupEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("unmarshal dedup state: %w", err)
	}

	return entries, nil
}

// Len returns the number of entries in the cache.
func (d *Deduplicator) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.cache)
}

// DetermineLifecycle sets the event type for each event based on dedup state.
// It modifies events in place, setting EventType to created, recurring, or regressed.
// Must be called BEFORE Filter() as it uses dedup state to determine lifecycle.
func (d *Deduplicator) DetermineLifecycle(events []*Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, event := range events {
		entry, exists := d.cache[event.Fingerprint]
		if !exists {
			// First time seeing this fingerprint
			event.EventType = EventTypeCreated
			continue
		}

		// Check if this was previously remediated
		if entry.LastStatus == FindingStatusRemediated {
			// Was remediated, now failing again → regressed
			event.EventType = EventTypeRegressed
			regressedAt := event.EventTime
			event.RegressedAt = &regressedAt
		} else {
			// Same status as before → recurring
			event.EventType = EventTypeRecurring
			event.OccurrenceCount++ // Increment occurrence count
		}
	}
}

// DetectRemediations finds fingerprints that were previously open for a system
// but are not in the current results, creating remediated events for them.
//
// IMPORTANT: executedControls must contain control codes that completed successfully
// (not ERROR). A missing fingerprint only proves remediation if its control ran.
// This prevents false remediation events when controls error, skip, or aren't included.
//
// Returns remediated events that should be emitted.
func (d *Deduplicator) DetectRemediations(systemID string, currentFingerprints map[string]bool, executedControls map[string]bool, ctx FindingContext) []*Event {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().UTC()
	windowDuration := time.Duration(d.windowHours) * time.Hour
	var remediatedEvents []*Event

	for fp, entry := range d.cache {
		// Only consider entries for this system
		if entry.SystemID != systemID {
			continue
		}

		// Skip if already remediated
		if entry.LastStatus == FindingStatusRemediated {
			continue
		}

		// Skip expired entries
		if now.Sub(entry.LastDelivered) > windowDuration {
			continue
		}

		// Skip if the control didn't execute successfully in this run.
		// Can't claim remediation if the control errored, was skipped, or wasn't included.
		if !executedControls[entry.ControlCode] {
			continue
		}

		// If fingerprint was present but not in current results → remediated
		if !currentFingerprints[fp] {
			controlPackName := entry.ControlPackName
			if controlPackName == "" {
				controlPackName = ctx.ControlPackName
			}
			controlPackVersion := entry.ControlPackVersion
			if controlPackVersion == "" {
				controlPackVersion = ctx.ControlPackVersion
			}
			remediatedAt := now

			event := &Event{
				Version:         EventVersion,
				EventType:       EventTypeRemediated,
				EventTime:       now,
				AgentID:         ctx.AgentID,
				SystemID:        systemID,
				SystemName:      ctx.SystemName,
				DatabaseEngine:  ctx.DatabaseEngine,
				Environment:     ctx.Environment,
				FindingID:       "find-" + fp,
				Fingerprint:     fp,
				ControlCode:     entry.ControlCode,
				ControlName:     entry.ControlName,
				FindingTitle:    "Finding remediated",
				Severity:        SeverityInfo, // Remediation is informational
				FindingStatus:   FindingStatusRemediated,
				FirstSeen:       entry.LastDelivered, // Approximate
				LastSeen:        now,
				RemediatedAt:    &remediatedAt,
				OccurrenceCount: 1,
				Source:          "control_audit",
				Export: &EventExport{
					ControlPackName:    controlPackName,
					ControlPackVersion: controlPackVersion,
					AgentVersion:       ctx.AgentVersion,
					Mode:               ctx.Mode,
					Destination:        ctx.Destination,
				},
			}
			remediatedEvents = append(remediatedEvents, event)
		}
	}

	return remediatedEvents
}

// Close persists state and releases resources.
func (d *Deduplicator) Close() error {
	return d.Persist()
}
