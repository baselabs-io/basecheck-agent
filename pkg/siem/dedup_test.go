package siem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func dedupTestEvent(fingerprint, status, eventType string) *Event {
	now := time.Now().UTC()
	return &Event{
		Version:        EventVersion,
		EventType:      eventType,
		EventTime:      now,
		AgentID:        "agent-1",
		SystemID:       "sys-1",
		SystemName:     "test-db",
		DatabaseEngine: "postgres",
		FindingID:      "find-" + fingerprint,
		Fingerprint:    fingerprint,
		ControlCode:    "PG-001",
		ControlName:    "Test Control",
		FindingTitle:   "Test Finding",
		Severity:       SeverityHigh,
		FindingStatus:  status,
		FirstSeen:      now,
		LastSeen:       now,
		Source:         "control_audit",
	}
}

// TestDeduplicatorPersistUsesRestrictivePermissions guards against dedup
// state (database names, control identifiers, findings, evidence) being
// readable by other local users via a permissive file/directory mode.
func TestDeduplicatorPersistUsesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}

	dir := t.TempDir()
	persistPath := filepath.Join(dir, "state", "siem-dedup.json")

	d, err := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})
	if err != nil {
		t.Fatalf("NewDeduplicator() error: %v", err)
	}

	if err := d.RecordDelivered([]*Event{dedupTestEvent("fp-1", FindingStatusOpen, EventTypeCreated)}); err != nil {
		t.Fatalf("RecordDelivered() error: %v", err)
	}

	fileInfo, err := os.Stat(persistPath)
	if err != nil {
		t.Fatalf("stat persist file: %v", err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("dedup persist file mode = %o, want %o", mode, 0o600)
	}

	dirInfo, err := os.Stat(filepath.Dir(persistPath))
	if err != nil {
		t.Fatalf("stat persist directory: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("dedup persist directory mode = %o, want %o", mode, 0o700)
	}
}

func TestNewDeduplicator(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		d, err := NewDeduplicator(DeduplicatorConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d == nil {
			t.Fatal("expected non-nil deduplicator")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{})
		if d.windowHours != 24 {
			t.Errorf("windowHours = %d, want 24", d.windowHours)
		}
	})
}

func TestDeduplicatorFilter(t *testing.T) {
	dir := t.TempDir()

	t.Run("first occurrence always emits", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "first.json"),
		})

		events := []*Event{
			dedupTestEvent("fp-1", FindingStatusOpen, EventTypeCreated),
		}

		result := d.Filter(events)
		if len(result) != 1 {
			t.Errorf("len(result) = %d, want 1", len(result))
		}
	})

	t.Run("filter atomically reserves so a second call suppresses without RecordDelivered", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "reserve.json"),
		})

		event := dedupTestEvent("fp-reserve", FindingStatusOpen, EventTypeCreated)

		// Filter reserves the fingerprint as it emits, so a second Filter
		// call for the same fingerprint -- even without an intervening
		// RecordDelivered -- must suppress it. This is what closes the
		// cross-process race where two overlapping runs both decide to emit
		// the same fingerprint before either records delivery.
		result1 := d.Filter([]*Event{event})
		result2 := d.Filter([]*Event{event})

		if len(result1) != 1 {
			t.Errorf("first Filter call should emit, got %d", len(result1))
		}
		if len(result2) != 0 {
			t.Errorf("second Filter call should be suppressed by the reservation, got %d", len(result2))
		}
	})

	t.Run("release gives back the reservation", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "release.json"),
		})

		event := dedupTestEvent("fp-release", FindingStatusOpen, EventTypeCreated)

		result1 := d.Filter([]*Event{event})
		if len(result1) != 1 {
			t.Fatalf("first Filter call should emit, got %d", len(result1))
		}

		if err := d.Release(result1); err != nil {
			t.Fatalf("release: %v", err)
		}

		result2 := d.Filter([]*Event{event})
		if len(result2) != 1 {
			t.Errorf("Filter after Release should emit again, got %d", len(result2))
		}
	})

	t.Run("duplicate within window suppressed after delivery", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "dup.json"),
		})

		event1 := dedupTestEvent("fp-dup", FindingStatusOpen, EventTypeCreated)
		event2 := dedupTestEvent("fp-dup", FindingStatusOpen, EventTypeRecurring)

		result1 := d.Filter([]*Event{event1})
		if len(result1) != 1 {
			t.Errorf("first event should emit")
		}

		// Record delivery
		d.RecordDelivered(result1)

		result2 := d.Filter([]*Event{event2})
		if len(result2) != 0 {
			t.Errorf("duplicate should be suppressed after delivery, got %d", len(result2))
		}
	})

	t.Run("different fingerprints both emit", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "diff.json"),
		})

		events := []*Event{
			dedupTestEvent("fp-a", FindingStatusOpen, EventTypeCreated),
			dedupTestEvent("fp-b", FindingStatusOpen, EventTypeCreated),
		}

		result := d.Filter(events)
		if len(result) != 2 {
			t.Errorf("len(result) = %d, want 2", len(result))
		}
	})

	t.Run("status change always emits", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "status.json"),
		})

		event1 := dedupTestEvent("fp-status", FindingStatusOpen, EventTypeCreated)
		event2 := dedupTestEvent("fp-status", FindingStatusRemediated, EventTypeRemediated)

		d.Filter([]*Event{event1})
		d.RecordDelivered([]*Event{event1})

		result := d.Filter([]*Event{event2})
		if len(result) != 1 {
			t.Errorf("status change should emit, got %d", len(result))
		}
	})

	t.Run("remediated event always emits", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "remediated.json"),
		})

		event1 := dedupTestEvent("fp-rem", FindingStatusOpen, EventTypeCreated)
		event2 := dedupTestEvent("fp-rem", FindingStatusRemediated, EventTypeRemediated)

		d.Filter([]*Event{event1})
		d.RecordDelivered([]*Event{event1})

		result := d.Filter([]*Event{event2})
		if len(result) != 1 {
			t.Errorf("remediated should emit")
		}
	})

	t.Run("regressed event always emits", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "regressed.json"),
		})

		event1 := dedupTestEvent("fp-reg", FindingStatusRemediated, EventTypeRemediated)
		event2 := dedupTestEvent("fp-reg", FindingStatusOpen, EventTypeRegressed)

		d.Filter([]*Event{event1})
		d.RecordDelivered([]*Event{event1})

		result := d.Filter([]*Event{event2})
		if len(result) != 1 {
			t.Errorf("regressed should emit")
		}
	})

	t.Run("updated event always emits", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "updated.json"),
		})

		event1 := dedupTestEvent("fp-upd", FindingStatusOpen, EventTypeCreated)
		event2 := dedupTestEvent("fp-upd", FindingStatusOpen, EventTypeUpdated)

		d.Filter([]*Event{event1})
		d.RecordDelivered([]*Event{event1})

		result := d.Filter([]*Event{event2})
		if len(result) != 1 {
			t.Errorf("updated should emit")
		}
	})
}

// TestDeduplicatorFilterCrossProcessRace guards against two independent
// Deduplicator instances sharing one persist path (e.g. two overlapping
// agent processes auditing the same system) both authorizing emission of
// the same fingerprint. Before Filter reserved atomically under the file
// lock, each instance decided purely from its own in-memory cache -- loaded
// once at construction and otherwise updated only after delivery -- so two
// instances racing Filter before either called RecordDelivered would both
// see "not seen yet" and both emit.
func TestDeduplicatorFilterCrossProcessRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.json")

	d1, err := NewDeduplicator(DeduplicatorConfig{PersistPath: path})
	if err != nil {
		t.Fatalf("new deduplicator 1: %v", err)
	}
	d2, err := NewDeduplicator(DeduplicatorConfig{PersistPath: path})
	if err != nil {
		t.Fatalf("new deduplicator 2: %v", err)
	}

	event1 := dedupTestEvent("fp-race", FindingStatusOpen, EventTypeCreated)
	event2 := dedupTestEvent("fp-race", FindingStatusOpen, EventTypeCreated)

	result1 := d1.Filter([]*Event{event1})
	result2 := d2.Filter([]*Event{event2})

	emitted := len(result1) + len(result2)
	if emitted != 1 {
		t.Fatalf("expected exactly one of the two racing Filter calls to emit, got %d (result1=%d, result2=%d)",
			emitted, len(result1), len(result2))
	}
}

func TestDeduplicatorWindowExpiry(t *testing.T) {
	dir := t.TempDir()

	d, _ := NewDeduplicator(DeduplicatorConfig{
		WindowHours: 1, // 1 hour window
		PersistPath: filepath.Join(dir, "expiry.json"),
	})

	// Add an entry and record delivery
	event1 := dedupTestEvent("fp-expire", FindingStatusOpen, EventTypeCreated)
	d.Filter([]*Event{event1})
	d.RecordDelivered([]*Event{event1})

	// Manually expire the entry, in-memory and on disk together: Filter
	// reloads and merges authoritative on-disk state by newest LastDelivered
	// (see reloadAndMergeLocked), so an in-memory-only rollback would lose to
	// the still-fresh on-disk copy during that merge instead of expiring.
	d.mu.Lock()
	if entry, ok := d.cache["fp-expire"]; ok {
		entry.LastDelivered = time.Now().Add(-2 * time.Hour) // 2 hours ago
	}
	entries := make([]*dedupEntry, 0, len(d.cache))
	for _, e := range d.cache {
		entries = append(entries, e)
	}
	d.mu.Unlock()

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal aged entries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expiry.json"), data, 0o600); err != nil {
		t.Fatalf("write aged entries: %v", err)
	}

	// Same event should now emit (outside window)
	event2 := dedupTestEvent("fp-expire", FindingStatusOpen, EventTypeRecurring)
	result := d.Filter([]*Event{event2})

	if len(result) != 1 {
		t.Errorf("expired entry should allow emit, got %d", len(result))
	}
}

func TestDeduplicatorPersistence(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "persist.json")

	// Create and populate deduplicator
	d1, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})
	events := []*Event{
		dedupTestEvent("fp-persist-1", FindingStatusOpen, EventTypeCreated),
		dedupTestEvent("fp-persist-2", FindingStatusOpen, EventTypeCreated),
	}
	d1.Filter(events)
	d1.RecordDelivered(events) // RecordDelivered persists automatically

	// Create new deduplicator with same path
	d2, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})

	// Should have loaded the entries
	if d2.Len() != 2 {
		t.Errorf("Len() = %d, want 2", d2.Len())
	}

	// Duplicates should be suppressed
	result := d2.Filter([]*Event{
		dedupTestEvent("fp-persist-1", FindingStatusOpen, EventTypeRecurring),
	})

	if len(result) != 0 {
		t.Errorf("loaded entry should suppress duplicate")
	}
}

func TestDeduplicatorPruneExpired(t *testing.T) {
	dir := t.TempDir()

	d, _ := NewDeduplicator(DeduplicatorConfig{
		WindowHours: 1,
		PersistPath: filepath.Join(dir, "prune.json"),
	})

	// Add entries and record delivery
	events := []*Event{
		dedupTestEvent("fp-prune-1", FindingStatusOpen, EventTypeCreated),
		dedupTestEvent("fp-prune-2", FindingStatusOpen, EventTypeCreated),
	}
	d.Filter(events)
	d.RecordDelivered(events)

	if d.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", d.Len())
	}

	// Expire one entry, in-memory and on disk together: persistLocked reloads
	// and merges authoritative on-disk state by newest LastDelivered (see
	// persistLocked), so an in-memory-only rollback to an older timestamp
	// would lose to the still-fresh on-disk copy during that merge instead of
	// pruning -- real deliveries only ever move LastDelivered forward, so
	// simulating one moving backward has to rewrite both sides directly to be
	// faithful to how the merge is meant to behave.
	d.mu.Lock()
	if entry, ok := d.cache["fp-prune-1"]; ok {
		entry.LastDelivered = time.Now().Add(-2 * time.Hour)
	}
	entries := make([]*dedupEntry, 0, len(d.cache))
	for _, e := range d.cache {
		entries = append(entries, e)
	}
	d.mu.Unlock()

	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal aged entries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prune.json"), data, 0o600); err != nil {
		t.Fatalf("write aged entries: %v", err)
	}

	// RecordDelivered triggers pruning
	newEvent := dedupTestEvent("fp-new", FindingStatusOpen, EventTypeCreated)
	d.RecordDelivered([]*Event{newEvent})

	// Should have 2 entries: fp-prune-2 and fp-new (fp-prune-1 expired)
	if d.Len() != 2 {
		t.Errorf("Len() = %d, want 2 after prune", d.Len())
	}

	// Verify fp-prune-1 was pruned
	d.mu.Lock()
	_, exists := d.cache["fp-prune-1"]
	d.mu.Unlock()

	if exists {
		t.Error("expired entry should be pruned")
	}
}

func TestDeduplicatorLoadFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "corrupt.json")

	// Write corrupt data
	os.WriteFile(persistPath, []byte("not valid json"), 0o644)

	_, err := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})

	if err == nil {
		t.Fatal("expected error for corrupt dedup state")
	}

	// Corrupt file should be moved aside with timestamp
	matches, _ := filepath.Glob(persistPath + ".corrupt.*")
	if len(matches) == 0 {
		t.Error("corrupt file should be moved to .corrupt.<timestamp>")
	}
}

func TestDeduplicatorClose(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "close.json")

	d, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})
	event := dedupTestEvent("fp-close", FindingStatusOpen, EventTypeCreated)
	d.Filter([]*Event{event})
	d.RecordDelivered([]*Event{event})

	if err := d.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify state was persisted
	d2, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})
	if d2.Len() != 1 {
		t.Errorf("state should be persisted on close")
	}
}

func TestRecordDeliveredPersistsImmediately(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "immediate.json")

	d1, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})
	event := dedupTestEvent("fp-immediate", FindingStatusOpen, EventTypeCreated)
	d1.Filter([]*Event{event})

	// RecordDelivered should persist immediately
	if err := d1.RecordDelivered([]*Event{event}); err != nil {
		t.Fatalf("RecordDelivered failed: %v", err)
	}

	// Create new deduplicator without closing d1
	d2, _ := NewDeduplicator(DeduplicatorConfig{PersistPath: persistPath})

	// Should have loaded the entry (persisted by RecordDelivered)
	if d2.Len() != 1 {
		t.Errorf("RecordDelivered should persist immediately, got %d entries", d2.Len())
	}
}

func TestIsSignificantEventTypeChange(t *testing.T) {
	tests := []struct {
		lastType    string
		newType     string
		significant bool
	}{
		{EventTypeCreated, EventTypeRecurring, false},
		{EventTypeRecurring, EventTypeRecurring, false},
		{EventTypeCreated, EventTypeRemediated, true},
		{EventTypeRecurring, EventTypeRemediated, true},
		{EventTypeRemediated, EventTypeRegressed, true},
		{EventTypeCreated, EventTypeUpdated, true},
		{EventTypeRecurring, EventTypeUpdated, true},
	}

	for _, tt := range tests {
		t.Run(tt.lastType+"->"+tt.newType, func(t *testing.T) {
			if got := isSignificantEventTypeChange(tt.lastType, tt.newType); got != tt.significant {
				t.Errorf("isSignificantEventTypeChange(%s, %s) = %v, want %v",
					tt.lastType, tt.newType, got, tt.significant)
			}
		})
	}
}

func TestDetermineLifecycle(t *testing.T) {
	dir := t.TempDir()

	t.Run("new finding is created", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "created.json"),
		})

		event := dedupTestEvent("fp-new", FindingStatusOpen, EventTypeCreated)
		d.DetermineLifecycle([]*Event{event})

		if event.EventType != EventTypeCreated {
			t.Errorf("EventType = %q, want %q", event.EventType, EventTypeCreated)
		}
	})

	t.Run("recurring finding with same status", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "recurring.json"),
		})

		// Record first occurrence
		event1 := dedupTestEvent("fp-recur", FindingStatusOpen, EventTypeCreated)
		d.RecordDelivered([]*Event{event1})

		// Second occurrence
		event2 := dedupTestEvent("fp-recur", FindingStatusOpen, EventTypeCreated)
		d.DetermineLifecycle([]*Event{event2})

		if event2.EventType != EventTypeRecurring {
			t.Errorf("EventType = %q, want %q", event2.EventType, EventTypeRecurring)
		}
	})

	t.Run("regressed finding after remediation", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "regressed.json"),
		})

		// Record remediated state
		event1 := dedupTestEvent("fp-regress", FindingStatusRemediated, EventTypeRemediated)
		d.RecordDelivered([]*Event{event1})

		// Finding returns
		event2 := dedupTestEvent("fp-regress", FindingStatusOpen, EventTypeCreated)
		d.DetermineLifecycle([]*Event{event2})

		if event2.EventType != EventTypeRegressed {
			t.Errorf("EventType = %q, want %q", event2.EventType, EventTypeRegressed)
		}
		if event2.RegressedAt.IsZero() {
			t.Error("RegressedAt should be set")
		}
	})
}

func TestDetectRemediations(t *testing.T) {
	dir := t.TempDir()

	t.Run("detects missing fingerprint as remediated when control executed", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "detect.json"),
		})

		// Record an open finding for sys-1
		event := dedupTestEvent("fp-will-remediate", FindingStatusOpen, EventTypeCreated)
		event.SystemID = "sys-1"
		event.ControlCode = "PG-001"
		d.RecordDelivered([]*Event{event})

		// Detect remediations with empty current findings but control executed
		ctx := FindingContext{
			AgentID:    "agent-1",
			SystemName: "test-db",
		}
		currentFingerprints := make(map[string]bool) // Empty - no current findings
		executedControls := map[string]bool{"PG-001": true}

		remediations := d.DetectRemediations("sys-1", currentFingerprints, executedControls, ctx)

		if len(remediations) != 1 {
			t.Fatalf("expected 1 remediation, got %d", len(remediations))
		}

		rem := remediations[0]
		if rem.EventType != EventTypeRemediated {
			t.Errorf("EventType = %q, want %q", rem.EventType, EventTypeRemediated)
		}
		if rem.FindingStatus != FindingStatusRemediated {
			t.Errorf("FindingStatus = %q, want %q", rem.FindingStatus, FindingStatusRemediated)
		}
		if rem.Fingerprint != "fp-will-remediate" {
			t.Errorf("Fingerprint = %q, want %q", rem.Fingerprint, "fp-will-remediate")
		}
	})

	t.Run("ignores missing fingerprint when control did not execute", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "noexec.json"),
		})

		// Record an open finding
		event := dedupTestEvent("fp-control-not-run", FindingStatusOpen, EventTypeCreated)
		event.SystemID = "sys-1"
		event.ControlCode = "PG-001"
		d.RecordDelivered([]*Event{event})

		ctx := FindingContext{AgentID: "agent-1", SystemName: "test-db"}
		currentFingerprints := make(map[string]bool)
		executedControls := map[string]bool{"PG-002": true} // Different control ran

		remediations := d.DetectRemediations("sys-1", currentFingerprints, executedControls, ctx)

		if len(remediations) != 0 {
			t.Errorf("expected 0 remediations when control didn't execute, got %d", len(remediations))
		}
	})

	t.Run("ignores already remediated entries", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "already.json"),
		})

		// Record an already-remediated finding
		event := dedupTestEvent("fp-already-fixed", FindingStatusRemediated, EventTypeRemediated)
		event.SystemID = "sys-1"
		event.ControlCode = "PG-001"
		d.RecordDelivered([]*Event{event})

		ctx := FindingContext{AgentID: "agent-1", SystemName: "test-db"}
		executedControls := map[string]bool{"PG-001": true}
		remediations := d.DetectRemediations("sys-1", make(map[string]bool), executedControls, ctx)

		if len(remediations) != 0 {
			t.Errorf("expected 0 remediations for already-remediated, got %d", len(remediations))
		}
	})

	t.Run("ignores fingerprints from other systems", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "other.json"),
		})

		// Record finding for sys-2
		event := dedupTestEvent("fp-other-system", FindingStatusOpen, EventTypeCreated)
		event.SystemID = "sys-2"
		event.ControlCode = "PG-001"
		d.RecordDelivered([]*Event{event})

		// Detect remediations for sys-1 (different system)
		ctx := FindingContext{AgentID: "agent-1", SystemName: "test-db"}
		executedControls := map[string]bool{"PG-001": true}
		remediations := d.DetectRemediations("sys-1", make(map[string]bool), executedControls, ctx)

		if len(remediations) != 0 {
			t.Errorf("expected 0 remediations for other system, got %d", len(remediations))
		}
	})

	t.Run("preserves control info in remediated event", func(t *testing.T) {
		d, _ := NewDeduplicator(DeduplicatorConfig{
			PersistPath: filepath.Join(dir, "control.json"),
		})

		// Record finding with control info
		event := dedupTestEvent("fp-with-control", FindingStatusOpen, EventTypeCreated)
		event.SystemID = "sys-1"
		event.ControlCode = "PG-SEC-001"
		event.ControlName = "Password Policy Check"
		d.RecordDelivered([]*Event{event})

		ctx := FindingContext{AgentID: "agent-1", SystemName: "test-db"}
		executedControls := map[string]bool{"PG-SEC-001": true}
		remediations := d.DetectRemediations("sys-1", make(map[string]bool), executedControls, ctx)

		if len(remediations) != 1 {
			t.Fatalf("expected 1 remediation, got %d", len(remediations))
		}

		if remediations[0].ControlCode != "PG-SEC-001" {
			t.Errorf("ControlCode = %q, want %q", remediations[0].ControlCode, "PG-SEC-001")
		}
		if remediations[0].ControlName != "Password Policy Check" {
			t.Errorf("ControlName = %q, want %q", remediations[0].ControlName, "Password Policy Check")
		}
	})
}
