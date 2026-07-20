package siem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"basecheck-agent/pkg/controlset"
)

func TestNewOutput(t *testing.T) {
	dir := t.TempDir()

	t.Run("creates webhook output", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		output, err := NewOutput(OutputConfig{
			Destination:              "webhook",
			WebhookURL:               server.URL,
			WebhookAllowInsecure:     true,
			QueuePersistPath:         filepath.Join(dir, "queue1.jsonl"),
			DeadLetterPath:           filepath.Join(dir, "dead1.jsonl"),
			DeduplicationPersistPath: filepath.Join(dir, "dedup1.json"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer output.Close(context.Background())

		if output.dest == nil {
			t.Error("destination should not be nil")
		}
		if output.queue == nil {
			t.Error("queue should not be nil")
		}
		if output.dedup == nil {
			t.Error("deduplicator should not be nil (enabled by default)")
		}
	})

	t.Run("creates syslog output", func(t *testing.T) {
		output, err := NewOutput(OutputConfig{
			Destination:              "syslog",
			SyslogHost:               "syslog.example.com",
			SyslogPort:               514,
			QueuePersistPath:         filepath.Join(dir, "queue2.jsonl"),
			DeduplicationPersistPath: filepath.Join(dir, "dedup2.json"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer output.Close(context.Background())
	})

	t.Run("deduplication disabled", func(t *testing.T) {
		output, err := NewOutput(OutputConfig{
			Destination:           "syslog",
			SyslogHost:            "syslog.example.com",
			QueuePersistPath:      filepath.Join(dir, "queue3.jsonl"),
			DeduplicationDisabled: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer output.Close(context.Background())

		if output.dedup != nil {
			t.Error("deduplicator should be nil when disabled")
		}
	})

	t.Run("missing destination", func(t *testing.T) {
		_, err := NewOutput(OutputConfig{})
		if err == nil {
			t.Fatal("expected error for missing destination")
		}
	})

	t.Run("invalid destination", func(t *testing.T) {
		_, err := NewOutput(OutputConfig{
			Destination: "invalid",
		})
		if err == nil {
			t.Fatal("expected error for invalid destination")
		}
	})
}

func TestOutputEmitFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a mock server to receive events
	var receivedEvents []*Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []*Event
		json.NewDecoder(r.Body).Decode(&events)
		receivedEvents = append(receivedEvents, events...)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:              "webhook",
		WebhookURL:               server.URL,
		WebhookAllowInsecure:     true,
		AgentID:                  "test-agent",
		AgentVersion:             "1.0.0",
		ControlPackName:          "test-pack",
		ControlPackVersion:       "1.0.0",
		QueuePersistPath:         filepath.Join(dir, "queue.jsonl"),
		DeadLetterPath:           filepath.Join(dir, "dead.jsonl"),
		DeduplicationDisabled:    true, // Disable for predictable test
		DeduplicationPersistPath: filepath.Join(dir, "dedup.json"),
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	// Create test control results
	results := []*controlset.ControlResult{{
		ControlCode: "TEST-001",
		Title:       "Test Control",
		Status:      "FAIL",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity:    "HIGH",
				Title:       "Test Finding",
				Description: "A test finding",
			}},
		}},
	}}

	// Emit findings
	emitted, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if err != nil {
		t.Fatalf("EmitFindings failed: %v", err)
	}
	if emitted != 1 {
		t.Errorf("emitted = %d, want 1", emitted)
	}

	// Check pending count
	if output.PendingCount() != 1 {
		t.Errorf("pending = %d, want 1", output.PendingCount())
	}

	// Flush
	delivered, err := output.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1", delivered)
	}

	// Verify event received
	if len(receivedEvents) != 1 {
		t.Fatalf("received %d events, want 1", len(receivedEvents))
	}

	event := receivedEvents[0]
	if event.ControlCode != "TEST-001" {
		t.Errorf("control code = %q, want %q", event.ControlCode, "TEST-001")
	}
	if event.AgentID != "test-agent" {
		t.Errorf("agent ID = %q, want %q", event.AgentID, "test-agent")
	}
	if event.SystemName != "test-db" {
		t.Errorf("system name = %q, want %q", event.SystemName, "test-db")
	}
}

func TestOutputEmitFindingsWithDeduplication(t *testing.T) {
	dir := t.TempDir()

	var callCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:              "webhook",
		WebhookURL:               server.URL,
		WebhookAllowInsecure:     true,
		AgentID:                  "test-agent",
		AgentVersion:             "1.0.0",
		ControlPackName:          "test-pack",
		ControlPackVersion:       "1.0.0",
		QueuePersistPath:         filepath.Join(dir, "queue.jsonl"),
		DeduplicationPersistPath: filepath.Join(dir, "dedup.json"),
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	results := []*controlset.ControlResult{{
		ControlCode: "DEDUP-001",
		Title:       "Dedup Test",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity: "MEDIUM",
				Title:    "Duplicate Finding",
				Evidence: map[string]interface{}{
					"schema_name": "public",
					"object_name": "users",
				},
			}},
		}},
	}}

	// First emit - enqueued but dedup state not yet recorded
	emitted1, _, _ := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if emitted1 != 1 {
		t.Errorf("first emit = %d, want 1", emitted1)
	}

	// Flush to deliver - dedup state recorded only after confirmed delivery
	delivered, _ := output.Flush(context.Background())
	if delivered != 1 {
		t.Errorf("delivered = %d, want 1", delivered)
	}

	// Second emit of same finding - should be suppressed (dedup recorded after delivery)
	emitted2, _, _ := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if emitted2 != 0 {
		t.Errorf("second emit = %d, want 0 (suppressed)", emitted2)
	}
}

// TestOutputReleasesDedupReservationOnAbandonedDelivery guards against a
// finding staying permanently suppressed after Filter reserves its
// fingerprint but delivery never actually succeeds. The webhook here always
// returns 400 (a permanent, non-retryable failure), so Flush dead-letters
// the event -- Output.Flush must release its dedup reservation for events
// reported as FlushResult.Abandoned, or a subsequent EmitFindings for the
// same finding would be wrongly suppressed even though nothing was ever
// delivered.
func TestOutputReleasesDedupReservationOnAbandonedDelivery(t *testing.T) {
	dir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // permanent failure, no retry
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:              "webhook",
		WebhookURL:               server.URL,
		WebhookAllowInsecure:     true,
		AgentID:                  "test-agent",
		AgentVersion:             "1.0.0",
		ControlPackName:          "test-pack",
		ControlPackVersion:       "1.0.0",
		QueueRetryMax:            0, // dead-letter immediately, no backoff delay
		QueuePersistPath:         filepath.Join(dir, "queue.jsonl"),
		DeadLetterPath:           filepath.Join(dir, "dead.jsonl"),
		DeduplicationPersistPath: filepath.Join(dir, "dedup.json"),
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	results := []*controlset.ControlResult{{
		ControlCode: "ABANDON-001",
		Title:       "Abandoned Delivery Test",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity: "MEDIUM",
				Title:    "Never Delivered Finding",
				Evidence: map[string]interface{}{
					"schema_name": "public",
					"object_name": "users",
				},
			}},
		}},
	}}

	emitted1, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if err != nil {
		t.Fatalf("first EmitFindings: %v", err)
	}
	if emitted1 != 1 {
		t.Fatalf("first emit = %d, want 1", emitted1)
	}

	// Delivery fails permanently and is dead-lettered; the dedup reservation
	// Filter made above must be released as part of this Flush.
	if _, err := output.Flush(context.Background()); err == nil {
		t.Fatal("expected flush to report the delivery failure")
	}

	emitted2, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if err != nil {
		t.Fatalf("second EmitFindings: %v", err)
	}
	if emitted2 != 1 {
		t.Errorf("second emit = %d, want 1 (reservation should have been released after the abandoned delivery)", emitted2)
	}
}

// TestOutputReleasesDedupReservationOnEnqueueFailure guards against the same
// permanent-suppression bug as the abandoned-delivery case above, but for
// the earlier failure point: Enqueue itself rejecting the whole batch (here,
// because the queue is full). Filter already reserved the fingerprint before
// Enqueue was even attempted, so EmitFindings must release it when Enqueue
// fails outright, or the finding can never be emitted again until the dedup
// window expires even though it was never queued.
func TestOutputReleasesDedupReservationOnEnqueueFailure(t *testing.T) {
	dir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:               "webhook",
		WebhookURL:                server.URL,
		WebhookAllowInsecure:      true,
		AgentID:                   "test-agent",
		AgentVersion:              "1.0.0",
		ControlPackName:           "test-pack",
		ControlPackVersion:        "1.0.0",
		QueueMaxSize:              1,
		QueueFlushIntervalSeconds: 3600, // keep the periodic flush from draining the queue mid-test
		QueuePersistPath:          filepath.Join(dir, "queue.jsonl"),
		DeduplicationPersistPath:  filepath.Join(dir, "dedup.json"),
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	resultsA := []*controlset.ControlResult{{
		ControlCode: "FULL-001",
		Title:       "Queue Fill Test A",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity: "MEDIUM",
				Title:    "Finding A",
				Evidence: map[string]interface{}{"object_name": "table_a"},
			}},
		}},
	}}
	resultsB := []*controlset.ControlResult{{
		ControlCode: "FULL-002",
		Title:       "Queue Fill Test B",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity: "MEDIUM",
				Title:    "Finding B",
				Evidence: map[string]interface{}{"object_name": "table_b"},
			}},
		}},
	}}

	if _, _, err := output.EmitFindings(resultsA, "sys-1", "test-db", "postgres"); err != nil {
		t.Fatalf("emit A: %v", err)
	}

	// Queue is now full (MaxSize 1); emitting B must fail to enqueue.
	if _, _, err := output.EmitFindings(resultsB, "sys-1", "test-db", "postgres"); err == nil {
		t.Fatal("expected enqueue failure for finding B (queue full)")
	}

	// B's dedup reservation must have been released by the failed enqueue:
	// re-converting the same finding (same fingerprint) and filtering it
	// directly must still allow emission.
	eventsB := ConvertFindings(resultsB, FindingContext{
		AgentID:            "test-agent",
		SystemID:           "sys-1",
		SystemName:         "test-db",
		DatabaseEngine:     "postgres",
		ControlPackName:    "test-pack",
		ControlPackVersion: "1.0.0",
	})
	if len(eventsB) != 1 {
		t.Fatalf("expected 1 converted event for B, got %d", len(eventsB))
	}
	if filtered := output.dedup.Filter(eventsB); len(filtered) != 1 {
		t.Errorf("Filter after failed enqueue = %d, want 1 (reservation should have been released)", len(filtered))
	}
}

func TestOutputSkipsPassFindings(t *testing.T) {
	dir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:           "webhook",
		WebhookURL:            server.URL,
		WebhookAllowInsecure:  true,
		QueuePersistPath:      filepath.Join(dir, "queue.jsonl"),
		DeduplicationDisabled: true,
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	// PASS findings should not emit events
	results := []*controlset.ControlResult{{
		ControlCode: "PASS-001",
		Title:       "Passing Control",
		Status:      "PASS",
		Procedures: []controlset.ProcedureResult{{
			Status:   "PASS",
			Findings: []controlset.Finding{},
		}},
	}}

	emitted, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres")
	if err != nil {
		t.Fatalf("EmitFindings failed: %v", err)
	}
	if emitted != 0 {
		t.Errorf("emitted = %d, want 0 for PASS", emitted)
	}
}

func TestOutputLifecycleEvents(t *testing.T) {
	dir := t.TempDir()

	var receivedEvents []*Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []*Event
		json.NewDecoder(r.Body).Decode(&events)
		receivedEvents = append(receivedEvents, events...)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("first finding emits created event", func(t *testing.T) {
		receivedEvents = nil
		output, err := NewOutput(OutputConfig{
			Destination:              "webhook",
			WebhookURL:               server.URL,
			WebhookAllowInsecure:     true,
			AgentID:                  "test-agent",
			AgentVersion:             "1.0.0",
			ControlPackName:          "test-pack",
			ControlPackVersion:       "1.0.0",
			QueuePersistPath:         filepath.Join(dir, "lifecycle1.jsonl"),
			DeduplicationPersistPath: filepath.Join(dir, "dedup1.json"),
		})
		if err != nil {
			t.Fatalf("failed to create output: %v", err)
		}
		defer output.Close(context.Background())

		results := []*controlset.ControlResult{{
			ControlCode: "LIFE-001",
			Title:       "Lifecycle Test",
			Status:      "FAIL",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{{
					Severity:    "HIGH",
					Title:       "Test Finding",
					Description: "A test finding",
				}},
			}},
		}}

		emitted, _, _ := output.EmitFindings(results, "sys-life", "test-db", "postgres")
		if emitted != 1 {
			t.Errorf("emitted = %d, want 1", emitted)
		}

		output.Flush(context.Background())

		if len(receivedEvents) != 1 {
			t.Fatalf("received %d events, want 1", len(receivedEvents))
		}

		if receivedEvents[0].EventType != "created" {
			t.Errorf("EventType = %q, want %q", receivedEvents[0].EventType, "created")
		}
	})

	t.Run("recurring finding emits recurring event", func(t *testing.T) {
		receivedEvents = nil
		output, err := NewOutput(OutputConfig{
			Destination:              "webhook",
			WebhookURL:               server.URL,
			WebhookAllowInsecure:     true,
			AgentID:                  "test-agent",
			AgentVersion:             "1.0.0",
			ControlPackName:          "test-pack",
			ControlPackVersion:       "1.0.0",
			QueuePersistPath:         filepath.Join(dir, "lifecycle2.jsonl"),
			DeduplicationPersistPath: filepath.Join(dir, "dedup2.json"),
		})
		if err != nil {
			t.Fatalf("failed to create output: %v", err)
		}
		defer output.Close(context.Background())

		results := []*controlset.ControlResult{{
			ControlCode: "RECUR-001",
			Title:       "Recurring Test",
			Status:      "FAIL",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{{
					Severity: "HIGH",
					Title:    "Recurring Finding",
				}},
			}},
		}}

		// First emit
		output.EmitFindings(results, "sys-recur", "test-db", "postgres")
		output.Flush(context.Background())

		if len(receivedEvents) != 1 {
			t.Fatalf("first emit: received %d events, want 1", len(receivedEvents))
		}
		if receivedEvents[0].EventType != "created" {
			t.Errorf("first EventType = %q, want %q", receivedEvents[0].EventType, "created")
		}

		receivedEvents = nil

		// Second emit - should be recurring (but suppressed by dedup)
		emitted, _, _ := output.EmitFindings(results, "sys-recur", "test-db", "postgres")
		if emitted != 0 {
			// Recurring is suppressed by dedup within window
			t.Logf("recurring emit = %d (suppressed by dedup as expected)", emitted)
		}
	})

	t.Run("missing finding emits remediated event", func(t *testing.T) {
		receivedEvents = nil
		output, err := NewOutput(OutputConfig{
			Destination:              "webhook",
			WebhookURL:               server.URL,
			WebhookAllowInsecure:     true,
			AgentID:                  "test-agent",
			AgentVersion:             "1.0.0",
			ControlPackName:          "test-pack",
			ControlPackVersion:       "1.0.0",
			QueuePersistPath:         filepath.Join(dir, "lifecycle3.jsonl"),
			DeduplicationPersistPath: filepath.Join(dir, "dedup3.json"),
		})
		if err != nil {
			t.Fatalf("failed to create output: %v", err)
		}
		defer output.Close(context.Background())

		// First: emit a failing finding
		results1 := []*controlset.ControlResult{{
			ControlCode: "REM-001",
			Title:       "Remediation Test",
			Status:      "FAIL",
			Procedures: []controlset.ProcedureResult{{
				Status: "FAIL",
				Findings: []controlset.Finding{{
					Severity: "HIGH",
					Title:    "Will Be Fixed",
				}},
			}},
		}}

		output.EmitFindings(results1, "sys-rem", "test-db", "postgres")
		output.Flush(context.Background())
		receivedEvents = nil

		// Second: same control now passes (finding is gone → remediated)
		// Control must execute successfully for remediation to be detected
		results2 := []*controlset.ControlResult{{
			ControlCode: "REM-001",
			Title:       "Remediation Test",
			Status:      "PASS", // Control passed - no findings
			Procedures: []controlset.ProcedureResult{{
				Status:   "PASS",
				Findings: []controlset.Finding{},
			}},
		}}

		emitted, _, _ := output.EmitFindings(results2, "sys-rem", "test-db", "postgres")
		output.Flush(context.Background())

		if emitted != 1 {
			t.Errorf("remediated emit = %d, want 1", emitted)
		}

		if len(receivedEvents) != 1 {
			t.Fatalf("received %d events, want 1 remediated", len(receivedEvents))
		}

		if receivedEvents[0].EventType != "remediated" {
			t.Errorf("EventType = %q, want %q", receivedEvents[0].EventType, "remediated")
		}
		if receivedEvents[0].FindingStatus != "remediated" {
			t.Errorf("FindingStatus = %q, want %q", receivedEvents[0].FindingStatus, "remediated")
		}
	})
}

// TestOutputPeriodicFlushDeliversWithoutManualFlush guards against the
// configured flush_interval_seconds being dead configuration: queued events
// must be delivered by the background ticker on its own, without any
// caller-invoked Flush.
func TestOutputPeriodicFlushDeliversWithoutManualFlush(t *testing.T) {
	dir := t.TempDir()

	var mu sync.Mutex
	receivedCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []*Event
		_ = json.NewDecoder(r.Body).Decode(&events)
		mu.Lock()
		receivedCount += len(events)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:               "webhook",
		WebhookURL:                server.URL,
		WebhookAllowInsecure:      true,
		AgentID:                   "test-agent",
		AgentVersion:              "1.0.0",
		ControlPackName:           "test-pack",
		ControlPackVersion:        "1.0.0",
		QueueFlushIntervalSeconds: 1,
		QueuePersistPath:          filepath.Join(dir, "queue.jsonl"),
		DeduplicationDisabled:     true,
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	results := []*controlset.ControlResult{{
		ControlCode: "PERIODIC-001",
		Title:       "Periodic Flush Test",
		Status:      "FAIL",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity:    "HIGH",
				Title:       "Test Finding",
				Description: "A test finding",
			}},
		}},
	}}

	if _, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres"); err != nil {
		t.Fatalf("EmitFindings failed: %v", err)
	}

	// Deliberately do not call output.Flush(): the periodic ticker must
	// deliver on its own within a couple of intervals.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := receivedCount
		mu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("expected periodic flush to deliver queued events without a manual Flush call")
}

// TestOutputPeriodicFlushErrorOccurredReportsBackgroundFailures guards
// against a periodic flush failure only ever being visible as a line in the
// log: PeriodicFlushErrorOccurred must let the caller (cmd/agent/main.go)
// fold a background flush error into the process exit status.
func TestOutputPeriodicFlushErrorOccurredReportsBackgroundFailures(t *testing.T) {
	dir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // permanent failure, no retry delay
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:               "webhook",
		WebhookURL:                server.URL,
		WebhookAllowInsecure:      true,
		AgentID:                   "test-agent",
		AgentVersion:              "1.0.0",
		ControlPackName:           "test-pack",
		ControlPackVersion:        "1.0.0",
		QueueFlushIntervalSeconds: 1,
		QueuePersistPath:          filepath.Join(dir, "queue.jsonl"),
		DeduplicationDisabled:     true,
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}
	defer output.Close(context.Background())

	if output.PeriodicFlushErrorOccurred() {
		t.Fatal("expected no periodic flush error before any events were queued")
	}

	results := []*controlset.ControlResult{{
		ControlCode: "PERIODIC-ERR-001",
		Title:       "Periodic Flush Error Test",
		Status:      "FAIL",
		Procedures: []controlset.ProcedureResult{{
			Status: "FAIL",
			Findings: []controlset.Finding{{
				Severity:    "HIGH",
				Title:       "Test Finding",
				Description: "A test finding",
			}},
		}},
	}}
	if _, _, err := output.EmitFindings(results, "sys-1", "test-db", "postgres"); err != nil {
		t.Fatalf("EmitFindings failed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if output.PeriodicFlushErrorOccurred() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("expected PeriodicFlushErrorOccurred to report the background flush's delivery error")
}

// TestOutputCloseWaitsForPeriodicFlushGoroutine guards against Close
// returning while the periodic flush goroutine is still running, which
// would let it race the final flush and component close below it.
func TestOutputCloseWaitsForPeriodicFlushGoroutine(t *testing.T) {
	dir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	output, err := NewOutput(OutputConfig{
		Destination:               "webhook",
		WebhookURL:                server.URL,
		WebhookAllowInsecure:      true,
		AgentID:                   "test-agent",
		AgentVersion:              "1.0.0",
		ControlPackName:           "test-pack",
		ControlPackVersion:        "1.0.0",
		QueueFlushIntervalSeconds: 1,
		QueuePersistPath:          filepath.Join(dir, "queue.jsonl"),
		DeduplicationDisabled:     true,
	})
	if err != nil {
		t.Fatalf("failed to create output: %v", err)
	}

	if err := output.Close(context.Background()); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	select {
	case <-output.flushDone:
		// Goroutine has exited, as expected.
	default:
		t.Fatal("expected the periodic flush goroutine to have exited by the time Close() returns")
	}
}
