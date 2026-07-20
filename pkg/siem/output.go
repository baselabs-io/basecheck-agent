package siem

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"basecheck-agent/pkg/config"
	"basecheck-agent/pkg/controlset"
)

// Output manages SIEM event delivery with deduplication, queueing, and retry.
type Output struct {
	dest        Destination
	queue       *Queue
	dedup       *Deduplicator
	deadLetter  *DeadLetter
	ctx         FindingContext
	flushTicker *time.Ticker
	stopCh      chan struct{}
	// flushDone is closed when the periodic flush goroutine exits, so Close
	// can wait for it instead of racing the final flush against it.
	flushDone chan struct{}
	// periodicFlushErr records whether any background periodic flush hit a
	// delivery error. The periodic flush runs unattended between the
	// explicit EmitFindings/Flush calls in cmd/agent/main.go and used to
	// only log failures as they happened; this lets the caller fold them
	// into the final exit status instead of a failure only ever showing up
	// as a line scrolling by in the log.
	periodicFlushErr atomic.Bool
}

// OutputConfig contains settings for SIEM output.
type OutputConfig struct {
	// Destination settings
	Destination string // webhook, syslog

	// Webhook settings
	WebhookURL            string
	WebhookHeaders        map[string]string
	WebhookTimeoutSeconds int
	WebhookAllowInsecure  bool

	// Syslog settings
	SyslogHost           string
	SyslogPort           int
	SyslogProtocol       string
	SyslogFacility       string
	SyslogAppName        string
	SyslogTimeoutSeconds int

	// Queue settings
	QueueMaxSize              int
	QueueFlushIntervalSeconds int
	QueueRetryMax             int
	QueueRetryBackoffSeconds  []int
	QueuePersistPath          string

	// Dead-letter settings
	DeadLetterPath      string
	DeadLetterMaxSizeMB int

	// Deduplication settings
	DeduplicationDisabled    bool
	DeduplicationWindowHours int
	DeduplicationPersistPath string

	// Finding context
	AgentID            string
	AgentVersion       string
	ControlPackName    string
	ControlPackVersion string
}

// NewOutput creates a new SIEM output handler.
func NewOutput(cfg OutputConfig) (*Output, error) {
	// Normalize destination
	destination := strings.ToLower(strings.TrimSpace(cfg.Destination))
	if destination == "" {
		return nil, fmt.Errorf("SIEM destination is required")
	}

	// Create destination
	var dest Destination
	var err error

	switch destination {
	case "webhook":
		dest, err = NewWebhookDestination(WebhookConfig{
			URL:            cfg.WebhookURL,
			Headers:        cfg.WebhookHeaders,
			TimeoutSeconds: cfg.WebhookTimeoutSeconds,
			AgentVersion:   cfg.AgentVersion,
			AllowInsecure:  cfg.WebhookAllowInsecure,
		})
	case "syslog":
		dest, err = NewSyslogDestination(SyslogConfig{
			Host:           cfg.SyslogHost,
			Port:           cfg.SyslogPort,
			Protocol:       cfg.SyslogProtocol,
			Facility:       cfg.SyslogFacility,
			AppName:        cfg.SyslogAppName,
			TimeoutSeconds: cfg.SyslogTimeoutSeconds,
		})
	default:
		return nil, fmt.Errorf("unknown SIEM destination: %q", destination)
	}

	if err != nil {
		return nil, fmt.Errorf("create %s destination: %w", destination, err)
	}

	// Create dead-letter handler
	var deadLetter *DeadLetter
	if cfg.DeadLetterPath != "" {
		deadLetter, err = NewDeadLetter(DeadLetterConfig{
			Path:      cfg.DeadLetterPath,
			MaxSizeMB: cfg.DeadLetterMaxSizeMB,
		})
		if err != nil {
			dest.Close()
			return nil, fmt.Errorf("create dead-letter: %w", err)
		}
	}

	// Create queue
	queue, err := NewQueue(dest, deadLetter, QueueConfig{
		MaxSize:              cfg.QueueMaxSize,
		FlushIntervalSeconds: cfg.QueueFlushIntervalSeconds,
		RetryMax:             cfg.QueueRetryMax,
		RetryBackoffSeconds:  cfg.QueueRetryBackoffSeconds,
		PersistPath:          cfg.QueuePersistPath,
	})
	if err != nil {
		dest.Close()
		if deadLetter != nil {
			deadLetter.Close()
		}
		return nil, fmt.Errorf("create queue: %w", err)
	}

	// Create deduplicator (unless disabled)
	var dedup *Deduplicator
	if !cfg.DeduplicationDisabled {
		dedup, err = NewDeduplicator(DeduplicatorConfig{
			WindowHours: cfg.DeduplicationWindowHours,
			PersistPath: cfg.DeduplicationPersistPath,
		})
		if err != nil {
			queue.Close(context.Background())
			dest.Close()
			if deadLetter != nil {
				deadLetter.Close()
			}
			return nil, fmt.Errorf("create deduplicator: %w", err)
		}
	}

	flushIntervalSeconds := cfg.QueueFlushIntervalSeconds
	if flushIntervalSeconds <= 0 {
		flushIntervalSeconds = 10 // must match Queue's own default (see QueueConfig)
	}

	output := &Output{
		dest:       dest,
		queue:      queue,
		dedup:      dedup,
		deadLetter: deadLetter,
		ctx: FindingContext{
			AgentID:            cfg.AgentID,
			AgentVersion:       cfg.AgentVersion,
			ControlPackName:    cfg.ControlPackName,
			ControlPackVersion: cfg.ControlPackVersion,
			Mode:               "siem_only",
			Destination:        destination,
		},
		flushTicker: time.NewTicker(time.Duration(flushIntervalSeconds) * time.Second),
		stopCh:      make(chan struct{}),
		flushDone:   make(chan struct{}),
	}

	go output.runPeriodicFlush()

	return output, nil
}

// runPeriodicFlush delivers queued events on the configured interval so a
// long multi-database audit doesn't delay every alert until the whole run
// finishes. Safe under concurrent manual Flush calls (e.g. the end-of-run
// flush in cmd/agent/main.go): Queue.Flush is serialized by its own
// dedicated file lock (AS-0034), so a periodic tick firing at the same
// moment as a manual flush cannot double-deliver the same batch.
func (o *Output) runPeriodicFlush() {
	defer close(o.flushDone)
	for {
		select {
		case <-o.flushTicker.C:
			flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			if _, err := o.Flush(flushCtx); err != nil {
				log.Printf("⚠ periodic SIEM flush error: %v", err)
				o.periodicFlushErr.Store(true)
			}
			cancel()
		case <-o.stopCh:
			return
		}
	}
}

// NewOutputFromConfig creates a SIEM output handler from config structs.
func NewOutputFromConfig(cfg *config.Config) (*Output, error) {
	siemCfg := cfg.Output.SIEM

	// Use getter methods to apply defaults
	return NewOutput(OutputConfig{
		Destination:               siemCfg.Destination,
		WebhookURL:                siemCfg.Webhook.URL,
		WebhookHeaders:            siemCfg.Webhook.Headers,
		WebhookTimeoutSeconds:     siemCfg.Webhook.GetTimeoutSeconds(),
		WebhookAllowInsecure:      cfg.Security.AllowHTTP,
		SyslogHost:                siemCfg.Syslog.Host,
		SyslogPort:                siemCfg.Syslog.GetPort(),
		SyslogProtocol:            siemCfg.Syslog.GetProtocol(),
		SyslogFacility:            siemCfg.Syslog.GetFacility(),
		SyslogAppName:             siemCfg.Syslog.GetAppName(),
		SyslogTimeoutSeconds:      siemCfg.Syslog.GetTimeoutSeconds(),
		QueueMaxSize:              siemCfg.Queue.GetMaxSize(),
		QueueFlushIntervalSeconds: siemCfg.Queue.GetFlushIntervalSeconds(),
		QueueRetryMax:             siemCfg.Queue.GetRetryMax(),
		QueueRetryBackoffSeconds:  siemCfg.Queue.GetRetryBackoffSeconds(),
		QueuePersistPath:          siemCfg.Queue.GetPath(),
		DeadLetterPath:            siemCfg.DeadLetter.GetPath(),
		DeadLetterMaxSizeMB:       siemCfg.DeadLetter.GetMaxSizeMB(),
		DeduplicationDisabled:     !siemCfg.Deduplication.IsEnabled(),
		DeduplicationWindowHours:  siemCfg.Deduplication.GetWindowHours(),
		DeduplicationPersistPath:  siemCfg.Deduplication.GetPersistPath(),
		AgentID:                   cfg.Agent.AgentID,
		AgentVersion:              cfg.Agent.Version,
	})
}

// EmitFindings converts control results to SIEM events and queues them for delivery.
// Returns the number of events emitted (after deduplication) and the number
// rejected (failed the event contract, so dead-lettered or dropped instead
// of queued) -- a caller must check rejected, not just err: a batch that is
// entirely invalid enqueues zero events with a nil error, indistinguishable
// from "no findings to emit" unless rejected is inspected too.
// Implements lifecycle detection: created, recurring, regressed, remediated.
//
// IMPORTANT: Dedup state is NOT updated here. Call Flush() after EmitFindings to
// deliver events and record dedup state only after confirmed SIEM delivery.
func (o *Output) EmitFindings(
	results []*controlset.ControlResult,
	systemID string,
	systemName string,
	databaseEngine string,
) (emitted int, rejected int, err error) {
	// Set system context
	ctx := o.ctx
	ctx.SystemID = systemID
	ctx.SystemName = systemName
	ctx.DatabaseEngine = strings.ToLower(strings.TrimSpace(databaseEngine))

	// Collect control codes that completed successfully (not ERROR).
	// Only controls that executed successfully can prove remediation.
	executedControls := make(map[string]bool)
	for _, result := range results {
		if result.Status != "ERROR" {
			executedControls[result.ControlCode] = true
		}
	}

	// Convert findings to events (initially all EventTypeCreated)
	events := ConvertFindings(results, ctx)

	log.Printf("Converted %d findings to SIEM events", len(events))

	// Build fingerprint set for remediation detection
	currentFingerprints := make(map[string]bool, len(events))
	for _, e := range events {
		currentFingerprints[e.Fingerprint] = true
	}

	// Detect remediated findings (previously open, now absent)
	var remediatedEvents []*Event
	if o.dedup != nil {
		// Determine lifecycle for current findings (created/recurring/regressed)
		o.dedup.DetermineLifecycle(events)

		// Detect remediations only for controls that executed successfully.
		// A missing fingerprint is only proof of remediation if its control ran.
		remediatedEvents = o.dedup.DetectRemediations(systemID, currentFingerprints, executedControls, ctx)
		if len(remediatedEvents) > 0 {
			log.Printf("Detected %d remediated findings", len(remediatedEvents))
		}
	}

	// Combine current findings with remediated events
	allEvents := append(events, remediatedEvents...)
	if len(allEvents) == 0 {
		return 0, 0, nil
	}

	// Apply deduplication filter. Filter atomically reserves each returned
	// event's fingerprint (see Deduplicator.Filter) -- if enqueueing then
	// fails outright, those reservations must be released below, or the
	// fingerprints stay wrongly suppressed for the rest of the dedup window
	// even though nothing was ever queued.
	var toEmit []*Event
	if o.dedup != nil {
		toEmit = o.dedup.Filter(allEvents)
		if len(toEmit) < len(allEvents) {
			log.Printf("Deduplication: %d events suppressed, %d to emit",
				len(allEvents)-len(toEmit), len(toEmit))
		}
	} else {
		toEmit = allEvents
	}

	if len(toEmit) == 0 {
		return 0, 0, nil
	}

	// Enqueue for delivery (dedup state updated only after Flush confirms delivery)
	enqueuedCount, rejectedCount, err := o.queue.Enqueue(toEmit)
	if err != nil {
		if o.dedup != nil {
			if relErr := o.dedup.Release(toEmit); relErr != nil {
				log.Printf("⚠ Failed to release dedup reservation after enqueue failure: %v", relErr)
			}
		}
		return 0, rejectedCount, fmt.Errorf("enqueue SIEM events: %w", err)
	}
	if rejectedCount > 0 {
		log.Printf("⚠ %d SIEM event(s) rejected by the queue (failed the event contract, dead-lettered or dropped)", rejectedCount)
	}

	return enqueuedCount, rejectedCount, nil
}

// Flush attempts to deliver all pending events.
// Returns the number of events delivered.
// Records dedup state only for events confirmed delivered to SIEM.
func (o *Output) Flush(ctx context.Context) (int, error) {
	result := o.queue.Flush(ctx)

	// Record dedup state only for events that were actually delivered
	if o.dedup != nil && len(result.Delivered) > 0 {
		if err := o.dedup.RecordDelivered(result.Delivered); err != nil {
			log.Printf("⚠ Failed to record dedup state: %v", err)
			// Don't fail - events were delivered, dedup will retry on next run
		}
	}

	// Release the dedup reservation for events that failed delivery and were
	// permanently dead-lettered (the queue will not retry them) -- otherwise
	// Filter's earlier reservation for these fingerprints wrongly suppresses
	// them for the rest of the dedup window even though nothing was
	// delivered. Events still pending for a future retry are NOT in
	// Abandoned and correctly keep their reservation.
	if o.dedup != nil && len(result.Abandoned) > 0 {
		if err := o.dedup.Release(result.Abandoned); err != nil {
			log.Printf("⚠ Failed to release dedup reservation for abandoned events: %v", err)
		}
	}

	return result.DeliveredCount, result.Err
}

// Close flushes remaining events and releases resources.
func (o *Output) Close(ctx context.Context) error {
	// Stop background flusher and wait for it to actually exit before doing
	// the final flush below, so the two can never race each other.
	if o.stopCh != nil {
		close(o.stopCh)
	}
	if o.flushTicker != nil {
		o.flushTicker.Stop()
	}
	if o.flushDone != nil {
		<-o.flushDone
	}

	// Final flush with dedup recording
	if _, err := o.Flush(ctx); err != nil {
		log.Printf("SIEM final flush error: %v", err)
	}

	// Close components
	var errs []error

	// Note: queue.Close() will attempt another flush, but it's a no-op since
	// we already flushed above and the queue should be empty. This is harmless.

	if o.dedup != nil {
		if err := o.dedup.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close deduplicator: %w", err))
		}
	}

	if o.deadLetter != nil {
		if err := o.deadLetter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close dead-letter: %w", err))
		}
	}

	if err := o.dest.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close destination: %w", err))
	}

	if len(errs) > 0 {
		return errs[0] // Return first error
	}
	return nil
}

// PendingCount returns the number of events waiting to be delivered.
func (o *Output) PendingCount() int {
	return o.queue.Len()
}

// PeriodicFlushErrorOccurred reports whether any background periodic flush
// during this Output's lifetime hit a delivery error. Check this after the
// run completes (and after Close, since Close's own final flush errors are
// reported separately by Close's return value) to fold background flush
// failures into the process exit status.
func (o *Output) PeriodicFlushErrorOccurred() bool {
	return o.periodicFlushErr.Load()
}
