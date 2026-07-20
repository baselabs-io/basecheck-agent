package siem

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// TestConfig contains settings for SIEM test event delivery.
type TestConfig struct {
	// Destination type: "webhook" or "syslog"
	Destination string

	// Webhook settings (used when Destination == "webhook")
	WebhookURL            string
	WebhookHeaders        map[string]string
	WebhookTimeoutSeconds int
	WebhookAgentVersion   string
	WebhookAllowInsecure  bool // Allow http:// URLs (for testing)

	// Syslog settings (used when Destination == "syslog")
	SyslogHost           string
	SyslogPort           int
	SyslogProtocol       string
	SyslogFacility       string
	SyslogAppName        string
	SyslogTimeoutSeconds int

	// Agent info for test event
	AgentID   string
	AgentName string
}

// TestResult contains the outcome of a SIEM test.
type TestResult struct {
	Success     bool
	Destination string
	Target      string // URL or host:port
	Duration    time.Duration
	Error       error
	EventID     string // ID of the test event sent
}

// RunTest sends a synthetic test event to the configured SIEM destination.
// Returns a TestResult with success/failure details.
func RunTest(ctx context.Context, cfg TestConfig) *TestResult {
	start := time.Now()

	// Normalize destination (case-insensitive, trim whitespace)
	destination := strings.ToLower(strings.TrimSpace(cfg.Destination))

	result := &TestResult{
		Destination: destination,
	}

	// Create test event
	testEvent := createTestEvent(cfg)
	result.EventID = testEvent.FindingID

	// Create destination based on config
	var dest Destination
	var err error

	switch destination {
	case "webhook":
		result.Target = cfg.WebhookURL
		dest, err = NewWebhookDestination(WebhookConfig{
			URL:           cfg.WebhookURL,
			Headers:       cfg.WebhookHeaders,
			TimeoutSeconds: cfg.WebhookTimeoutSeconds,
			AgentVersion:  cfg.WebhookAgentVersion,
			AllowInsecure: cfg.WebhookAllowInsecure,
		})
	case "syslog":
		result.Target = fmt.Sprintf("%s:%d", cfg.SyslogHost, cfg.SyslogPort)
		dest, err = NewSyslogDestination(SyslogConfig{
			Host:           cfg.SyslogHost,
			Port:           cfg.SyslogPort,
			Protocol:       cfg.SyslogProtocol,
			Facility:       cfg.SyslogFacility,
			AppName:        cfg.SyslogAppName,
			TimeoutSeconds: cfg.SyslogTimeoutSeconds,
		})
	default:
		result.Error = fmt.Errorf("unknown destination type: %q (must be 'webhook' or 'syslog')", destination)
		result.Duration = time.Since(start)
		return result
	}

	if err != nil {
		result.Error = fmt.Errorf("failed to create %s destination: %w", destination, err)
		result.Duration = time.Since(start)
		return result
	}
	defer dest.Close()

	// Send test event
	err = dest.Send(ctx, []*Event{testEvent})
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("failed to send test event: %w", err)
		return result
	}

	result.Success = true
	return result
}

// createTestEvent generates a synthetic test event for SIEM validation.
func createTestEvent(cfg TestConfig) *Event {
	now := time.Now().UTC()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	agentID := cfg.AgentID
	if agentID == "" {
		agentID = cfg.AgentName
	}
	if agentID == "" {
		agentID = "test-agent"
	}

	event := &Event{
		Version:        EventVersion,
		EventType:      EventTypeCreated,
		EventTime:      now,
		AgentID:        agentID,
		SystemID:       "test-system",
		SystemName:     hostname,
		DatabaseEngine: "test",
		ControlCode:    "TEST-001",
		ControlName:    "SIEM Connectivity Test",
		FindingTitle:   "Test event for SIEM connectivity validation",
		Severity:       SeverityInfo,
		FindingStatus:  FindingStatusOpen,
		FirstSeen:      now,
		LastSeen:       now,
		Source:         "test_siem",
		Evidence: &EventEvidence{
			Summary: "This is a test event sent by the --test-siem command to validate SIEM connectivity.",
		},
		Export: &EventExport{
			AgentVersion: cfg.WebhookAgentVersion,
			Mode:         "siem_only",
			Destination:  cfg.Destination,
			DeliveryID:   fmt.Sprintf("test-%d", now.UnixNano()),
		},
	}

	// Set fingerprint and finding ID
	event.SetFingerprint()

	return event
}

// FormatTestResult returns a human-readable summary of the test result.
func FormatTestResult(r *TestResult) string {
	if r.Success {
		return fmt.Sprintf(
			"SIEM test successful\n"+
				"  Destination: %s\n"+
				"  Target: %s\n"+
				"  Event ID: %s\n"+
				"  Duration: %s\n",
			r.Destination,
			r.Target,
			r.EventID,
			r.Duration.Round(time.Millisecond),
		)
	}

	return fmt.Sprintf(
		"SIEM test FAILED\n"+
			"  Destination: %s\n"+
			"  Target: %s\n"+
			"  Event ID: %s\n"+
			"  Duration: %s\n"+
			"  Error: %v\n",
		r.Destination,
		r.Target,
		r.EventID,
		r.Duration.Round(time.Millisecond),
		r.Error,
	)
}
