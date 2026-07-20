package siem

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunTestWebhook(t *testing.T) {
	t.Run("successful webhook test", func(t *testing.T) {
		var received *Event
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var events []*Event
			if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
				t.Errorf("failed to decode request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(events) > 0 {
				received = events[0]
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		result := RunTest(context.Background(), TestConfig{
			Destination:          "webhook",
			WebhookURL:           server.URL,
			WebhookTimeoutSeconds: 5,
			WebhookAllowInsecure: true, // httptest uses http://
			AgentID:              "test-agent-id",
			AgentName:            "test-agent",
		})

		if !result.Success {
			t.Fatalf("test should succeed: %v", result.Error)
		}
		if result.Destination != "webhook" {
			t.Errorf("destination = %q, want %q", result.Destination, "webhook")
		}
		if result.Target != server.URL {
			t.Errorf("target = %q, want %q", result.Target, server.URL)
		}
		if result.EventID == "" {
			t.Error("event ID should be set")
		}
		if received == nil {
			t.Fatal("no event received by server")
		}
		if received.ControlCode != "TEST-001" {
			t.Errorf("control code = %q, want %q", received.ControlCode, "TEST-001")
		}
		if received.Source != "test_siem" {
			t.Errorf("source = %q, want %q", received.Source, "test_siem")
		}
	})

	t.Run("webhook server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		result := RunTest(context.Background(), TestConfig{
			Destination:          "webhook",
			WebhookURL:           server.URL,
			WebhookTimeoutSeconds: 5,
			WebhookAllowInsecure: true,
		})

		if result.Success {
			t.Fatal("test should fail on 500 response")
		}
		if result.Error == nil {
			t.Fatal("error should be set")
		}
	})

	t.Run("webhook connection refused", func(t *testing.T) {
		result := RunTest(context.Background(), TestConfig{
			Destination:           "webhook",
			WebhookURL:            "http://127.0.0.1:59998/nonexistent",
			WebhookTimeoutSeconds: 1,
		})

		if result.Success {
			t.Fatal("test should fail on connection refused")
		}
		if result.Error == nil {
			t.Fatal("error should be set")
		}
	})
}

func TestRunTestSyslog(t *testing.T) {
	t.Run("successful syslog test TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start listener: %v", err)
		}
		defer listener.Close()

		addr := listener.Addr().(*net.TCPAddr)

		var received string
		done := make(chan struct{})
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				received = string(buf[:n])
				conn.Close()
			}
			close(done)
		}()

		result := RunTest(context.Background(), TestConfig{
			Destination:          "syslog",
			SyslogHost:           "127.0.0.1",
			SyslogPort:           addr.Port,
			SyslogProtocol:       "tcp",
			SyslogTimeoutSeconds: 5,
			AgentID:              "test-agent-id",
		})

		// Close triggers server read completion
		<-done

		if !result.Success {
			t.Fatalf("test should succeed: %v", result.Error)
		}
		if result.Destination != "syslog" {
			t.Errorf("destination = %q, want %q", result.Destination, "syslog")
		}
		if !strings.Contains(received, "TEST-001") {
			t.Errorf("syslog message should contain control code: %s", received)
		}
	})

	t.Run("syslog connection refused", func(t *testing.T) {
		result := RunTest(context.Background(), TestConfig{
			Destination:          "syslog",
			SyslogHost:           "127.0.0.1",
			SyslogPort:           59997,
			SyslogProtocol:       "tcp",
			SyslogTimeoutSeconds: 1,
		})

		if result.Success {
			t.Fatal("test should fail on connection refused")
		}
		if result.Error == nil {
			t.Fatal("error should be set")
		}
	})
}

func TestRunTestInvalidDestination(t *testing.T) {
	result := RunTest(context.Background(), TestConfig{
		Destination: "invalid",
	})

	if result.Success {
		t.Fatal("test should fail for invalid destination")
	}
	if !strings.Contains(result.Error.Error(), "unknown destination type") {
		t.Errorf("error should mention unknown destination: %v", result.Error)
	}
}

func TestRunTestDestinationNormalization(t *testing.T) {
	// Test that destination is normalized (case-insensitive, trimmed)
	tests := []struct {
		input    string
		expected string
	}{
		{"webhook", "webhook"},
		{"WEBHOOK", "webhook"},
		{"Webhook", "webhook"},
		{"  webhook  ", "webhook"},
		{"syslog", "syslog"},
		{"SYSLOG", "syslog"},
		{"  Syslog  ", "syslog"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// We can't easily test success without a server, but we can verify
			// the destination is normalized in the result
			result := RunTest(context.Background(), TestConfig{
				Destination:           tt.input,
				WebhookURL:            "http://127.0.0.1:59996/test",
				WebhookTimeoutSeconds: 1,
				WebhookAllowInsecure:  true,
				SyslogHost:            "127.0.0.1",
				SyslogPort:            59996,
				SyslogTimeoutSeconds:  1,
			})

			// Result should have normalized destination
			if result.Destination != tt.expected {
				t.Errorf("destination = %q, want %q", result.Destination, tt.expected)
			}
		})
	}
}

func TestCreateTestEvent(t *testing.T) {
	cfg := TestConfig{
		AgentID:              "agent-123",
		AgentName:            "my-agent",
		WebhookAgentVersion:  "1.2.3",
		Destination:          "webhook",
	}

	event := createTestEvent(cfg)

	if event.Version != EventVersion {
		t.Errorf("version = %q, want %q", event.Version, EventVersion)
	}
	if event.EventType != EventTypeCreated {
		t.Errorf("event type = %q, want %q", event.EventType, EventTypeCreated)
	}
	if event.AgentID != "agent-123" {
		t.Errorf("agent ID = %q, want %q", event.AgentID, "agent-123")
	}
	if event.ControlCode != "TEST-001" {
		t.Errorf("control code = %q, want %q", event.ControlCode, "TEST-001")
	}
	if event.Source != "test_siem" {
		t.Errorf("source = %q, want %q", event.Source, "test_siem")
	}
	if event.Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", event.Severity, SeverityInfo)
	}
	if event.Fingerprint == "" {
		t.Error("fingerprint should be set")
	}
	if event.FindingID == "" {
		t.Error("finding ID should be set")
	}
	if event.Export == nil {
		t.Fatal("export should be set")
	}
	if event.Export.Destination != "webhook" {
		t.Errorf("export destination = %q, want %q", event.Export.Destination, "webhook")
	}
}

func TestFormatTestResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &TestResult{
			Success:     true,
			Destination: "webhook",
			Target:      "https://example.com/events",
			Duration:    123 * time.Millisecond,
			EventID:     "find-abc123",
		}

		output := FormatTestResult(result)

		if !strings.Contains(output, "successful") {
			t.Errorf("should contain 'successful': %s", output)
		}
		if !strings.Contains(output, "webhook") {
			t.Errorf("should contain destination: %s", output)
		}
		if !strings.Contains(output, "https://example.com/events") {
			t.Errorf("should contain target: %s", output)
		}
		if !strings.Contains(output, "find-abc123") {
			t.Errorf("should contain event ID: %s", output)
		}
	})

	t.Run("failure", func(t *testing.T) {
		result := &TestResult{
			Success:     false,
			Destination: "syslog",
			Target:      "syslog.example.com:514",
			Duration:    50 * time.Millisecond,
			EventID:     "find-def456",
			Error:       context.DeadlineExceeded,
		}

		output := FormatTestResult(result)

		if !strings.Contains(output, "FAILED") {
			t.Errorf("should contain 'FAILED': %s", output)
		}
		if !strings.Contains(output, "syslog") {
			t.Errorf("should contain destination: %s", output)
		}
		if !strings.Contains(output, "deadline exceeded") {
			t.Errorf("should contain error: %s", output)
		}
	})
}
