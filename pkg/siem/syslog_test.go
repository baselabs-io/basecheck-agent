package siem

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewSyslogDestination(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		dest, err := NewSyslogDestination(SyslogConfig{
			Host:     "syslog.example.com",
			Port:     514,
			Protocol: "tcp",
			Facility: "local0",
			AppName:  "basecheck",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest == nil {
			t.Fatal("expected non-nil destination")
		}
	})

	t.Run("missing host", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{})
		if err == nil {
			t.Fatal("expected error for missing host")
		}
	})

	t.Run("invalid port too high", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{
			Host: "syslog.example.com",
			Port: 70000,
		})
		if err == nil {
			t.Fatal("expected error for invalid port")
		}
	})

	t.Run("invalid port negative", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{
			Host: "syslog.example.com",
			Port: -1,
		})
		if err == nil {
			t.Fatal("expected error for negative port")
		}
	})

	t.Run("invalid protocol", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{
			Host:     "syslog.example.com",
			Protocol: "http",
		})
		if err == nil {
			t.Fatal("expected error for invalid protocol")
		}
	})

	t.Run("invalid facility", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{
			Host:     "syslog.example.com",
			Facility: "invalid",
		})
		if err == nil {
			t.Fatal("expected error for invalid facility")
		}
	})

	t.Run("defaults applied", func(t *testing.T) {
		dest, err := NewSyslogDestination(SyslogConfig{
			Host: "syslog.example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest.port != 514 {
			t.Errorf("port = %d, want 514", dest.port)
		}
		if dest.protocol != "tcp" {
			t.Errorf("protocol = %s, want tcp", dest.protocol)
		}
		if dest.appName != "basecheck" {
			t.Errorf("appName = %s, want basecheck", dest.appName)
		}
		if dest.facility != 16 { // local0
			t.Errorf("facility = %d, want 16 (local0)", dest.facility)
		}
	})

	t.Run("all facilities", func(t *testing.T) {
		facilities := []string{
			"kern", "user", "mail", "daemon", "auth", "syslog",
			"lpr", "news", "uucp", "cron", "authpriv", "ftp",
			"local0", "local1", "local2", "local3",
			"local4", "local5", "local6", "local7",
		}
		for _, f := range facilities {
			_, err := NewSyslogDestination(SyslogConfig{
				Host:     "syslog.example.com",
				Facility: f,
			})
			if err != nil {
				t.Errorf("facility %q should be valid: %v", f, err)
			}
		}
	})

	t.Run("whitespace trimmed", func(t *testing.T) {
		dest, err := NewSyslogDestination(SyslogConfig{
			Host:     "  syslog.example.com  ",
			Protocol: "  tcp  ",
			Facility: "  local0  ",
			AppName:  "  myapp  ",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest.host != "syslog.example.com" {
			t.Errorf("host = %q, want %q", dest.host, "syslog.example.com")
		}
		if dest.protocol != "tcp" {
			t.Errorf("protocol = %q, want %q", dest.protocol, "tcp")
		}
		if dest.appName != "myapp" {
			t.Errorf("appName = %q, want %q", dest.appName, "myapp")
		}
	})

	t.Run("whitespace only host rejected", func(t *testing.T) {
		_, err := NewSyslogDestination(SyslogConfig{
			Host: "   ",
		})
		if err == nil {
			t.Fatal("expected error for whitespace-only host")
		}
	})
}

func TestSyslogDestinationSend(t *testing.T) {
	event := &Event{
		Version:        EventVersion,
		EventType:      EventTypeCreated,
		EventTime:      time.Now().UTC(),
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
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
		Source:         "control_audit",
	}

	// TestSyslogDestinationSend/ipv6_host guards against constructing the dial
	// address with fmt.Sprintf("%s:%d", host, port) (ambiguous/invalid for an
	// IPv6 host, e.g. "::1:5140") instead of net.JoinHostPort (correct bracket
	// notation, e.g. "[::1]:5140").
	t.Run("ipv6 host", func(t *testing.T) {
		listener, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback not available in this environment: %v", err)
		}
		defer listener.Close()

		addr := listener.Addr().(*net.TCPAddr)

		done := make(chan struct{})
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				conn.Close()
			}
			close(done)
		}()

		dest, err := NewSyslogDestination(SyslogConfig{
			Host:     "::1",
			Port:     addr.Port,
			Protocol: "tcp",
		})
		if err != nil {
			t.Fatalf("NewSyslogDestination failed: %v", err)
		}
		defer dest.Close()

		if err := dest.Send(context.Background(), []*Event{event}); err != nil {
			t.Fatalf("Send to IPv6 host failed: %v", err)
		}

		dest.Close()
		<-done
	})

	t.Run("successful delivery TCP", func(t *testing.T) {
		// Start mock syslog server
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

		dest, _ := NewSyslogDestination(SyslogConfig{
			Host:     "127.0.0.1",
			Port:     addr.Port,
			Protocol: "tcp",
		})
		defer dest.Close()

		err = dest.Send(context.Background(), []*Event{event})
		if err != nil {
			t.Fatalf("Send failed: %v", err)
		}

		dest.Close() // Close to trigger server read
		<-done

		// Verify RFC 5424 format
		if !strings.HasPrefix(received, "<") {
			t.Errorf("message should start with PRI: %s", received)
		}
		if !strings.Contains(received, "basecheck") {
			t.Errorf("message should contain app name: %s", received)
		}
		if !strings.Contains(received, event.FindingID) {
			t.Errorf("message should contain finding ID: %s", received)
		}
	})

	t.Run("successful delivery UDP", func(t *testing.T) {
		// Start mock UDP server
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("failed to start UDP listener: %v", err)
		}
		defer conn.Close()

		addr := conn.LocalAddr().(*net.UDPAddr)

		var received string
		done := make(chan struct{})
		go func() {
			buf := make([]byte, 4096)
			n, _, _ := conn.ReadFromUDP(buf)
			received = string(buf[:n])
			close(done)
		}()

		dest, _ := NewSyslogDestination(SyslogConfig{
			Host:     "127.0.0.1",
			Port:     addr.Port,
			Protocol: "udp",
		})
		defer dest.Close()

		err = dest.Send(context.Background(), []*Event{event})
		if err != nil {
			t.Fatalf("Send failed: %v", err)
		}

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for UDP message")
		}

		if !strings.Contains(received, event.FindingID) {
			t.Errorf("message should contain finding ID: %s", received)
		}
	})

	t.Run("empty events", func(t *testing.T) {
		dest, _ := NewSyslogDestination(SyslogConfig{
			Host: "syslog.example.com",
		})

		err := dest.Send(context.Background(), []*Event{})
		if err != nil {
			t.Fatalf("empty events should succeed: %v", err)
		}
	})

	t.Run("connection refused is retryable", func(t *testing.T) {
		dest, _ := NewSyslogDestination(SyslogConfig{
			Host:           "127.0.0.1",
			Port:           59999, // unlikely to be listening
			TimeoutSeconds: 1,
		})

		err := dest.Send(context.Background(), []*Event{event})
		if err == nil {
			t.Fatal("expected error for connection refused")
		}
		if !IsRetryable(err) {
			t.Errorf("connection error should be retryable: %v", err)
		}
	})

	t.Run("context canceled wraps error", func(t *testing.T) {
		// Start mock syslog server that blocks
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start listener: %v", err)
		}
		defer listener.Close()

		addr := listener.Addr().(*net.TCPAddr)

		// Accept but don't read - this will make write block eventually
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				// Hold connection open but don't read
				time.Sleep(2 * time.Second)
				conn.Close()
			}
		}()

		dest, _ := NewSyslogDestination(SyslogConfig{
			Host: "127.0.0.1",
			Port: addr.Port,
		})
		defer dest.Close()

		// Cancel context immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = dest.Send(ctx, []*Event{event})
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
		// Error should wrap context.Canceled so queue recognizes it
		if !strings.Contains(err.Error(), "canceled") {
			t.Errorf("error should mention cancellation: %v", err)
		}
		// Should NOT be retryable (queue will keep pending via context.Canceled check)
		if IsRetryable(err) {
			t.Errorf("canceled context should not be retryable: %v", err)
		}
	})
}

func TestSyslogFormatMessage(t *testing.T) {
	dest, _ := NewSyslogDestination(SyslogConfig{
		Host:     "syslog.example.com",
		Facility: "local0",
		AppName:  "basecheck",
	})

	event := &Event{
		Version:        EventVersion,
		EventType:      EventTypeCreated,
		EventTime:      time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
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
		FirstSeen:      time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		LastSeen:       time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		Source:         "control_audit",
	}

	msg, err := dest.formatMessage(event)
	if err != nil {
		t.Fatalf("formatMessage failed: %v", err)
	}

	msgStr := string(msg)

	// Check RFC 5424 structure
	// PRI for local0 (16) + error (3) = 16*8 + 3 = 131
	if !strings.HasPrefix(msgStr, "<131>1 ") {
		t.Errorf("expected PRI <131>1, got: %s", msgStr[:20])
	}

	// Check timestamp format
	if !strings.Contains(msgStr, "2026-06-15T12:00:00") {
		t.Errorf("expected RFC 5424 timestamp: %s", msgStr)
	}

	// Check app name
	if !strings.Contains(msgStr, "basecheck") {
		t.Errorf("expected app name: %s", msgStr)
	}

	// Check JSON payload
	if !strings.Contains(msgStr, `"finding_id":"find-123"`) {
		t.Errorf("expected JSON payload: %s", msgStr)
	}

	// Check newline termination
	if !strings.HasSuffix(msgStr, "\n") {
		t.Errorf("expected newline termination: %s", msgStr)
	}
}

func TestSyslogMapSeverity(t *testing.T) {
	dest := &SyslogDestination{}

	tests := []struct {
		severity string
		expected int
	}{
		{SeverityCritical, severityCritical},
		{SeverityHigh, severityError},
		{SeverityMedium, severityWarning},
		{SeverityLow, severityNotice},
		{SeverityInfo, severityInfo},
		{"unknown", severityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := dest.mapSeverity(tt.severity)
			if got != tt.expected {
				t.Errorf("mapSeverity(%s) = %d, want %d", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestSyslogClose(t *testing.T) {
	dest, _ := NewSyslogDestination(SyslogConfig{
		Host: "syslog.example.com",
	})

	// Close without connecting should be safe
	if err := dest.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be safe
	if err := dest.Close(); err != nil {
		t.Errorf("Double close failed: %v", err)
	}
}
