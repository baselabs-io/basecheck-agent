package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewWebhookDestination(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		dest, err := NewWebhookDestination(WebhookConfig{
			URL:            "https://example.com/events",
			TimeoutSeconds: 10,
			Headers:        map[string]string{"Authorization": "Bearer token"},
			AgentVersion:   "2.5.0",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest == nil {
			t.Fatal("expected non-nil destination")
		}
		if dest.agentVersion != "2.5.0" {
			t.Errorf("agentVersion = %q, want %q", dest.agentVersion, "2.5.0")
		}
	})

	t.Run("missing URL", func(t *testing.T) {
		_, err := NewWebhookDestination(WebhookConfig{})
		if err == nil {
			t.Fatal("expected error for missing URL")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := NewWebhookDestination(WebhookConfig{URL: "not-a-url"})
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})

	t.Run("ftp scheme rejected", func(t *testing.T) {
		_, err := NewWebhookDestination(WebhookConfig{URL: "ftp://example.com/events"})
		if err == nil {
			t.Fatal("expected error for ftp scheme")
		}
	})

	t.Run("http rejected without AllowInsecure", func(t *testing.T) {
		_, err := NewWebhookDestination(WebhookConfig{URL: "http://example.com/events"})
		if err == nil {
			t.Fatal("expected error for http without AllowInsecure")
		}
	})

	t.Run("http allowed with AllowInsecure", func(t *testing.T) {
		dest, err := NewWebhookDestination(WebhookConfig{
			URL:           "http://example.com/events",
			AllowInsecure: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest == nil {
			t.Fatal("expected non-nil destination")
		}
	})

	t.Run("missing host rejected", func(t *testing.T) {
		_, err := NewWebhookDestination(WebhookConfig{URL: "https:///path"})
		if err == nil {
			t.Fatal("expected error for missing host")
		}
	})

	t.Run("default timeout", func(t *testing.T) {
		dest, err := NewWebhookDestination(WebhookConfig{URL: "https://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest.timeout != 30*time.Second {
			t.Errorf("timeout = %v, want 30s", dest.timeout)
		}
	})

	t.Run("default agent version", func(t *testing.T) {
		dest, err := NewWebhookDestination(WebhookConfig{URL: "https://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dest.agentVersion != "unknown" {
			t.Errorf("agentVersion = %q, want %q", dest.agentVersion, "unknown")
		}
	})
}

func TestWebhookDestinationSend(t *testing.T) {
	events := []*Event{
		{
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
		},
	}

	t.Run("successful delivery", func(t *testing.T) {
		var receivedEvents []*Event
		var userAgent string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %s, want application/json", r.Header.Get("Content-Type"))
			}
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("Authorization header not set correctly")
			}
			userAgent = r.Header.Get("User-Agent")

			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedEvents)

			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{
			URL:           server.URL,
			Headers:       map[string]string{"Authorization": "Bearer secret"},
			AgentVersion:  "2.5.0",
			AllowInsecure: true,
		})

		err := dest.Send(context.Background(), events)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(receivedEvents) != 1 {
			t.Errorf("received %d events, want 1", len(receivedEvents))
		}

		if userAgent != "basecheck-agent/2.5.0" {
			t.Errorf("User-Agent = %q, want %q", userAgent, "basecheck-agent/2.5.0")
		}
	})

	t.Run("empty events", func(t *testing.T) {
		dest, _ := NewWebhookDestination(WebhookConfig{URL: "https://example.com"})
		err := dest.Send(context.Background(), []*Event{})
		if err != nil {
			t.Fatalf("empty events should succeed: %v", err)
		}
	})

	t.Run("server error is retryable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})
		err := dest.Send(context.Background(), events)

		if err == nil {
			t.Fatal("expected error for 500 response")
		}
		if !IsRetryable(err) {
			t.Errorf("500 error should be retryable: %v", err)
		}
	})

	t.Run("rate limit is retryable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})
		err := dest.Send(context.Background(), events)

		if err == nil {
			t.Fatal("expected error for 429 response")
		}
		if !IsRetryable(err) {
			t.Errorf("429 error should be retryable: %v", err)
		}
	})

	t.Run("client error is permanent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})
		err := dest.Send(context.Background(), events)

		if err == nil {
			t.Fatal("expected error for 400 response")
		}
		if IsRetryable(err) {
			t.Errorf("400 error should not be retryable: %v", err)
		}
	})

	t.Run("unauthorized is permanent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})
		err := dest.Send(context.Background(), events)

		if err == nil {
			t.Fatal("expected error for 401 response")
		}
		if IsRetryable(err) {
			t.Errorf("401 error should not be retryable: %v", err)
		}
	})

	t.Run("connection refused is retryable", func(t *testing.T) {
		dest, _ := NewWebhookDestination(WebhookConfig{
			URL:            "http://localhost:59999", // unlikely to be listening
			TimeoutSeconds: 1,
			AllowInsecure:  true,
		})
		err := dest.Send(context.Background(), events)

		if err == nil {
			t.Fatal("expected error for connection refused")
		}
		if !IsRetryable(err) {
			t.Errorf("connection error should be retryable: %v", err)
		}
	})

	t.Run("context deadline exceeded is retryable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := dest.Send(ctx, events)
		if err == nil {
			t.Fatal("expected error for timeout")
		}
		// DeadlineExceeded (timeout) is retryable
		if !IsRetryable(err) {
			t.Errorf("timeout should be retryable: %v", err)
		}
	})

	t.Run("context canceled is not retryable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(5 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		dest, _ := NewWebhookDestination(WebhookConfig{URL: server.URL, AllowInsecure: true})

		ctx, cancel := context.WithCancel(context.Background())
		// Cancel immediately to simulate clean shutdown
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := dest.Send(ctx, events)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
		// Caller-initiated cancellation is NOT retryable
		if IsRetryable(err) {
			t.Errorf("context.Canceled should not be retryable: %v", err)
		}
	})
}

func TestWebhookDestinationClose(t *testing.T) {
	dest, _ := NewWebhookDestination(WebhookConfig{URL: "https://example.com"})
	if err := dest.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestClassifyResponse(t *testing.T) {
	dest := &WebhookDestination{}

	tests := []struct {
		code      int
		wantErr   bool
		retryable bool
	}{
		{200, false, false},
		{201, false, false},
		{204, false, false},
		{400, true, false},
		{401, true, false},
		{403, true, false},
		{404, true, false},
		{429, true, true},
		{500, true, true},
		{502, true, true},
		{503, true, true},
		{504, true, true},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.code), func(t *testing.T) {
			err := dest.classifyResponse(tt.code)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %d", tt.code)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %d: %v", tt.code, err)
			}
			if tt.wantErr && IsRetryable(err) != tt.retryable {
				t.Errorf("retryable(%d) = %v, want %v", tt.code, IsRetryable(err), tt.retryable)
			}
		})
	}
}
