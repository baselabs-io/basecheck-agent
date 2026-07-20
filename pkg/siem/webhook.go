package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// WebhookDestination delivers SIEM events via HTTP POST.
type WebhookDestination struct {
	url          string
	headers      map[string]string
	timeout      time.Duration
	agentVersion string
	client       *http.Client
}

// WebhookConfig contains webhook destination settings.
type WebhookConfig struct {
	URL            string
	Headers        map[string]string
	TimeoutSeconds int
	AgentVersion   string // For User-Agent header; falls back to "unknown" if empty
	AllowInsecure  bool   // Allow http:// URLs (should match security.allow_http)
}

// NewWebhookDestination creates a new webhook destination.
// Validates URL format and scheme (https required unless AllowInsecure is true).
func NewWebhookDestination(cfg WebhookConfig) (*WebhookDestination, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("webhook URL must use http or https scheme, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("webhook URL missing host")
	}
	if !cfg.AllowInsecure && parsed.Scheme == "http" {
		return nil, fmt.Errorf("webhook URL uses insecure http; set AllowInsecure to permit")
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	agentVersion := cfg.AgentVersion
	if agentVersion == "" {
		agentVersion = "unknown"
	}

	return &WebhookDestination{
		url:          cfg.URL,
		headers:      cfg.Headers,
		timeout:      timeout,
		agentVersion: agentVersion,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Send delivers events to the webhook endpoint.
// Returns RetryableError for transient failures (5xx, timeouts, connection errors).
// Returns permanent error for 4xx responses (except 429).
func (w *WebhookDestination) Send(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "basecheck-agent/"+w.agentVersion)

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		// Caller-initiated cancellation is not retryable (clean shutdown)
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("webhook request canceled: %w", err)
		}
		// Network errors, timeouts (DeadlineExceeded), DNS failures are retryable
		return NewRetryableError(fmt.Errorf("webhook request failed: %w", err))
	}
	defer resp.Body.Close()

	// Drain response body to enable connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	return w.classifyResponse(resp.StatusCode)
}

// classifyResponse determines if a status code indicates success, retryable, or permanent failure.
func (w *WebhookDestination) classifyResponse(statusCode int) error {
	switch {
	case statusCode >= 200 && statusCode < 300:
		// Success
		return nil

	case statusCode == 429:
		// Rate limited - retryable
		return NewRetryableError(fmt.Errorf("rate limited (429)"))

	case statusCode >= 500:
		// Server errors are retryable
		return NewRetryableError(fmt.Errorf("server error (%d)", statusCode))

	case statusCode >= 400:
		// Client errors are permanent (bad request, unauthorized, forbidden, not found)
		return fmt.Errorf("client error (%d)", statusCode)

	default:
		// Unexpected status codes (1xx, 3xx) - treat as permanent
		return fmt.Errorf("unexpected status code (%d)", statusCode)
	}
}

// Close releases resources. WebhookDestination has no persistent resources.
func (w *WebhookDestination) Close() error {
	return nil
}

// Ensure WebhookDestination implements Destination.
var _ Destination = (*WebhookDestination)(nil)
