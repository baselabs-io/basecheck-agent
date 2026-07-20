package siem

import (
	"errors"
	"fmt"
	"testing"
)

func TestRetryableError(t *testing.T) {
	baseErr := errors.New("connection refused")
	retryErr := NewRetryableError(baseErr)

	if retryErr.Error() != "connection refused" {
		t.Errorf("Error() = %q, want %q", retryErr.Error(), "connection refused")
	}

	if retryErr.Unwrap() != baseErr {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestRetryableErrorNilSafe(t *testing.T) {
	// Manually construct with nil to test Error() doesn't panic
	retryErr := &RetryableError{Err: nil}
	if retryErr.Error() != "retryable error" {
		t.Errorf("Error() with nil = %q, want %q", retryErr.Error(), "retryable error")
	}
}

func TestNewRetryableErrorPanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewRetryableError(nil) should panic")
		}
	}()
	NewRetryableError(nil)
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("permanent failure"),
			expected: false,
		},
		{
			name:     "retryable error",
			err:      NewRetryableError(errors.New("timeout")),
			expected: true,
		},
		{
			name:     "wrapped retryable error",
			err:      fmt.Errorf("webhook failed: %w", NewRetryableError(errors.New("timeout"))),
			expected: true,
		},
		{
			name:     "double wrapped retryable error",
			err:      fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", NewRetryableError(errors.New("timeout")))),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.expected {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDestinationConfigDefaults(t *testing.T) {
	cfg := DestinationConfig{}

	if cfg.GetTimeoutSeconds() != 30 {
		t.Errorf("GetTimeoutSeconds() = %d, want 30", cfg.GetTimeoutSeconds())
	}

	if cfg.GetBatchSize() != 100 {
		t.Errorf("GetBatchSize() = %d, want 100", cfg.GetBatchSize())
	}

	// With explicit values
	cfg2 := DestinationConfig{
		TimeoutSeconds: 60,
		BatchSize:      50,
	}

	if cfg2.GetTimeoutSeconds() != 60 {
		t.Errorf("GetTimeoutSeconds() = %d, want 60", cfg2.GetTimeoutSeconds())
	}

	if cfg2.GetBatchSize() != 50 {
		t.Errorf("GetBatchSize() = %d, want 50", cfg2.GetBatchSize())
	}
}
