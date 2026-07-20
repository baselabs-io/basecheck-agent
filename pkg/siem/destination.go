// Package siem provides SIEM event output for security findings.
package siem

import (
	"context"
	"errors"
	"io"
)

// Destination is the interface for SIEM event delivery targets.
// Implementations handle protocol-specific delivery (webhook, syslog, etc.).
type Destination interface {
	// Send delivers a batch of events to the destination.
	// Returns nil on success, or an error indicating delivery failure.
	// Implementations should return RetryableError for transient failures
	// that the queue should retry, or a permanent error to send to dead-letter.
	Send(ctx context.Context, events []*Event) error

	// Close releases any resources held by the destination.
	io.Closer
}

// RetryableError wraps an error to indicate the delivery failure is transient
// and the queue should retry delivery after backoff.
type RetryableError struct {
	Err error
}

func (e *RetryableError) Error() string {
	if e.Err == nil {
		return "retryable error"
	}
	return e.Err.Error()
}

func (e *RetryableError) Unwrap() error {
	return e.Err
}

// IsRetryable checks if an error indicates a transient failure that should be retried.
// Uses errors.As to detect RetryableError even when wrapped with context.
func IsRetryable(err error) bool {
	var retryable *RetryableError
	return errors.As(err, &retryable)
}

// NewRetryableError wraps an error to mark it as retryable.
// Panics if err is nil; use only for actual errors.
func NewRetryableError(err error) *RetryableError {
	if err == nil {
		panic("NewRetryableError called with nil error")
	}
	return &RetryableError{Err: err}
}

// DeliveryResult represents the outcome of a Send operation.
type DeliveryResult struct {
	// Delivered is the count of events successfully delivered.
	Delivered int

	// Failed is the count of events that failed delivery.
	Failed int

	// Retryable indicates if the failure is transient.
	Retryable bool

	// Error is the delivery error, if any.
	Error error
}

// DestinationConfig contains common configuration for all destinations.
type DestinationConfig struct {
	// Name identifies this destination for logging/metrics.
	Name string

	// BatchSize is the maximum number of events per Send call.
	// Zero means no limit.
	BatchSize int

	// TimeoutSeconds is the per-batch delivery timeout.
	TimeoutSeconds int
}

// GetTimeoutSeconds returns the timeout with a default of 30 seconds.
func (c *DestinationConfig) GetTimeoutSeconds() int {
	if c.TimeoutSeconds <= 0 {
		return 30
	}
	return c.TimeoutSeconds
}

// GetBatchSize returns the batch size with a default of 100.
func (c *DestinationConfig) GetBatchSize() int {
	if c.BatchSize <= 0 {
		return 100
	}
	return c.BatchSize
}
