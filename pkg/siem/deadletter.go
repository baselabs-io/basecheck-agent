package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DeadLetter handles failed event storage for post-mortem analysis.
type DeadLetter struct {
	mu        sync.Mutex
	path      string
	maxSizeMB int
	file      *os.File
}

// DeadLetterConfig contains dead-letter file settings.
type DeadLetterConfig struct {
	Path      string
	MaxSizeMB int
}

// DeadLetterEntry represents a failed event with error context.
type DeadLetterEntry struct {
	Event     *Event    `json:"event"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// NewDeadLetter creates a new dead-letter handler.
func NewDeadLetter(cfg DeadLetterConfig) (*DeadLetter, error) {
	if cfg.Path == "" {
		cfg.Path = ".cache/siem-dead-letter.jsonl"
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create dead-letter directory: %w", err)
	}

	return &DeadLetter{
		path:      cfg.Path,
		maxSizeMB: cfg.MaxSizeMB,
	}, nil
}

// Write appends a failed event to the dead-letter file.
func (d *DeadLetter) Write(event *Event, err error) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check file size and rotate if needed
	if err := d.checkRotate(); err != nil {
		return fmt.Errorf("check rotate: %w", err)
	}

	// Open file in append mode
	if d.file == nil {
		f, err := os.OpenFile(d.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open dead-letter file: %w", err)
		}
		d.file = f
	}

	entry := DeadLetterEntry{
		Event:     event,
		Error:     err.Error(),
		Timestamp: time.Now().UTC(),
	}

	data, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		return fmt.Errorf("marshal entry: %w", marshalErr)
	}

	if _, writeErr := d.file.Write(append(data, '\n')); writeErr != nil {
		return fmt.Errorf("write entry: %w", writeErr)
	}

	return nil
}

// checkRotate rotates the dead-letter file if it exceeds max size.
func (d *DeadLetter) checkRotate() error {
	info, err := os.Stat(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	maxBytes := int64(d.maxSizeMB) * 1024 * 1024
	if info.Size() < maxBytes {
		return nil
	}

	// Close current file
	if d.file != nil {
		d.file.Close()
		d.file = nil
	}

	// Rotate: rename to .old (overwrites previous .old)
	oldPath := d.path + ".old"
	if err := os.Rename(d.path, oldPath); err != nil {
		return fmt.Errorf("rotate dead-letter: %w", err)
	}

	return nil
}

// Close closes the dead-letter file.
func (d *DeadLetter) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file != nil {
		err := d.file.Close()
		d.file = nil
		return err
	}
	return nil
}

// Count returns the number of entries in the dead-letter file.
// Expensive: reads entire file to count entries.
func (d *DeadLetter) Count() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	f, err := os.Open(d.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	count := 0
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var entry DeadLetterEntry
		if err := decoder.Decode(&entry); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}
