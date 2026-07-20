package logs

import "time"

// Source describes a configured log source bound to a database.
type Source struct {
	DatabaseName  string
	DatabaseType  string
	Name          string
	Type          string
	Path          string
	Enabled       bool
	MultilineMode string
	Timezone      string
}

// CursorState tracks the reader position for a log source.
type CursorState struct {
	SourceKey     string    `json:"source_key"`
	DatabaseName  string    `json:"database_name"`
	SourceName    string    `json:"source_name"`
	Path          string    `json:"path"`
	FileID        string    `json:"file_id,omitempty"`
	Offset        int64     `json:"offset"`
	LastEventTime time.Time `json:"last_event_time,omitempty"`
	LastReadTime  time.Time `json:"last_read_time,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Event is a normalized log event emitted by a database-specific parser.
type Event struct {
	SourceKey           string    `json:"source_key"`
	DatabaseName        string    `json:"database_name"`
	DatabaseType        string    `json:"database_type"`
	SourceName          string    `json:"source_name"`
	SourceType          string    `json:"source_type"`
	SourcePath          string    `json:"source_path"`
	EventTime           time.Time `json:"event_time"`
	Severity            string    `json:"severity"`
	Code                string    `json:"code,omitempty"`
	Category            string    `json:"category,omitempty"`
	Message             string    `json:"message"`
	RawExcerpt          string    `json:"raw_excerpt"`
	RawExcerptTruncated bool      `json:"raw_excerpt_truncated"`
	LineCount           int       `json:"line_count"`
	ByteCount           int       `json:"byte_count"`
	Fingerprint         string    `json:"fingerprint"`
}
