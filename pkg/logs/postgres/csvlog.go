// Package postgres provides PostgreSQL CSV audit log parsing.
package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// StateDir is the directory for storing CSV log state files.
	StateDir = ".cache/audit-logs"
	// DefaultMaxRows is the default maximum rows to process per run.
	DefaultMaxRows = 500
	// MaxRowsHardLimit is the absolute maximum rows allowed.
	MaxRowsHardLimit = 5000
)

// State tracks CSV log processing progress.
type State struct {
	SourcePath         string   `json:"source_path"`
	SourceFingerprint  string   `json:"source_fingerprint"`
	LastOffset         int64    `json:"last_offset"`
	LastLineNumber     int64    `json:"last_line_number"`
	LastEventTimestamp string   `json:"last_event_timestamp"`
	Headers            []string `json:"headers"`
}

// LeaseInfo contains backend lease information if available.
type LeaseInfo struct {
	LeaseToken  string
	SourceKey   string
	SourceMode  string
	LastOffset  int64
	LastLineNumber int64
	LastEventTimestamp string
	SourceFingerprint string
}

// CollectorConfig configures the CSV log collector.
type CollectorConfig struct {
	DatabaseName string
	DatabaseType string
	LogPath      string
	MaxRows      int
	DefaultDB    string // Fallback database name if not in log
}

// countingReader wraps a reader and counts bytes read.
type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

// Collect reads CSV log events from the configured path.
// Returns ingestion state, raw events, and any error.
func Collect(cfg CollectorConfig, lease *LeaseInfo) (map[string]interface{}, []map[string]interface{}, error) {
	logPath := strings.TrimSpace(cfg.LogPath)
	if logPath == "" {
		return nil, nil, nil
	}

	maxRows := cfg.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	if maxRows > MaxRowsHardLimit {
		maxRows = MaxRowsHardLimit
	}

	file, err := os.Open(logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat audit log file: %w", err)
	}
	fingerprint := BuildSourceFingerprint(fileInfo)

	state, statePath, err := LoadState(cfg.DatabaseName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load audit log state: %w", err)
	}

	// Reset state if log path changed
	if state.SourcePath != "" && state.SourcePath != logPath {
		state = &State{}
	}

	// Apply lease state if provided
	if lease != nil {
		state.LastOffset = lease.LastOffset
		state.LastLineNumber = lease.LastLineNumber
		state.LastEventTimestamp = lease.LastEventTimestamp
		state.SourceFingerprint = lease.SourceFingerprint
	}

	// Reset if file rotated (fingerprint changed)
	if state.SourceFingerprint != "" && state.SourceFingerprint != fingerprint {
		state.LastOffset = 0
		state.LastLineNumber = 0
		state.LastEventTimestamp = ""
		state.Headers = nil
	}

	// Reset if file truncated
	if state.LastOffset > fileInfo.Size() {
		state.LastOffset = 0
		state.LastLineNumber = 0
		state.LastEventTimestamp = ""
		state.Headers = nil
	}

	if _, err := file.Seek(state.LastOffset, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("failed to seek audit log file: %w", err)
	}

	counter := &countingReader{reader: file}
	csvReader := csv.NewReader(counter)
	csvReader.FieldsPerRecord = -1
	csvReader.LazyQuotes = true

	// Read headers if at start of file
	if state.LastOffset == 0 {
		headers, err := csvReader.Read()
		if err == io.EOF {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read csvlog header: %w", err)
		}
		state.Headers = headers
		state.LastOffset += counter.count
		counter.count = 0
	}

	lineNumber := state.LastLineNumber
	events := make([]map[string]interface{}, 0, maxRows)

	for len(events) < maxRows {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, events, fmt.Errorf("failed to read csvlog record: %w", err)
		}

		lineNumber++
		offset := state.LastOffset + counter.count

		event, timestamp := MapEvent(cfg, logPath, lineNumber, offset, state.Headers, record)
		events = append(events, event)

		state.LastOffset = offset
		state.LastLineNumber = lineNumber
		if timestamp != "" {
			state.LastEventTimestamp = timestamp
		}
	}

	state.SourcePath = logPath
	state.SourceFingerprint = fingerprint

	if err := SaveState(statePath, state); err != nil {
		return nil, events, fmt.Errorf("failed to save audit log state: %w", err)
	}

	ingestionState := map[string]interface{}{
		"DatabaseType":       cfg.DatabaseType,
		"DatabaseName":       cfg.DatabaseName,
		"SourceType":         "csvlog",
		"SourcePath":         state.SourcePath,
		"SourceFingerprint":  state.SourceFingerprint,
		"LastOffset":         state.LastOffset,
		"LastLineNumber":     state.LastLineNumber,
		"LastEventTimestamp": state.LastEventTimestamp,
		"Status":             "Active",
	}
	if lease != nil {
		ingestionState["LeaseToken"] = lease.LeaseToken
		ingestionState["SourceKey"] = lease.SourceKey
		ingestionState["SourceMode"] = lease.SourceMode
	}

	return ingestionState, events, nil
}

// MapEvent converts a CSV record to an event map.
func MapEvent(
	cfg CollectorConfig,
	logPath string,
	lineNumber int64,
	offset int64,
	headers []string,
	record []string,
) (map[string]interface{}, string) {
	parsed := make(map[string]interface{})
	normalized := make(map[string]string)

	for i, value := range record {
		fieldName := fmt.Sprintf("col_%d", i)
		if i < len(headers) {
			if h := strings.TrimSpace(headers[i]); h != "" {
				fieldName = h
			}
		}
		parsed[fieldName] = value
		normalized[strings.ToLower(fieldName)] = value
	}

	timestamp := strings.TrimSpace(normalized["log_time"])
	dbName := strings.TrimSpace(normalized["database_name"])
	if dbName == "" {
		dbName = cfg.DefaultDB
	}

	dbUser := strings.TrimSpace(normalized["user_name"])
	operation := strings.TrimSpace(normalized["command_tag"])
	query := strings.TrimSpace(normalized["query"])
	message := strings.TrimSpace(normalized["message"])
	severity := strings.TrimSpace(normalized["error_severity"])

	statement := query
	if statement == "" {
		statement = message
	}
	if operation == "" {
		operation = DetectOperation(statement)
	}

	rawRecord := FormatRecord(record)
	eventHash := HashEvent(logPath, lineNumber, rawRecord)

	return map[string]interface{}{
		"EventHash":        eventHash,
		"EventTimestamp":   timestamp,
		"DatabaseType":     cfg.DatabaseType,
		"DatabaseName":     dbName,
		"SourceType":       "csvlog",
		"SourcePath":       logPath,
		"SourceLineNumber": lineNumber,
		"SourceOffset":     offset,
		"Severity":         severity,
		"DatabaseUser":     dbUser,
		"Operation":        operation,
		"Statement":        statement,
		"RawRecord":        rawRecord,
		"ParsedRecord":     parsed,
		"IngestionStatus":  "New",
	}, timestamp
}

// DetectOperation infers the SQL operation from a statement.
func DetectOperation(statement string) string {
	upper := strings.ToUpper(strings.TrimSpace(statement))
	switch {
	case strings.HasPrefix(upper, "CREATE "):
		return "CREATE"
	case strings.HasPrefix(upper, "ALTER "):
		return "ALTER"
	case strings.HasPrefix(upper, "DROP "):
		return "DROP"
	case strings.HasPrefix(upper, "TRUNCATE "):
		return "TRUNCATE"
	case strings.HasPrefix(upper, "GRANT "):
		return "GRANT"
	case strings.HasPrefix(upper, "REVOKE "):
		return "REVOKE"
	case strings.HasPrefix(upper, "INSERT "):
		return "INSERT"
	case strings.HasPrefix(upper, "UPDATE "):
		return "UPDATE"
	case strings.HasPrefix(upper, "DELETE "):
		return "DELETE"
	case strings.HasPrefix(upper, "SELECT "):
		return "SELECT"
	default:
		return "OTHER"
	}
}

// FormatRecord converts a CSV record back to a string.
func FormatRecord(record []string) string {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	if err := w.Write(record); err != nil {
		return strings.Join(record, ",")
	}
	w.Flush()
	return strings.TrimSuffix(buf.String(), "\n")
}

// HashEvent generates a unique hash for a log event.
func HashEvent(logPath string, lineNumber int64, rawRecord string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", logPath, lineNumber, rawRecord)))
	return hex.EncodeToString(h[:])
}

// BuildSourceFingerprint creates a fingerprint from file info.
func BuildSourceFingerprint(info os.FileInfo) string {
	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().UnixNano())
}

// SanitizeFilePart sanitizes a string for use in a filename.
func SanitizeFilePart(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if s := b.String(); s != "" {
		return s
	}
	return "database"
}

// LoadState loads the CSV log state from disk.
func LoadState(dbName string) (*State, string, error) {
	stateFile := filepath.Join(StateDir, SanitizeFilePart(dbName)+".json")
	state := &State{}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return state, stateFile, nil
		}
		return nil, "", err
	}

	if err := json.Unmarshal(data, state); err != nil {
		return nil, "", err
	}

	return state, stateFile, nil
}

// SaveState saves the CSV log state to disk.
func SaveState(stateFile string, state *State) error {
	if err := os.MkdirAll(StateDir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, stateFile)
}
