package oracle

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
	"time"

	"basecheck-agent/pkg/logs"
)

var (
	timestampPattern = regexp.MustCompile(`^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$`)
	codePattern      = regexp.MustCompile(`(ORA-\d{4,5}|TNS-\d{4,5})`)
	spacePattern     = regexp.MustCompile(`\s+`)
)

const oracleTimestampLayout = "Mon Jan 2 15:04:05 2006"

// Parser parses Oracle alert.log content into normalized events.
type Parser struct {
	MaxExcerptBytes int
}

// Parse reads alert.log content and emits multiline Oracle events.
func (p *Parser) Parse(r io.Reader, source logs.Source) ([]logs.Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var events []logs.Event
	var lines []string

	flush := func() {
		if len(lines) == 0 {
			return
		}
		event := buildEvent(lines, source, p.MaxExcerptBytes)
		if event.Message != "" || event.RawExcerpt != "" {
			events = append(events, event)
		}
		lines = nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if isTimestampLine(line) {
			flush()
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	flush()

	return events, nil
}

func isTimestampLine(line string) bool {
	return timestampPattern.MatchString(strings.TrimSpace(line))
}

func buildEvent(lines []string, source logs.Source, maxExcerptBytes int) logs.Event {
	raw := strings.Join(lines, "\n")
	excerpt := raw
	truncated := false
	if maxExcerptBytes > 0 && len(excerpt) > maxExcerptBytes {
		excerpt = excerpt[:maxExcerptBytes]
		truncated = true
	}

	var eventTime time.Time
	if isTimestampLine(lines[0]) {
		eventTime, _ = time.Parse(oracleTimestampLayout, strings.TrimSpace(lines[0]))
	}

	code := ""
	if match := codePattern.FindStringSubmatch(raw); len(match) > 1 {
		code = match[1]
	}

	message := firstMessageLine(lines)

	return logs.Event{
		SourceKey:           source.DatabaseName + "/" + source.Name,
		DatabaseName:        source.DatabaseName,
		DatabaseType:        source.DatabaseType,
		SourceName:          source.Name,
		SourceType:          source.Type,
		SourcePath:          source.Path,
		EventTime:           eventTime.UTC(),
		Severity:            classifySeverity(code),
		Code:                code,
		Category:            classifyCategory(code),
		Message:             message,
		RawExcerpt:          excerpt,
		RawExcerptTruncated: truncated,
		LineCount:           len(lines),
		ByteCount:           len(raw),
		Fingerprint:         buildFingerprint(code, message),
	}
}

func firstMessageLine(lines []string) string {
	for i, line := range lines {
		if i == 0 && isTimestampLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func classifySeverity(code string) string {
	switch {
	case strings.HasPrefix(code, "ORA-00600"), strings.HasPrefix(code, "ORA-07445"):
		return "critical"
	case strings.HasPrefix(code, "ORA-"), strings.HasPrefix(code, "TNS-"):
		return "high"
	default:
		return "info"
	}
}

func classifyCategory(code string) string {
	switch {
	case strings.HasPrefix(code, "TNS-"):
		return "listener_network"
	case strings.HasPrefix(code, "ORA-00060"):
		return "deadlock"
	case strings.HasPrefix(code, "ORA-01555"):
		return "undo_pressure"
	case strings.HasPrefix(code, "ORA-04031"):
		return "memory_pressure"
	case strings.HasPrefix(code, "ORA-00257"), strings.HasPrefix(code, "ORA-19809"), strings.HasPrefix(code, "ORA-19815"):
		return "storage_capacity"
	case strings.HasPrefix(code, "ORA-1691"), strings.HasPrefix(code, "ORA-01653"), strings.HasPrefix(code, "ORA-01654"):
		return "storage_capacity"
	case strings.HasPrefix(code, "ORA-00600"), strings.HasPrefix(code, "ORA-07445"):
		return "internal_error"
	case strings.HasPrefix(code, "ORA-"):
		return "database_error"
	default:
		return "informational"
	}
}

func buildFingerprint(code, message string) string {
	normalized := strings.TrimSpace(spacePattern.ReplaceAllString(strings.ToUpper(code+" "+message), " "))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
