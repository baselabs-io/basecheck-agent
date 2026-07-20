package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogDestination delivers SIEM events via syslog (RFC 5424).
type SyslogDestination struct {
	mu       sync.Mutex
	host     string
	port     int
	protocol string
	facility int
	appName  string
	hostname string
	conn     net.Conn
	timeout  time.Duration
}

// SyslogConfig contains syslog destination settings.
type SyslogConfig struct {
	Host           string
	Port           int
	Protocol       string // tcp, udp
	Facility       string // local0-local7, user, daemon, etc.
	AppName        string
	TimeoutSeconds int
}

// Syslog facilities (RFC 5424)
var facilityMap = map[string]int{
	"kern":     0,
	"user":     1,
	"mail":     2,
	"daemon":   3,
	"auth":     4,
	"syslog":   5,
	"lpr":      6,
	"news":     7,
	"uucp":     8,
	"cron":     9,
	"authpriv": 10,
	"ftp":      11,
	"local0":   16,
	"local1":   17,
	"local2":   18,
	"local3":   19,
	"local4":   20,
	"local5":   21,
	"local6":   22,
	"local7":   23,
}

// Syslog severity levels (RFC 5424)
const (
	severityEmergency = 0
	severityAlert     = 1
	severityCritical  = 2
	severityError     = 3
	severityWarning   = 4
	severityNotice    = 5
	severityInfo      = 6
	severityDebug     = 7
)

// NewSyslogDestination creates a new syslog destination.
func NewSyslogDestination(cfg SyslogConfig) (*SyslogDestination, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return nil, fmt.Errorf("syslog host is required")
	}

	port := cfg.Port
	if port < 0 {
		return nil, fmt.Errorf("invalid syslog port: %d", port)
	}
	if port == 0 {
		port = 514
	}
	if port > 65535 {
		return nil, fmt.Errorf("invalid syslog port: %d", port)
	}

	protocol := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, fmt.Errorf("syslog protocol must be tcp or udp, got %q", cfg.Protocol)
	}

	facility := facilityMap["local0"] // default
	facilityStr := strings.TrimSpace(cfg.Facility)
	if facilityStr != "" {
		f, ok := facilityMap[strings.ToLower(facilityStr)]
		if !ok {
			return nil, fmt.Errorf("unknown syslog facility: %q", cfg.Facility)
		}
		facility = f
	}

	appName := strings.TrimSpace(cfg.AppName)
	if appName == "" {
		appName = "basecheck"
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &SyslogDestination{
		host:     host,
		port:     port,
		protocol: protocol,
		facility: facility,
		appName:  appName,
		hostname: hostname,
		timeout:  timeout,
	}, nil
}

// Send delivers events to the syslog server.
func (s *SyslogDestination) Send(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	// Format all messages first - fail batch if any fail to format.
	// Formatting errors are surfaced as permanent errors.
	// Single formatting error fails entire batch for dead-letter (MVP design).
	messages := make([][]byte, len(events))
	for i, event := range events {
		msg, err := s.formatMessage(event)
		if err != nil {
			// Formatting error is permanent - fail the batch for dead-letter
			return fmt.Errorf("format event %s: %w", event.FindingID, err)
		}
		messages[i] = msg
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure connection
	if err := s.ensureConnection(); err != nil {
		return NewRetryableError(fmt.Errorf("syslog connect: %w", err))
	}

	for _, msg := range messages {
		select {
		case <-ctx.Done():
			// Context canceled - wrap error so queue keeps events pending
			return fmt.Errorf("syslog send canceled: %w", ctx.Err())
		default:
		}

		if err := s.sendMessage(msg); err != nil {
			// Connection error - close and mark retryable
			s.closeConnection()
			return NewRetryableError(fmt.Errorf("syslog send: %w", err))
		}
	}

	return nil
}

// ensureConnection establishes connection if not already connected.
func (s *SyslogDestination) ensureConnection() error {
	if s.conn != nil {
		return nil
	}

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	conn, err := net.DialTimeout(s.protocol, addr, s.timeout)
	if err != nil {
		return err
	}

	s.conn = conn
	return nil
}

// sendMessage sends a formatted syslog message.
func (s *SyslogDestination) sendMessage(msg []byte) error {
	if s.conn == nil {
		return fmt.Errorf("not connected")
	}

	s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	n, err := s.conn.Write(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(msg))
	}
	return nil
}

// closeConnection closes the current connection.
func (s *SyslogDestination) closeConnection() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// formatMessage creates an RFC 5424 syslog message with JSON payload.
func (s *SyslogDestination) formatMessage(event *Event) ([]byte, error) {
	// Map event severity to syslog severity
	syslogSeverity := s.mapSeverity(event.Severity)

	// Calculate PRI: facility * 8 + severity
	pri := s.facility*8 + syslogSeverity

	// RFC 5424 timestamp format
	timestamp := event.EventTime.UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	// JSON payload
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}

	// RFC 5424 format:
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	// PROCID, MSGID, STRUCTURED-DATA set to "-" (nil values per RFC 5424)
	msg := fmt.Sprintf("<%d>1 %s %s %s - - - %s\n",
		pri,
		timestamp,
		s.hostname,
		s.appName,
		string(payload),
	)

	return []byte(msg), nil
}

// mapSeverity converts SIEM severity to syslog severity.
func (s *SyslogDestination) mapSeverity(severity string) int {
	switch strings.ToUpper(severity) {
	case SeverityCritical:
		return severityCritical
	case SeverityHigh:
		return severityError
	case SeverityMedium:
		return severityWarning
	case SeverityLow:
		return severityNotice
	case SeverityInfo:
		return severityInfo
	default:
		return severityInfo
	}
}

// Close releases resources.
func (s *SyslogDestination) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeConnection()
	return nil
}

// Ensure SyslogDestination implements Destination.
var _ Destination = (*SyslogDestination)(nil)
