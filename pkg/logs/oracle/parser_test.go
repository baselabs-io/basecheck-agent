package oracle

import (
	"strings"
	"testing"

	"basecheck-agent/pkg/logs"
)

func TestParseMultilineOracleAlertLog(t *testing.T) {
	parser := Parser{MaxExcerptBytes: 1024}
	source := logs.Source{
		DatabaseName:  "oracle-prod",
		DatabaseType:  "oracle",
		Name:          "alert-log",
		Type:          "oracle_alert_log",
		Path:          "/var/log/oracle/alert.log",
		Enabled:       true,
		MultilineMode: "timestamp",
	}

	input := strings.NewReader(`Thu Mar 14 10:12:33 2026
Errors in file /u01/diag/rdbms/trace/ora_123.trc:
ORA-1691: unable to extend lob segment
Additional detail line
Thu Mar 14 10:15:01 2026
TNS-12543: TNS:destination host unreachable
Listener refused connection`)

	events, err := parser.Parse(input, source)
	if err != nil {
		t.Fatalf("failed to parse alert log: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Code != "ORA-1691" {
		t.Fatalf("unexpected first code: %s", events[0].Code)
	}
	if events[0].Category != "storage_capacity" {
		t.Fatalf("unexpected first category: %s", events[0].Category)
	}
	if events[0].LineCount != 4 {
		t.Fatalf("unexpected first line count: %d", events[0].LineCount)
	}
	if !strings.Contains(events[0].RawExcerpt, "Additional detail line") {
		t.Fatalf("expected multiline excerpt to include detail lines")
	}
	if events[1].Code != "TNS-12543" {
		t.Fatalf("unexpected second code: %s", events[1].Code)
	}
	if events[1].Category != "listener_network" {
		t.Fatalf("unexpected second category: %s", events[1].Category)
	}
}

func TestParseOracleAlertLogTruncatesExcerpt(t *testing.T) {
	parser := Parser{MaxExcerptBytes: 32}
	source := logs.Source{
		DatabaseName: "oracle-prod",
		DatabaseType: "oracle",
		Name:         "alert-log",
		Type:         "oracle_alert_log",
		Path:         "/var/log/oracle/alert.log",
	}

	input := strings.NewReader(`Thu Mar 14 10:12:33 2026
ORA-00600: internal error code
Stack line 1
Stack line 2`)

	events, err := parser.Parse(input, source)
	if err != nil {
		t.Fatalf("failed to parse alert log: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].RawExcerptTruncated {
		t.Fatalf("expected excerpt to be truncated")
	}
	if events[0].Severity != "critical" {
		t.Fatalf("unexpected severity: %s", events[0].Severity)
	}
}

func TestParseOracleAlertLogClassifiesSpecificDatabaseErrors(t *testing.T) {
	parser := Parser{MaxExcerptBytes: 1024}
	source := logs.Source{
		DatabaseName: "oracle-prod",
		DatabaseType: "oracle",
		Name:         "alert-log",
		Type:         "oracle_alert_log",
		Path:         "/var/log/oracle/alert.log",
	}

	input := strings.NewReader(`Thu Mar 14 10:12:33 2026
ORA-00060: deadlock detected while waiting for resource
Thu Mar 14 10:15:01 2026
ORA-01555: snapshot too old: rollback segment number with name too small
Thu Mar 14 10:16:01 2026
ORA-04031: unable to allocate 4096 bytes of shared memory
Thu Mar 14 10:17:01 2026
ORA-00257: archiver error. Connect internal only, until freed.
`)

	events, err := parser.Parse(input, source)
	if err != nil {
		t.Fatalf("failed to parse alert log: %v", err)
	}

	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	if events[0].Category != "deadlock" {
		t.Fatalf("unexpected deadlock category: %s", events[0].Category)
	}
	if events[1].Category != "undo_pressure" {
		t.Fatalf("unexpected undo category: %s", events[1].Category)
	}
	if events[2].Category != "memory_pressure" {
		t.Fatalf("unexpected memory category: %s", events[2].Category)
	}
	if events[3].Category != "storage_capacity" {
		t.Fatalf("unexpected storage category: %s", events[3].Category)
	}
}
