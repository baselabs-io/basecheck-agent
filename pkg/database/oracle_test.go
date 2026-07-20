package database

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyReadOnlyModeErrorFailsClosedByDefault guards against a
// misconfigured or downgraded Oracle target silently losing its
// database-level read-only enforcement: when ALTER SESSION SET READ ONLY
// fails with ORA-02248 and the operator has not explicitly acknowledged
// query-guard-only enforcement, Connect must refuse rather than warn-and-continue.
func TestClassifyReadOnlyModeErrorFailsClosedByDefault(t *testing.T) {
	ora02248 := errors.New("ORA-02248: invalid option for ALTER SESSION")

	if err := classifyReadOnlyModeError(ora02248, false, "db.example.com"); err == nil {
		t.Fatal("expected ORA-02248 to fail closed when allowFallback is false")
	} else if !strings.Contains(err.Error(), "allow_read_only_fallback") {
		t.Fatalf("expected error to mention allow_read_only_fallback, got: %v", err)
	}
}

func TestClassifyReadOnlyModeErrorAllowsExplicitFallback(t *testing.T) {
	ora02248 := errors.New("ORA-02248: invalid option for ALTER SESSION")

	if err := classifyReadOnlyModeError(ora02248, true, "db.example.com"); err != nil {
		t.Fatalf("expected ORA-02248 to be tolerated when allowFallback is true, got: %v", err)
	}
}

func TestClassifyReadOnlyModeErrorAlwaysFailsOnOtherErrors(t *testing.T) {
	other := errors.New("ORA-01031: insufficient privileges")

	if err := classifyReadOnlyModeError(other, true, "db.example.com"); err == nil {
		t.Fatal("expected non-ORA-02248 errors to always be fatal, even with allowFallback true")
	}
}

func TestClassifyReadOnlyModeErrorNilIsNil(t *testing.T) {
	if err := classifyReadOnlyModeError(nil, false, "db.example.com"); err != nil {
		t.Fatalf("expected nil error to pass through as nil, got: %v", err)
	}
}
