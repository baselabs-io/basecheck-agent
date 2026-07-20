package logs

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCursorStoreSaveAndLoad(t *testing.T) {
	store := NewCursorStore(t.TempDir())
	now := time.Now().UTC().Truncate(time.Second)

	states := map[string]CursorState{
		"oracle-prod/alert-log": {
			SourceKey:     "oracle-prod/alert-log",
			DatabaseName:  "oracle-prod",
			SourceName:    "alert-log",
			Path:          "/var/log/oracle/alert.log",
			FileID:        "inode-123",
			Offset:        4096,
			LastReadTime:  now,
			LastEventTime: now,
			UpdatedAt:     now,
		},
	}

	if err := store.Save(states); err != nil {
		t.Fatalf("failed to save states: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load states: %v", err)
	}

	state, ok := loaded["oracle-prod/alert-log"]
	if !ok {
		t.Fatalf("expected cursor state to be loaded")
	}
	if state.Offset != 4096 {
		t.Fatalf("unexpected offset: %d", state.Offset)
	}
	if filepath.Base(store.FilePath()) != "cursors.json" {
		t.Fatalf("unexpected file path: %s", store.FilePath())
	}
}

func TestCursorStoreLoadMissingFile(t *testing.T) {
	store := NewCursorStore(t.TempDir())

	states, err := store.Load()
	if err != nil {
		t.Fatalf("expected missing file load to succeed: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("expected no states, got %d", len(states))
	}
}
