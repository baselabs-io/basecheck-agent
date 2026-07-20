package logs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const cursorFileName = "cursors.json"

// CursorStore persists log reader cursors on disk.
type CursorStore struct {
	path string
}

// NewCursorStore creates a cursor store rooted at the provided state path.
func NewCursorStore(path string) *CursorStore {
	return &CursorStore{path: strings.TrimSpace(path)}
}

// FilePath returns the full cursor state file path.
func (s *CursorStore) FilePath() string {
	return filepath.Join(s.path, cursorFileName)
}

// Load reads the cursor state map from disk.
func (s *CursorStore) Load() (map[string]CursorState, error) {
	if strings.TrimSpace(s.path) == "" {
		return map[string]CursorState{}, nil
	}

	data, err := os.ReadFile(s.FilePath())
	if os.IsNotExist(err) {
		return map[string]CursorState{}, nil
	}
	if err != nil {
		return nil, err
	}

	var states map[string]CursorState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, err
	}
	if states == nil {
		return map[string]CursorState{}, nil
	}

	return states, nil
}

// Save writes the cursor state map to disk atomically.
func (s *CursorStore) Save(states map[string]CursorState) error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	if err := os.MkdirAll(s.path, 0o755); err != nil {
		return err
	}

	ordered := make(map[string]CursorState, len(states))
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ordered[key] = states[key]
	}

	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := s.FilePath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}

	return os.Rename(tmpPath, s.FilePath())
}
