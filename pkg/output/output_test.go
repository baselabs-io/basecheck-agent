package output

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteResultsStdout(t *testing.T) {
	cfg := Config{
		AgentName:  "test-agent",
		OutputMode: "stdout",
	}

	results := map[string]interface{}{
		"test": "data",
	}

	// Stdout mode doesn't error
	err := WriteResults(cfg, results, false)
	if err != nil {
		t.Errorf("WriteResults(stdout) failed: %v", err)
	}
}

func TestWriteResultsFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
	}{
		{
			name:     "directory path",
			filePath: t.TempDir() + "/",
		},
		{
			name:     "explicit file path",
			filePath: filepath.Join(t.TempDir(), "output.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				AgentName:  "test-agent",
				OutputMode: "file",
				FilePath:   tt.filePath,
			}

			results := map[string]interface{}{
				"test": "data",
			}

			err := WriteResults(cfg, results, false)
			if err != nil {
				t.Fatalf("WriteResults() failed: %v", err)
			}

			// Find the created file
			var files []string
			if strings.HasSuffix(tt.filePath, ".json") {
				files = []string{tt.filePath}
			} else {
				dir := strings.TrimRight(tt.filePath, "/")
				matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
				files = matches
			}

			if len(files) == 0 {
				t.Fatal("No output file created")
			}

			// Verify content
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatalf("Failed to read output file: %v", err)
			}

			var output map[string]interface{}
			if err := json.Unmarshal(data, &output); err != nil {
				t.Fatalf("Failed to parse output JSON: %v", err)
			}

			if output["agent"] == nil {
				t.Error("Output missing 'agent' field")
			}
			if output["databases"] == nil {
				t.Error("Output missing 'databases' field")
			}
		})
	}
}

func TestWriteResultsHTTPOnline(t *testing.T) {
	// Mock HTTP server
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}
		if r.Header.Get("X-Agent-Token") != "test-token" {
			t.Error("Expected X-Agent-Token header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		AgentName:   "test-agent",
		AgentToken:  "test-token",
		OutputMode:  "http",
		HTTPURL:     server.URL,
		HTTPTimeout: 5,
		AllowHTTP:   true,
	}

	results := map[string]interface{}{
		"test": "data",
	}

	err := WriteResults(cfg, results, false)
	if err != nil {
		t.Fatalf("WriteResults(http) failed: %v", err)
	}

	if !received {
		t.Error("HTTP request not sent")
	}
}

func TestWriteResultsHTTPOfflineQueues(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be sent in offline mode")
	}))
	defer server.Close()

	cfg := Config{
		AgentName:   "test-agent",
		OutputMode:  "http",
		HTTPURL:     server.URL,
		HTTPTimeout: 5,
		AllowHTTP:   true,
	}

	results := map[string]interface{}{
		"test": "data",
	}

	// Offline mode should queue
	err := WriteResults(cfg, results, true)
	if err != nil {
		t.Fatalf("WriteResults(offline) failed: %v", err)
	}

	// Verify queue file created
	files, err := filepath.Glob(filepath.Join(PendingDir, "*.json"))
	if err != nil {
		t.Fatalf("Failed to list queue files: %v", err)
	}
	if len(files) == 0 {
		t.Error("No queue file created in offline mode")
	}
}

func TestQueueResult(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	data := []byte(`{"test":"data"}`)

	file, err := QueueResult(data)
	if err != nil {
		t.Fatalf("QueueResult() failed: %v", err)
	}

	if !strings.Contains(file, PendingDir) {
		t.Errorf("Queue file not in correct directory: %s", file)
	}

	// Verify file exists
	if _, err := os.Stat(file); err != nil {
		t.Errorf("Queue file not created: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Failed to read queue file: %v", err)
	}
	if string(content) != string(data) {
		t.Error("Queue file content doesn't match")
	}
}

func TestQueueStats(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Empty queue
	count, size, err := QueueStats()
	if err != nil {
		t.Fatalf("QueueStats() failed: %v", err)
	}
	if count != 0 || size != 0 {
		t.Errorf("Expected empty queue, got %d files, %d bytes", count, size)
	}

	// Add some files
	data1 := []byte(`{"test":"data1"}`)
	data2 := []byte(`{"test":"data2"}`)

	if _, err := QueueResult(data1); err != nil {
		t.Fatalf("QueueResult(1) failed: %v", err)
	}
	if _, err := QueueResult(data2); err != nil {
		t.Fatalf("QueueResult(2) failed: %v", err)
	}

	count, size, err = QueueStats()
	if err != nil {
		t.Fatalf("QueueStats() failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 files, got %d", count)
	}
	expectedSize := int64(len(data1) + len(data2))
	if size != expectedSize {
		t.Errorf("Expected %d bytes, got %d", expectedSize, size)
	}
}

func TestQueueCapacity(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Fill queue to limit
	largeData := make([]byte, 1024*1024) // 1MB

	// Queue should accept files up to limit
	for i := 0; i < PendingMaxFiles; i++ {
		_, err := QueueResult(largeData)
		if err != nil {
			t.Fatalf("QueueResult(%d) failed: %v", i, err)
		}
	}

	// Next one should fail (file limit)
	_, err := QueueResult([]byte("test"))
	if err == nil {
		t.Error("QueueResult() should fail when file limit reached")
	}
	if !strings.Contains(err.Error(), "pending queue full") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestUploadPending(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Mock server
	uploadCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Queue some results
	data1 := []byte(`{"test":"data1"}`)
	data2 := []byte(`{"test":"data2"}`)

	if _, err := QueueResult(data1); err != nil {
		t.Fatalf("QueueResult(1) failed: %v", err)
	}
	if _, err := QueueResult(data2); err != nil {
		t.Fatalf("QueueResult(2) failed: %v", err)
	}

	// Upload
	err := UploadPending(server.URL, "test-token", true)
	if err != nil {
		t.Fatalf("UploadPending() failed: %v", err)
	}

	if uploadCount != 2 {
		t.Errorf("Expected 2 uploads, got %d", uploadCount)
	}

	// Queue should be empty now
	count, _, _ := QueueStats()
	if count != 0 {
		t.Errorf("Expected empty queue after upload, got %d files", count)
	}
}

func TestUploadPendingServerError(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Mock server that fails
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Queue some results
	if _, err := QueueResult([]byte(`{"test":"data"}`)); err != nil {
		t.Fatalf("QueueResult() failed: %v", err)
	}

	// Upload should stop on error
	err := UploadPending(server.URL, "test-token", true)
	if err != nil {
		t.Fatalf("UploadPending() failed: %v", err)
	}

	// File should still be in queue
	count, _, _ := QueueStats()
	if count != 1 {
		t.Errorf("Expected 1 file in queue after failed upload, got %d", count)
	}

	// Should have attempted once
	if attempts != 1 {
		t.Errorf("Expected 1 upload attempt, got %d", attempts)
	}
}

func TestUploadPendingNoURL(t *testing.T) {
	err := UploadPending("", "test-token", true)
	if err == nil {
		t.Error("UploadPending() should fail with empty URL")
	}
}

func TestUploadPendingRateLimiting(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Queue more than the per-run limit
	for i := 0; i < UploadMaxFilesPerRun+5; i++ {
		if _, err := QueueResult([]byte(`{"test":"data"}`)); err != nil {
			t.Fatalf("QueueResult(%d) failed: %v", i, err)
		}
	}

	// Upload should stop at limit
	err := UploadPending(server.URL, "test-token", true)
	if err != nil {
		t.Fatalf("UploadPending() failed: %v", err)
	}

	// Should have uploaded exactly the limit
	count, _, _ := QueueStats()
	expected := 5 // We queued (limit + 5), so 5 should remain
	if count != expected {
		t.Errorf("Expected %d files remaining, got %d", expected, count)
	}
}

func TestWriteResultsHTTPError(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	cfg := Config{
		AgentName:   "test-agent",
		OutputMode:  "http",
		HTTPURL:     server.URL,
		HTTPTimeout: 5,
		AllowHTTP:   true,
	}

	results := map[string]interface{}{
		"test": "data",
	}

	// Should queue on error
	err := WriteResults(cfg, results, false)
	if err != nil {
		t.Fatalf("WriteResults() should not error (should queue): %v", err)
	}

	// Should have queued the result
	count, _, _ := QueueStats()
	if count != 1 {
		t.Errorf("Expected 1 queued file, got %d", count)
	}
}
