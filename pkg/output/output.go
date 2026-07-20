// Package output handles result output to file, HTTP, and pending queue.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"basecheck-agent/pkg/security"
)

// Queue configuration constants.
const (
	PendingDir              = "results-pending"
	PendingMaxFiles         = 200
	PendingMaxTotalBytes    = 512 * 1024 * 1024 // 512 MB
	UploadMaxFilesPerRun    = 10
	UploadMaxBytesPerRun    = 50 * 1024 * 1024 // 50 MB
	UploadDelay             = 250 * time.Millisecond
)

// Config contains output configuration.
type Config struct {
	AgentName   string
	AgentToken  string
	AllowHTTP   bool
	OutputMode  string // "file", "http", or empty for stdout
	FilePath    string
	HTTPURL     string
	HTTPTimeout int
}

// WriteResults outputs results based on configuration.
// If offline is true and mode is "http", results are queued for later upload.
func WriteResults(cfg Config, results map[string]interface{}, offline bool) error {
	output := map[string]interface{}{
		"agent": map[string]string{
			"name": cfg.AgentName,
		},
		"databases":    results,
		"collected_at": time.Now(),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	switch cfg.OutputMode {
	case "file":
		return writeToFile(cfg.FilePath, cfg.AgentName, data)

	case "http":
		return writeToHTTP(cfg, data, offline)

	default:
		fmt.Println(string(data))
	}

	return nil
}

// writeToFile writes results to a file.
func writeToFile(filePath, agentName string, data []byte) error {
	if filePath == "" || filePath[len(filePath)-1] == '/' || filePath[len(filePath)-1] == '\\' {
		outputDir := filePath
		if outputDir == "" {
			outputDir = "output"
		}
		for len(outputDir) > 0 && (outputDir[len(outputDir)-1] == '/' || outputDir[len(outputDir)-1] == '\\') {
			outputDir = outputDir[:len(outputDir)-1]
		}
		if outputDir == "" {
			outputDir = "output"
		}

		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		filePath = filepath.Join(outputDir,
			fmt.Sprintf("basecheck-output-%s-%s.json", agentName, time.Now().Format("20060102-150405")))
	} else {
		outputDir := filepath.Dir(filePath)
		if outputDir != "" && outputDir != "." {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
		}
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	log.Printf("✓ Output written to %s", filePath)
	return nil
}

// writeToHTTP sends results to HTTP endpoint, queuing if offline or on error.
func writeToHTTP(cfg Config, data []byte, offline bool) error {
	if cfg.HTTPURL == "" {
		return fmt.Errorf("HTTP output mode requires URL configuration")
	}

	if err := security.ValidateHTTPS(cfg.HTTPURL, cfg.AllowHTTP); err != nil {
		return err
	}

	// Queue results if offline
	if offline {
		log.Printf("Offline mode - queuing results to %s/", PendingDir)
		pendingFile, err := QueueResult(data)
		if err != nil {
			return fmt.Errorf("failed to queue pending results: %w", err)
		}

		log.Printf("✓ Results queued: %s (will upload when online)", pendingFile)
		return nil
	}

	log.Printf("Sending data to %s...", cfg.HTTPURL)

	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 30
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("POST", cfg.HTTPURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if cfg.AgentToken != "" {
		req.Header.Set("X-Agent-Token", cfg.AgentToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		log.Printf("⚠ Failed to send results to backend: %v", err)
		log.Printf("Queuing results to %s/ for later upload...", PendingDir)

		pendingFile, queueErr := QueueResult(data)
		if queueErr != nil {
			return fmt.Errorf("failed to queue pending results: %w", queueErr)
		}

		log.Printf("✓ Results queued: %s (will retry on next run)", pendingFile)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		log.Printf("⚠ Backend returned status %d: %s", resp.StatusCode, string(body))
		log.Printf("Queuing results to %s/ for later upload...", PendingDir)

		pendingFile, queueErr := QueueResult(data)
		if queueErr != nil {
			return fmt.Errorf("failed to queue pending results: %w", queueErr)
		}

		log.Printf("✓ Results queued: %s (will retry on next run)", pendingFile)
		return nil
	}

	log.Printf("✓ Data sent successfully to backend")

	// Also write to file if configured as backup
	if cfg.FilePath != "" {
		if err := os.WriteFile(cfg.FilePath, data, 0600); err != nil {
			log.Printf("⚠ Warning: failed to write backup file: %v", err)
		}
	}

	return nil
}

// UploadPending uploads queued results to the backend.
func UploadPending(httpURL, agentToken string, allowHTTP bool) error {
	if httpURL == "" {
		return fmt.Errorf("output.http.url not configured - cannot upload pending results")
	}

	if err := security.ValidateHTTPS(httpURL, allowHTTP); err != nil {
		return err
	}

	if _, err := os.Stat(PendingDir); os.IsNotExist(err) {
		return nil
	}

	files, err := filepath.Glob(filepath.Join(PendingDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to list pending files: %w", err)
	}

	if len(files) == 0 {
		return nil
	}
	sort.Strings(files)

	log.Printf("Found %d pending results file(s), uploading...", len(files))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	successCount := 0
	attemptCount := 0
	var uploadedBytes int64

	for _, file := range files {
		if attemptCount >= UploadMaxFilesPerRun {
			log.Printf("Reached pending upload file limit (%d/%d), leaving remaining files for next run", attemptCount, len(files))
			break
		}

		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read pending file %s: %w", file, err)
		}
		fileSize := int64(len(data))

		if attemptCount > 0 && uploadedBytes+fileSize > UploadMaxBytesPerRun {
			log.Printf("Reached pending upload size limit (%d bytes), leaving remaining files for next run", UploadMaxBytesPerRun)
			break
		}
		attemptCount++

		req, err := http.NewRequest("POST", httpURL, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("failed to create request for %s: %w", file, err)
		}

		req.Header.Set("Content-Type", "application/json")
		if agentToken != "" {
			req.Header.Set("X-Agent-Token", agentToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			log.Printf("⚠ Stopping pending uploads on network error for %s: %v", file, err)
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := os.Remove(file); err != nil {
				log.Printf("⚠ Failed to delete %s: %v", file, err)
				break
			}
			successCount++
			uploadedBytes += fileSize
			log.Printf("✓ Uploaded and deleted: %s", filepath.Base(file))
			time.Sleep(UploadDelay)
		} else {
			log.Printf("⚠ Stopping pending uploads on backend error for %s: status %d, response: %s",
				filepath.Base(file), resp.StatusCode, string(body))
			break
		}
	}

	log.Printf("✓ Uploaded %d/%d pending results (attempted: %d, bytes: %d)",
		successCount, len(files), attemptCount, uploadedBytes)
	return nil
}

// QueueResult queues a result for later upload.
func QueueResult(data []byte) (string, error) {
	if err := os.MkdirAll(PendingDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create %s directory: %w", PendingDir, err)
	}

	if err := ensureQueueCapacity(int64(len(data))); err != nil {
		return "", err
	}

	now := time.Now().UTC()
	baseName := fmt.Sprintf("audit-%s-%d.json", now.Format("20060102-150405"), now.UnixNano())
	pendingFile := filepath.Join(PendingDir, baseName)
	tmpFile := pendingFile + ".tmp"

	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write pending temp file: %w", err)
	}
	if err := os.Rename(tmpFile, pendingFile); err != nil {
		_ = os.Remove(tmpFile)
		return "", fmt.Errorf("failed to finalize pending file: %w", err)
	}

	return pendingFile, nil
}

// ensureQueueCapacity checks that the queue has room for a new file.
func ensureQueueCapacity(nextFileSize int64) error {
	fileCount, totalSize, err := QueueStats()
	if err != nil {
		return fmt.Errorf("failed to inspect pending queue: %w", err)
	}

	if fileCount >= PendingMaxFiles {
		return fmt.Errorf("pending queue full: %d files (max %d) - refusing to queue new results", fileCount, PendingMaxFiles)
	}
	if totalSize+nextFileSize > PendingMaxTotalBytes {
		return fmt.Errorf("pending queue full: %d bytes + %d bytes exceeds max %d bytes - refusing to queue new results",
			totalSize, nextFileSize, PendingMaxTotalBytes)
	}

	return nil
}

// QueueStats returns the number of files and total size of the pending queue.
func QueueStats() (int, int64, error) {
	if _, err := os.Stat(PendingDir); os.IsNotExist(err) {
		return 0, 0, nil
	}

	files, err := filepath.Glob(filepath.Join(PendingDir, "*.json"))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list pending files: %w", err)
	}

	var totalSize int64
	for _, file := range files {
		info, statErr := os.Stat(file)
		if statErr != nil {
			return 0, 0, fmt.Errorf("failed to stat pending file %s: %w", file, statErr)
		}
		totalSize += info.Size()
	}

	return len(files), totalSize, nil
}
