package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"basecheck-agent/pkg/controlset"
	"basecheck-agent/pkg/database"
)

func TestValidateSQLitePath_RejectsEmptyPath(t *testing.T) {
	tests := []string{
		"",
		"   ",
		"\t",
		"\n",
	}

	for _, path := range tests {
		err := validateSQLitePath(path)
		if err == nil {
			t.Fatalf("expected empty path to be rejected: %q", path)
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Fatalf("expected empty path error, got: %v", err)
		}
	}
}

func TestValidateSQLitePath_RejectsDirectoryTraversal(t *testing.T) {
	tests := []string{
		"../etc/passwd",
		"/var/data/../../../etc/passwd",
		"/home/user/../admin/data.db",
		"../../sensitive.db",
	}

	for _, path := range tests {
		err := validateSQLitePath(path)
		if err == nil {
			t.Fatalf("expected directory traversal to be rejected: %s", path)
		}
		if !strings.Contains(err.Error(), "directory traversal") {
			t.Fatalf("expected directory traversal error, got: %v", err)
		}
	}
}

func TestValidateSQLitePath_RejectsRelativePath(t *testing.T) {
	tests := []string{
		"data.db",
		"./data.db",
		"databases/production.db",
		"~/data.db",
	}

	for _, path := range tests {
		err := validateSQLitePath(path)
		if err == nil {
			t.Fatalf("expected relative path to be rejected: %s", path)
		}
		if !strings.Contains(err.Error(), "must be absolute") {
			t.Fatalf("expected absolute path error, got: %v", err)
		}
	}
}

func TestValidateSQLitePath_RejectsNonExistentFile(t *testing.T) {
	path := "/tmp/nonexistent-database-file-12345.db"
	err := validateSQLitePath(path)
	if err == nil {
		t.Fatalf("expected non-existent file to be rejected: %s", path)
	}
	if !strings.Contains(err.Error(), "not accessible") {
		t.Fatalf("expected file not accessible error, got: %v", err)
	}
}

func TestValidateSQLitePath_RejectsDirectory(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "sqlite-test-dir-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	err = validateSQLitePath(tmpDir)
	if err == nil {
		t.Fatalf("expected directory to be rejected: %s", tmpDir)
	}
	if !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("expected regular file error, got: %v", err)
	}
}

func TestValidateSQLitePath_AcceptsValidFile(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "sqlite-test-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Verify the file path is absolute
	absPath, err := filepath.Abs(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	err = validateSQLitePath(absPath)
	if err != nil {
		t.Fatalf("expected valid file to be accepted: %s, got error: %v", absPath, err)
	}
}

func TestValidateSQLitePath_RejectsSymlink(t *testing.T) {
	// Create a temporary file and symlink
	tmpFile, err := os.CreateTemp("", "sqlite-test-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	symlinkPath := tmpFile.Name() + ".link"
	if err := os.Symlink(tmpFile.Name(), symlinkPath); err != nil {
		t.Skip("symlink creation not supported on this system")
	}
	defer os.Remove(symlinkPath)

	err = validateSQLitePath(symlinkPath)
	if err == nil {
		t.Fatalf("expected symlink to be rejected: %s", symlinkPath)
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("expected symlink rejection error, got: %v", err)
	}
}

func TestCanDiscover_AllowsSupabaseRemoteHost(t *testing.T) {
	service := &DiscoveryService{}
	system := SystemToDiscover{
		Name: "supabase-prod",
		Type: "supabase",
		Credentials: []map[string]interface{}{
			{
				"host": "aws-1-ap-northeast-2.pooler.supabase.com",
			},
		},
	}

	if !service.CanDiscover(system, "lightsail-runner-01") {
		t.Fatalf("expected Supabase discovery to be allowed from external agent host")
	}
}

func TestExtractAttributes_AcceptsLowercaseKeys(t *testing.T) {
	service := &DiscoveryService{}

	results := []*controlset.ControlResult{
		{
			Procedures: []controlset.ProcedureResult{
				{
					Status: "PASS",
					Rows: []database.Row{
						{
							"attribute_name":  "DATABASE_NAME",
							"attribute_value": "postgres",
							"attribute_type":  "text",
							"category":        "Identity",
						},
					},
				},
			},
		},
	}

	attributes := service.extractAttributes(results)
	expected := []map[string]interface{}{
		{
			"name":     "DATABASE_NAME",
			"value":    "postgres",
			"type":     "text",
			"category": "Identity",
		},
	}

	if !reflect.DeepEqual(attributes, expected) {
		t.Fatalf("expected attributes %v, got %v", expected, attributes)
	}
}
