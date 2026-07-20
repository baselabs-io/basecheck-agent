package oracle

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"basecheck-agent/pkg/database"
)

type Resolver struct{}

func (Resolver) ResolveAlertLogPath(ctx context.Context, db database.Database, instanceName string) (string, error) {
	tracePath, err := lookupValue(ctx, db, "SELECT value FROM v$diag_info WHERE name = 'Diag Trace'")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(tracePath) == "" {
		tracePath, err = lookupValue(ctx, db, "SELECT value FROM v$parameter WHERE name = 'background_dump_dest'")
		if err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(tracePath) == "" {
		return "", fmt.Errorf("Oracle alert log autodiscovery failed: trace directory not found")
	}

	currentInstanceName := strings.TrimSpace(instanceName)
	if currentInstanceName == "" {
		return "", fmt.Errorf("Oracle alert log autodiscovery failed: instance name is empty")
	}

	return filepath.Join(strings.TrimSpace(tracePath), "alert_"+currentInstanceName+".log"), nil
}

func lookupValue(ctx context.Context, db database.Database, query string) (string, error) {
	rows, err := db.ExecuteQuery(ctx, query)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	if value, ok := rows[0]["VALUE"]; ok && value != nil {
		return fmt.Sprint(value), nil
	}
	return "", nil
}
