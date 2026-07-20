package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	data, err = expandEnvVars(data)
	if err != nil {
		return nil, fmt.Errorf("config env-var expansion failed: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// envVarPattern matches ${VAR_NAME} references, the substitution syntax
// documented in config.yaml.example (e.g. ${DB_PASSWORD}).
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnvVars replaces every ${VAR_NAME} reference in data with the value
// of the corresponding environment variable. Fails closed: a variable that
// is unset or set to an empty string is an error naming the variable, rather
// than silently substituting an empty/literal value (which would send a
// blank credential and cause a confusing downstream auth failure).
func expandEnvVars(data []byte) ([]byte, error) {
	var missing []string

	expanded := envVarPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		name := string(envVarPattern.FindSubmatch(match)[1])
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			missing = append(missing, name)
			return match
		}
		return []byte(value)
	})

	if len(missing) > 0 {
		return nil, fmt.Errorf("undefined or empty environment variable(s) referenced in config: %s",
			strings.Join(missing, ", "))
	}

	return expanded, nil
}
