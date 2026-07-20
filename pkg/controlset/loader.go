package controlset

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadControlSet loads a control set from a YAML file
func LoadControlSet(path string) (*ControlSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read control set file: %w", err)
	}

	var set ControlSet
	if err := yaml.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("failed to parse control set YAML: %w", err)
	}

	// Basic validation
	if err := validateControlSet(&set); err != nil {
		return nil, fmt.Errorf("control set validation failed: %w", err)
	}

	return &set, nil
}

// validateControlSet performs basic validation
func validateControlSet(set *ControlSet) error {
	if set.Metadata.ControlSetID == "" {
		return fmt.Errorf("missing control_set_id")
	}

	if set.Metadata.DatabaseType == "" {
		return fmt.Errorf("missing database_type")
	}

	if len(set.Controls) == 0 {
		return fmt.Errorf("no controls defined")
	}

	// Validate each control
	for i, control := range set.Controls {
		if control.ControlID == "" {
			return fmt.Errorf("control[%d]: missing control_id", i)
		}
		if len(control.Procedures) == 0 {
			return fmt.Errorf("control[%d] '%s': missing procedures", i, control.ControlID)
		}
		for j, procedure := range control.Procedures {
			if procedure.ProcedureID == "" {
				return fmt.Errorf("control[%d] '%s' procedure[%d]: missing procedure_id", i, control.ControlID, j)
			}
			if procedure.Tests == "" {
				return fmt.Errorf("control[%d] '%s' procedure[%d] '%s': missing tests", i, control.ControlID, j, procedure.ProcedureID)
			}
			for k, criteria := range procedure.Criteria {
				if err := validateConditionSyntax(criteria.Condition); err != nil {
					return fmt.Errorf("control[%d] '%s' procedure[%d] '%s' criteria[%d]: invalid condition: %w",
						i, control.ControlID, j, procedure.ProcedureID, k, err)
				}
			}
		}
	}

	return nil
}
