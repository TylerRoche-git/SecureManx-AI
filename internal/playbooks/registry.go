// Package playbooks manages playbook definitions and their execution against
// security incidents. It provides a registry for loading playbook definitions
// from YAML files or built-in defaults, and an executor for running them.
package playbooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// StepDefinition describes a single step within a playbook.
type StepDefinition struct {
	Name        string `json:"name" yaml:"name"`
	Action      string `json:"action" yaml:"action"`
	Description string `json:"description" yaml:"description"`
	Timeout     string `json:"timeout" yaml:"timeout"`
}

// PlaybookDefinition describes a complete playbook with its trigger conditions
// and ordered sequence of enforcement steps.
type PlaybookDefinition struct {
	ID      string           `json:"id" yaml:"id"`
	Name    string           `json:"name" yaml:"name"`
	Trigger TriggerCondition `json:"trigger" yaml:"trigger"`
	Steps   []StepDefinition `json:"steps" yaml:"steps"`
}

// TriggerCondition specifies when a playbook should be activated based on
// confidence thresholds and matching action types.
type TriggerCondition struct {
	MinConfidence float64  `json:"min_confidence" yaml:"min_confidence"`
	Actions       []string `json:"actions" yaml:"actions"`
}

// Registry holds playbook definitions indexed by their ID and provides lookup
// and listing operations.
type Registry struct {
	playbooks map[string]*PlaybookDefinition
}

// NewRegistry creates a Registry populated with playbook definitions. If the
// provided directory exists and contains .yaml or .yml files, those are loaded.
// If the directory does not exist, is empty, or is the empty string, the
// registry falls back to built-in default playbooks.
func NewRegistry(playbooksDir string) (*Registry, error) {
	r := &Registry{
		playbooks: make(map[string]*PlaybookDefinition),
	}

	loaded := false
	if playbooksDir != "" {
		pbs, err := loadFromDir(playbooksDir)
		if err != nil {
			return nil, fmt.Errorf("load playbooks from %s: %w", playbooksDir, err)
		}
		if len(pbs) > 0 {
			for _, pb := range pbs {
				r.playbooks[pb.ID] = pb
			}
			loaded = true
		}
	}

	if !loaded {
		for _, pb := range defaultPlaybooks() {
			r.playbooks[pb.ID] = pb
		}
	}

	return r, nil
}

// Get returns the playbook definition with the given ID. The second return
// value is false if no playbook with that ID is registered.
func (r *Registry) Get(id string) (*PlaybookDefinition, bool) {
	pb, ok := r.playbooks[id]
	return pb, ok
}

// List returns all registered playbook definitions as a slice.
func (r *Registry) List() []PlaybookDefinition {
	result := make([]PlaybookDefinition, 0, len(r.playbooks))
	for _, pb := range r.playbooks {
		result = append(result, *pb)
	}
	return result
}

// loadFromDir reads all .yaml and .yml files from the directory, unmarshalling
// each into a PlaybookDefinition. Returns nil (not an error) if the directory
// does not exist.
func loadFromDir(dir string) ([]*PlaybookDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read playbooks directory %s: %w", dir, err)
	}

	var playbooks []*PlaybookDefinition
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil {
			return nil, fmt.Errorf("read playbook file %s: %w", name, readErr)
		}

		var pb PlaybookDefinition
		if unmarshalErr := yaml.Unmarshal(data, &pb); unmarshalErr != nil {
			return nil, fmt.Errorf("parse playbook file %s: %w", name, unmarshalErr)
		}

		if pb.ID == "" {
			return nil, fmt.Errorf("playbook file %s is missing required 'id' field", name)
		}

		playbooks = append(playbooks, &pb)
	}

	return playbooks, nil
}

// defaultPlaybooks returns the built-in playbook definitions for the two core
// response patterns: network isolation and kill-and-replace.
func defaultPlaybooks() []*PlaybookDefinition {
	return []*PlaybookDefinition{
		{
			ID:   "isolate",
			Name: "Network Isolation",
			Trigger: TriggerCondition{
				MinConfidence: 0.3,
				Actions:       []string{"isolate", "block_egress"},
			},
			Steps: []StepDefinition{
				{
					Name:        "apply-network-policy",
					Action:      "isolate",
					Description: "Apply Kubernetes NetworkPolicy to deny all egress from the target workload",
					Timeout:     "30s",
				},
				{
					Name:        "verify-isolation",
					Action:      "detect_only",
					Description: "Verify network isolation by checking connectivity from the target",
					Timeout:     "15s",
				},
				{
					Name:        "notify-operator",
					Action:      "detect_only",
					Description: "Send notification to the security operations channel",
					Timeout:     "10s",
				},
			},
		},
		{
			ID:   "kill-replace",
			Name: "Kill and Replace",
			Trigger: TriggerCondition{
				MinConfidence: 0.7,
				Actions:       []string{"kill_replace", "quarantine"},
			},
			Steps: []StepDefinition{
				{
					Name:        "snapshot-state",
					Action:      "detect_only",
					Description: "Capture forensic snapshot of the target pod before termination",
					Timeout:     "30s",
				},
				{
					Name:        "kill-workload",
					Action:      "kill_replace",
					Description: "Terminate the compromised pod and let the controller spawn a clean replacement",
					Timeout:     "60s",
				},
				{
					Name:        "verify-replacement",
					Action:      "detect_only",
					Description: "Confirm the replacement pod is running and healthy",
					Timeout:     "30s",
				},
				{
					Name:        "revoke-credentials",
					Action:      "revoke_credentials",
					Description: "Rotate any credentials that were accessible to the compromised workload",
					Timeout:     "30s",
				},
			},
		},
	}
}
