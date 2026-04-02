// Package policy implements Stage 3 of the decision pipeline: deterministic
// policy evaluation using a hardcoded policy matrix, with future support for
// OPA/Rego-based policies.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PolicyFile represents a loaded policy file with its raw content and source path.
type PolicyFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// LoadPolicy reads a single Rego policy file from disk and returns its content.
// This is a forward-looking function for OPA integration; the MVP evaluator
// uses the hardcoded policy matrix instead.
func LoadPolicy(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}

	if !strings.HasSuffix(path, ".rego") {
		return nil, fmt.Errorf("policy file %s does not have .rego extension", path)
	}

	return &PolicyFile{
		Path:    path,
		Content: string(data),
	}, nil
}

// LoadPoliciesFromDir reads all .rego files from the given directory and returns
// their contents. Returns an empty slice (not an error) if the directory does
// not exist or contains no .rego files.
func LoadPoliciesFromDir(dir string) ([]*PolicyFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read policy directory %s: %w", dir, err)
	}

	var policies []*PolicyFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		pf, loadErr := LoadPolicy(filepath.Join(dir, entry.Name()))
		if loadErr != nil {
			return nil, loadErr
		}
		policies = append(policies, pf)
	}

	return policies, nil
}
