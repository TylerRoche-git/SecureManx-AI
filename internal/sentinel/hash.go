// Package sentinel provides self-integrity monitoring for the security-brain
// control plane. It detects binary tampering, policy file modifications, and
// pipeline behavioural anomalies through periodic verification checks.
package sentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// HashFile computes the SHA-256 hex digest of the file at the given path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashDir computes a combined SHA-256 of all files in a directory, sorted by
// name. It returns a single hex digest representing the directory's aggregate
// content. Sub-directories are traversed recursively; entries are sorted by
// their full relative path to ensure deterministic output.
func HashDir(dir string) (string, error) {
	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk %s: %w", dir, err)
	}

	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return "", fmt.Errorf("relative path for %s: %w", p, relErr)
		}
		// Include the relative path in the hash so that renaming a file
		// changes the digest even if the content stays the same.
		h.Write([]byte(rel))

		f, openErr := os.Open(p)
		if openErr != nil {
			return "", fmt.Errorf("open %s: %w", p, openErr)
		}
		if _, copyErr := io.Copy(h, f); copyErr != nil {
			f.Close()
			return "", fmt.Errorf("hash %s: %w", p, copyErr)
		}
		f.Close()
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashBytes computes the SHA-256 hex digest of raw bytes.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
