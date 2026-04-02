package sentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile_ReturnsCorrectSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte("hello world")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile returned error: %v", err)
	}

	h := sha256.Sum256(content)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("HashFile = %s, want %s", got, want)
	}
}

func TestHashFile_ErrorOnMissingFile(t *testing.T) {
	_, err := HashFile("/nonexistent/path/file.bin")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile returned error: %v", err)
	}

	h := sha256.Sum256([]byte{})
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("HashFile(empty) = %s, want %s", got, want)
	}
}

func TestHashDir_DeterministicOutput(t *testing.T) {
	dir := t.TempDir()

	// Create files in non-alphabetical order.
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("beta"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}

	hash1, err := HashDir(dir)
	if err != nil {
		t.Fatalf("HashDir returned error: %v", err)
	}

	hash2, err := HashDir(dir)
	if err != nil {
		t.Fatalf("HashDir returned error on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("HashDir is non-deterministic: %s != %s", hash1, hash2)
	}
}

func TestHashDir_ChangesWhenFileModified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(path, []byte("version: 1"), 0644); err != nil {
		t.Fatal(err)
	}

	hashBefore, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("version: 2"), 0644); err != nil {
		t.Fatal(err)
	}

	hashAfter, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if hashBefore == hashAfter {
		t.Error("HashDir returned same hash after file modification")
	}
}

func TestHashDir_ChangesWhenFileAdded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}

	hashBefore, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte("gamma"), 0644); err != nil {
		t.Fatal(err)
	}

	hashAfter, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if hashBefore == hashAfter {
		t.Error("HashDir returned same hash after file addition")
	}
}

func TestHashDir_ChangesWhenFileRenamed(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	renamed := filepath.Join(dir, "renamed.txt")

	if err := os.WriteFile(original, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	hashBefore, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}

	hashAfter, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if hashBefore == hashAfter {
		t.Error("HashDir returned same hash after file rename (path is included in hash)")
	}
}

func TestHashDir_ErrorOnMissingDirectory(t *testing.T) {
	_, err := HashDir("/nonexistent/directory")
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestHashDir_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	hash, err := HashDir(dir)
	if err != nil {
		t.Fatalf("HashDir on empty dir returned error: %v", err)
	}

	// Empty directory should still produce a valid hash (of zero content).
	if hash == "" {
		t.Error("HashDir on empty dir returned empty string")
	}
}

func TestHashDir_RecursesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("deep content"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Error("HashDir returned empty string for directory with nested files")
	}
}

func TestHashBytes_ReturnsCorrectSHA256(t *testing.T) {
	data := []byte("test data")
	got := HashBytes(data)

	h := sha256.Sum256(data)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("HashBytes = %s, want %s", got, want)
	}
}

func TestHashBytes_EmptyInput(t *testing.T) {
	got := HashBytes([]byte{})

	h := sha256.Sum256([]byte{})
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("HashBytes(empty) = %s, want %s", got, want)
	}
}
