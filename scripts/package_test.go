//go:build ignore

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOutputRemovesPartialArchiveOnFailure(t *testing.T) {
	output := filepath.Join(t.TempDir(), "partial.tar.gz")
	wantErr := errors.New("injected archive failure")

	err := writeOutput(output, func(dst io.Writer) error {
		if _, writeErr := io.WriteString(dst, "partial archive bytes"); writeErr != nil {
			return writeErr
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("writeOutput error = %v, want %v", err, wantErr)
	}
	if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
		t.Fatalf("partial archive remains at %s; stat error = %v", output, statErr)
	}
}

func TestWriteOutputKeepsCompleteArchive(t *testing.T) {
	output := filepath.Join(t.TempDir(), "complete.tar.gz")
	const content = "complete archive bytes"

	if err := writeOutput(output, func(dst io.Writer) error {
		_, err := io.WriteString(dst, content)
		return err
	}); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read complete output: %v", err)
	}
	if string(got) != content {
		t.Fatalf("output = %q, want %q", got, content)
	}
}
