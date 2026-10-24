//go:build ignore

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
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

func TestArchivesIncludeExecutableAndLicenseWithNormalizedModes(t *testing.T) {
	for _, format := range []string{"tar.gz", "zip"} {
		t.Run(format, func(t *testing.T) {
			directory := t.TempDir()
			binary, license, output := filepath.Join(directory, "binary"), filepath.Join(directory, "notice"), filepath.Join(directory, "release")
			if err := os.WriteFile(binary, []byte("binary fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(license, []byte("license fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"--source", binary, "--name", "gitctx", "--license", license, "--output", output, "--format", format}); err != nil {
				t.Fatal(err)
			}
			contents := map[string]string{}
			modes := map[string]os.FileMode{}
			if format == "tar.gz" {
				file, err := os.Open(output)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				gz, err := gzip.NewReader(file)
				if err != nil {
					t.Fatal(err)
				}
				defer gz.Close()
				reader := tar.NewReader(gz)
				for {
					header, err := reader.Next()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if header.Typeflag != tar.TypeReg || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(archiveTime) {
						t.Fatal("archive metadata is not normalized")
					}
					data, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					contents[header.Name], modes[header.Name] = string(data), os.FileMode(header.Mode)
				}
			} else {
				reader, err := zip.OpenReader(output)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				for _, file := range reader.File {
					entry, err := file.Open()
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(entry)
					entry.Close()
					if err != nil || !file.Modified.Equal(archiveTime) {
						t.Fatal("archive metadata or data is invalid")
					}
					contents[file.Name], modes[file.Name] = string(data), file.Mode().Perm()
				}
			}
			if len(contents) != 2 || contents["gitctx"] != "binary fixture" || contents["LICENSE"] != "license fixture" || modes["gitctx"] != 0o755 || modes["LICENSE"] != 0o644 {
				t.Fatal("archive must contain exactly the executable and readable, non-executable license")
			}
		})
	}
}

func TestArchiveRejectsUnsafeLicenseSource(t *testing.T) {
	directory := t.TempDir()
	binary, output := filepath.Join(directory, "binary"), filepath.Join(directory, "release")
	if err := os.WriteFile(binary, []byte("binary fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, license := range []string{directory, filepath.Join(directory, "missing")} {
		if err := run([]string{"--source", binary, "--name", "gitctx", "--license", license, "--output", output, "--format", "tar.gz"}); err == nil {
			t.Fatal("unsafe license source accepted")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("unsafe license source left an output archive")
		}
	}
}
