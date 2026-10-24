//go:build ignore

// package.go creates release archives with normalized metadata. It is invoked
// by release.sh and intentionally excluded from normal package builds.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var archiveTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

type archiveEntry struct {
	name string
	file *os.File
	info os.FileInfo
	mode int64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "package release: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("package release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "binary to archive")
	name := flags.String("name", "", "binary name inside the archive")
	license := flags.String("license", "", "optional license file included as LICENSE")
	output := flags.String("output", "", "archive destination")
	format := flags.String("format", "", "archive format: tar.gz or zip")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 || *source == "" || *name == "" || *output == "" || *format == "" {
		return errors.New("source, name, output, and format are required")
	}
	if filepath.Base(*name) != *name || *name == "." || *name == ".." {
		return errors.New("archive entry name must be a base name")
	}

	var create func(io.Writer, []archiveEntry) error
	switch *format {
	case "tar.gz":
		create = createTarGzip
	case "zip":
		create = createZip
	default:
		return fmt.Errorf("unsupported archive format %q", *format)
	}

	binary, err := openEntry(*source, *name, 0o755)
	if err != nil {
		return err
	}
	defer binary.file.Close()
	entries := []archiveEntry{binary}
	if *license != "" {
		if *name == "LICENSE" {
			return errors.New("binary name conflicts with the license entry")
		}
		notice, err := openEntry(*license, "LICENSE", 0o644)
		if err != nil {
			return err
		}
		defer notice.file.Close()
		entries = append(entries, notice)
	}

	return writeOutput(*output, func(out io.Writer) error {
		return create(out, entries)
	})
}

func openEntry(path, name string, mode int64) (archiveEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return archiveEntry{}, fmt.Errorf("inspect archive source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return archiveEntry{}, errors.New("archive source must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return archiveEntry{}, fmt.Errorf("open archive source: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return archiveEntry{}, errors.New("archive source changed while opening")
	}
	return archiveEntry{name: name, file: file, info: opened, mode: mode}, nil
}

func writeOutput(output string, write func(io.Writer) error) (err error) {
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	complete := false
	defer func() {
		if closeErr := out.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close output: %w", closeErr)
			complete = false
		}
		if !complete {
			if removeErr := os.Remove(output); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
				err = fmt.Errorf("remove partial output: %w", removeErr)
			}
		}
	}()

	if err := write(out); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	complete = true
	return nil
}

func createTarGzip(dst io.Writer, entries []archiveEntry) error {
	gz, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gz.Header.ModTime = archiveTime
	gz.Header.OS = 255

	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Uid:      0,
			Gid:      0,
			Size:     entry.info.Size(),
			ModTime:  archiveTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header: %w", err)
		}
		if _, err := io.Copy(tw, entry.file); err != nil {
			return fmt.Errorf("write tar data: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

func createZip(dst io.Writer, entries []archiveEntry) error {
	zw := zip.NewWriter(dst)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(os.FileMode(entry.mode))
		header.SetModTime(archiveTime)
		file, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("write zip header: %w", err)
		}
		if _, err := io.Copy(file, entry.file); err != nil {
			return fmt.Errorf("write zip data: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip writer: %w", err)
	}
	return nil
}
