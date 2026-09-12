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

	info, err := os.Lstat(*source)
	if err != nil {
		return fmt.Errorf("inspect source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("archive source must be a regular file")
	}

	var create func(io.Writer, *os.File, os.FileInfo, string) error
	switch *format {
	case "tar.gz":
		create = createTarGzip
	case "zip":
		create = createZip
	default:
		return fmt.Errorf("unsupported archive format %q", *format)
	}

	in, err := os.Open(*source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	return writeOutput(*output, func(out io.Writer) error {
		return create(out, in, info, *name)
	})
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

func createTarGzip(dst io.Writer, src *os.File, info os.FileInfo, name string) error {
	gz, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gz.Header.ModTime = archiveTime
	gz.Header.OS = 255

	tw := tar.NewWriter(gz)
	header := &tar.Header{
		Name:     name,
		Mode:     0o755,
		Uid:      0,
		Gid:      0,
		Size:     info.Size(),
		ModTime:  archiveTime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatUSTAR,
	}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header: %w", err)
	}
	if _, err := io.Copy(tw, src); err != nil {
		return fmt.Errorf("write tar data: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

func createZip(dst io.Writer, src *os.File, _ os.FileInfo, name string) error {
	zw := zip.NewWriter(dst)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o755)
	header.SetModTime(archiveTime)

	entry, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("write zip header: %w", err)
	}
	if _, err := io.Copy(entry, src); err != nil {
		return fmt.Errorf("write zip data: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip writer: %w", err)
	}
	return nil
}
