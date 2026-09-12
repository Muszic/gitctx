//go:build ignore

// fileops.go provides exact-path file operations for the install scripts.
// BSD mv/ln treat a destination symlink-to-directory as a container, which is
// unsafe for a transaction whose final filename must never be retargeted.
package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		fail(errors.New("usage: fileops <link-new|move-new> <source> <destination>"))
	}

	operation, source, destination := os.Args[1], os.Args[2], os.Args[3]
	info, err := os.Lstat(source)
	if err != nil {
		fail(fmt.Errorf("inspect source: %w", err))
	}
	if !info.Mode().IsRegular() {
		fail(errors.New("source must be a regular file"))
	}
	if _, err := os.Lstat(destination); err == nil {
		fail(errors.New("destination already exists"))
	} else if !errors.Is(err, os.ErrNotExist) {
		fail(fmt.Errorf("inspect destination: %w", err))
	}

	switch operation {
	case "link-new":
		if err := os.Link(source, destination); err != nil {
			fail(fmt.Errorf("link destination: %w", err))
		}
	case "move-new":
		if err := os.Link(source, destination); err != nil {
			fail(fmt.Errorf("link destination: %w", err))
		}
		if err := os.Remove(source); err != nil {
			if cleanupErr := os.Remove(destination); cleanupErr != nil {
				fail(fmt.Errorf("remove source: %w (also could not roll back destination: %v)", err, cleanupErr))
			}
			fail(fmt.Errorf("remove source: %w", err))
		}
	default:
		fail(fmt.Errorf("unknown operation %q", operation))
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "gitctx file operation: %v\n", err)
	os.Exit(1)
}
