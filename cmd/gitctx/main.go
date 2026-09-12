package main

import (
	"os"

	"gitctx/internal/cli"
)

var version = "0.1.0"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
