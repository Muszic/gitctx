package main

import (
	"os"

	"gitctx/internal/cli"
	"gitctx/internal/managedkey"
)

var version = "0.2.0"

func main() {
	if handled, code := managedkey.RunAskpass(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
