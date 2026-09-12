//go:build !darwin && !linux && !windows

package cli

import "os"

func isTerminalFile(*os.File) bool {
	return false
}
