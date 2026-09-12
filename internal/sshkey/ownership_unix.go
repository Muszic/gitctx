//go:build !windows

package sshkey

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwnedByCurrentUser(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect owner of SSH key %s: unsupported file metadata", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("SSH key %s is not owned by the current user", path)
	}
	return nil
}
