//go:build !windows

package managedkey

import (
	"errors"
	"os"
	"syscall"
)

func checkOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("the managed key directory is not owned by the current user")
	}
	return nil
}
