//go:build windows

package sshkey

import "os"

func checkOwnedByCurrentUser(_ string, _ os.FileInfo) error {
	// Windows ACL validation remains outside the supported key-generation
	// security boundary. Callers should gate generation on supported platforms.
	return nil
}
