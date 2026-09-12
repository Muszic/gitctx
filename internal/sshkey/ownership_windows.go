//go:build windows

package sshkey

import "os"

const posixPermissionChecks = false

func checkOwnedByCurrentUser(_ string, _ os.FileInfo) error {
	// Windows reports synthetic Unix ownership and mode bits. The CLI keeps the
	// remaining file, fingerprint, and no-clobber checks and warns that ACL
	// protection was not verified.
	return nil
}
