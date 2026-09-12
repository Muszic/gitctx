//go:build windows

package sshkey

// Windows cannot flush a directory through os.File.Sync. The generated key
// files themselves are flushed before their no-clobber hard-link publication.
func syncDirectory(string) error {
	return nil
}
