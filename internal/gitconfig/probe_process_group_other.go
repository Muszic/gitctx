//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package gitconfig

import "os/exec"

// Windows builds remain experimental. CommandContext still terminates Git on
// timeout there, while supported Unix targets additionally terminate the SSH
// process group.
func configureProbeProcessGroup(_ *exec.Cmd) {}
