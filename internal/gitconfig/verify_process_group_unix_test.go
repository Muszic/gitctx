//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package gitconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVerifyRemoteAccessKillsChildProcessGroupOnTimeout(t *testing.T) {
	directory := t.TempDir()
	pidPath := filepath.Join(directory, "child-pid")
	wrapper := filepath.Join(directory, "git")
	script := `#!/bin/sh
trap '' HUP TERM
sleep 60 &
child=$!
printf '%s\n' "$child" > "$GITCTX_VERIFY_CHILD_PID"
wait "$child"
`
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GITCTX_VERIFY_CHILD_PID", pidPath)
	client := &Client{Env: os.Environ(), remoteVerificationTimeout: time.Second}
	err := client.VerifyRemoteAccess(t.TempDir(), "git@example.test:owner/repo.git", "ssh -F none")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("VerifyRemoteAccess error = %v, want timeout", err)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("verification child process %d remained alive after timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
