package managedkey

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const askpassArgument = "--gitctx-internal-askpass"
const askpassRequest = "gitctx-askpass-v1\n"
const askpassIOTimeout = 2 * time.Second

// RunAskpass handles only the private OpenSSH helper invocation. It never
// opens the OS vault, accepts a passphrase on argv/env, or prints diagnostics.
// The caller must run this before normal CLI dispatch.
func RunAskpass(args []string, output io.Writer) (handled bool, code int) {
	if len(args) == 0 || args[0] != askpassArgument {
		return false, 0
	}
	// The script deliberately drops OpenSSH's prompt argument. This worker
	// accepts only its private socket, never arbitrary extra CLI arguments.
	if len(args) != 2 || output == nil {
		return true, 1
	}
	socket := args[1]
	directory := filepath.Dir(socket)
	if !filepath.IsAbs(socket) || filepath.Base(socket) != "s" || !strings.HasPrefix(filepath.Base(directory), "gitctx-ap-") || protectedDirectory(directory) != nil {
		return true, 1
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 || checkOwner(info) != nil {
		return true, 1
	}
	connection, err := net.DialTimeout("unix", socket, askpassIOTimeout)
	if err != nil {
		return true, 1
	}
	defer connection.Close()
	if connection.SetDeadline(time.Now().Add(askpassIOTimeout)) != nil {
		return true, 1
	}
	if _, err := io.WriteString(connection, askpassRequest); err != nil {
		return true, 1
	}
	value, err := io.ReadAll(io.LimitReader(connection, 66))
	defer clear(value)
	if err != nil || len(value) != 65 || value[64] != '\n' || !validHex(string(value[:64]), 64) {
		return true, 1
	}
	if n, err := output.Write(value); err != nil || n != len(value) {
		return true, 1
	}
	return true, 0
}

// newAskpassRelay reuses an already approved passphrase through an owner-only
// Unix socket. The short-lived executable script contains only paths, never
// a secret. At most two reads are needed for keygen's enter/confirm prompts;
// ssh-add needs one. No passphrase is stored in a file, argv, or environment.
func newAskpassRelay(secret string, reads int) (string, func(), error) {
	if !validHex(secret, 64) || reads < 1 || reads > 2 {
		return "", nil, errors.New("invalid private askpass operation")
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return "", nil, errors.New("cannot locate the private gitctx askpass helper")
	}
	// Keep the socket path short enough for macOS, even when the config or
	// platform TMPDIR is long. MkdirTemp creates an unpredictable mode-0700
	// directory; the IPC file itself is mode 0600.
	directory, err := os.MkdirTemp("/tmp", "gitctx-ap-")
	if err != nil {
		return "", nil, errors.New("cannot create a private askpass directory")
	}
	remove := func() { _ = os.RemoveAll(directory) } // Only this freshly created operation directory.
	if err := protectedDirectory(directory); err != nil {
		remove()
		return "", nil, err
	}
	socket := filepath.Join(directory, "s")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		remove()
		return "", nil, errors.New("cannot open the private askpass channel")
	}
	helper := filepath.Join(directory, "askpass")
	script := "#!/bin/sh\nexec " + shellQuote(executable) + " " + askpassArgument + " " + shellQuote(socket) + "\n"
	if os.Chmod(socket, 0o600) != nil || os.WriteFile(helper, []byte(script), 0o700) != nil {
		listener.Close()
		remove()
		return "", nil, errors.New("cannot protect the private askpass channel")
	}
	value := []byte(secret + "\n")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clear(value)
		defer listener.Close()
		// Bound malformed requests as well as successful reads. The containing
		// directory already excludes other OS users.
		for attempts, served := 0, 0; attempts < reads+4 && served < reads; attempts++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			if relayPassphrase(connection, value) {
				served++
			}
		}
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			listener.Close()
			<-done
			remove()
		})
	}
	return helper, cleanup, nil
}

func relayPassphrase(connection net.Conn, value []byte) bool {
	defer connection.Close()
	if connection.SetDeadline(time.Now().Add(askpassIOTimeout)) != nil {
		return false
	}
	request := make([]byte, len(askpassRequest))
	if _, err := io.ReadFull(connection, request); err != nil || string(request) != askpassRequest {
		return false
	}
	_, err := connection.Write(value)
	return err == nil
}
