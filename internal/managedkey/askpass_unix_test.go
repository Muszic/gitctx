//go:build darwin || linux

package managedkey

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OpenSSH invokes this test executable through the same private helper used
// by the real CLI. No real OS vault is accessed by any of these tests.
func TestMain(m *testing.M) {
	if handled, code := RunAskpass(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestAskpassRelayIsPrivateBoundedAndEphemeral(t *testing.T) {
	secret := strings.Repeat("c", 64)
	helper, cleanup, err := newAskpassRelay(secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	directory := filepath.Dir(helper)
	socket := filepath.Join(directory, "s")
	for path, mode := range map[string]os.FileMode{directory: 0o700, helper: 0o700, socket: 0o600} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("private askpass paths have unsafe permissions")
		}
	}
	script, err := os.ReadFile(helper)
	if err != nil || strings.Contains(string(script), secret) || strings.Contains(string(script), "security ") || strings.Contains(string(script), "secret-tool ") {
		t.Fatal("helper exposed a secret or performed another OS vault read")
	}
	// A malformed IPC request must receive no secret and must not consume a
	// successful read from keygen's limited enter/confirm allowance.
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(connection, strings.Repeat("?", len(askpassRequest)))
	response, _ := io.ReadAll(io.LimitReader(connection, 66))
	connection.Close()
	if len(response) != 0 {
		t.Fatal("malformed IPC request received a passphrase")
	}
	for i := 0; i < 2; i++ {
		var output bytes.Buffer
		handled, code := RunAskpass([]string{askpassArgument, socket}, &output)
		if !handled || code != 0 || output.String() != secret+"\n" {
			t.Fatal("approved passphrase was not delivered through private IPC")
		}
	}
	var output bytes.Buffer
	if handled, code := RunAskpass([]string{askpassArgument, socket}, &output); !handled || code == 0 || output.Len() != 0 {
		t.Fatal("the relay served more than the permitted number of requests")
	}
	cleanup()
	cleanup() // Cleanup is safe after normal completion and on repeated errors.
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("askpass channel was not removed after its operation")
	}
}

func TestAskpassWorkerRejectsMalformedSecretResponses(t *testing.T) {
	for _, response := range []string{"diagnostic data must not be printed", strings.Repeat("g", 64) + "\n", strings.Repeat("b", 65) + "\n"} {
		directory, err := os.MkdirTemp("/tmp", "gitctx-ap-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		socket := filepath.Join(directory, "s")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(socket, 0o600); err != nil {
			listener.Close()
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer listener.Close()
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(time.Second))
			io.ReadFull(connection, make([]byte, len(askpassRequest)))
			io.WriteString(connection, response)
		}()
		var output bytes.Buffer
		_, code := RunAskpass([]string{askpassArgument, socket}, &output)
		listener.Close()
		<-done
		if code == 0 || output.Len() != 0 {
			t.Fatal("malformed IPC response was accepted or printed to OpenSSH")
		}
	}
}

func TestAskpassWorkerRejectsUnsafePathsAndArguments(t *testing.T) {
	if handled, _ := RunAskpass([]string{"help"}, new(bytes.Buffer)); handled {
		t.Fatal("normal CLI command was consumed by the private helper")
	}
	helper, cleanup, err := newAskpassRelay(strings.Repeat("a", 64), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	directory := filepath.Dir(helper)
	socket := filepath.Join(directory, "s")
	for _, args := range [][]string{{askpassArgument}, {askpassArgument, socket, "extra"}, {askpassArgument, "relative/s"}, {askpassArgument, helper}} {
		var output bytes.Buffer
		if handled, code := RunAskpass(args, &output); !handled || code == 0 || output.Len() != 0 {
			t.Fatal("unsafe askpass invocation was accepted or printed a secret")
		}
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, code := RunAskpass([]string{askpassArgument, socket}, &output); code == 0 || output.Len() != 0 {
		t.Fatal("an exposed IPC directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "gitctx-ap-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, code := RunAskpass([]string{askpassArgument, filepath.Join(link, "s")}, &output); code == 0 || output.Len() != 0 {
		t.Fatal("a symbolic-link IPC directory was accepted")
	}
	if _, _, err := newAskpassRelay("not a managed passphrase", 1); err == nil {
		t.Fatal("invalid passphrase accepted")
	}
	if _, _, err := newAskpassRelay(strings.Repeat("a", 64), 3); err == nil {
		t.Fatal("an excessive relay request allowance was accepted")
	}
}
