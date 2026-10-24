//go:build darwin || linux

package managedkey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVaultPassphrasesTravelOnStdinNotArguments(t *testing.T) {
	for _, mac := range []bool{true, false} {
		directory := t.TempDir()
		argsPath, inputPath, valuePath := filepath.Join(directory, "args"), filepath.Join(directory, "input"), filepath.Join(directory, "value")
		program := filepath.Join(directory, "mock vault")
		secret, id := strings.Repeat("b", 64), strings.Repeat("a", 32)
		if err := os.WriteFile(valuePath, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\numask 077\nprintf '%s\\n' \"$@\" > " + shellQuote(argsPath) + "\ncase \"$1\" in -i|store) /bin/cat > " + shellQuote(inputPath) + " ;; *) /bin/cat " + shellQuote(valuePath) + " ;; esac\n"
		if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		v := commandVault{program: program, mac: mac}
		if err := v.put(id, secret); err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(argsPath)
		if err != nil || strings.Contains(string(args), secret) {
			t.Fatal("passphrase appeared in vault process arguments")
		}
		input, err := os.ReadFile(inputPath)
		if err != nil || !strings.Contains(string(input), secret) {
			t.Fatal("vault did not receive the passphrase on stdin")
		}
		if mac && (string(args) != "-i\n" || strings.Contains(string(input), " -A") || !strings.Contains(string(input), `-T ""`)) {
			t.Fatal("macOS vault used an unsafe access/argument policy")
		}
		if got, err := v.get(id); err != nil || got != secret {
			t.Fatalf("read-back failed: %v", err)
		}
		if err := v.put("not-a-vault-id", secret); err == nil {
			t.Fatal("invalid vault ID accepted")
		}
	}
}

func TestVaultOutputIsBounded(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write(make([]byte, 4097)); err == nil {
		t.Fatal("unbounded vault response accepted")
	}
}

func TestVaultApprovalAllowsHumanResponseAndRemainsCancellable(t *testing.T) {
	ctx, cancel := vaultApprovalContext()
	defer cancel()
	deadline, ok := ctx.Deadline()
	if remaining := time.Until(deadline); !ok || remaining < 4*time.Minute || remaining > 5*time.Minute {
		t.Fatal("vault approval must allow a bounded five-minute human response, not a 30-second subprocess timeout")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("vault approval is not cancellable")
	}
}

func TestVaultCommandFailuresKeepSecretsPrivateAndDistinguishTimeout(t *testing.T) {
	program := filepath.Join(t.TempDir(), "mock approval")
	// Even hostile command output must never appear in a failure. These are
	// synthetic test values; no real Keychain item or passphrase is accessed.
	script := "#!/bin/sh\n/bin/cat\nprintf '%s\\n' diagnostic-secret >&2\ncase \"$1\" in wait) exec /bin/sleep 5 ;; *) exit 1 ;; esac\n"
	if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"timeout", "cancelled", "refused", "approved"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := []string{"refuse"}
			testProgram := program
			want := errVaultAccess
			switch mode {
			case "timeout":
				short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
				defer stop()
				ctx, args, want = short, []string{"wait"}, errVaultTimeout
			case "cancelled":
				cancel()
				want = errVaultCancelled
			case "approved":
				args, want = []string{"approved"}, nil
				// A real vault returns only the secret after approval.
				approved := filepath.Join(t.TempDir(), "approved vault")
				if err := os.WriteFile(approved, []byte("#!/bin/sh\n/bin/sleep 0.1\nexec /bin/cat\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				testProgram = approved
			}
			secret := strings.Repeat("d", 64)
			output, err := vaultCommandContext(ctx, testProgram, args, secret)
			if want == nil {
				if err != nil || string(output) != secret {
					t.Fatal("approval did not return the secret privately")
				}
				return
			}
			if !errors.Is(err, want) || len(output) != 0 {
				t.Fatal("vault failure lost its safe error category or returned secret output")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "diagnostic-secret") {
				t.Fatal("vault failure exposed command output")
			}
		})
	}
}
