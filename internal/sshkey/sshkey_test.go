package sshkey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeExecutor struct {
	run    func([]string, io.Reader, io.Writer, io.Writer) error
	output func([]string) ([]byte, error)
}

func (fake fakeExecutor) Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if fake.run == nil {
		return nil
	}
	return fake.run(args, stdin, stdout, stderr)
}

func (fake fakeExecutor) Output(args []string) ([]byte, error) {
	if fake.output != nil {
		return fake.output(args)
	}
	return []byte("256 SHA256:matching gitctx:test (ED25519)\n"), nil
}

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := DefaultPath("personal.one")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh", "id_ed25519_gitctx_personal.one")
	if path != want {
		t.Fatalf("DefaultPath() = %q, want %q", path, want)
	}
	if _, err := DefaultPath("../unsafe"); err == nil {
		t.Fatal("DefaultPath accepted an invalid profile name")
	}
}

func TestGeneratePublishesValidatedPairWithoutClobber(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "keys with spaces", "personal key")
	input := strings.NewReader("passphrase input")
	var stdout, stderr bytes.Buffer
	var capturedArgs []string
	runner := fakeExecutor{run: func(args []string, stdin io.Reader, out, errOut io.Writer) error {
		capturedArgs = append([]string(nil), args...)
		if stdin != input || out != &stdout || errOut != &stderr {
			t.Fatal("Generate did not pass the supplied streams directly to ssh-keygen")
		}
		private := optionValue(t, args, "-f")
		writeFakePair(t, private, 0o666, 0o666)
		return nil
	}}

	pair, err := generate("personal", destination, input, &stdout, &stderr, runner)
	if err != nil {
		t.Fatal(err)
	}
	absDestination, err := canonicalTestPath(destination)
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivatePath != absDestination || pair.PublicPath != absDestination+".pub" || pair.Fingerprint != "SHA256:matching" {
		t.Fatalf("Generate() pair = %#v", pair)
	}
	if strings.Join(capturedArgs, " ") == "" || optionValue(t, capturedArgs, "-t") != "ed25519" {
		t.Fatalf("ssh-keygen args = %#v", capturedArgs)
	}
	for _, forbidden := range []string{"-N", "--", "passphrase input"} {
		for _, arg := range capturedArgs {
			if arg == forbidden {
				t.Fatalf("ssh-keygen args unexpectedly contain %q: %#v", forbidden, capturedArgs)
			}
		}
	}
	if runtime.GOOS != "windows" {
		assertMode(t, pair.PrivatePath, 0o600)
		assertMode(t, pair.PublicPath, 0o644)
	}
	entries, err := os.ReadDir(filepath.Dir(pair.PrivatePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".gitctx-keygen-") || strings.HasSuffix(entry.Name(), ".gitctx-generate.lock") {
			t.Fatalf("temporary key-generation artifact remains: %s", entry.Name())
		}
	}
}

func TestGenerateRejectsEveryExistingTargetKindBeforeExecution(t *testing.T) {
	tests := []struct {
		name            string
		requiresSymlink bool
		makeTarget      func(*testing.T, string)
	}{
		{"private file", false, func(t *testing.T, path string) { mustWrite(t, path, "private-original", 0o600) }},
		{"public file", false, func(t *testing.T, path string) { mustWrite(t, path+".pub", "public-original", 0o644) }},
		{"private directory", false, func(t *testing.T, path string) { mustMkdir(t, path) }},
		{"public directory", false, func(t *testing.T, path string) { mustMkdir(t, path+".pub") }},
		{"private dangling symlink", true, func(t *testing.T, path string) { mustSymlink(t, "missing", path) }},
		{"public dangling symlink", true, func(t *testing.T, path string) { mustSymlink(t, "missing", path+".pub") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && test.requiresSymlink {
				t.Skip("symbolic-link creation is not generally available to unprivileged Windows tests")
			}
			destination := filepath.Join(t.TempDir(), "key")
			test.makeTarget(t, destination)
			var calls atomic.Int32
			runner := fakeExecutor{run: func([]string, io.Reader, io.Writer, io.Writer) error {
				calls.Add(1)
				return nil
			}}
			if _, err := generate("personal", destination, nil, io.Discard, io.Discard, runner); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
				t.Fatalf("Generate() error = %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("ssh-keygen ran %d times despite a collision", calls.Load())
			}
		})
	}
}

func TestGeneratePublicationRaceDoesNotOverwriteOrRemoveOtherFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "key")
	runner := fakeExecutor{run: func(args []string, _ io.Reader, _, _ io.Writer) error {
		writeFakePair(t, optionValue(t, args, "-f"), 0o600, 0o644)
		mustWrite(t, destination, "other process's key", 0o600)
		return nil
	}}
	if _, err := generate("personal", destination, nil, io.Discard, io.Discard, runner); err == nil || !strings.Contains(err.Error(), "without overwriting") {
		t.Fatalf("Generate() error = %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "other process's key" {
		t.Fatalf("racing private key was changed: %q", data)
	}
	if _, err := os.Lstat(destination + ".pub"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public key published by failed invocation remains: %v", err)
	}
}

func TestGenerateFailureLeavesNoTargetsOrStagingFiles(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "key")
	runner := fakeExecutor{run: func(args []string, _ io.Reader, _, _ io.Writer) error {
		private := optionValue(t, args, "-f")
		mustWrite(t, private, "-----BEGIN OPENSSH PRIVATE KEY-----\npartial secret\n", 0o600)
		return errors.New("exit status 1")
	}}
	_, err := generate("personal", destination, nil, io.Discard, io.Discard, runner)
	if err == nil || strings.Contains(err.Error(), "partial secret") {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, path := range []string{destination, destination + ".pub"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed generation left %s: %v", path, statErr)
		}
	}
	entries, readErr := os.ReadDir(filepath.Dir(destination))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed generation left artifacts: %#v", entries)
	}
}

func TestGenerateRejectsWritableKeyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and mode check")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	var calls atomic.Int32
	runner := fakeExecutor{run: func([]string, io.Reader, io.Writer, io.Writer) error {
		calls.Add(1)
		return nil
	}}
	if _, err := generate("personal", filepath.Join(dir, "key"), nil, io.Discard, io.Discard, runner); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("Generate() error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("ssh-keygen ran inside an unsafe key directory")
	}
}

func TestGenerateSerializesSameDestination(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "key")
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFirst := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseFirst)
	firstRunner := fakeExecutor{run: func(args []string, _ io.Reader, _, _ io.Writer) error {
		close(started)
		<-release
		writeFakePair(t, optionValue(t, args, "-f"), 0o600, 0o644)
		return nil
	}}
	var secondRuns atomic.Int32
	secondRunner := fakeExecutor{run: func(args []string, _ io.Reader, _, _ io.Writer) error {
		secondRuns.Add(1)
		writeFakePair(t, optionValue(t, args, "-f"), 0o600, 0o644)
		return nil
	}}
	type result struct {
		pair Pair
		err  error
	}
	firstResult := make(chan result, 1)
	secondResult := make(chan result, 1)
	go func() {
		pair, err := generate("personal", destination, nil, io.Discard, io.Discard, firstRunner)
		firstResult <- result{pair, err}
	}()
	select {
	case <-started:
	case early := <-firstResult:
		t.Fatalf("first Generate() returned before ssh-keygen started: %v", early.err)
	case <-time.After(5 * time.Second):
		t.Fatal("first Generate() did not reach ssh-keygen within 5 seconds")
	}
	go func() {
		pair, err := generate("personal", destination, nil, io.Discard, io.Discard, secondRunner)
		secondResult <- result{pair, err}
	}()
	time.Sleep(100 * time.Millisecond)
	if secondRuns.Load() != 0 {
		t.Fatal("second ssh-keygen invocation ran before the first released its lock")
	}
	releaseFirst()
	select {
	case result := <-firstResult:
		if result.err != nil {
			t.Fatalf("first Generate() error = %v", result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first Generate() did not finish within 5 seconds")
	}
	select {
	case result := <-secondResult:
		if result.err == nil || !strings.Contains(result.err.Error(), "already exists") {
			t.Fatalf("second Generate() error = %v", result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Generate() did not finish within 5 seconds")
	}
	if secondRuns.Load() != 0 {
		t.Fatalf("second ssh-keygen ran %d times", secondRuns.Load())
	}
}

func TestInspectPairCanonicalizesSafePrivateSymlinkAndMatchesFingerprints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link creation is not generally available to unprivileged Windows tests")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "actual-key")
	writeFakePair(t, target, 0o600, 0o644)
	alias := filepath.Join(dir, "key-alias")
	mustSymlink(t, target, alias)
	pair, err := inspectPair(alias, fakeExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	canonicalTarget, err := canonicalTestPath(target)
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivatePath != canonicalTarget || pair.PublicPath != canonicalTarget+".pub" || pair.Fingerprint != "SHA256:matching" {
		t.Fatalf("InspectPair() = %#v", pair)
	}
}

func TestInspectPairRejectsMissingUnsafeOrMismatchedPublicKey(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		private := filepath.Join(t.TempDir(), "key")
		mustWrite(t, private, fakePrivate, 0o600)
		if _, err := inspectPair(private, fakeExecutor{}); err == nil || !strings.Contains(err.Error(), "inspect public key") {
			t.Fatalf("InspectPair() error = %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		private := filepath.Join(t.TempDir(), "key")
		writeFakePair(t, private, 0o600, 0o644)
		runner := fakeExecutor{output: func(args []string) ([]byte, error) {
			path := optionValue(t, args, "-f")
			fingerprint := "SHA256:private"
			if strings.HasSuffix(path, ".pub") {
				fingerprint = "SHA256:public"
			}
			return []byte("256 " + fingerprint + " test (ED25519)\n"), nil
		}}
		if _, err := inspectPair(private, runner); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("InspectPair() error = %v", err)
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("public symlink", func(t *testing.T) {
			dir := t.TempDir()
			private := filepath.Join(dir, "key")
			mustWrite(t, private, fakePrivate, 0o600)
			actualPublic := filepath.Join(dir, "actual.pub")
			mustWrite(t, actualPublic, fakePublic, 0o644)
			mustSymlink(t, actualPublic, private+".pub")
			if _, err := inspectPair(private, fakeExecutor{}); err == nil || !strings.Contains(err.Error(), "non-symbolic-link") {
				t.Fatalf("InspectPair() error = %v", err)
			}
		})
	}
	if runtime.GOOS != "windows" {
		t.Run("loose private permissions", func(t *testing.T) {
			private := filepath.Join(t.TempDir(), "key")
			writeFakePair(t, private, 0o644, 0o644)
			if _, err := inspectPair(private, fakeExecutor{}); err == nil || !strings.Contains(err.Error(), "permissions") {
				t.Fatalf("InspectPair() error = %v", err)
			}
		})
	}
}

func TestInspectPairWithRealSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	private := filepath.Join(t.TempDir(), "key")
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", private, "-C", "gitctx-test")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create test key: %v: %s", err, output)
	}
	pair, err := InspectPair(private)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pair.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint = %q", pair.Fingerprint)
	}
	publicKey, err := os.ReadFile(pair.PublicPath)
	if err != nil {
		t.Fatal(err)
	}
	inlineFingerprint, err := Fingerprint("key::" + strings.TrimSpace(string(publicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if inlineFingerprint != pair.Fingerprint {
		t.Fatalf("inline fingerprint = %q, want %q", inlineFingerprint, pair.Fingerprint)
	}
}

const fakePrivate = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-private-material\n-----END OPENSSH PRIVATE KEY-----\n"
const fakePublic = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey gitctx:test\n"

func writeFakePair(t *testing.T, private string, privateMode, publicMode os.FileMode) {
	t.Helper()
	mustWrite(t, private, fakePrivate, privateMode)
	mustWrite(t, private+".pub", fakePublic, publicMode)
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func optionValue(t *testing.T, args []string, option string) string {
	t.Helper()
	for index := range args {
		if args[index] == option && index+1 < len(args) {
			return args[index+1]
		}
	}
	t.Fatalf("option %s missing from arguments %#v", option, args)
	return ""
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %04o, want %04o", path, got, want)
	}
}

func canonicalTestPath(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func TestFingerprintRejectsUnexpectedOutput(t *testing.T) {
	runner := fakeExecutor{output: func([]string) ([]byte, error) {
		return []byte(fmt.Sprintf("%s\n", "not-a-fingerprint")), nil
	}}
	if _, err := fingerprint("key", runner); err == nil {
		t.Fatal("fingerprint accepted output without a SHA256 fingerprint")
	}
}
