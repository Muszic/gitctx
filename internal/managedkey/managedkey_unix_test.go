//go:build darwin || linux

package managedkey

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitctx/internal/profile"
)

// This test vault uses throwaway fixture files only. Production never writes
// the passphrase to such a file: it uses Keychain/Secret Service instead.
type fixtureVault struct {
	directory string
	fail      bool
	gets      int
	readErr   error
	readValue string
	afterGet  func()
}

func (v *fixtureVault) put(id, secret string) error {
	if v.fail {
		return errors.New("locked test vault")
	}
	return os.WriteFile(filepath.Join(v.directory, id), []byte(secret), 0o600)
}
func (v *fixtureVault) get(id string) (string, error) {
	v.gets++
	if v.readErr != nil {
		return "", v.readErr
	}
	if v.readValue != "" {
		return v.readValue, nil
	}
	b, err := os.ReadFile(filepath.Join(v.directory, id))
	if err == nil && v.afterGet != nil {
		v.afterGet()
	}
	return string(b), err
}
func testAgent(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"ssh-agent", "ssh-add", "ssh-keygen", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	directory, err := os.MkdirTemp("", "gctx-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "s")
	command := exec.Command("ssh-agent", "-D", "-a", socket)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Skipf("cannot start isolated test agent: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated SSH agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Setenv("SSH_AUTH_SOCK", socket)
}

func testRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", name, err, output)
	}
	return string(output)
}

func TestManagedKeyEncryptedGenerationUnlockAndSignedCommit(t *testing.T) {
	testAgent(t)
	vault := &fixtureVault{directory: t.TempDir()}
	manager := &Manager{vault: vault}
	if err := manager.Preflight(); err != nil {
		t.Fatal(err)
	}
	// An unrelated key stands in for the work key. It must remain loaded.
	workKey := filepath.Join(t.TempDir(), "work")
	testRun(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", workKey)
	testRun(t, "ssh-add", workKey)
	workFingerprint := strings.Fields(testRun(t, "ssh-keygen", "-lf", workKey))[1]
	config := filepath.Join(t.TempDir(), "user with spaces", "config.json")
	key, err := manager.Create("personal", config)
	if err != nil {
		t.Fatal(err)
	}
	if !validHex(key.ID, 32) {
		t.Fatal("invalid vault ID")
	}
	if vault.gets != 1 {
		t.Fatal("generation and initial unlock must share one approved vault read")
	}
	info, err := os.Stat(key.Pair.PrivatePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("private-key permissions are unsafe")
	}
	// A truly encrypted private key cannot be decrypted with an empty password.
	if err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", key.Pair.PrivatePath).Run(); err == nil {
		t.Fatal("managed key was stored without encryption")
	}
	selected := profile.Profile{GitName: "Native User", GitEmail: "native@example.invalid", GitHubUser: "native-user", GitHubAccountID: 42, SSHKey: key.Pair.PrivatePath, SSHFingerprint: key.Pair.Fingerprint, SigningKey: key.Pair.PublicPath, SigningFormat: "ssh", ManagedKeyID: key.ID, GitHubConnected: true}
	if err := manager.Unlock(selected); err != nil {
		t.Fatal(err)
	}
	if vault.gets != 1 {
		t.Fatal("already loaded key unnecessarily accessed the vault")
	}
	// A fresh manager represents another invocation, not a persistent
	// in-process passphrase cache. Reuse must also work with a locked vault.
	locked := &fixtureVault{directory: t.TempDir(), readErr: errors.New("must not read a locked vault")}
	if err := (&Manager{vault: locked}).Unlock(selected); err != nil || locked.gets != 0 {
		t.Fatal("a repeated invocation reread the vault despite a loaded matching key")
	}
	listing := testRun(t, "ssh-add", "-l", "-E", "sha256")
	if !strings.Contains(listing, workFingerprint) || !strings.Contains(listing, key.Pair.Fingerprint) {
		t.Fatal("unlock removed the existing work key or failed to add the personal key")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(key.Pair.PrivatePath), ".askpass-*"))
	if len(leftovers) != 0 {
		t.Fatal("askpass helper was not cleaned up")
	}
	repository := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "empty-global"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	testRun(t, "git", "init", "--quiet", "--template=", repository)
	for field, value := range map[string]string{"user.name": selected.GitName, "user.email": selected.GitEmail, "user.signingKey": key.Pair.PublicPath, "gpg.format": "ssh", "commit.gpgSign": "true"} {
		testRun(t, "git", "-C", repository, "config", "--local", field, value)
	}
	testRun(t, "git", "-C", repository, "commit", "--allow-empty", "-m", "native managed-key signing")
	publicKey, err := os.ReadFile(key.Pair.PublicPath)
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(t.TempDir(), "allowed-signers")
	if err := os.WriteFile(allowed, append([]byte(selected.GitEmail+" "), publicKey...), 0o600); err != nil {
		t.Fatal(err)
	}
	testRun(t, "git", "-C", repository, "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD")
	// Loading again after agent eviction requires no new browser authorization.
	testRun(t, "ssh-add", "-d", key.Pair.PublicPath)
	beforeUnlock := vault.gets
	if err := manager.Unlock(selected); err != nil {
		t.Fatal(err)
	}
	if vault.gets != beforeUnlock+1 {
		t.Fatal("a real unlock must read the vault exactly once")
	}
	if listing := testRun(t, "ssh-add", "-l"); !strings.Contains(listing, workFingerprint) {
		t.Fatal("work key lost while re-unlocking")
	}
}

func TestManagedKeyStorageAndTamperFailuresAreClosed(t *testing.T) {
	testAgent(t)
	v := &fixtureVault{directory: t.TempDir(), fail: true}
	m := &Manager{vault: v}
	config := filepath.Join(t.TempDir(), "config.json")
	if _, err := m.Create("personal", config); err == nil {
		t.Fatal("unavailable vault did not stop key creation")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(config), "keys", "*"))
	if len(files) != 0 {
		t.Fatal("key was created despite failed secure storage")
	}
	v.fail = false
	key, err := m.Create("personal", config)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{GitName: "Test", GitEmail: "test@example.invalid", GitHubUser: "test", GitHubAccountID: 42, SSHKey: key.Pair.PrivatePath, SSHFingerprint: "SHA256:" + strings.Repeat("a", 43), ManagedKeyID: key.ID}
	gets := v.gets
	if err := m.Unlock(p); err == nil || v.gets != gets {
		t.Fatal("tampered key accessed the password vault")
	}
	p.SSHFingerprint = key.Pair.Fingerprint
	testRun(t, "ssh-add", "-d", key.Pair.PublicPath)
	if err := os.Remove(filepath.Join(v.directory, key.ID)); err != nil {
		t.Fatal(err)
	}
	if err := m.Unlock(p); err == nil {
		t.Fatal("missing passphrase did not fail closed")
	}
}

func TestAgentListingRequiresExactFingerprintField(t *testing.T) {
	fingerprint := "SHA256:" + strings.Repeat("a", 43)
	other := "SHA256:" + strings.Repeat("b", 43)
	for _, listing := range []string{"", "256 " + other + " comment mentions " + fingerprint + " (ED25519)\n", "256 " + fingerprint + "suffix (ED25519)\n"} {
		if agentListingContains(listing, fingerprint) {
			t.Fatal("a missing key or a fingerprint appearing only in a comment was treated as loaded")
		}
	}
	if !agentListingContains("256 "+other+" work (ED25519)\n256 "+fingerprint+" personal (ED25519)\n", fingerprint) {
		t.Fatal("the selected key's exact agent fingerprint was not recognized")
	}
	if agentListingContains("256 "+fingerprint+" personal (ED25519)\n", "") {
		t.Fatal("an empty requested fingerprint matched the agent")
	}
}

func TestManagedKeyInitialAgentFailureRetainsEncryptedPairForRetry(t *testing.T) {
	testAgent(t)
	socket := os.Getenv("SSH_AUTH_SOCK")
	v := &fixtureVault{directory: t.TempDir()}
	v.afterGet = func() { t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing-agent")) }
	m := &Manager{vault: v}
	key, err := m.Create("personal", filepath.Join(t.TempDir(), "config.json"))
	if err == nil || key.ID == "" || key.Pair.PrivatePath == "" || v.gets != 1 {
		t.Fatal("initial agent failure lost generated-key metadata or reread the vault")
	}
	if err := exec.Command("ssh-keygen", "-y", "-P", "", "-f", key.Pair.PrivatePath).Run(); err == nil {
		t.Fatal("failed agent setup left an unencrypted key")
	}
	v.afterGet = nil
	t.Setenv("SSH_AUTH_SOCK", socket)
	selected := profile.Profile{GitName: "Native User", GitEmail: "native@example.invalid", GitHubUser: "native-user", GitHubAccountID: 42, SSHKey: key.Pair.PrivatePath, SSHFingerprint: key.Pair.Fingerprint, ManagedKeyID: key.ID}
	if err := m.Unlock(selected); err != nil || v.gets != 2 {
		t.Fatal("retry did not unlock the retained key with one approved vault read")
	}
}

func TestManagedKeyReadbackFailureExplainsCauseWithoutGeneratingKey(t *testing.T) {
	for _, cause := range []error{errVaultTimeout, errVaultCancelled, errVaultAccess, nil} {
		v := &fixtureVault{directory: t.TempDir(), readErr: cause}
		if cause == nil {
			v.readValue = "a deliberately mismatched vault value"
		}
		m := &Manager{vault: v}
		config := filepath.Join(t.TempDir(), "config.json")
		_, err := m.Create("personal", config)
		if err == nil || !strings.Contains(err.Error(), "no SSH key was generated") || (cause != nil && !errors.Is(err, cause)) {
			t.Fatal("vault read-back failure did not preserve a safe, actionable cause")
		}
		if strings.Contains(err.Error(), v.readValue) && v.readValue != "" {
			t.Fatal("vault mismatch error exposed its returned value")
		}
		entries, readErr := os.ReadDir(filepath.Join(filepath.Dir(config), "keys"))
		if readErr != nil || len(entries) != 0 {
			t.Fatal("failed vault verification generated a key or askpass helper")
		}
	}
}

func TestManagedKeyRejectsSymlinkAndExposedDirectory(t *testing.T) {
	v := &fixtureVault{directory: t.TempDir()}
	m := &Manager{vault: v}
	for _, symlink := range []bool{true, false} {
		directory := t.TempDir()
		keys := filepath.Join(directory, "keys")
		if symlink {
			if err := os.Symlink(t.TempDir(), keys); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(keys, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keys, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.Create("personal", filepath.Join(directory, "config.json")); err == nil {
			t.Fatal("unsafe key directory accepted")
		}
	}
}

func TestManagedKeyRequiresExistingAgentAndNeverOverridesWorkAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	m := &Manager{vault: &fixtureVault{directory: t.TempDir()}}
	if err := m.Preflight(); err == nil || !strings.Contains(err.Error(), "will not replace") {
		t.Fatalf("missing agent error=%v", err)
	}
	t.Setenv("SSH_ASKPASS", "/untrusted-helper")
	t.Setenv("SSH_ASKPASS_REQUIRE", "prefer")
	env := askpassEnvironment("/managed-helper")
	if strings.Contains(strings.Join(env, "\n"), "untrusted-helper") {
		t.Fatal("inherited askpass retained")
	}
}
